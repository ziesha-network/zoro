mod bank;
mod circuits;
mod client;
mod config;

use circuits::{Deposit, Withdraw};

use bazuka::blockchain::BlockchainConfig;
use bazuka::config::blockchain::get_blockchain_config;
use bazuka::core::{Money, MpnDeposit, MpnWithdraw};
use bazuka::db::KvStore;
use bazuka::db::ReadOnlyLevelDbKvStore;
use bazuka::zk::MpnTransaction;
use bellman::{groth16, Circuit};
use bls12_381::Bls12;
use client::SyncClient;
use colored::Colorize;
use std::fs::File;
use std::path::PathBuf;
use structopt::StructOpt;
use zeekit::BellmanFr;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Debug, StructOpt)]
#[structopt(name = "Zoro", about = "Zeeka's MPN Executor")]
struct Opt {
    #[structopt(long)]
    seed: String,
    #[structopt(long)]
    node: String,
    #[structopt(long)]
    db: String,
    #[structopt(long, default_value = "mainnet")]
    network: String,
    #[structopt(long, default_value = "update_params.dat")]
    update_circuit_params: PathBuf,
    #[structopt(long, default_value = "deposit_params.dat")]
    deposit_circuit_params: PathBuf,
    #[structopt(long, default_value = "withdraw_params.dat")]
    withdraw_circuit_params: PathBuf,
    #[structopt(long)]
    generate_params: bool,
    #[structopt(long, default_value = "1")]
    deposit_batches: usize,
    #[structopt(long, default_value = "1")]
    withdraw_batches: usize,
    #[structopt(long, default_value = "1")]
    update_batches: usize,
    #[structopt(long)]
    gpu: bool,
    #[structopt(long, default_value = "")]
    miner_token: String,
}

fn load_params<C: Circuit<BellmanFr> + Default>(
    path: PathBuf,
    generate: bool,
) -> groth16::Parameters<Bls12> {
    if generate {
        println!("Generating {}...", path.to_string_lossy());
        let c = C::default();

        let mut rng = rand::thread_rng();
        let p = groth16::generate_random_parameters::<Bls12, _, _>(c, &mut rng).unwrap();
        let param_file = File::create(path.clone()).expect("Unable to create parameters file!");
        p.write(param_file)
            .expect("Unable to write parameters file!");
        println!("VK of {}: {}", path.to_string_lossy(), vk_to_hex(&p.vk));
        p
    } else {
        println!("Loading {}...", path.to_string_lossy());
        let param_file = File::open(path).expect("Unable to open parameters file!");
        groth16::Parameters::<Bls12>::read(param_file, false /* false for better performance*/)
            .expect("Unable to read parameters file!")
    }
}

fn vk_to_hex(vk: &bellman::groth16::VerifyingKey<Bls12>) -> String {
    hex::encode(
        &bincode::serialize(&unsafe {
            std::mem::transmute::<
                bellman::groth16::VerifyingKey<Bls12>,
                bazuka::zk::groth16::Groth16VerifyingKey,
            >(vk.clone())
        })
        .unwrap(),
    )
}

fn db_shutter(path: &str) -> ReadOnlyLevelDbKvStore {
    ReadOnlyLevelDbKvStore::read_only(std::path::Path::new(path), 64).unwrap()
}

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZoroError {
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("node error: {0}")]
    NodeError(#[from] bazuka::client::NodeError),
    #[error("bank error: {0}")]
    BankError(#[from] bank::BankError),
}

fn process_deposits<K: bazuka::db::KvStore>(
    conf: &BlockchainConfig,
    mempool: &mut HashMap<MpnDeposit, ()>,
    b: &bank::Bank<
        { config::LOG4_DEPOSIT_BATCH_SIZE },
        { config::LOG4_WITHDRAW_BATCH_SIZE },
        { config::LOG4_UPDATE_BATCH_SIZE },
        { config::LOG4_TREE_SIZE },
    >,
    db_mirror: &mut bazuka::db::RamMirrorKvStore<K>,
    cancel: &Arc<RwLock<bool>>,
) -> Result<bazuka::core::ContractUpdate, ZoroError> {
    for (tx, _) in mempool
        .clone()
        .iter()
        .filter(|(dw, _)| &dw.payment.contract_id != &conf.mpn_contract_id)
    {
        mempool.remove(tx);
    }

    let deposits = mempool
        .clone()
        .into_keys()
        .map(|dw| Deposit {
            mpn_deposit: Some(dw.clone()),
            index: dw.zk_address_index,
            pub_key: dw.zk_address.0.decompress(),
            amount: dw.payment.amount,
        })
        .collect::<Vec<_>>();

    let (accepted, rejected, new_root, proof) = b.deposit(db_mirror, deposits, cancel.clone())?;

    for tx in accepted.iter().chain(rejected.iter()) {
        mempool.remove(&tx.mpn_deposit.as_ref().unwrap());
    }

    Ok(bazuka::core::ContractUpdate::Deposit {
        deposit_circuit_id: 0,
        deposits: accepted
            .into_iter()
            .map(|dw| dw.mpn_deposit.unwrap().payment)
            .collect(),
        next_state: new_root,
        proof: bazuka::zk::ZkProof::Groth16(Box::new(proof)),
    })
}

fn process_withdraws<K: bazuka::db::KvStore>(
    conf: &BlockchainConfig,
    mempool: &mut HashMap<MpnWithdraw, ()>,
    b: &bank::Bank<
        { config::LOG4_DEPOSIT_BATCH_SIZE },
        { config::LOG4_WITHDRAW_BATCH_SIZE },
        { config::LOG4_UPDATE_BATCH_SIZE },
        { config::LOG4_TREE_SIZE },
    >,
    db_mirror: &mut bazuka::db::RamMirrorKvStore<K>,
    cancel: &Arc<RwLock<bool>>,
) -> Result<bazuka::core::ContractUpdate, ZoroError> {
    for (tx, _) in mempool
        .clone()
        .iter()
        .filter(|(dw, _)| &dw.payment.contract_id != &conf.mpn_contract_id)
    {
        mempool.remove(tx);
    }

    let withdraws = mempool
        .clone()
        .into_keys()
        .map(|dw| Withdraw {
            mpn_withdraw: Some(dw.clone()),
            index: dw.zk_address_index,
            pub_key: dw.zk_address.0.decompress(),
            fingerprint: dw.payment.fingerprint(),
            nonce: dw.zk_nonce,
            sig: dw.zk_sig,
            amount: dw.payment.amount + dw.payment.fee,
        })
        .collect::<Vec<_>>();

    let (accepted, rejected, new_root, proof) = b.withdraw(db_mirror, withdraws, cancel.clone())?;

    for tx in accepted.iter().chain(rejected.iter()) {
        mempool.remove(&tx.mpn_withdraw.as_ref().unwrap());
    }

    Ok(bazuka::core::ContractUpdate::Withdraw {
        withdraw_circuit_id: 0,
        withdraws: accepted
            .into_iter()
            .map(|dw| dw.mpn_withdraw.unwrap().payment)
            .collect(),
        next_state: new_root,
        proof: bazuka::zk::ZkProof::Groth16(Box::new(proof)),
    })
}

fn process_updates<K: bazuka::db::KvStore>(
    mempool: &mut HashMap<MpnTransaction, ()>,
    b: &bank::Bank<
        { config::LOG4_DEPOSIT_BATCH_SIZE },
        { config::LOG4_WITHDRAW_BATCH_SIZE },
        { config::LOG4_UPDATE_BATCH_SIZE },
        { config::LOG4_TREE_SIZE },
    >,
    db_mirror: &mut bazuka::db::RamMirrorKvStore<K>,
    cancel: &Arc<RwLock<bool>>,
) -> Result<bazuka::core::ContractUpdate, ZoroError> {
    let (accepted, rejected, new_root, proof) = b.change_state(
        db_mirror,
        mempool.clone().into_keys().collect(),
        cancel.clone(),
    )?;

    let fee_sum = accepted
        .iter()
        .map(|tx| Into::<u64>::into(tx.fee))
        .sum::<u64>();
    for tx in accepted.into_iter().chain(rejected.into_iter()) {
        mempool.remove(&tx);
    }

    Ok(bazuka::core::ContractUpdate::FunctionCall {
        fee: fee_sum.into(),
        function_id: 0,
        next_state: new_root,
        proof: bazuka::zk::ZkProof::Groth16(Box::new(proof)),
    })
}

fn alice_shuffle() {
    println!(
        "{} {} {}",
        bazuka::config::SYMBOL.bright_red(),
        "Alice is shuffling the balls...".bright_cyan(),
        bazuka::config::SYMBOL.bright_red()
    );
}

fn main() {
    env_logger::init();
    println!(
        "{} v{} - A CPU/GPU-based MPN Executor for Zeeka Cryptocurrency",
        "Zoro!".bright_green(),
        env!("CARGO_PKG_VERSION")
    );
    let opt = Opt::from_args();

    let exec_wallet = bazuka::wallet::TxBuilder::new(opt.seed.as_bytes().to_vec());

    let update_params = load_params::<
        circuits::UpdateCircuit<{ config::LOG4_UPDATE_BATCH_SIZE }, { config::LOG4_TREE_SIZE }>,
    >(opt.update_circuit_params, opt.generate_params);

    let deposit_params = load_params::<
        circuits::DepositCircuit<{ config::LOG4_DEPOSIT_BATCH_SIZE }, { config::LOG4_TREE_SIZE }>,
    >(opt.deposit_circuit_params, opt.generate_params);

    let withdraw_params = load_params::<
        circuits::WithdrawCircuit<{ config::LOG4_WITHDRAW_BATCH_SIZE }, { config::LOG4_TREE_SIZE }>,
    >(opt.withdraw_circuit_params, opt.generate_params);

    let node_addr = bazuka::client::PeerAddress(opt.node.parse().unwrap());
    let client = SyncClient::new(node_addr, &opt.network, opt.miner_token.clone());

    let conf = get_blockchain_config();
    let b = bank::Bank::new(
        conf.clone(),
        update_params,
        deposit_params,
        withdraw_params,
        opt.gpu,
    );

    let mut update_mempool = HashMap::<MpnTransaction, ()>::new();
    let mut deposit_mempool = HashMap::<MpnDeposit, ()>::new();
    let mut withdraw_mempool = HashMap::<MpnWithdraw, ()>::new();

    loop {
        if let Err(e) = || -> Result<(), ZoroError> {
            let cancel = Arc::new(RwLock::new(false));

            let db_shutter = db_shutter(&opt.db);
            let db = db_shutter.snapshot();

            // Wait till mine is done
            if client.is_mining()? {
                log::info!("Nothing to mine!");
                std::thread::sleep(std::time::Duration::from_millis(1000));
                return Ok(());
            }

            // Wait till chain gets updated
            if client.is_outdated()? {
                log::info!("Chain is outdated!");
                std::thread::sleep(std::time::Duration::from_millis(1000));
                return Ok(());
            }

            let curr_height = client.get_height()?;
            println!("Started on height: {}", curr_height);

            let cancel_cloned = cancel.clone();
            let cancel_controller_client = client.clone();
            let (cancel_controller_tx, cancel_controller_rx) = std::sync::mpsc::channel();
            let cancel_controller = std::thread::spawn(move || loop {
                match cancel_controller_rx.try_recv() {
                    Ok(_) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        break;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        if let Ok(height) = cancel_controller_client.get_height() {
                            if height != curr_height {
                                *cancel_cloned.write().unwrap() = true;
                            }
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(2000));
            });

            let mut db_mirror = db.mirror();
            let acc = client.get_account(exec_wallet.get_address())?.account;

            let mempool = client.get_zero_mempool()?;
            for update in mempool.updates.iter() {
                update_mempool.insert(update.clone(), ());
            }
            for deposit in mempool.deposits.iter() {
                deposit_mempool.insert(deposit.clone(), ());
            }
            for withdraw in mempool.withdraws.iter() {
                withdraw_mempool.insert(withdraw.clone(), ());
            }

            let mut updates = Vec::new();

            for i in 0..opt.deposit_batches {
                let start = std::time::Instant::now();
                println!(
                    "{} Deposit-Transactions ({}/{})...",
                    "Processing:".bright_yellow(),
                    i + 1,
                    opt.deposit_batches
                );
                alice_shuffle();
                updates.push(process_deposits(
                    &conf,
                    &mut deposit_mempool,
                    &b,
                    &mut db_mirror,
                    &cancel,
                )?);
                println!(
                    "{} {}ms",
                    "Proving took:".bright_green(),
                    (std::time::Instant::now() - start).as_millis()
                );
            }

            for i in 0..opt.withdraw_batches {
                let start = std::time::Instant::now();
                println!(
                    "{} Withdraw-Transactions ({}/{})...",
                    "Processing:".bright_yellow(),
                    i + 1,
                    opt.withdraw_batches
                );
                alice_shuffle();
                updates.push(process_withdraws(
                    &conf,
                    &mut withdraw_mempool,
                    &b,
                    &mut db_mirror,
                    &cancel,
                )?);
                println!(
                    "{} {}ms",
                    "Proving took:".bright_green(),
                    (std::time::Instant::now() - start).as_millis()
                );
            }

            for i in 0..opt.update_batches {
                let start = std::time::Instant::now();
                println!(
                    "{} Zero-Transactions ({}/{})...",
                    "Processing:".bright_yellow(),
                    i + 1,
                    opt.update_batches
                );
                alice_shuffle();
                updates.push(process_updates(
                    &mut update_mempool,
                    &b,
                    &mut db_mirror,
                    &cancel,
                )?);
                println!(
                    "{} {}ms",
                    "Proving took:".bright_green(),
                    (std::time::Instant::now() - start).as_millis()
                );
            }

            let mut update = bazuka::core::Transaction {
                src: exec_wallet.get_address(),
                nonce: acc.nonce + 1,
                fee: Money(0),
                data: bazuka::core::TransactionData::UpdateContract {
                    contract_id: conf.mpn_contract_id.clone(),
                    updates,
                },
                sig: bazuka::core::Signature::Unsigned,
            };
            exec_wallet.sign(&mut update);

            let ops = db_mirror.to_ops();
            let delta = bank::extract_delta(ops);

            let tx_delta = bazuka::core::TransactionAndDelta {
                tx: update,
                state_delta: Some(delta),
            };

            client.transact(tx_delta)?;

            let _ = cancel_controller_tx.send(());
            cancel_controller.join().unwrap();

            Ok(())
        }() {
            println!("Error happened! Error: {}", e);
            std::thread::sleep(std::time::Duration::from_millis(1000));
        }
    }
}
