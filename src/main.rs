#[macro_use]
extern crate lazy_static;

mod bank;
mod circuits;
mod config;

use circuits::DepositWithdraw;

use bazuka::config::blockchain::MPN_CONTRACT_ID;
use bazuka::core::{Money, PaymentDirection};
use bazuka::db::KvStore;
use bazuka::db::ReadOnlyLevelDbKvStore;
use bellman::{groth16, Circuit};
use bls12_381::Bls12;
use colored::Colorize;
use rand_core::OsRng;
use std::fs::File;
use std::path::PathBuf;
use structopt::StructOpt;
use zeekit::BellmanFr;

#[derive(Debug, StructOpt)]
#[structopt(name = "Zoro", about = "Zeeka's MPN Executor")]
struct Opt {
    #[structopt(long)]
    seed: String,
    #[structopt(long)]
    node: String,
    #[structopt(long, default_value = "mainnet")]
    network: String,
    #[structopt(long, default_value = "update_params.dat")]
    update_circuit_params: PathBuf,
    #[structopt(long, default_value = "payment_params.dat")]
    payment_circuit_params: PathBuf,
    #[structopt(long)]
    generate_params: bool,
}

fn load_params<C: Circuit<BellmanFr> + Default>(
    path: PathBuf,
    generate: bool,
) -> groth16::Parameters<Bls12> {
    if generate {
        log::info!("Generating {}...", path.to_string_lossy());
        let c = C::default();

        let p = groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap();
        let param_file = File::create(path.clone()).expect("Unable to create parameters file!");
        p.write(param_file)
            .expect("Unable to write parameters file!");
        println!("VK of {}: {}", path.to_string_lossy(), vk_to_hex(&p.vk));
        p
    } else {
        log::info!("Loading {}...", path.to_string_lossy());
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

fn db_shutter() -> ReadOnlyLevelDbKvStore {
    ReadOnlyLevelDbKvStore::read_only(std::path::Path::new("/home/keyvan/.bazuka"), 64).unwrap()
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

fn transact(
    node: bazuka::client::PeerAddress,
    tx: bazuka::core::TransactionAndDelta,
) -> Result<bazuka::client::messages::TransactResponse, ZoroError> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let sk =
                <bazuka::core::Signer as bazuka::crypto::SignatureScheme>::generate_keys(b"dummy")
                    .1;
            let (lp, client) = bazuka::client::BazukaClient::connect(sk, node, "mainnet".into());

            let (res, _) = tokio::join!(
                async move { Ok::<_, bazuka::client::NodeError>(client.transact(tx).await) },
                lp
            );

            res
        })??)
}

fn get_account(
    node: bazuka::client::PeerAddress,
    address: bazuka::core::Address,
) -> Result<bazuka::client::messages::GetAccountResponse, ZoroError> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let sk =
                <bazuka::core::Signer as bazuka::crypto::SignatureScheme>::generate_keys(b"dummy")
                    .1;
            let (lp, client) = bazuka::client::BazukaClient::connect(sk, node, "mainnet".into());

            let (res, _) = tokio::join!(
                async move { Ok::<_, bazuka::client::NodeError>(client.get_account(address).await) },
                lp
            );

            res
        })??)
}

fn get_zero_mempool(
    node: bazuka::client::PeerAddress,
) -> Result<bazuka::client::messages::GetZeroMempoolResponse, ZoroError> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let sk =
                <bazuka::core::Signer as bazuka::crypto::SignatureScheme>::generate_keys(b"dummy")
                    .1;
            let (lp, client) = bazuka::client::BazukaClient::connect(sk, node, "mainnet".into());

            let (res, _) = tokio::join!(
                async move { Ok::<_, bazuka::client::NodeError>(client.get_zero_mempool().await) },
                lp
            );

            res
        })??)
}

fn chain_height<K: bazuka::db::KvStore>(db: &K) -> u64 {
    if let Some(v) = db.get("height".into()).unwrap() {
        v.try_into().unwrap()
    } else {
        0
    }
}

fn process_payments<K: bazuka::db::KvStore>(
    b: &bank::Bank,
    node_addr: bazuka::client::PeerAddress,
    db_mirror: &mut bazuka::db::RamMirrorKvStore<K>,
) -> Result<bazuka::core::ContractUpdate, ZoroError> {
    let mempool = get_zero_mempool(node_addr)?;

    let contract_payments = mempool
        .payments
        .iter()
        .filter(|dw| dw.contract_id == *MPN_CONTRACT_ID)
        .cloned()
        .collect::<Vec<_>>();

    let payments = contract_payments
        .iter()
        .map(|dw| DepositWithdraw {
            index: dw.zk_address_index,
            pub_key: dw.zk_address.0.decompress(),
            amount: match dw.direction {
                PaymentDirection::Deposit(_) => (Into::<u64>::into(dw.amount) as i64),
                PaymentDirection::Withdraw(_) => -(Into::<u64>::into(dw.amount) as i64),
            },
        })
        .collect::<Vec<_>>();

    let (new_root, proof) = b.deposit_withdraw(db_mirror, payments)?;

    Ok(bazuka::core::ContractUpdate::Payment {
        circuit_id: 0,
        payments: contract_payments,
        next_state: new_root,
        proof: bazuka::zk::ZkProof::Groth16(Box::new(proof)),
    })
}

fn process_updates<K: bazuka::db::KvStore>(
    b: &bank::Bank,
    node_addr: bazuka::client::PeerAddress,
    db_mirror: &mut bazuka::db::RamMirrorKvStore<K>,
) -> Result<bazuka::core::ContractUpdate, ZoroError> {
    let mempool = get_zero_mempool(node_addr)?;

    let updates = mempool.updates.iter().cloned().collect::<Vec<_>>();

    let (new_root, proof) = b.change_state(db_mirror, updates)?;

    Ok(bazuka::core::ContractUpdate::FunctionCall {
        fee: Money(0),
        function_id: 0,
        next_state: new_root,
        proof: bazuka::zk::ZkProof::Groth16(Box::new(proof)),
    })
}

fn main() {
    env_logger::init();
    println!(
        "{} v{} - A CPU-based MPN Executor for Zeeka Cryptocurrency",
        "Zoro!".bright_green(),
        env!("CARGO_PKG_VERSION")
    );
    let opt = Opt::from_args();

    let exec_wallet = bazuka::wallet::Wallet::new(opt.seed.as_bytes().to_vec());

    let update_params =
        load_params::<circuits::UpdateCircuit>(opt.update_circuit_params, opt.generate_params);
    let deposit_withdraw_params = load_params::<circuits::DepositWithdrawCircuit>(
        opt.payment_circuit_params,
        opt.generate_params,
    );

    let node_addr = bazuka::client::PeerAddress(opt.node.parse().unwrap());

    let b = bank::Bank::new(update_params, deposit_withdraw_params);

    let mut latest_processed = None;
    loop {
        let db_shutter = db_shutter();
        let db = db_shutter.snapshot();

        if latest_processed == Some(chain_height(&db)) {
            std::thread::sleep(std::time::Duration::from_millis(1000));
            continue;
        } else {
            latest_processed = Some(chain_height(&db));
        }

        let mut db_mirror = db.mirror();
        let mut acc = get_account(node_addr, exec_wallet.get_address())
            .unwrap()
            .account;

        let mut updates = Vec::new();

        let start = std::time::Instant::now();
        println!(
            "{} {}",
            "Processing:".bright_yellow(),
            "Payment-Transactions..."
        );
        println!(
            "{} {} {}",
            bazuka::config::SYMBOL.bright_red(),
            "Alice is shuffling the balls!".bright_cyan(),
            bazuka::config::SYMBOL.bright_red()
        );
        updates.push(process_payments(&b, node_addr, &mut db_mirror).unwrap());
        println!(
            "{} {}ms",
            "Proving took:".bright_green(),
            (std::time::Instant::now() - start).as_millis()
        );

        let start = std::time::Instant::now();
        println!(
            "{} {}",
            "Processing:".bright_yellow(),
            "Zero-Transactions..."
        );
        println!(
            "{} {} {}",
            bazuka::config::SYMBOL.bright_red(),
            "Alice is shuffling the balls!".bright_cyan(),
            bazuka::config::SYMBOL.bright_red()
        );
        updates.push(process_updates(&b, node_addr, &mut db_mirror).unwrap());
        println!(
            "{} {}ms",
            "Proving took:".bright_green(),
            (std::time::Instant::now() - start).as_millis()
        );

        let mut update = bazuka::core::Transaction {
            src: exec_wallet.get_address(),
            nonce: acc.nonce + 1,
            fee: Money(0),
            data: bazuka::core::TransactionData::UpdateContract {
                contract_id: *MPN_CONTRACT_ID,
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

        transact(node_addr, tx_delta).unwrap();
    }
}
