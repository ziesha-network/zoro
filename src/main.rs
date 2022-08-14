#[macro_use]
extern crate lazy_static;

mod bank;
mod circuits;
mod config;
mod core;

use circuits::DepositWithdraw;

use bazuka::config::blockchain::MPN_CONTRACT_ID;
use bazuka::core::{Money, PaymentDirection};
use bazuka::db::ReadOnlyLevelDbKvStore;
use bellman::{groth16, Circuit};
use bls12_381::Bls12;
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
        let c = C::default();

        let p = groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap();
        let param_file = File::create(path.clone()).expect("Unable to create parameters file!");
        p.write(param_file)
            .expect("Unable to write parameters file!");
        println!("VK of {}: {}", path.to_string_lossy(), vk_to_hex(&p.vk));
        p
    } else {
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

fn main() {
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

        let acc = get_account(node_addr, exec_wallet.get_address())
            .unwrap()
            .account;

        if latest_processed == Some(chain_height(&db)) {
            std::thread::sleep(std::time::Duration::from_millis(1000));
            continue;
        }

        println!("Processing block...");

        latest_processed = Some(chain_height(&db));

        let mempool = get_zero_mempool(node_addr).unwrap();

        let contract_payments = mempool
            .payments
            .iter()
            .filter(|dw| dw.contract_id == *MPN_CONTRACT_ID)
            .cloned()
            .take(config::BATCH_SIZE)
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
        println!(
            "Got {}/{} transactions...",
            payments.len(),
            config::BATCH_SIZE
        );

        let (delta, new_root, proof) = b.deposit_withdraw(&db, payments).unwrap();

        let dw = bazuka::core::ContractUpdate::Payment {
            payments: contract_payments,
            next_state: new_root,
            proof: bazuka::zk::ZkProof::Groth16(Box::new(proof)),
        };

        let mut update = bazuka::core::Transaction {
            src: exec_wallet.get_address(),
            nonce: acc.nonce + 1,
            fee: Money(0),
            data: bazuka::core::TransactionData::UpdateContract {
                contract_id: *MPN_CONTRACT_ID,
                updates: vec![dw],
            },
            sig: bazuka::core::Signature::Unsigned,
        };
        exec_wallet.sign(&mut update);

        let tx_delta = bazuka::core::TransactionAndDelta {
            tx: update,
            state_delta: Some(delta),
        };

        transact(node_addr, tx_delta).unwrap();
    }

    /*println!("{:?}", b.balances(&db));

    let mut tx1 = ZeroTransaction {
        nonce: 0,
        src_index: alice_index,
        dst_index: bob_index,
        dst_pub_key: bob_keys.0.clone(),
        amount: 200,
        fee: 1,
        sig: jubjub::Signature::default(),
    };
    tx1.sign(alice_keys.1.clone());

    let mut tx2 = ZeroTransaction {
        nonce: 0,
        src_index: bob_index,
        dst_index: alice_index,
        dst_pub_key: alice_keys.0.clone(),
        amount: 50,
        fee: 1,
        sig: jubjub::Signature::default(),
    };
    tx2.sign(bob_keys.1.clone());

    let mut tx3 = ZeroTransaction {
        nonce: 1,
        src_index: bob_index,
        dst_index: alice_index,
        dst_pub_key: alice_keys.0.clone(),
        amount: 647,
        fee: 2,
        sig: jubjub::Signature::default(),
    };
    tx3.sign(bob_keys.1);

    let mut tx4 = ZeroTransaction {
        nonce: 1,
        src_index: alice_index,
        dst_index: charlie_index,
        dst_pub_key: charlie_keys.0.clone(),
        amount: 197,
        fee: 2,
        sig: jubjub::Signature::default(),
    };
    tx4.sign(alice_keys.1);

    b.change_state(&db, vec![tx1, tx2, tx3, tx4]).unwrap();
    println!("{:?}", b.balances(&db));*/
}
