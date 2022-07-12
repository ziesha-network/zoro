#[macro_use]
extern crate lazy_static;

mod bank;
mod circuits;
mod config;
mod core;

use bazuka::core::ZkHasher;
use bazuka::crypto::{jubjub, ZkSignatureScheme};
use bazuka::db::KvStore;
use bazuka::zk::ZeroTransaction;
use bellman::{groth16, Circuit};
use bls12_381::Bls12;
use rand_core::OsRng;
use std::fs::File;
use zeekit::BellmanFr;

fn load_params<C: Circuit<BellmanFr> + Default>(
    path: &str,
    use_cache: bool,
) -> groth16::Parameters<Bls12> {
    if use_cache {
        let param_file = File::open(path).expect("Unable to open parameters file!");
        groth16::Parameters::<Bls12>::read(param_file, false /* false for better performance*/)
            .expect("Unable to read parameters file!")
    } else {
        let c = C::default();

        let p = groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap();
        let param_file = File::create(path).expect("Unable to create parameters file!");
        p.write(param_file)
            .expect("Unable to write parameters file!");
        p
    }
}

fn main() {
    let use_cache = false;
    let update_params = load_params::<circuits::UpdateCircuit>("groth16_mpn_update.dat", use_cache);
    let deposit_withdraw_params = load_params::<circuits::DepositWithdrawCircuit>(
        "groth16_mpn_deposit_withdraw.dat",
        use_cache,
    );

    let mut db = bazuka::db::RamKvStore::new();

    db.update(&[bazuka::db::WriteOp::Put(
        format!("contract_{}", bank::CONTRACT_ID.clone()).into(),
        bazuka::zk::ZkContract {
            initial_state: bazuka::zk::ZkCompressedState::empty::<ZkHasher>(
                bank::STATE_MODEL.clone(),
            )
            .into(),
            state_model: bank::STATE_MODEL.clone(),
            log4_deposit_withdraw_capacity: 0,
            deposit_withdraw_function: bazuka::zk::ZkVerifierKey::Dummy,
            functions: vec![],
        }
        .into(),
    )])
    .unwrap();

    let mut b = bank::Bank::new(update_params, deposit_withdraw_params, db);
    let alice_keys = jubjub::JubJub::<ZkHasher>::generate_keys(b"alice");
    let bob_keys = jubjub::JubJub::<ZkHasher>::generate_keys(b"bob");
    let charlie_keys = jubjub::JubJub::<ZkHasher>::generate_keys(b"charlie");
    let alice_index = 0;
    let bob_index = 1;
    let charlie_index = 2;

    b.deposit_withdraw(vec![
        core::DepositWithdraw {
            index: alice_index,
            pub_key: alice_keys.0.clone(),
            amount: 1000,
        },
        core::DepositWithdraw {
            index: bob_index,
            pub_key: bob_keys.0.clone(),
            amount: 500,
        },
        core::DepositWithdraw {
            index: alice_index,
            pub_key: alice_keys.0.clone(),
            amount: -200,
        },
    ])
    .unwrap();

    println!("{:?}", b.balances());

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

    b.change_state(vec![tx1, tx2, tx3, tx4]).unwrap();
    println!("{:?}", b.balances());
}
