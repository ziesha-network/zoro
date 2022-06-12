mod bank;
mod circuits;
mod config;
mod core;

use ff::Field;
//use rand_core::OsRng;
use zeekit::{eddsa, mimc, Fr};

fn main() {
    /*let pp = if std::path::Path::new("params.dat").exists() {
        println!("Reading params...");
        unsafe { PublicParameters::from_slice_unchecked(&std::fs::read("params.dat").unwrap()) }
    } else {
        println!("Generating params...");
        let pp = PublicParameters::setup(1 << 19, &mut OsRng).unwrap();
        std::fs::write("params.dat", pp.to_raw_var_bytes()).unwrap();
        pp
    };
    println!("Params are ready!");*/

    let rand1 = mimc::double_mimc(Fr::one(), Fr::one());
    let rand2 = mimc::double_mimc(Fr::zero(), Fr::one());

    let mut b = bank::Bank::new(/*pp*/);
    let alice_keys = eddsa::generate_keys(rand1, rand2);
    let bob_keys = eddsa::generate_keys(rand2, rand1);
    let charlie_keys = eddsa::generate_keys(rand2, rand2);
    let alice_index = 0;
    let bob_index = 1;
    let charlie_index = 2;

    b.deposit_withdraw(vec![
        core::DepositWithdraw {
            index: alice_index,
            pub_key: alice_keys.0.clone(),
            amount: 1000,
            withdraw: false,
        },
        core::DepositWithdraw {
            index: bob_index,
            pub_key: bob_keys.0.clone(),
            amount: 500,
            withdraw: false,
        },
        core::DepositWithdraw {
            index: alice_index,
            pub_key: alice_keys.0.clone(),
            amount: 200,
            withdraw: true,
        },
    ])
    .unwrap();

    println!("{:?}", b.balances());

    let mut tx1 = core::Transaction {
        nonce: 0,
        src_index: alice_index,
        dst_index: bob_index,
        dst_pub_key: bob_keys.0.clone(),
        amount: 200,
        fee: 1,
        sig: eddsa::Signature::default(),
    };
    tx1.sign(alice_keys.1.clone());

    let mut tx2 = core::Transaction {
        nonce: 0,
        src_index: bob_index,
        dst_index: alice_index,
        dst_pub_key: alice_keys.0.clone(),
        amount: 50,
        fee: 1,
        sig: eddsa::Signature::default(),
    };
    tx2.sign(bob_keys.1.clone());

    let mut tx3 = core::Transaction {
        nonce: 1,
        src_index: bob_index,
        dst_index: alice_index,
        dst_pub_key: alice_keys.0.clone(),
        amount: 647,
        fee: 2,
        sig: eddsa::Signature::default(),
    };
    tx3.sign(bob_keys.1);

    let mut tx4 = core::Transaction {
        nonce: 1,
        src_index: alice_index,
        dst_index: charlie_index,
        dst_pub_key: charlie_keys.0.clone(),
        amount: 197,
        fee: 2,
        sig: eddsa::Signature::default(),
    };
    tx4.sign(alice_keys.1);

    b.change_state(vec![tx1, tx2, tx3, tx4]).unwrap();
    println!("{:?}", b.balances());
}
