#[macro_use]
extern crate lazy_static;

mod bank;
mod circuit;
mod config;
mod core;
mod eddsa;
mod gadgets;
mod merkle;
mod mimc;
mod utils;

use circuit::MainCircuit;

use dusk_plonk::prelude::*;

fn main() {
    let alice_keys =
        eddsa::generate_keys(vec![mimc::mimc(vec![BlsScalar::one(), BlsScalar::one()])]);
    let bob_keys =
        eddsa::generate_keys(vec![mimc::mimc(vec![BlsScalar::zero(), BlsScalar::one()])]);
    let mut b = bank::Bank::new();
    let alice_index = b.add_account(alice_keys.public_key, 1000);
    let bob_index = b.add_account(bob_keys.public_key, 500);

    let mut tx1 = core::Transaction {
        nonce: 0,
        src_index: alice_index,
        dst_index: bob_index,
        amount: 200,
        fee: 1,
        sig: eddsa::Signature::default(),
    };
    tx1.sign(alice_keys);

    let mut tx2 = core::Transaction {
        nonce: 0,
        src_index: bob_index,
        dst_index: alice_index,
        amount: 50,
        fee: 1,
        sig: eddsa::Signature::default(),
    };
    tx2.sign(bob_keys);

    b.change_state(vec![tx1, tx2]).unwrap();
    println!("{:?}", b.balances());
}
