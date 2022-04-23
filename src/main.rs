#[macro_use]
extern crate lazy_static;

mod bank;
mod circuit;
mod core;
mod eddsa;
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
    let mut tx = core::Transaction {
        nonce: 0,
        src_index: alice_index,
        dst_index: bob_index,
        amount: 200,
        fee: 1,
        sig: eddsa::Signature::default(),
    };
    tx.sign(alice_keys);
    b.change_state(vec![tx]).unwrap();
    println!("{:?}", b.balances());
}
