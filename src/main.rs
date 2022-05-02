#[macro_use]
extern crate lazy_static;

mod bank;
mod circuits;
mod config;
mod core;
mod gadgets;

use dusk_plonk::prelude::*;
use ff::Field;
use rand_core::OsRng;
use zeekit::{eddsa, mimc, Fr};

fn main() {
    let pp = if std::path::Path::new("params.dat").exists() {
        println!("Reading params...");
        unsafe { PublicParameters::from_slice_unchecked(&std::fs::read("params.dat").unwrap()) }
    } else {
        println!("Generating params...");
        let pp = PublicParameters::setup(1 << 19, &mut OsRng).unwrap();
        std::fs::write("params.dat", pp.to_raw_var_bytes()).unwrap();
        pp
    };
    println!("Params are ready!");

    let rand1 = mimc::mimc(vec![Fr::one(), Fr::one()]);
    let rand2 = mimc::mimc(vec![Fr::zero(), Fr::one()]);

    let mut b = bank::Bank::new(pp);
    let alice_keys = eddsa::generate_keys(rand1, rand2);
    let bob_keys = eddsa::generate_keys(rand2, rand1);
    let alice_index = b.add_account(alice_keys.0, 1000);
    let bob_index = b.add_account(bob_keys.0, 500);

    let mut tx1 = core::Transaction {
        nonce: 0,
        src_index: alice_index,
        dst_index: bob_index,
        amount: 200,
        fee: 1,
        sig: eddsa::Signature::default(),
    };
    tx1.sign(alice_keys.1);

    let mut tx2 = core::Transaction {
        nonce: 0,
        src_index: bob_index,
        dst_index: alice_index,
        amount: 50,
        fee: 1,
        sig: eddsa::Signature::default(),
    };
    tx2.sign(bob_keys.1);

    b.change_state(vec![tx1, tx2]).unwrap();
    println!("{:?}", b.balances());
}
