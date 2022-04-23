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
use rand_core::OsRng;

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

    let pp = PublicParameters::setup(1 << 15, &mut OsRng).unwrap();
    let mut circuit = MainCircuit::default();
    let (pk, vd) = circuit.compile(&pp).unwrap();

    let proof = {
        let mut circuit = MainCircuit {
            state: BlsScalar::from(20u64),
            next_state: BlsScalar::from(794794754447u64),
            transitions: Vec::new(),
        };
        circuit.prove(&pp, &pk, b"Test").unwrap()
    };

    let public_inputs: Vec<PublicInputValue> = vec![BlsScalar::from(794794754447u64).into()];
    MainCircuit::verify(&pp, &vd, &proof, &public_inputs, b"Test").unwrap();
}
