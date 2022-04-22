#[macro_use]
extern crate lazy_static;

mod bank;
mod circuit;
mod core;
mod eddsa;
mod merkle;
mod mimc;

use circuit::MainCircuit;

use dusk_plonk::prelude::*;
use rand_core::OsRng;

fn main() {
    let pp = PublicParameters::setup(1 << 13, &mut OsRng).unwrap();
    let mut circuit = MainCircuit::default();
    let (pk, vd) = circuit.compile(&pp).unwrap();

    let proof = {
        let mut circuit = MainCircuit {
            state: BlsScalar::from(20u64),
            next_state: BlsScalar::from(794794754447u64),
        };
        circuit.prove(&pp, &pk, b"Test").unwrap()
    };

    let public_inputs: Vec<PublicInputValue> = vec![BlsScalar::from(794794754447u64).into()];
    MainCircuit::verify(&pp, &vd, &proof, &public_inputs, b"Test").unwrap();
}
