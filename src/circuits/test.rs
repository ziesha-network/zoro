use super::*;
use bellman::groth16;
use bls12_381::Bls12;
use rand::rngs::OsRng;

#[test]
fn test_update_empty() {
    let c = UpdateCircuit::<1, 1>::default();
    let _p = groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap();
}

#[test]
fn test_deposit_empty() {
    let c = DepositCircuit::<1, 1>::default();
    let _p = groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap();
}
