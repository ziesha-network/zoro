use super::config::MIMC_PARAMS;
use dusk_plonk::prelude::*;

pub mod gadget;

pub fn mimc_encrypt(mut inp: BlsScalar, k: BlsScalar) -> BlsScalar {
    for c in MIMC_PARAMS.iter() {
        inp = inp + k + c;
        inp = inp * inp * inp;
    }
    inp
}

pub fn mimc(inp: Vec<BlsScalar>) -> BlsScalar {
    let mut digest = BlsScalar::zero();
    for d in inp {
        let encrypted = mimc_encrypt(d, digest);
        digest = digest + encrypted;
    }
    digest
}
