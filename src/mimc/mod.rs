use dusk_plonk::prelude::*;

lazy_static! {
    pub static ref MIMC_PARAMS: Vec<BlsScalar> = vec![BlsScalar::from(1u64), BlsScalar::from(2u64)];
}

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
