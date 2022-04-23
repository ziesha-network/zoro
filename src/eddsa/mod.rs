pub mod gadget;

use crate::{mimc, utils};
use dusk_bytes::Serializable;
use dusk_plonk::prelude::*;
use num_bigint::BigUint;
use num_integer::Integer;
use std::ops::*;
use std::str::FromStr;

lazy_static! {
    pub static ref BASE: JubJubAffine = JubJubAffine::from_raw_unchecked(
        BlsScalar::from_raw([
            0x4df7b7ffec7beaca,
            0x2e3ebb21fd6c54ed,
            0xf1fbf02d0fd6cce6,
            0x3fd2814c43ac65a6,
        ]),
        BlsScalar::from(18),
    );
    pub static ref ORDER: BigUint = BigUint::from_str(
        "6554484396890773809930967563523245729705921265872317281365359162392183254199"
    )
    .unwrap();
}

#[derive(Debug, Clone, PartialEq)]
pub struct PrivateKey {
    pub public_key: JubJubAffine,
    randomness: BlsScalar,
    scalar: JubJubScalar,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Signature {
    pub r: JubJubAffine,
    pub s: JubJubScalar,
}

pub fn generate_keys(seed: Vec<BlsScalar>) -> PrivateKey {
    let randomness = mimc::mimc(seed.clone());
    let scalar = utils::bls_to_jubjub(mimc::mimc(vec![randomness]));
    let point = JubJubExtended::from(*BASE) * scalar;
    PrivateKey {
        public_key: JubJubAffine::from(point),
        randomness,
        scalar,
    }
}
pub fn sign(sk: &PrivateKey, message: BlsScalar) -> Signature {
    // r=H(b,M)
    let r = utils::bls_to_jubjub(mimc::mimc(vec![sk.randomness, message]));

    // R=rB
    let rr = JubJubAffine::from(JubJubExtended::from(*BASE) * r);

    // h=H(R,A,M)
    let mut inp = Vec::new();
    inp.push(rr.get_x());
    inp.push(rr.get_y());
    inp.push(sk.public_key.get_x());
    inp.push(sk.public_key.get_y());
    inp.push(message);
    let h = utils::bls_to_jubjub(mimc::mimc(inp));

    // s = (r + ha) mod ORDER
    let mut s = BigUint::from_bytes_le(&r.to_bytes());
    let mut ha = BigUint::from_bytes_le(&h.to_bytes());
    ha.mul_assign(&BigUint::from_bytes_le(&sk.scalar.to_bytes()));
    s.add_assign(&ha);
    s = s.mod_floor(&*ORDER);

    let mut s_data = [0u8; 32];
    s_data.copy_from_slice(&s.to_bytes_le());

    Signature {
        r: JubJubAffine::from(rr),
        s: JubJubScalar::from_bytes(&s_data).unwrap(),
    }
}

pub fn verify(pk: JubJubAffine, msg: BlsScalar, sig: Signature) -> bool {
    // h=H(R,A,M)
    let mut inp = Vec::new();
    inp.push(sig.r.get_x());
    inp.push(sig.r.get_y());
    inp.push(pk.get_x());
    inp.push(pk.get_y());
    inp.push(msg);
    let h = utils::bls_to_jubjub(mimc::mimc(inp));

    let sb = JubJubExtended::from(*BASE) * sig.s;

    let r_plus_ha = JubJubExtended::from(pk) * h + sig.r;

    r_plus_ha == sb
}
