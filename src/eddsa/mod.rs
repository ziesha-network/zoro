pub mod gadget;

use crate::mimc;
use dusk_plonk::prelude::*;
use std::ops::Mul;

#[derive(Debug, Clone, PartialEq)]
pub struct Signature {
    r: JubJubAffine,
    s: JubJubScalar,
}

fn verify(composer: &mut TurboComposer, pk: JubJubAffine, msg: BlsScalar, sig: Signature) -> bool {
    // h=H(R,A,M)
    let mut inp = Vec::new();
    inp.push(sig.r.get_x());
    inp.push(sig.r.get_y());
    inp.push(pk.get_x());
    inp.push(pk.get_y());
    inp.push(msg);
    let h = mimc::mimc(inp);

    /*let BASE = JubJubExtended::from(JubJubAffine::from_raw_unchecked(
        BlsScalar::from(10),
        BlsScalar::from(18),
    ));
    let sb = BASE * sig.s;

    let mut r_plus_ha = pk * JubJubScalar::from(h);
    r_plus_ha = r_plus_ha + sig.r;

    r_plus_ha == sb*/
    false
}
