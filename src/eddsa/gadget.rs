use super::Signature;
use crate::mimc;
use dusk_plonk::prelude::*;

pub struct WitnessSignature {
    pub r: WitnessPoint,
    pub s: Witness,
}

fn verify(composer: &mut TurboComposer, pk: WitnessPoint, msg: Witness, sig: WitnessSignature) {
    // h=H(R,A,M)
    let mut inp = Vec::new();
    inp.push(*sig.r.x());
    inp.push(*sig.r.y());
    inp.push(*pk.x());
    inp.push(*pk.y());
    inp.push(msg);
    let h = mimc::gadget::mimc(composer, inp);

    let base = JubJubAffine::from_raw_unchecked(BlsScalar::from(10), BlsScalar::from(18));
    let sb = composer.component_mul_generator(sig.s, base);

    let mut r_plus_ha = composer.component_mul_point(h, pk);
    r_plus_ha = composer.component_add_point(r_plus_ha, sig.r);

    composer.assert_equal_point(r_plus_ha, sb)
}
