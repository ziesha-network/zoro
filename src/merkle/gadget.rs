use crate::mimc;
use dusk_plonk::prelude::*;

fn merge_hash(composer: &mut TurboComposer, dir: Witness, a: Witness, b: Witness) -> Witness {
    let l = mimc::gadget::mimc(composer, vec![a, b]);
    let r = mimc::gadget::mimc(composer, vec![b, a]);
    composer.component_boolean(dir);
    composer.component_select(dir, r, l)
}

pub fn check_proof(
    composer: &mut TurboComposer,
    index: Witness,
    val: Witness,
    proof: Vec<Witness>,
    root: Witness,
) {
    let selectors = composer.component_decomposition::<64>(index);
    let mut curr = val;
    for (p, dir) in proof.into_iter().zip(selectors.into_iter()) {
        curr = merge_hash(composer, dir, curr, p);
    }
    composer.assert_equal(curr, root)
}

pub fn check_proof2(
    composer: &mut TurboComposer,
    index: Witness,
    val: Witness,
    proof: Vec<Witness>,
    root: Witness,
) {
    let selectors = composer.component_decomposition::<64>(index);
    for sel in selectors.iter() {
        println!("{:?}", unsafe { composer.evaluate_witness(sel) });
    }
}
