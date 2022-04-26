use dusk_plonk::prelude::*;

pub fn bit_and(composer: &mut TurboComposer, a: Witness, b: Witness) -> Witness {
    composer.gate_mul(Constraint::new().mult(1).output(1).a(a).b(b))
}

pub fn bit_or(composer: &mut TurboComposer, a: Witness, b: Witness) -> Witness {
    let and = bit_and(composer, a, b);
    composer.gate_add(
        Constraint::new()
            .left(1)
            .right(1)
            .fourth(BlsScalar::one().neg())
            .output(1)
            .a(a)
            .b(b)
            .d(and),
    )
}

pub fn bit_not(composer: &mut TurboComposer, a: Witness) -> Witness {
    composer.gate_add(
        Constraint::new()
            .left(BlsScalar::one().neg())
            .constant(BlsScalar::one())
            .output(1)
            .a(a),
    )
}

pub fn bit_eq(composer: &mut TurboComposer, a: Witness, b: Witness) -> Witness {
    let xor = composer.component_xor(a, b, 2);
    composer.gate_add(
        Constraint::new()
            .left(BlsScalar::one().neg())
            .constant(BlsScalar::one())
            .output(1)
            .a(xor),
    )
}

pub fn bit_lt(composer: &mut TurboComposer, a: Witness, b: Witness) -> Witness {
    let not_a = bit_not(composer, a);
    bit_and(composer, not_a, b)
}

pub fn eq<const N: usize>(composer: &mut TurboComposer, a: Witness, b: Witness) -> Witness {
    let a_bits = composer.component_decomposition::<N>(a);
    let b_bits = composer.component_decomposition::<N>(b);

    let mut accum = composer.append_constant(BlsScalar::one());
    for (aa, bb) in a_bits.into_iter().zip(b_bits.into_iter()) {
        let eq = bit_eq(composer, aa, bb);
        accum = composer.gate_mul(Constraint::new().mult(1).output(1).a(accum).b(eq));
    }
    accum
}

pub fn lte<const N: usize>(composer: &mut TurboComposer, a: Witness, b: Witness) -> Witness {
    let a_bits = composer.component_decomposition::<N>(a);
    let b_bits = composer.component_decomposition::<N>(b);

    let mut lt = composer.append_constant(BlsScalar::zero());
    let mut gt = composer.append_constant(BlsScalar::zero());
    for (a, b) in a_bits.into_iter().zip(b_bits.into_iter()).rev() {
        let not_gt = bit_not(composer, gt);
        let a_lt_b = bit_lt(composer, a, b);
        let not_gt_and_a_lt_b = bit_and(composer, not_gt, a_lt_b);
        lt = bit_or(composer, lt, not_gt_and_a_lt_b);

        let not_lt = bit_not(composer, gt);
        let b_lt_a = bit_lt(composer, b, a);
        let not_lt_and_b_lt_a = bit_and(composer, not_lt, b_lt_a);
        gt = bit_or(composer, gt, not_lt_and_b_lt_a);
    }

    let not_lt = bit_not(composer, lt);
    let not_gt = bit_not(composer, gt);
    let not_lt_and_not_gt = bit_and(composer, not_lt, not_gt);
    bit_or(composer, lt, not_lt_and_not_gt)
}
