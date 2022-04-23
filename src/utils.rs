use dusk_plonk::prelude::*;

pub fn bls_to_jubjub(s: BlsScalar) -> JubJubScalar {
    let mut data = [0u64; 4];
    let u64s = s
        .to_bits()
        .chunks(64)
        .map(|bits| {
            let mut num = 0u64;
            for b in bits.iter().rev() {
                num = num << 1;
                num = num | (*b as u64);
            }
            num
        })
        .collect::<Vec<u64>>();
    data.copy_from_slice(&u64s);
    JubJubScalar::from_raw(data)
}

pub fn component_bit_equals(composer: &mut TurboComposer, a: Witness, b: Witness) -> Witness {
    let xor = composer.component_xor(a, b, 2);
    composer.gate_add(
        Constraint::new()
            .left(BlsScalar::one().neg())
            .constant(BlsScalar::one())
            .output(1)
            .a(xor),
    )
}

pub fn component_equals(composer: &mut TurboComposer, a: Witness, b: Witness) -> Witness {
    let a_bits = composer.component_decomposition::<256>(a);
    let b_bits = composer.component_decomposition::<256>(b);

    let mut accum = composer.append_constant(BlsScalar::one());
    for (aa, bb) in a_bits.into_iter().zip(b_bits.into_iter()) {
        let eq = component_bit_equals(composer, aa, bb);
        accum = composer.gate_mul(Constraint::new().mult(1).output(1).a(accum).b(eq));
    }
    accum
}
