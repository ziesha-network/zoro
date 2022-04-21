use super::MIMC_PARAMS;
use dusk_plonk::prelude::*;

// Constraints:
// q_mult · a · b  + q_left · a + q_right · b + q_output · o + q_fourth · d + q_constant + public_input = 0

fn mimc_encrypt(composer: &mut TurboComposer, mut inp: Witness, k: Witness) -> Witness {
    for c in MIMC_PARAMS.iter() {
        // inp = inp + k + c
        let new_inp = composer.gate_add(
            Constraint::new()
                .left(1)
                .right(1)
                .constant(c.clone())
                .output(1)
                .a(inp)
                .b(k),
        );
        let new_inp_squared =
            composer.gate_mul(Constraint::new().mult(1).output(1).a(new_inp).b(new_inp));
        inp = composer.gate_mul(
            Constraint::new()
                .mult(1)
                .output(1)
                .a(new_inp_squared)
                .b(new_inp),
        );
    }
    inp
}

pub fn mimc(composer: &mut TurboComposer, inp: Vec<Witness>) -> Witness {
    let mut digest = composer.append_constant(BlsScalar::zero());
    for d in inp.into_iter() {
        let encrypted = mimc_encrypt(composer, d, digest);
        digest = composer.gate_add(
            Constraint::new()
                .left(1)
                .right(1)
                .output(1)
                .a(digest)
                .b(encrypted),
        );
    }
    digest
}
