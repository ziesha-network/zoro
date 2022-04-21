use dusk_plonk::prelude::*;
use rand_core::OsRng;

#[derive(Debug, Default)]
pub struct MimcCircuit {
    inp: BlsScalar,
    out: BlsScalar,
}

// Constraints:
// q_mult · a · b  + q_left · a + q_right · b + q_output · o + q_fourth · d + q_constant + public_input = 0

fn mimc_encrypt(composer: &mut TurboComposer, mut inp: Witness, k: Witness) -> Witness {
    let params = vec![BlsScalar::from(1u64), BlsScalar::from(2u64)];
    for c in params.iter() {
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
fn mimc(composer: &mut TurboComposer, inp: Vec<Witness>) -> Witness {
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

impl Circuit for MimcCircuit {
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];
    fn gadget(&mut self, composer: &mut TurboComposer) -> Result<(), Error> {
        let inp = composer.append_witness(self.inp);
        let out = mimc(composer, vec![inp]);
        let outp = composer.append_public_witness(self.out);
        composer.assert_equal(out, outp);
        Ok(())
    }

    fn public_inputs(&self) -> Vec<PublicInputValue> {
        vec![self.out.into()]
    }

    fn padded_gates(&self) -> usize {
        1 << 11
    }
}

fn main() {
    let pp = PublicParameters::setup(1 << 12, &mut OsRng).unwrap();
    let mut circuit = MimcCircuit::default();
    let (pk, vd) = circuit.compile(&pp).unwrap();

    let proof = {
        let mut circuit = MimcCircuit {
            inp: BlsScalar::from(20u64),
            out: BlsScalar::from(794794754447u64),
        };
        circuit.prove(&pp, &pk, b"Test").unwrap()
    };

    let public_inputs: Vec<PublicInputValue> = vec![BlsScalar::from(794794754447u64).into()];
    MimcCircuit::verify(&pp, &vd, &proof, &public_inputs, b"Test").unwrap();
}
