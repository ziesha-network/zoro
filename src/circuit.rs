use super::{core, eddsa, merkle, mimc};
use dusk_plonk::prelude::*;

// Validation:
// 0. Check verify_sig(tx)
// 1. Check verify_proof(curr_root, src_before, src_proof)
// 2. src_after := update_acc(src_before, tx)
// 3. root_after_src := calc_new_root(src_after, src_proof)
// 4. Check verify_proof(root_after_src, dst_before, dst_proof)
// 5. dst_after := update_acc(dst_after, tx)
// 6. root_after_dst := calc_new_root(dst_after, dst_proof)
// 7. Check next_state == root_after_dst
#[derive(Debug, Clone, Default)]
pub struct Transition {
    pub tx: core::Transaction,
    pub src_before: core::Account, // src_after can be derived
    pub src_proof: merkle::Proof,
    pub dst_before: core::Account, // dst_after can be derived
    pub dst_proof: merkle::Proof,
}

const BATCH_SIZE: usize = 1;

#[derive(Debug, Clone)]
pub struct TransitionBatch(pub [Transition; BATCH_SIZE]);
impl TransitionBatch {
    pub fn new(mut ts: Vec<Transition>) -> Self {
        while ts.len() < BATCH_SIZE {
            ts.push(Transition::default());
        }
        Self(ts.try_into().unwrap())
    }
}
impl Default for TransitionBatch {
    fn default() -> Self {
        Self(
            (0..BATCH_SIZE)
                .map(|_| Transition::default())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )
    }
}

#[derive(Debug, Default)]
pub struct MainCircuit {
    pub state: BlsScalar,
    pub next_state: BlsScalar,
    pub transitions: TransitionBatch,
}

impl Circuit for MainCircuit {
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];
    fn gadget(&mut self, composer: &mut TurboComposer) -> Result<(), Error> {
        let mut state_wit = composer.append_public_witness(self.state);
        for trans in self.transitions.0.iter() {
            let index_wit = composer.append_witness(BlsScalar::from(trans.tx.src_index));
            let val_wit = composer.append_witness(trans.src_before.hash());
            let mut proof_wits = Vec::new();
            for b in trans.src_proof.0.clone() {
                proof_wits.push(composer.append_witness(b));
            }

            merkle::gadget::check_proof(composer, index_wit, val_wit, proof_wits, state_wit);
        }

        Ok(())
    }

    fn public_inputs(&self) -> Vec<PublicInputValue> {
        vec![self.state.into(), self.next_state.into()]
    }

    fn padded_gates(&self) -> usize {
        1 << 14
    }
}
