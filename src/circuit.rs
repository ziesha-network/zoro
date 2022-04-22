use super::merkle;
use dusk_plonk::prelude::*;

#[derive(Debug, Default)]
pub struct MainCircuit {
    pub state: BlsScalar,
    pub next_state: BlsScalar,
}

impl Circuit for MainCircuit {
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];
    fn gadget(&mut self, composer: &mut TurboComposer) -> Result<(), Error> {
        let mut tree = merkle::SparseTree::new();
        tree.set(12345, BlsScalar::one());
        let prf = tree.prove(12345);
        let mut proof_wits = Vec::new();
        for b in prf.clone() {
            proof_wits.push(composer.append_witness(b));
        }
        merkle::SparseTree::verify(12345, BlsScalar::from(1), prf.clone(), tree.root());
        let index_wit = composer.append_witness(BlsScalar::from(12345));
        let val_wit = composer.append_witness(BlsScalar::from(1));
        let root_wit = composer.append_witness(tree.root());
        merkle::gadget::check_proof(composer, index_wit, val_wit, proof_wits, root_wit);

        Ok(())
    }

    fn public_inputs(&self) -> Vec<PublicInputValue> {
        vec![self.state.into(), self.next_state.into()]
    }

    fn padded_gates(&self) -> usize {
        1 << 12
    }
}
