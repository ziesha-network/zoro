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
#[derive(Debug, Clone)]
pub struct Transition {
    pub tx: core::Transaction,
    pub src_before: core::Account, // src_after can be derived
    pub src_proof: [BlsScalar; 64],
    pub dst_before: core::Account, // dst_after can be derived
    pub dst_proof: [BlsScalar; 64],
}

#[derive(Debug, Default)]
pub struct MainCircuit {
    pub state: BlsScalar,
    pub next_state: BlsScalar,
    pub transitions: Vec<Transition>,
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

        let sk = eddsa::generate_keys(vec![mimc::mimc(vec![BlsScalar::one(), BlsScalar::one()])]);
        let sig = eddsa::sign(&sk, BlsScalar::from(12345));

        let pk_wit = composer.append_point(sk.public_key);
        let msg_wit = composer.append_witness(BlsScalar::from(12345));
        let sig_wit = eddsa::gadget::WitnessSignature {
            r: composer.append_point(sig.r),
            s: composer.append_witness(sig.s),
        };
        eddsa::gadget::verify(composer, pk_wit, msg_wit, sig_wit);

        Ok(())
    }

    fn public_inputs(&self) -> Vec<PublicInputValue> {
        vec![self.state.into(), self.next_state.into()]
    }

    fn padded_gates(&self) -> usize {
        1 << 14
    }
}
