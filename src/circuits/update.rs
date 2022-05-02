use crate::config::*;
use crate::{core, gadgets};
use dusk_plonk::prelude::*;
use zeekit::{eddsa, merkle, mimc};

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
    pub enabled: bool,
    pub tx: core::Transaction,
    pub src_before: core::Account, // src_after can be derived
    pub src_proof: merkle::Proof,
    pub dst_before: core::Account, // dst_after can be derived
    pub dst_proof: merkle::Proof,
}

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
pub struct UpdateCircuit {
    pub state: BlsScalar,             // Public
    pub next_state: BlsScalar,        // Public
    pub transitions: TransitionBatch, // Secret :)
}

impl Circuit for UpdateCircuit {
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];
    fn gadget(&mut self, composer: &mut TurboComposer) -> Result<(), Error> {
        let mut state_wit = composer.append_public_witness(self.state);
        for trans in self.transitions.0.iter() {
            let enabled_wit =
                composer.append_witness(BlsScalar::from(if trans.enabled { 1 } else { 0 }));
            composer.component_boolean(enabled_wit);

            let src_nonce_wit = composer.append_witness(BlsScalar::from(trans.src_before.nonce));
            let src_addr_wit = composer.append_point(trans.src_before.address.0.decompress());
            let src_balance_wit =
                composer.append_witness(BlsScalar::from(trans.src_before.balance));
            let src_hash_wit = mimc::gadget::mimc(
                composer,
                vec![
                    src_nonce_wit,
                    *src_addr_wit.x(),
                    *src_addr_wit.y(),
                    src_balance_wit,
                ],
            );
            let mut src_proof_wits = Vec::new();
            for b in trans.src_proof.0.clone() {
                src_proof_wits.push(composer.append_witness(b));
            }

            let tx_nonce_wit = composer.append_witness(BlsScalar::from(trans.tx.nonce));
            let tx_src_index_wit = composer.append_witness(BlsScalar::from(trans.tx.src_index));
            let tx_dst_index_wit = composer.append_witness(BlsScalar::from(trans.tx.dst_index));
            let tx_amount_wit = composer.append_witness(BlsScalar::from(trans.tx.amount));
            let tx_fee_wit = composer.append_witness(BlsScalar::from(trans.tx.fee));
            let tx_hash_wit = mimc::gadget::mimc(
                composer,
                vec![
                    tx_nonce_wit,
                    tx_src_index_wit,
                    tx_dst_index_wit,
                    tx_amount_wit,
                    tx_fee_wit,
                ],
            );
            let tx_sig_r_wit = composer.append_point(trans.tx.sig.r);
            let tx_sig_s_wit = composer.append_witness(trans.tx.sig.s);
            let tx_sig_wit = eddsa::gadget::WitnessSignature {
                r: tx_sig_r_wit,
                s: tx_sig_s_wit,
            };

            let new_src_nonce_wit = composer.gate_add(
                Constraint::new()
                    .left(1)
                    .constant(BlsScalar::one())
                    .output(1)
                    .a(src_nonce_wit),
            );
            let new_src_balance_wit = composer.gate_add(
                Constraint::new()
                    .left(1)
                    .right(BlsScalar::one().neg())
                    .fourth(BlsScalar::one().neg())
                    .output(1)
                    .a(src_balance_wit)
                    .b(tx_amount_wit)
                    .d(tx_fee_wit),
            );
            let new_src_hash_wit = mimc::gadget::mimc(
                composer,
                vec![
                    new_src_nonce_wit,
                    *src_addr_wit.x(),
                    *src_addr_wit.y(),
                    new_src_balance_wit,
                ],
            );

            let middle_root_wit = merkle::gadget::calc_root(
                composer,
                tx_src_index_wit,
                new_src_hash_wit,
                src_proof_wits.clone(),
            );

            let dst_nonce_wit = composer.append_witness(BlsScalar::from(trans.dst_before.nonce));
            let dst_addr_wit = composer.append_point(trans.dst_before.address.0.decompress());
            let dst_balance_wit =
                composer.append_witness(BlsScalar::from(trans.dst_before.balance));
            let dst_hash_wit = mimc::gadget::mimc(
                composer,
                vec![
                    dst_nonce_wit,
                    *dst_addr_wit.x(),
                    *dst_addr_wit.y(),
                    dst_balance_wit,
                ],
            );
            let mut dst_proof_wits = Vec::new();
            for b in trans.dst_proof.0.clone() {
                dst_proof_wits.push(composer.append_witness(b));
            }

            let new_dst_balance_wit = composer.gate_add(
                Constraint::new()
                    .left(1)
                    .right(1)
                    .output(1)
                    .a(dst_balance_wit)
                    .b(tx_amount_wit),
            );
            let new_dst_hash_wit = mimc::gadget::mimc(
                composer,
                vec![
                    dst_nonce_wit,
                    *dst_addr_wit.x(),
                    *dst_addr_wit.y(),
                    new_dst_balance_wit,
                ],
            );

            merkle::gadget::check_proof(
                composer,
                enabled_wit,
                tx_dst_index_wit,
                dst_hash_wit,
                dst_proof_wits.clone(),
                middle_root_wit,
            );
            merkle::gadget::check_proof(
                composer,
                enabled_wit,
                tx_src_index_wit,
                src_hash_wit,
                src_proof_wits,
                state_wit,
            );

            let tx_balance_plus_fee = composer.gate_add(
                Constraint::new()
                    .left(1)
                    .right(1)
                    .output(1)
                    .a(tx_amount_wit)
                    .b(tx_fee_wit),
            ); // WARN: MIGHT OVERFLOW!

            let balance_enough =
                gadgets::lte::<255>(composer, tx_balance_plus_fee, src_balance_wit);
            composer.assert_equal_constant(balance_enough, BlsScalar::one(), None);

            eddsa::gadget::verify(composer, enabled_wit, src_addr_wit, tx_hash_wit, tx_sig_wit);

            let next_state_wit = merkle::gadget::calc_root(
                composer,
                tx_dst_index_wit,
                new_dst_hash_wit,
                dst_proof_wits,
            );

            state_wit = composer.component_select(enabled_wit, next_state_wit, state_wit);
        }

        let claimed_next_state_wit = composer.append_public_witness(self.next_state);
        composer.assert_equal(state_wit, claimed_next_state_wit);

        Ok(())
    }

    fn public_inputs(&self) -> Vec<PublicInputValue> {
        vec![self.state.into(), self.next_state.into()]
    }

    fn padded_gates(&self) -> usize {
        1 << (15 + LOG_BATCH_SIZE)
    }
}
