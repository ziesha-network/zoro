use bazuka::zk::{MpnAccount, MpnTransaction, ZkScalar};
use bellman::gadgets::boolean::{AllocatedBit, Boolean};
use bellman::gadgets::num::AllocatedNum;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use zeekit::common::Number;
use zeekit::common::UnsignedInteger;
use zeekit::eddsa::AllocatedPoint;
use zeekit::merkle;
use zeekit::{common, eddsa, poseidon, BellmanFr};

// Validation:
// 0. Check verify_sig(tx)
// 1. Check verify_proof(curr_root, src_before, src_proof)
// 2. src_after := update_acc(src_before, tx)
// 3. root_after_src := calc_new_root(src_after, src_proof)
// 4. Check verify_proof(root_after_src, dst_before, dst_proof)
// 5. dst_after := update_acc(dst_after, tx)
// 6. root_after_dst := calc_new_root(dst_after, dst_proof)
// 7. Check next_state == root_after_dst
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Transition<const LOG4_TREE_SIZE: u8> {
    pub enabled: bool,
    pub tx: MpnTransaction,
    pub src_before: MpnAccount, // src_after can be derived
    pub src_proof: merkle::Proof<LOG4_TREE_SIZE>,
    pub dst_before: MpnAccount, // dst_after can be derived
    pub dst_proof: merkle::Proof<LOG4_TREE_SIZE>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransitionBatch<const LOG4_BATCH_SIZE: u8, const LOG4_TREE_SIZE: u8>(
    Vec<Transition<LOG4_TREE_SIZE>>,
);
impl<const LOG4_BATCH_SIZE: u8, const LOG4_TREE_SIZE: u8>
    TransitionBatch<LOG4_BATCH_SIZE, LOG4_TREE_SIZE>
{
    pub fn new(mut ts: Vec<Transition<LOG4_TREE_SIZE>>) -> Self {
        while ts.len() < 1 << (2 * LOG4_BATCH_SIZE) {
            ts.push(Transition::default());
        }
        Self(ts)
    }
}
impl<const LOG4_BATCH_SIZE: u8, const LOG4_TREE_SIZE: u8> Default
    for TransitionBatch<LOG4_BATCH_SIZE, LOG4_TREE_SIZE>
{
    fn default() -> Self {
        Self(
            (0..1 << (2 * LOG4_BATCH_SIZE))
                .map(|_| Transition::default())
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct UpdateCircuit<const LOG4_BATCH_SIZE: u8, const LOG4_TREE_SIZE: u8> {
    pub height: u64,                                                        // Public
    pub state: ZkScalar,                                                    // Public
    pub aux_data: ZkScalar,                                                 // Public
    pub next_state: ZkScalar,                                               // Public
    pub transitions: Box<TransitionBatch<LOG4_BATCH_SIZE, LOG4_TREE_SIZE>>, // Secret :)
}

impl<const LOG4_BATCH_SIZE: u8, const LOG4_TREE_SIZE: u8> Circuit<BellmanFr>
    for UpdateCircuit<LOG4_BATCH_SIZE, LOG4_TREE_SIZE>
{
    fn synthesize<CS: ConstraintSystem<BellmanFr>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // Contract height feeded as input
        let height_wit = AllocatedNum::alloc(&mut *cs, || Ok(self.height.into()))?;
        height_wit.inputize(&mut *cs)?;

        // Previous state feeded as input
        let mut state_wit = AllocatedNum::alloc(&mut *cs, || Ok(self.state.into()))?;
        state_wit.inputize(&mut *cs)?;

        // Sum of internal tx fees feeded as input
        let aux_wit = AllocatedNum::alloc(&mut *cs, || Ok(self.aux_data.into()))?;
        aux_wit.inputize(&mut *cs)?;

        // Expected next state feeded as input
        let claimed_next_state_wit = AllocatedNum::alloc(&mut *cs, || Ok(self.next_state.into()))?;
        claimed_next_state_wit.inputize(&mut *cs)?;

        // Sum of tx fees as a linear-combination of tx fees
        let mut fee_sum = Number::zero();

        for trans in self.transitions.0.iter() {
            // If enabled, transaction is validated, otherwise neglected
            let enabled_wit = Boolean::Is(AllocatedBit::alloc(&mut *cs, Some(trans.enabled))?);

            let src_nonce_wit =
                AllocatedNum::alloc(&mut *cs, || Ok(trans.src_before.nonce.into()))?;

            let src_addr_wit = AllocatedPoint::alloc(&mut *cs, || Ok(trans.src_before.address))?;
            // Sender address should be on curve in case transaction slot is non-empty
            src_addr_wit.assert_on_curve(&mut *cs, &enabled_wit)?;

            // We need bits of sender balance for the LTE operation
            let src_balance_wit =
                UnsignedInteger::alloc_64(&mut *cs, trans.src_before.balance.into())?;

            let src_hash_wit = poseidon::poseidon(
                &mut *cs,
                &[
                    &src_nonce_wit.clone().into(),
                    &src_addr_wit.x.clone().into(),
                    &src_addr_wit.y.clone().into(),
                    &src_balance_wit.clone().into(),
                ],
            )?;
            let mut src_proof_wits = Vec::new();
            for b in trans.src_proof.0.clone() {
                src_proof_wits.push([
                    AllocatedNum::alloc(&mut *cs, || Ok(b[0].into()))?,
                    AllocatedNum::alloc(&mut *cs, || Ok(b[1].into()))?,
                    AllocatedNum::alloc(&mut *cs, || Ok(b[2].into()))?,
                ]);
            }

            let tx_nonce_wit = AllocatedNum::alloc(&mut *cs, || Ok(trans.tx.nonce.into()))?;

            // src and dst indices should only have 2 * LOG4_TREE_SIZE bits
            let tx_src_index_wit = UnsignedInteger::alloc(
                &mut *cs,
                (trans.tx.src_index as u64).into(),
                LOG4_TREE_SIZE as usize * 2,
            )?;
            let tx_dst_index_wit = UnsignedInteger::alloc(
                &mut *cs,
                (trans.tx.dst_index as u64).into(),
                LOG4_TREE_SIZE as usize * 2,
            )?;

            let tx_dst_addr_wit =
                AllocatedPoint::alloc(&mut *cs, || Ok(trans.tx.dst_pub_key.0.decompress()))?;
            // Destination address should be on curve in case transaction slot is non-empty
            tx_dst_addr_wit.assert_on_curve(&mut *cs, &enabled_wit)?;

            // Transaction amount and fee should at most have 64 bits
            let tx_amount_wit = UnsignedInteger::alloc_64(&mut *cs, trans.tx.amount.into())?;
            let tx_fee_wit = UnsignedInteger::alloc_64(&mut *cs, trans.tx.fee.into())?;

            // Fee is zero if transaction slot is empty, otherwise it equals to transaction fee
            let final_fee = common::mux(
                &mut *cs,
                &enabled_wit,
                &Number::zero(),
                &tx_fee_wit.clone().into(),
            )?;
            fee_sum.add_num(BellmanFr::one(), &final_fee);

            let tx_hash_wit = poseidon::poseidon(
                &mut *cs,
                &[
                    &tx_nonce_wit.clone().into(),
                    &tx_src_index_wit.clone().into(),
                    &tx_dst_index_wit.clone().into(),
                    &tx_amount_wit.clone().into(),
                    &tx_fee_wit.clone().into(),
                ],
            )?;

            let tx_sig_r_wit = AllocatedPoint::alloc(&mut *cs, || Ok(trans.tx.sig.r))?;
            // Check if sig_r resides on curve
            tx_sig_r_wit.assert_on_curve(&mut *cs, &enabled_wit)?;

            let tx_sig_s_wit = AllocatedNum::alloc(&mut *cs, || Ok(trans.tx.sig.s.into()))?;

            // Source nonce is incremented by one and balance is decreased by amount+fee
            let new_src_nonce_wit =
                Number::from(src_nonce_wit.clone()) + Number::constant::<CS>(BellmanFr::one());
            let new_src_balance_wit = Number::from(src_balance_wit.clone())
                - Number::from(tx_amount_wit.clone())
                - Number::from(tx_fee_wit.clone());

            let new_src_hash_wit = poseidon::poseidon(
                &mut *cs,
                &[
                    &new_src_nonce_wit,
                    &src_addr_wit.x.clone().into(),
                    &src_addr_wit.y.clone().into(),
                    &new_src_balance_wit,
                ],
            )?;

            // Root of the merkle tree after src account is updated
            let middle_root_wit = merkle::calc_root_poseidon4(
                &mut *cs,
                &tx_src_index_wit.clone().into(),
                &new_src_hash_wit,
                &src_proof_wits,
            )?;

            let dst_nonce_wit =
                AllocatedNum::alloc(&mut *cs, || Ok(trans.dst_before.nonce.into()))?;

            // Destination address doesn't necessarily need to reside on curve as it might be empty
            let dst_addr_wit = AllocatedPoint::alloc(&mut *cs, || Ok(trans.dst_before.address))?;

            // We also don't need to make sure dst balance is 64 bits. If everything works as expected
            // nothing like this should happen.
            let dst_balance_wit = AllocatedNum::alloc(&mut *cs, || {
                Ok(Into::<u64>::into(trans.dst_before.balance).into())
            })?;

            let dst_hash_wit = poseidon::poseidon(
                &mut *cs,
                &[
                    &dst_nonce_wit.clone().into(),
                    &dst_addr_wit.x.clone().into(),
                    &dst_addr_wit.y.clone().into(),
                    &dst_balance_wit.clone().into(),
                ],
            )?;
            let mut dst_proof_wits = Vec::new();
            for b in trans.dst_proof.0.clone() {
                dst_proof_wits.push([
                    AllocatedNum::alloc(&mut *cs, || Ok(b[0].into()))?,
                    AllocatedNum::alloc(&mut *cs, || Ok(b[1].into()))?,
                    AllocatedNum::alloc(&mut *cs, || Ok(b[2].into()))?,
                ]);
            }

            // Increase destination balance by tx amount
            let new_dst_balance_wit =
                Number::from(dst_balance_wit.clone()) + Number::from(tx_amount_wit.clone());

            // Address of destination account slot can either be empty or equal with tx destination
            let is_dst_null = dst_addr_wit.is_null(&mut *cs)?;
            let is_dst_and_tx_dst_equal = dst_addr_wit.is_equal(&mut *cs, &tx_dst_addr_wit)?;
            let addr_valid = common::boolean_or(&mut *cs, &is_dst_null, &is_dst_and_tx_dst_equal)?;
            common::assert_true(&mut *cs, &addr_valid);

            let new_dst_hash_wit = poseidon::poseidon(
                &mut *cs,
                &[
                    &dst_nonce_wit.into(),
                    &tx_dst_addr_wit.x.into(),
                    &tx_dst_addr_wit.y.into(),
                    &new_dst_balance_wit,
                ],
            )?;

            // Check merkle proofs
            merkle::check_proof_poseidon4(
                &mut *cs,
                &enabled_wit,
                &tx_dst_index_wit.clone().into(),
                &dst_hash_wit,
                &dst_proof_wits,
                &middle_root_wit,
            )?;
            merkle::check_proof_poseidon4(
                &mut *cs,
                &enabled_wit,
                &tx_src_index_wit.into(),
                &src_hash_wit,
                &src_proof_wits,
                &state_wit.clone().into(),
            )?;

            // tx amount+fee should be <= src balance
            let tx_balance_plus_fee_64 = UnsignedInteger::constrain(
                &mut *cs,
                Number::from(tx_amount_wit.clone()) + Number::from(tx_fee_wit.clone()),
                64,
            )?;
            let is_lte = tx_balance_plus_fee_64.lte(&mut *cs, &src_balance_wit)?;
            common::assert_true(&mut *cs, &is_lte);

            // Check tx nonce is equal with account nonce to prevent double spending
            cs.enforce(
                || "",
                |lc| lc + tx_nonce_wit.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + src_nonce_wit.get_variable(),
            );

            // Check EdDSA signature
            eddsa::verify_eddsa(
                &mut *cs,
                &enabled_wit,
                &src_addr_wit,
                &tx_hash_wit,
                &tx_sig_r_wit,
                &tx_sig_s_wit,
            )?;

            // Calculate next-state hash and update state if tx is enabled
            let next_state_wit = merkle::calc_root_poseidon4(
                &mut *cs,
                &tx_dst_index_wit.into(),
                &new_dst_hash_wit,
                &dst_proof_wits,
            )?;
            state_wit = common::mux(&mut *cs, &enabled_wit, &state_wit.into(), &next_state_wit)?;
        }

        // Check if sum of tx fees is equal with the feeded aux
        cs.enforce(
            || "",
            |lc| lc + aux_wit.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + fee_sum.get_lc(),
        );

        // Check if applying txs result in the claimed next state
        cs.enforce(
            || "",
            |lc| lc + state_wit.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + claimed_next_state_wit.get_variable(),
        );

        Ok(())
    }
}
