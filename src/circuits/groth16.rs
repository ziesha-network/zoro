use bellman::gadgets::boolean::{AllocatedBit, Boolean};
use bellman::gadgets::num::AllocatedNum;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use zeekit::common::groth16::Number;
use zeekit::common::groth16::UnsignedInteger;
use zeekit::eddsa::groth16::AllocatedPoint;
use zeekit::reveal::groth16::{reveal, AllocatedState};
use zeekit::{common, eddsa, poseidon, BellmanFr};

use super::*;

impl Circuit<BellmanFr> for UpdateCircuit {
    fn synthesize<CS: ConstraintSystem<BellmanFr>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // Previous state feeded as input
        let mut state_wit = AllocatedNum::alloc(&mut *cs, || Ok(self.state.into()))?;
        state_wit.inputize(&mut *cs)?;

        // Sum of internal tx fees feeded as input
        let aux_wit = AllocatedNum::alloc(&mut *cs, || Ok(self.aux_data.into()))?;
        aux_wit.inputize(&mut *cs)?;

        // Sum of tx fees as a linear-combination of tx fees
        let mut fee_sum = Number::zero();

        for trans in self.transitions.0.iter() {
            // If enabled, transaction is validated, otherwise neglected
            let enabled_wit = Boolean::Is(AllocatedBit::alloc(&mut *cs, Some(trans.enabled))?);

            let src_nonce_wit =
                AllocatedNum::alloc(&mut *cs, || Ok(trans.src_before.nonce.into()))?;

            let src_addr_wit = AllocatedPoint::alloc(&mut *cs, || Ok(trans.src_before.address))?;
            src_addr_wit.assert_on_curve(&mut *cs, &enabled_wit)?;

            let src_balance_wit =
                UnsignedInteger::alloc_64(&mut *cs, trans.src_before.balance.into())?;
            let src_hash_wit = poseidon::groth16::poseidon(
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
            let tx_src_index_wit = UnsignedInteger::alloc_32(&mut *cs, trans.tx.src_index)?;
            let tx_dst_index_wit = UnsignedInteger::alloc_32(&mut *cs, trans.tx.dst_index)?;
            let tx_dst_addr_wit =
                AllocatedPoint::alloc(&mut *cs, || Ok(trans.tx.dst_pub_key.0.decompress()))?;
            tx_dst_addr_wit.assert_on_curve(&mut *cs, &enabled_wit)?;

            let tx_amount_wit = UnsignedInteger::alloc_64(&mut *cs, trans.tx.amount.into())?;
            let tx_fee_wit = UnsignedInteger::alloc_64(&mut *cs, trans.tx.fee.into())?;

            let final_fee = common::groth16::mux(
                &mut *cs,
                &enabled_wit.clone(),
                &Number::zero(),
                &tx_fee_wit.clone().into(),
            )?;
            fee_sum.add_num(BellmanFr::one(), &final_fee);

            let tx_hash_wit = poseidon::groth16::poseidon(
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
            tx_sig_r_wit.assert_on_curve(&mut *cs, &enabled_wit)?;

            let tx_sig_s_wit = AllocatedNum::alloc(&mut *cs, || Ok(trans.tx.sig.s.into()))?;

            let new_src_nonce_wit =
                Number::from(src_nonce_wit.clone()) + Number::constant::<CS>(BellmanFr::one());
            let new_src_balance_wit = Number::from(src_balance_wit.clone())
                - Number::from(tx_amount_wit.clone())
                - Number::from(tx_fee_wit.clone());

            let new_src_hash_wit = poseidon::groth16::poseidon(
                &mut *cs,
                &[
                    &new_src_nonce_wit,
                    &src_addr_wit.x.clone().into(),
                    &src_addr_wit.y.clone().into(),
                    &new_src_balance_wit,
                ],
            )?;

            let middle_root_wit = merkle::groth16::calc_root_poseidon4(
                &mut *cs,
                &tx_src_index_wit.clone().into(),
                &new_src_hash_wit,
                &src_proof_wits,
            )?;

            let dst_nonce_wit =
                AllocatedNum::alloc(&mut *cs, || Ok(trans.dst_before.nonce.into()))?;
            let dst_addr_wit = AllocatedPoint::alloc(&mut *cs, || Ok(trans.dst_before.address))?;
            let dst_balance_wit = AllocatedNum::alloc(&mut *cs, || {
                Ok(Into::<u64>::into(trans.dst_before.balance).into())
            })?;
            let dst_hash_wit = poseidon::groth16::poseidon(
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

            let new_dst_balance_wit =
                Number::from(dst_balance_wit.clone()) + Number::from(tx_amount_wit.clone());

            // enforce dst_addr_wit == tx_dst_addr_wit or zero!
            cs.enforce(
                || "",
                |lc| lc + dst_addr_wit.x.get_variable(),
                |lc| lc + dst_addr_wit.x.get_variable() - tx_dst_addr_wit.x.get_variable(),
                |lc| lc,
            );
            cs.enforce(
                || "",
                |lc| lc + dst_addr_wit.y.get_variable(),
                |lc| lc + dst_addr_wit.y.get_variable() - tx_dst_addr_wit.y.get_variable(),
                |lc| lc,
            );

            let new_dst_hash_wit = poseidon::groth16::poseidon(
                &mut *cs,
                &[
                    &dst_nonce_wit.into(),
                    &tx_dst_addr_wit.x.into(),
                    &tx_dst_addr_wit.y.into(),
                    &new_dst_balance_wit,
                ],
            )?;

            merkle::groth16::check_proof_poseidon4(
                &mut *cs,
                &enabled_wit,
                &tx_dst_index_wit.clone().into(),
                &dst_hash_wit,
                &dst_proof_wits,
                &middle_root_wit,
            )?;
            merkle::groth16::check_proof_poseidon4(
                &mut *cs,
                &enabled_wit,
                &tx_src_index_wit.into(),
                &src_hash_wit,
                &src_proof_wits,
                &state_wit.clone().into(),
            )?;

            let tx_balance_plus_fee_64 = UnsignedInteger::constrain(
                &mut *cs,
                Number::from(tx_amount_wit.clone()) + Number::from(tx_fee_wit.clone()),
                64,
            )?;

            let is_lte = tx_balance_plus_fee_64.lte(&mut *cs, &src_balance_wit)?;
            common::groth16::assert_true(&mut *cs, &is_lte);

            cs.enforce(
                || "",
                |lc| lc + tx_nonce_wit.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + src_nonce_wit.get_variable(),
            );

            eddsa::groth16::verify_eddsa(
                &mut *cs,
                &enabled_wit,
                &src_addr_wit,
                &tx_hash_wit,
                &tx_sig_r_wit,
                &tx_sig_s_wit,
            )?;

            let next_state_wit = merkle::groth16::calc_root_poseidon4(
                &mut *cs,
                &tx_dst_index_wit.into(),
                &new_dst_hash_wit,
                &dst_proof_wits,
            )?;

            state_wit =
                common::groth16::mux(&mut *cs, &enabled_wit, &state_wit.into(), &next_state_wit)?;
        }

        let claimed_next_state_wit = AllocatedNum::alloc(&mut *cs, || Ok(self.next_state.into()))?;
        claimed_next_state_wit.inputize(&mut *cs)?;

        cs.enforce(
            || "",
            |lc| lc + aux_wit.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + fee_sum.get_lc(),
        );

        cs.enforce(
            || "",
            |lc| lc + state_wit.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + claimed_next_state_wit.get_variable(),
        );

        Ok(())
    }
}

impl Circuit<BellmanFr> for DepositWithdrawCircuit {
    fn synthesize<CS: ConstraintSystem<BellmanFr>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let mut state_wit = AllocatedNum::alloc(&mut *cs, || Ok(self.state.into()))?;
        state_wit.inputize(&mut *cs)?;

        let aux_wit = AllocatedNum::alloc(&mut *cs, || Ok(self.aux_data.into()))?;
        aux_wit.inputize(&mut *cs)?;

        let state_model = bazuka::zk::ZkStateModel::List {
            item_type: Box::new(bazuka::zk::CONTRACT_PAYMENT_STATE_MODEL.clone()),
            log4_size: LOG4_BATCH_SIZE as u8,
        };

        let mut tx_wits = Vec::new();
        let mut children = Vec::new();
        for trans in self.transitions.0.iter() {
            let index = UnsignedInteger::alloc_32(&mut *cs, trans.tx.index)?;
            let amount = UnsignedInteger::alloc_64(&mut *cs, trans.tx.amount.into())?;
            let withdraw = AllocatedBit::alloc(&mut *cs, Some(trans.tx.withdraw))?;
            let pk = trans.tx.pub_key;
            let pubx = AllocatedNum::alloc(&mut *cs, || Ok(pk.0.into()))?;
            let puby = AllocatedNum::alloc(&mut *cs, || Ok(pk.1.into()))?;
            tx_wits.push((
                index.clone(),
                amount.clone(),
                withdraw.clone(),
                AllocatedPoint {
                    x: pubx.clone(),
                    y: puby.clone(),
                },
            ));
            children.push(AllocatedState::Children(vec![
                AllocatedState::Value(index.into()),
                AllocatedState::Value(amount.into()),
                AllocatedState::Value(withdraw.into()),
                AllocatedState::Value(pubx.into()),
                AllocatedState::Value(puby.into()),
            ]));
        }
        let tx_root = reveal(
            &mut *cs,
            state_model.clone(),
            AllocatedState::Children(children),
        )?;

        cs.enforce(
            || "",
            |lc| lc + aux_wit.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + tx_root.get_lc(),
        );

        for (trans, (tx_index_wit, tx_amount_wit, tx_withdraw_wit, tx_pub_key_wit)) in
            self.transitions.0.iter().zip(tx_wits.into_iter())
        {
            let enabled_wit = Boolean::Is(AllocatedBit::alloc(&mut *cs, Some(trans.enabled))?);

            let src_nonce_wit = AllocatedNum::alloc(&mut *cs, || Ok(trans.before.nonce.into()))?;
            let src_addr_wit = AllocatedPoint::alloc(&mut *cs, || Ok(trans.before.address))?;
            let src_balance_wit = UnsignedInteger::alloc_64(&mut *cs, trans.before.balance.into())?;
            let src_hash_wit = poseidon::groth16::poseidon(
                &mut *cs,
                &[
                    &src_nonce_wit.clone().into(),
                    &src_addr_wit.x.clone().into(),
                    &src_addr_wit.y.clone().into(),
                    src_balance_wit.get_number(),
                ],
            )?;

            let mut proof_wits = Vec::new();
            for b in trans.proof.0.clone() {
                proof_wits.push([
                    AllocatedNum::alloc(&mut *cs, || Ok(b[0].into()))?,
                    AllocatedNum::alloc(&mut *cs, || Ok(b[1].into()))?,
                    AllocatedNum::alloc(&mut *cs, || Ok(b[2].into()))?,
                ]);
            }

            // enforce src_addr_wit == tx_pub_key_wit or zero!
            cs.enforce(
                || "",
                |lc| lc + src_addr_wit.x.get_variable(),
                |lc| lc + src_addr_wit.x.get_variable() - tx_pub_key_wit.x.get_variable(),
                |lc| lc,
            );
            cs.enforce(
                || "",
                |lc| lc + src_addr_wit.y.get_variable(),
                |lc| lc + src_addr_wit.y.get_variable() - tx_pub_key_wit.y.get_variable(),
                |lc| lc,
            );

            merkle::groth16::check_proof_poseidon4(
                &mut *cs,
                &enabled_wit,
                &tx_index_wit.clone().into(),
                &src_hash_wit,
                &proof_wits,
                &state_wit.clone().into(),
            )?;

            let src_balance_lc = Number::from(src_balance_wit);
            let tx_amount_lc = Number::from(tx_amount_wit);
            let new_balance_wit = common::groth16::mux(
                &mut *cs,
                &Boolean::Is(tx_withdraw_wit.clone()),
                &(src_balance_lc.clone() + tx_amount_lc.clone()),
                &(src_balance_lc - tx_amount_lc),
            )?;

            let new_hash_wit = poseidon::groth16::poseidon(
                &mut *cs,
                &[
                    &src_nonce_wit.into(),
                    &tx_pub_key_wit.x.clone().into(),
                    &tx_pub_key_wit.y.clone().into(),
                    &new_balance_wit.into(),
                ],
            )?;

            let next_state_wit = merkle::groth16::calc_root_poseidon4(
                &mut *cs,
                &tx_index_wit,
                &new_hash_wit,
                &proof_wits,
            )?;

            state_wit =
                common::groth16::mux(&mut *cs, &enabled_wit, &state_wit.into(), &next_state_wit)?;
        }

        let claimed_next_state_wit = AllocatedNum::alloc(&mut *cs, || Ok(self.next_state.into()))?;
        claimed_next_state_wit.inputize(&mut *cs)?;

        cs.enforce(
            || "",
            |lc| lc + state_wit.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + claimed_next_state_wit.get_variable(),
        );

        Ok(())
    }
}
