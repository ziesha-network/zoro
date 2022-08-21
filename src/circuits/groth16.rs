use bazuka::crypto::jubjub::PointAffine;
use bazuka::zk::ZkScalar;
use bellman::gadgets::boolean::{AllocatedBit, Boolean};
use bellman::gadgets::num::AllocatedNum;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use ff::Field;
use zeekit::common::groth16::Number;
use zeekit::common::groth16::UnsignedInteger;
use zeekit::eddsa::groth16::AllocatedPoint;
use zeekit::reveal::groth16::{reveal, AllocatedState};
use zeekit::{common, eddsa, poseidon, BellmanFr};

use super::*;

fn alloc_num<CS: ConstraintSystem<BellmanFr>>(
    cs: &mut CS,
    val: ZkScalar,
) -> Result<AllocatedNum<BellmanFr>, SynthesisError> {
    AllocatedNum::alloc(&mut *cs, || Ok(val.into()))
}

fn alloc_point<CS: ConstraintSystem<BellmanFr>>(
    cs: &mut CS,
    val: PointAffine,
) -> Result<AllocatedPoint, SynthesisError> {
    Ok(AllocatedPoint {
        x: alloc_num(&mut *cs, val.0)?,
        y: alloc_num(&mut *cs, val.1)?,
    })
}

impl Circuit<BellmanFr> for UpdateCircuit {
    fn synthesize<CS: ConstraintSystem<BellmanFr>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let mut state_wit = alloc_num(&mut *cs, self.state)?;
        state_wit.inputize(&mut *cs)?;

        let aux_wit = alloc_num(&mut *cs, self.aux_data)?;
        aux_wit.inputize(&mut *cs)?;

        let mut fee_sum = Number::zero();

        for trans in self.transitions.0.iter() {
            let enabled_wit = AllocatedBit::alloc(&mut *cs, Some(trans.enabled))?;

            let src_nonce_wit = alloc_num(&mut *cs, ZkScalar::from(trans.src_before.nonce))?;
            let src_addr_wit = alloc_point(&mut *cs, trans.src_before.address)?;
            let src_balance_wit = alloc_num(&mut *cs, ZkScalar::from(trans.src_before.balance))?;
            let src_hash_wit = poseidon::groth16::poseidon(
                &mut *cs,
                &[
                    src_nonce_wit.clone().into(),
                    src_addr_wit.x.clone().into(),
                    src_addr_wit.y.clone().into(),
                    src_balance_wit.clone().into(),
                ],
            )?;
            let mut src_proof_wits = Vec::new();
            for b in trans.src_proof.0.clone() {
                src_proof_wits.push([
                    alloc_num(&mut *cs, b[0])?,
                    alloc_num(&mut *cs, b[1])?,
                    alloc_num(&mut *cs, b[2])?,
                ]);
            }

            let tx_nonce_wit = alloc_num(&mut *cs, ZkScalar::from(trans.tx.nonce))?;
            let tx_src_index_wit = alloc_num(&mut *cs, ZkScalar::from(trans.tx.src_index as u64))?;
            let tx_dst_index_wit = alloc_num(&mut *cs, ZkScalar::from(trans.tx.dst_index as u64))?;
            let tx_dst_addr_wit = alloc_point(&mut *cs, trans.tx.dst_pub_key.0.decompress())?;
            let tx_amount_wit = alloc_num(&mut *cs, ZkScalar::from(trans.tx.amount))?;
            let tx_fee_wit = alloc_num(&mut *cs, ZkScalar::from(trans.tx.fee))?;

            let final_fee = common::groth16::mux(
                &mut *cs,
                &Boolean::Is(enabled_wit.clone()),
                &Number::zero(),
                &tx_fee_wit.clone().into(),
            )?;
            fee_sum.add_num(&final_fee);

            let tx_hash_wit = poseidon::groth16::poseidon(
                &mut *cs,
                &[
                    tx_nonce_wit.clone().into(),
                    tx_src_index_wit.clone().into(),
                    tx_dst_index_wit.clone().into(),
                    tx_amount_wit.clone().into(),
                    tx_fee_wit.clone().into(),
                ],
            )?
            .alloc(&mut *cs)?;
            let tx_sig_r_wit = alloc_point(&mut *cs, trans.tx.sig.r)?;
            let tx_sig_s_wit = alloc_num(&mut *cs, trans.tx.sig.s)?;

            let new_src_nonce_wit =
                Number::from(src_nonce_wit.clone()) + Number::constant::<CS>(BellmanFr::one());
            let new_src_balance_wit = Number::from(src_balance_wit.clone())
                - Number::from(tx_amount_wit.clone())
                - Number::from(tx_fee_wit.clone());

            let new_src_hash_wit = poseidon::groth16::poseidon(
                &mut *cs,
                &[
                    new_src_nonce_wit,
                    src_addr_wit.x.clone().into(),
                    src_addr_wit.y.clone().into(),
                    new_src_balance_wit,
                ],
            )?;

            let middle_root_wit = merkle::groth16::calc_root_poseidon4(
                &mut *cs,
                tx_src_index_wit.clone().into(),
                new_src_hash_wit,
                src_proof_wits.clone(),
            )?;

            let dst_nonce_wit = alloc_num(&mut *cs, ZkScalar::from(trans.dst_before.nonce))?;
            let dst_addr_wit = alloc_point(&mut *cs, trans.dst_before.address)?;
            let dst_balance_wit = alloc_num(&mut *cs, ZkScalar::from(trans.dst_before.balance))?;
            let dst_hash_wit = poseidon::groth16::poseidon(
                &mut *cs,
                &[
                    dst_nonce_wit.clone().into(),
                    dst_addr_wit.x.clone().into(),
                    dst_addr_wit.y.clone().into(),
                    dst_balance_wit.clone().into(),
                ],
            )?;
            let mut dst_proof_wits = Vec::new();
            for b in trans.dst_proof.0.clone() {
                dst_proof_wits.push([
                    alloc_num(&mut *cs, b[0])?,
                    alloc_num(&mut *cs, b[1])?,
                    alloc_num(&mut *cs, b[2])?,
                ]);
            }

            let new_dst_balance_wit = alloc_num(
                &mut *cs,
                ZkScalar::from(trans.dst_before.balance + trans.tx.amount),
            )?;
            cs.enforce(
                || "",
                |lc| lc + dst_balance_wit.get_variable() + tx_amount_wit.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + new_dst_balance_wit.get_variable(),
            );

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
                    dst_nonce_wit.into(),
                    tx_dst_addr_wit.x.into(),
                    tx_dst_addr_wit.y.into(),
                    new_dst_balance_wit.into(),
                ],
            )?;

            merkle::groth16::check_proof_poseidon4(
                &mut *cs,
                enabled_wit.clone(),
                tx_dst_index_wit.clone().into(),
                dst_hash_wit,
                dst_proof_wits.clone(),
                middle_root_wit,
            )?;
            merkle::groth16::check_proof_poseidon4(
                &mut *cs,
                enabled_wit.clone(),
                tx_src_index_wit.into(),
                src_hash_wit,
                src_proof_wits,
                state_wit.clone().into(),
            )?;

            // WARN: MIGHT OVERFLOW!
            let tx_balance_plus_fee_64 = UnsignedInteger::constrain(
                &mut *cs,
                Number::from(tx_amount_wit.clone()) + Number::from(tx_fee_wit.clone()),
                64,
            )?;
            let src_balance_64 =
                UnsignedInteger::constrain(&mut *cs, src_balance_wit.clone().into(), 64)?;
            tx_balance_plus_fee_64.lte(&mut *cs, &src_balance_64)?;

            cs.enforce(
                || "",
                |lc| lc + tx_nonce_wit.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + src_nonce_wit.get_variable(),
            );

            eddsa::groth16::verify_eddsa(
                &mut *cs,
                enabled_wit.clone(),
                src_addr_wit,
                tx_hash_wit,
                tx_sig_r_wit,
                tx_sig_s_wit,
            )?;

            let next_state_wit = merkle::groth16::calc_root_poseidon4(
                &mut *cs,
                tx_dst_index_wit.into(),
                new_dst_hash_wit,
                dst_proof_wits,
            )?;

            state_wit = common::groth16::mux(
                &mut *cs,
                &Boolean::Is(enabled_wit),
                &state_wit.into(),
                &next_state_wit,
            )?;
        }

        let claimed_next_state_wit = alloc_num(&mut *cs, self.next_state)?;
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
        let mut state_wit = alloc_num(&mut *cs, self.state)?;
        state_wit.inputize(&mut *cs)?;

        let aux_wit = alloc_num(&mut *cs, self.aux_data)?;
        aux_wit.inputize(&mut *cs)?;

        let state_model = bazuka::zk::ZkStateModel::List {
            item_type: Box::new(bazuka::zk::CONTRACT_PAYMENT_STATE_MODEL.clone()),
            log4_size: LOG4_BATCH_SIZE as u8,
        };

        let mut tx_wits = Vec::new();
        let mut children = Vec::new();
        for trans in self.transitions.0.iter() {
            let index = alloc_num(&mut *cs, ZkScalar::from(trans.tx.index as u64))?;
            let amount = alloc_num(&mut *cs, ZkScalar::from(trans.tx.amount))?;
            let withdraw = alloc_num(
                &mut *cs,
                ZkScalar::from(if trans.tx.withdraw { 1 } else { 0 }),
            )?;
            let pk = trans.tx.pub_key;
            let pubx = alloc_num(&mut *cs, pk.0)?;
            let puby = alloc_num(&mut *cs, pk.1)?;
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
                AllocatedState::Value(index),
                AllocatedState::Value(amount),
                AllocatedState::Value(withdraw),
                AllocatedState::Value(pubx),
                AllocatedState::Value(puby),
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
            |lc| lc + tx_root.get_variable(),
        );

        for (trans, (tx_index_wit, tx_amount_wit, tx_withdraw_wit, tx_pub_key_wit)) in
            self.transitions.0.iter().zip(tx_wits.into_iter())
        {
            cs.enforce(
                || "",
                |lc| lc + tx_withdraw_wit.get_variable(),
                |lc| lc + tx_withdraw_wit.get_variable() - CS::one(),
                |lc| lc,
            );
            let tx_withdraw_wit = AllocatedBit::alloc(
                &mut *cs,
                tx_withdraw_wit
                    .get_value()
                    .map(|v| !Into::<bool>::into(v.is_zero())),
            )?;

            let enabled_wit = AllocatedBit::alloc(&mut *cs, Some(trans.enabled))?;

            let src_nonce_wit = alloc_num(&mut *cs, ZkScalar::from(trans.before.nonce))?;
            let src_addr_wit = alloc_point(&mut *cs, trans.before.address)?;
            let src_balance_wit = alloc_num(&mut *cs, ZkScalar::from(trans.before.balance))?;
            let src_hash_wit = poseidon::groth16::poseidon(
                &mut *cs,
                &[
                    src_nonce_wit.clone().into(),
                    src_addr_wit.x.clone().into(),
                    src_addr_wit.y.clone().into(),
                    src_balance_wit.clone().into(),
                ],
            )?;

            let mut proof_wits = Vec::new();
            for b in trans.proof.0.clone() {
                proof_wits.push([
                    alloc_num(&mut *cs, b[0])?,
                    alloc_num(&mut *cs, b[1])?,
                    alloc_num(&mut *cs, b[2])?,
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
                enabled_wit.clone(),
                tx_index_wit.clone().into(),
                src_hash_wit,
                proof_wits.clone(),
                state_wit.clone().into(),
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
                    src_nonce_wit.into(),
                    tx_pub_key_wit.x.clone().into(),
                    tx_pub_key_wit.y.clone().into(),
                    new_balance_wit.into(),
                ],
            )?;

            let next_state_wit = merkle::groth16::calc_root_poseidon4(
                &mut *cs,
                tx_index_wit.into(),
                new_hash_wit,
                proof_wits,
            )?;

            state_wit = common::groth16::mux(
                &mut *cs,
                &Boolean::Is(enabled_wit),
                &state_wit.into(),
                &next_state_wit,
            )?;
        }

        let claimed_next_state_wit = alloc_num(&mut *cs, self.next_state)?;
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
