use bellman::gadgets::boolean::{AllocatedBit, Boolean};
use bellman::gadgets::num::AllocatedNum;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use zeekit::eddsa::{groth16::AllocatedPoint, PointAffine};
use zeekit::{common, eddsa, BellmanFr, Fr};

use std::ops::Neg;

use super::*;

fn alloc_num<CS: ConstraintSystem<BellmanFr>>(
    cs: &mut CS,
    filled: bool,
    val: Fr,
) -> Result<AllocatedNum<BellmanFr>, SynthesisError> {
    AllocatedNum::alloc(&mut *cs, || {
        filled
            .then(|| val.into())
            .ok_or(SynthesisError::AssignmentMissing)
    })
}

fn alloc_point<CS: ConstraintSystem<BellmanFr>>(
    cs: &mut CS,
    filled: bool,
    val: PointAffine,
) -> Result<AllocatedPoint, SynthesisError> {
    Ok(AllocatedPoint {
        x: alloc_num(&mut *cs, filled, val.0)?,
        y: alloc_num(&mut *cs, filled, val.1)?,
    })
}

impl Circuit<BellmanFr> for UpdateCircuit {
    fn synthesize<CS: ConstraintSystem<BellmanFr>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let filled = self.filled;

        let mut state_wit = alloc_num(&mut *cs, filled, self.state)?;
        state_wit.inputize(&mut *cs)?;

        let curve_a = alloc_num(&mut *cs, filled, zeekit::eddsa::A.clone())?;
        let curve_d = alloc_num(&mut *cs, filled, zeekit::eddsa::D.clone())?;
        let curve_base = alloc_point(&mut *cs, filled, zeekit::eddsa::BASE.clone())?;

        for trans in self.transitions.0.iter() {
            let enabled_wit = AllocatedBit::alloc(&mut *cs, filled.then(|| trans.enabled))?;

            let src_nonce_wit = alloc_num(&mut *cs, filled, Fr::from(trans.src_before.nonce))?;
            let src_addr_wit =
                alloc_point(&mut *cs, filled, trans.src_before.address.0.decompress())?;
            let src_balance_wit = alloc_num(&mut *cs, filled, Fr::from(trans.src_before.balance))?;
            let src_hash_wit = mimc::groth16::mimc(
                &mut *cs,
                &[
                    src_nonce_wit.clone(),
                    src_addr_wit.x.clone(),
                    src_addr_wit.y.clone(),
                    src_balance_wit.clone(),
                ],
            )?;
            let mut src_proof_wits = Vec::new();
            for b in trans.src_proof.0.clone() {
                src_proof_wits.push(alloc_num(&mut *cs, filled, b)?);
            }

            let tx_nonce_wit = alloc_num(&mut *cs, filled, Fr::from(trans.tx.nonce))?;
            let tx_src_index_wit = alloc_num(&mut *cs, filled, Fr::from(trans.tx.src_index))?;
            let tx_dst_index_wit = alloc_num(&mut *cs, filled, Fr::from(trans.tx.dst_index))?;
            let tx_amount_wit = alloc_num(&mut *cs, filled, Fr::from(trans.tx.amount))?;
            let tx_fee_wit = alloc_num(&mut *cs, filled, Fr::from(trans.tx.fee))?;
            let tx_hash_wit = mimc::groth16::mimc(
                &mut *cs,
                &[
                    tx_nonce_wit.clone(),
                    tx_src_index_wit.clone(),
                    tx_dst_index_wit.clone(),
                    tx_amount_wit.clone(),
                    tx_fee_wit.clone(),
                ],
            )?;
            let tx_sig_r_wit = alloc_point(&mut *cs, filled, trans.tx.sig.r)?;
            let tx_sig_s_wit = alloc_num(&mut *cs, filled, trans.tx.sig.s)?;

            let new_src_nonce_wit =
                alloc_num(&mut *cs, filled, Fr::from(trans.src_before.nonce + 1))?;
            cs.enforce(
                || "",
                |lc| lc + src_nonce_wit.get_variable() + CS::one(),
                |lc| lc + CS::one(),
                |lc| lc + new_src_nonce_wit.get_variable(),
            );
            let new_src_balance_wit = alloc_num(
                &mut *cs,
                filled,
                Fr::from(trans.src_before.balance - trans.tx.amount - trans.tx.fee),
            )?;
            cs.enforce(
                || "",
                |lc| {
                    lc + src_balance_wit.get_variable()
                        - tx_amount_wit.get_variable()
                        - tx_fee_wit.get_variable()
                },
                |lc| lc + CS::one(),
                |lc| lc + new_src_balance_wit.get_variable(),
            );
            let new_src_hash_wit = mimc::groth16::mimc(
                &mut *cs,
                &[
                    new_src_nonce_wit,
                    src_addr_wit.x.clone(),
                    src_addr_wit.y.clone(),
                    new_src_balance_wit,
                ],
            )?;

            let middle_root_wit = merkle::groth16::calc_root(
                &mut *cs,
                tx_src_index_wit.clone(),
                new_src_hash_wit,
                src_proof_wits.clone(),
            )?;

            let dst_nonce_wit = alloc_num(&mut *cs, filled, Fr::from(trans.dst_before.nonce))?;
            let dst_addr_wit =
                alloc_point(&mut *cs, filled, trans.dst_before.address.0.decompress())?;
            let dst_balance_wit = alloc_num(&mut *cs, filled, Fr::from(trans.dst_before.balance))?;
            let dst_hash_wit = mimc::groth16::mimc(
                &mut *cs,
                &[
                    dst_nonce_wit.clone(),
                    dst_addr_wit.x.clone(),
                    dst_addr_wit.y.clone(),
                    dst_balance_wit.clone(),
                ],
            )?;
            let mut dst_proof_wits = Vec::new();
            for b in trans.dst_proof.0.clone() {
                dst_proof_wits.push(alloc_num(&mut *cs, filled, b)?);
            }

            let new_dst_balance_wit = alloc_num(
                &mut *cs,
                filled,
                Fr::from(trans.dst_before.balance + trans.tx.amount),
            )?;
            cs.enforce(
                || "",
                |lc| lc + dst_balance_wit.get_variable() + tx_amount_wit.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + new_dst_balance_wit.get_variable(),
            );

            let new_dst_hash_wit = mimc::groth16::mimc(
                &mut *cs,
                &[
                    dst_nonce_wit,
                    dst_addr_wit.x,
                    dst_addr_wit.y,
                    new_dst_balance_wit,
                ],
            )?;

            merkle::groth16::check_proof(
                &mut *cs,
                enabled_wit.clone(),
                tx_dst_index_wit.clone(),
                dst_hash_wit,
                dst_proof_wits.clone(),
                middle_root_wit,
            )?;
            merkle::groth16::check_proof(
                &mut *cs,
                enabled_wit.clone(),
                tx_src_index_wit,
                src_hash_wit,
                src_proof_wits,
                state_wit.clone(),
            )?;

            // WARN: MIGHT OVERFLOW!
            let tx_balance_plus_fee =
                alloc_num(&mut *cs, filled, Fr::from(trans.tx.amount + trans.tx.fee))?;
            cs.enforce(
                || "",
                |lc| lc + tx_amount_wit.get_variable() + tx_fee_wit.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + tx_balance_plus_fee.get_variable(),
            );
            common::groth16::lte(&mut *cs, tx_balance_plus_fee, src_balance_wit)?;

            cs.enforce(
                || "",
                |lc| lc + tx_nonce_wit.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + src_nonce_wit.get_variable(),
            );

            eddsa::groth16::verify_eddsa(
                &mut *cs,
                enabled_wit.clone(),
                curve_a.clone(),
                curve_d.clone(),
                curve_base.clone(),
                src_addr_wit,
                tx_hash_wit,
                tx_sig_r_wit,
                tx_sig_s_wit,
            )?;

            let next_state_wit = merkle::groth16::calc_root(
                &mut *cs,
                tx_dst_index_wit,
                new_dst_hash_wit,
                dst_proof_wits,
            )?;

            state_wit = AllocatedNum::conditionally_reverse(
                &mut *cs,
                &state_wit,
                &next_state_wit,
                &Boolean::Is(enabled_wit),
            )?
            .0;
        }

        let claimed_next_state_wit = alloc_num(&mut *cs, filled, self.next_state)?;
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

impl Circuit<BellmanFr> for DepositWithdrawCircuit {
    fn synthesize<CS: ConstraintSystem<BellmanFr>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let filled = self.filled;

        let mut state_wit = alloc_num(&mut *cs, filled, self.state)?;
        state_wit.inputize(&mut *cs)?;

        for trans in self.transitions.0.iter() {
            let enabled_wit = AllocatedBit::alloc(&mut *cs, filled.then(|| trans.enabled))?;

            let src_nonce_wit = alloc_num(&mut *cs, filled, Fr::from(trans.before.nonce))?;
            let src_addr_wit = alloc_point(&mut *cs, filled, trans.before.address.0.decompress())?;
            let src_balance_wit = alloc_num(&mut *cs, filled, Fr::from(trans.before.balance))?;
            let src_hash_wit = mimc::groth16::mimc(
                &mut *cs,
                &[
                    src_nonce_wit.clone(),
                    src_addr_wit.x.clone(),
                    src_addr_wit.y.clone(),
                    src_balance_wit.clone(),
                ],
            )?;

            let mut proof_wits = Vec::new();
            for b in trans.proof.0.clone() {
                proof_wits.push(alloc_num(&mut *cs, filled, b)?);
            }

            let tx_index_wit = alloc_num(&mut *cs, filled, Fr::from(trans.tx.index))?;
            let tx_pub_key_wit = alloc_point(&mut *cs, filled, trans.tx.pub_key.0.decompress())?;
            let tx_amount_wit = alloc_num(&mut *cs, filled, Fr::from(trans.tx.amount))?;
            let tx_withdraw_wit = AllocatedBit::alloc(&mut *cs, filled.then(|| trans.tx.withdraw))?;
            tx_withdraw_wit.get_variable();

            merkle::groth16::check_proof(
                &mut *cs,
                enabled_wit.clone(),
                tx_index_wit.clone(),
                src_hash_wit,
                proof_wits.clone(),
                state_wit.clone(),
            )?;

            let new_nonce_wit = alloc_num(&mut *cs, filled, Fr::from(trans.before.nonce + 1))?;
            cs.enforce(
                || "",
                |lc| lc + src_nonce_wit.get_variable() + CS::one(),
                |lc| lc + CS::one(),
                |lc| lc + new_nonce_wit.get_variable(),
            );
            let new_balance_wit = alloc_num(
                &mut *cs,
                filled,
                Fr::from(if trans.tx.withdraw {
                    trans.before.balance - trans.tx.amount
                } else {
                    trans.before.balance + trans.tx.amount
                }),
            )?;

            // -2.amount.withdraw == new_balance - balance - amount
            // if withdraw == 0 then new_balance = balance + amount
            // else new_balance = balance - amount
            cs.enforce(
                || "",
                |lc| lc + (BellmanFr::from(2).neg(), tx_amount_wit.get_variable()),
                |lc| lc + tx_withdraw_wit.get_variable(),
                |lc| {
                    lc + new_balance_wit.get_variable()
                        - src_balance_wit.get_variable()
                        - tx_amount_wit.get_variable()
                },
            );

            let new_hash_wit = mimc::groth16::mimc(
                &mut *cs,
                &[
                    new_nonce_wit,
                    tx_pub_key_wit.x.clone(),
                    tx_pub_key_wit.y.clone(),
                    new_balance_wit,
                ],
            )?;

            let next_state_wit =
                merkle::groth16::calc_root(&mut *cs, tx_index_wit, new_hash_wit, proof_wits)?;

            state_wit = AllocatedNum::conditionally_reverse(
                &mut *cs,
                &state_wit,
                &next_state_wit,
                &Boolean::Is(enabled_wit),
            )?
            .0;
        }

        let claimed_next_state_wit = alloc_num(&mut *cs, filled, self.next_state)?;
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
