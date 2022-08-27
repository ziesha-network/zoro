use bazuka::core::{ContractPayment, Money};
use bazuka::crypto::jubjub;
use bazuka::zk::{MpnAccount, ZkScalar};
use bellman::gadgets::boolean::{AllocatedBit, Boolean};
use bellman::gadgets::num::AllocatedNum;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use zeekit::common::Number;
use zeekit::common::UnsignedInteger;
use zeekit::eddsa::AllocatedPoint;
use zeekit::merkle;
use zeekit::reveal::{reveal, AllocatedState};
use zeekit::{common, poseidon, BellmanFr};

#[derive(Debug, Clone, Default)]
pub struct DepositWithdraw {
    pub contract_payment: Option<ContractPayment>,
    pub index: u32,
    pub pub_key: jubjub::PointAffine,
    pub amount: Money,
    pub withdraw: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DepositWithdrawTransition<const LOG4_TREE_SIZE: u8> {
    pub enabled: bool,
    pub tx: DepositWithdraw,
    pub before: MpnAccount,
    pub proof: merkle::Proof<LOG4_TREE_SIZE>,
}

#[derive(Debug, Clone)]
pub struct DepositWithdrawTransitionBatch<const LOG4_BATCH_SIZE: u8, const LOG4_TREE_SIZE: u8>(
    Vec<DepositWithdrawTransition<LOG4_TREE_SIZE>>,
);
impl<const LOG4_BATCH_SIZE: u8, const LOG4_TREE_SIZE: u8>
    DepositWithdrawTransitionBatch<LOG4_BATCH_SIZE, LOG4_TREE_SIZE>
{
    pub fn new(mut ts: Vec<DepositWithdrawTransition<LOG4_TREE_SIZE>>) -> Self {
        while ts.len() < 1 << LOG4_BATCH_SIZE {
            ts.push(DepositWithdrawTransition::default());
        }
        Self(ts)
    }
}
impl<const LOG4_BATCH_SIZE: u8, const LOG4_TREE_SIZE: u8> Default
    for DepositWithdrawTransitionBatch<LOG4_BATCH_SIZE, LOG4_TREE_SIZE>
{
    fn default() -> Self {
        Self(
            (0..1 << LOG4_BATCH_SIZE)
                .map(|_| DepositWithdrawTransition::default())
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Debug, Default)]
pub struct DepositWithdrawCircuit<const LOG4_BATCH_SIZE: u8, const LOG4_TREE_SIZE: u8> {
    pub state: ZkScalar,      // Public
    pub aux_data: ZkScalar,   // Public
    pub next_state: ZkScalar, // Public
    pub transitions: Box<DepositWithdrawTransitionBatch<LOG4_BATCH_SIZE, LOG4_TREE_SIZE>>, // Secret :)
}

impl<const LOG4_BATCH_SIZE: u8, const LOG4_TREE_SIZE: u8> Circuit<BellmanFr>
    for DepositWithdrawCircuit<LOG4_BATCH_SIZE, LOG4_TREE_SIZE>
{
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
            log4_size: LOG4_BATCH_SIZE,
        };

        let mut tx_wits = Vec::new();
        let mut children = Vec::new();
        for trans in self.transitions.0.iter() {
            let index = UnsignedInteger::alloc(
                &mut *cs,
                (trans.tx.index as u64).into(),
                LOG4_TREE_SIZE as usize * 2,
            )?;
            let amount = UnsignedInteger::alloc_64(&mut *cs, trans.tx.amount.into())?;
            let withdraw = AllocatedBit::alloc(&mut *cs, Some(trans.tx.withdraw))?;
            let pk = trans.tx.pub_key;
            let pub_key = AllocatedPoint::alloc(&mut *cs, || Ok(pk))?;
            tx_wits.push((
                index.clone(),
                amount.clone(),
                withdraw.clone(),
                pub_key.clone(),
            ));
            children.push(AllocatedState::Children(vec![
                AllocatedState::Value(index.into()),
                AllocatedState::Value(amount.into()),
                AllocatedState::Value(withdraw.into()),
                AllocatedState::Value(pub_key.x.into()),
                AllocatedState::Value(pub_key.y.into()),
            ]));
        }
        let tx_root = reveal(&mut *cs, &state_model, &AllocatedState::Children(children))?;

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

            tx_pub_key_wit.assert_on_curve(&mut *cs, &enabled_wit)?;

            let src_nonce_wit = AllocatedNum::alloc(&mut *cs, || Ok(trans.before.nonce.into()))?;
            let src_addr_wit = AllocatedPoint::alloc(&mut *cs, || Ok(trans.before.address))?;
            let src_balance_wit = AllocatedNum::alloc(&mut *cs, || {
                Ok(Into::<u64>::into(trans.before.balance).into())
            })?;
            let src_hash_wit = poseidon::poseidon(
                &mut *cs,
                &[
                    &src_nonce_wit.clone().into(),
                    &src_addr_wit.x.clone().into(),
                    &src_addr_wit.y.clone().into(),
                    &src_balance_wit.clone().into(),
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
            let is_src_addr_null = src_addr_wit.is_null(&mut *cs)?;
            let is_src_and_tx_pub_key_equal = src_addr_wit.is_equal(&mut *cs, &tx_pub_key_wit)?;
            let addr_valid =
                common::boolean_or(&mut *cs, &is_src_addr_null, &is_src_and_tx_pub_key_equal)?;
            common::assert_true_if_enabled(&mut *cs, &enabled_wit, &addr_valid)?;

            merkle::check_proof_poseidon4(
                &mut *cs,
                &enabled_wit,
                &tx_index_wit.clone().into(),
                &src_hash_wit,
                &proof_wits,
                &state_wit.clone().into(),
            )?;

            let src_balance_lc = Number::from(src_balance_wit);
            let tx_amount_lc = Number::from(tx_amount_wit);
            let new_balance_wit = common::mux(
                &mut *cs,
                &Boolean::Is(tx_withdraw_wit.clone()),
                &(src_balance_lc.clone() + tx_amount_lc.clone()),
                &(src_balance_lc - tx_amount_lc),
            )?;

            let new_hash_wit = poseidon::poseidon(
                &mut *cs,
                &[
                    &src_nonce_wit.into(),
                    &tx_pub_key_wit.x.clone().into(),
                    &tx_pub_key_wit.y.clone().into(),
                    &new_balance_wit.into(),
                ],
            )?;

            let next_state_wit =
                merkle::calc_root_poseidon4(&mut *cs, &tx_index_wit, &new_hash_wit, &proof_wits)?;

            state_wit = common::mux(&mut *cs, &enabled_wit, &state_wit.into(), &next_state_wit)?;
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
