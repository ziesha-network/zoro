use bazuka::core::{Money, MpnWithdraw};
use bazuka::crypto::jubjub;
use bazuka::zk::{MpnAccount, ZkScalar};
use bellman::gadgets::boolean::{AllocatedBit, Boolean};
use bellman::gadgets::num::AllocatedNum;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use zeekit::common::Number;
use zeekit::common::UnsignedInteger;
use zeekit::eddsa;
use zeekit::eddsa::AllocatedPoint;
use zeekit::merkle;
use zeekit::reveal::{reveal, AllocatedState};
use zeekit::{common, poseidon, BellmanFr};

#[derive(Debug, Clone, Default)]
pub struct Withdraw {
    pub mpn_withdraw: Option<MpnWithdraw>,
    pub index: u32,
    pub pub_key: jubjub::PointAffine,
    pub fingerprint: ZkScalar,
    pub nonce: u64,
    pub sig: jubjub::Signature,
    pub amount: Money,
}

#[derive(Debug, Clone, Default)]
pub struct WithdrawTransition<const LOG4_TREE_SIZE: u8> {
    pub enabled: bool,
    pub tx: Withdraw,
    pub before: MpnAccount,
    pub proof: merkle::Proof<LOG4_TREE_SIZE>,
}

#[derive(Debug, Clone)]
pub struct WithdrawTransitionBatch<const LOG4_BATCH_SIZE: u8, const LOG4_TREE_SIZE: u8>(
    Vec<WithdrawTransition<LOG4_TREE_SIZE>>,
);
impl<const LOG4_BATCH_SIZE: u8, const LOG4_TREE_SIZE: u8>
    WithdrawTransitionBatch<LOG4_BATCH_SIZE, LOG4_TREE_SIZE>
{
    pub fn new(mut ts: Vec<WithdrawTransition<LOG4_TREE_SIZE>>) -> Self {
        while ts.len() < 1 << (2 * LOG4_BATCH_SIZE) {
            ts.push(WithdrawTransition::default());
        }
        Self(ts)
    }
}
impl<const LOG4_BATCH_SIZE: u8, const LOG4_TREE_SIZE: u8> Default
    for WithdrawTransitionBatch<LOG4_BATCH_SIZE, LOG4_TREE_SIZE>
{
    fn default() -> Self {
        Self(
            (0..1 << (2 * LOG4_BATCH_SIZE))
                .map(|_| WithdrawTransition::default())
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Debug, Default, Clone)]
pub struct WithdrawCircuit<const LOG4_BATCH_SIZE: u8, const LOG4_TREE_SIZE: u8> {
    pub height: u64,          // Public
    pub state: ZkScalar,      // Public
    pub aux_data: ZkScalar,   // Public
    pub next_state: ZkScalar, // Public
    pub transitions: Box<WithdrawTransitionBatch<LOG4_BATCH_SIZE, LOG4_TREE_SIZE>>, // Secret :)
}

impl<const LOG4_BATCH_SIZE: u8, const LOG4_TREE_SIZE: u8> Circuit<BellmanFr>
    for WithdrawCircuit<LOG4_BATCH_SIZE, LOG4_TREE_SIZE>
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

        let state_model = bazuka::zk::ZkStateModel::List {
            item_type: Box::new(bazuka::zk::ZkStateModel::Struct {
                field_types: vec![
                    bazuka::zk::ZkStateModel::Scalar, // Enabled
                    bazuka::zk::ZkStateModel::Scalar, // Amount
                    bazuka::zk::ZkStateModel::Scalar, // Fingerprint
                    bazuka::zk::ZkStateModel::Scalar, // Calldata
                ],
            }),
            log4_size: LOG4_BATCH_SIZE,
        };

        // Uncompress all the Withdraw txs that were compressed inside aux_witness
        let mut tx_wits = Vec::new();
        let mut children = Vec::new();
        for trans in self.transitions.0.iter() {
            // If enabled, transaction is validated, otherwise neglected
            let enabled = AllocatedBit::alloc(&mut *cs, Some(trans.enabled))?;

            // Tx amount should always have at most 64 bits
            let amount = UnsignedInteger::alloc_64(&mut *cs, trans.tx.amount.into())?;

            // Tx amount should always have at most 64 bits
            let fingerprint = AllocatedNum::alloc(&mut *cs, || Ok(trans.tx.fingerprint.into()))?;

            // Pub-key only needs to reside on curve if tx is enabled, which is checked in the main loop
            let pub_key = AllocatedPoint::alloc(&mut *cs, || Ok(trans.tx.pub_key))?;
            let nonce = AllocatedNum::alloc(&mut *cs, || Ok(trans.tx.nonce.into()))?;
            let sig_r = AllocatedPoint::alloc(&mut *cs, || Ok(trans.tx.sig.r))?;
            let sig_s = AllocatedNum::alloc(&mut *cs, || Ok(trans.tx.sig.s.into()))?;

            tx_wits.push((
                Boolean::Is(enabled.clone()),
                amount.clone(),
                fingerprint.clone(),
                pub_key.clone(),
                nonce.clone(),
                sig_r.clone(),
                sig_s.clone(),
            ));

            let calldata_hash = poseidon::poseidon(
                &mut *cs,
                &[
                    &pub_key.x.into(),
                    &pub_key.y.into(),
                    &nonce.into(),
                    &sig_r.x.into(),
                    &sig_r.y.into(),
                    &sig_s.into(),
                ],
            )?;

            let calldata = common::mux(
                &mut *cs,
                &enabled.clone().into(),
                &Number::zero(),
                &calldata_hash,
            )?;

            children.push(AllocatedState::Children(vec![
                AllocatedState::Value(enabled.into()),
                AllocatedState::Value(amount.into()),
                AllocatedState::Value(fingerprint.into()),
                AllocatedState::Value(calldata.into()),
            ]));
        }
        let tx_root = reveal(&mut *cs, &state_model, &AllocatedState::Children(children))?;
        cs.enforce(
            || "",
            |lc| lc + aux_wit.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + tx_root.get_lc(),
        );

        for (
            trans,
            (
                enabled_wit,
                tx_amount_wit,
                fingerprint_wit,
                tx_pub_key_wit,
                tx_nonce_wit,
                tx_sig_r_wit,
                tx_sig_s_wit,
            ),
        ) in self.transitions.0.iter().zip(tx_wits.into_iter())
        {
            // Tx index should always have at most LOG4_TREE_SIZE * 2 bits
            let tx_index_wit = UnsignedInteger::alloc(
                &mut *cs,
                (trans.tx.index as u64).into(),
                LOG4_TREE_SIZE as usize * 2,
            )?;

            // Check if tx pub-key resides on the curve if tx is enabled
            tx_pub_key_wit.assert_on_curve(&mut *cs, &enabled_wit)?;

            let tx_hash_wit = poseidon::poseidon(
                &mut *cs,
                &[
                    &fingerprint_wit.clone().into(),
                    &tx_nonce_wit.clone().into(),
                ],
            )?;
            // Check if sig_r resides on curve
            tx_sig_r_wit.assert_on_curve(&mut *cs, &enabled_wit)?;
            // Check EdDSA signature
            eddsa::verify_eddsa(
                &mut *cs,
                &enabled_wit,
                &tx_pub_key_wit,
                &tx_hash_wit,
                &tx_sig_r_wit,
                &tx_sig_s_wit,
            )?;

            let src_nonce_wit = AllocatedNum::alloc(&mut *cs, || Ok(trans.before.nonce.into()))?;

            // Account address doesn't necessarily need to reside on curve as it might be empty
            let src_addr_wit = AllocatedPoint::alloc(&mut *cs, || Ok(trans.before.address))?;

            // We don't need to make sure account balance is 64 bits. If everything works as expected
            // nothing like this should happen.
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

            // Check tx nonce is equal with account nonce to prevent double spending
            cs.enforce(
                || "",
                |lc| lc + tx_nonce_wit.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + src_nonce_wit.get_variable(),
            );

            let mut proof_wits = Vec::new();
            for b in trans.proof.0.clone() {
                proof_wits.push([
                    AllocatedNum::alloc(&mut *cs, || Ok(b[0].into()))?,
                    AllocatedNum::alloc(&mut *cs, || Ok(b[1].into()))?,
                    AllocatedNum::alloc(&mut *cs, || Ok(b[2].into()))?,
                ]);
            }

            // Address of account slot can either be empty or equal with tx destination
            let is_src_addr_null = src_addr_wit.is_null(&mut *cs)?;
            let is_src_and_tx_pub_key_equal = src_addr_wit.is_equal(&mut *cs, &tx_pub_key_wit)?;
            let addr_valid =
                common::boolean_or(&mut *cs, &is_src_addr_null, &is_src_and_tx_pub_key_equal)?;
            common::assert_true(&mut *cs, &addr_valid);

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

            // Calculate next-state hash and update state if tx is enabled
            let new_hash_wit = poseidon::poseidon(
                &mut *cs,
                &[
                    &(Number::from(src_nonce_wit) + Number::constant::<CS>(BellmanFr::one())),
                    &tx_pub_key_wit.x.clone().into(),
                    &tx_pub_key_wit.y.clone().into(),
                    &(src_balance_lc.clone() - tx_amount_lc.clone()),
                ],
            )?;
            let next_state_wit =
                merkle::calc_root_poseidon4(&mut *cs, &tx_index_wit, &new_hash_wit, &proof_wits)?;
            state_wit = common::mux(&mut *cs, &enabled_wit, &state_wit.into(), &next_state_wit)?;
        }

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
