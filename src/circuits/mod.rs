mod groth16;

use bazuka::core::{ContractPayment, Money};
use bazuka::crypto::jubjub;
use bazuka::zk::{MpnAccount, ZeroTransaction, ZkScalar};
use zeekit::merkle;

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
pub struct Transition<const LOG4_TREE_SIZE: u8> {
    pub enabled: bool,
    pub tx: ZeroTransaction,
    pub src_before: MpnAccount, // src_after can be derived
    pub src_proof: merkle::Proof<LOG4_TREE_SIZE>,
    pub dst_before: MpnAccount, // dst_after can be derived
    pub dst_proof: merkle::Proof<LOG4_TREE_SIZE>,
}

#[derive(Debug, Clone)]
pub struct TransitionBatch<const LOG4_BATCH_SIZE: u8, const LOG4_TREE_SIZE: u8>(
    Vec<Transition<LOG4_TREE_SIZE>>,
);
impl<const LOG4_BATCH_SIZE: u8, const LOG4_TREE_SIZE: u8>
    TransitionBatch<LOG4_BATCH_SIZE, LOG4_TREE_SIZE>
{
    pub fn new(mut ts: Vec<Transition<LOG4_TREE_SIZE>>) -> Self {
        while ts.len() < 1 << LOG4_BATCH_SIZE {
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
            (0..1 << LOG4_BATCH_SIZE)
                .map(|_| Transition::default())
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct DepositWithdraw {
    pub contract_payment: Option<ContractPayment>,
    pub index: u32,
    pub pub_key: jubjub::PointAffine,
    pub amount: Money,
    pub withdraw: bool,
}

#[derive(Debug, Default)]
pub struct UpdateCircuit<const LOG4_BATCH_SIZE: u8, const LOG4_TREE_SIZE: u8> {
    pub state: ZkScalar,                                                    // Public
    pub aux_data: ZkScalar,                                                 // Public
    pub next_state: ZkScalar,                                               // Public
    pub transitions: Box<TransitionBatch<LOG4_BATCH_SIZE, LOG4_TREE_SIZE>>, // Secret :)
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
