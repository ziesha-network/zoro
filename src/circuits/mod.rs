mod groth16;

use crate::config::BATCH_SIZE;
use crate::core;
use bazuka::zk::ZkScalar;
use zeekit::merkle;

const LOG4_TREE_SIZE: usize = 2;

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
    pub src_proof: merkle::Proof<LOG4_TREE_SIZE>,
    pub dst_before: core::Account, // dst_after can be derived
    pub dst_proof: merkle::Proof<LOG4_TREE_SIZE>,
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
    pub filled: bool,
    pub state: ZkScalar,                   // Public
    pub next_state: ZkScalar,              // Public
    pub transitions: Box<TransitionBatch>, // Secret :)
}

#[derive(Debug, Clone, Default)]
pub struct DepositWithdrawTransition {
    pub enabled: bool,
    pub tx: core::DepositWithdraw,
    pub before: core::Account,
    pub proof: merkle::Proof<LOG4_TREE_SIZE>,
}

#[derive(Debug, Clone)]
pub struct DepositWithdrawTransitionBatch(pub [DepositWithdrawTransition; BATCH_SIZE]);
impl DepositWithdrawTransitionBatch {
    pub fn new(mut ts: Vec<DepositWithdrawTransition>) -> Self {
        while ts.len() < BATCH_SIZE {
            ts.push(DepositWithdrawTransition::default());
        }
        Self(ts.try_into().unwrap())
    }
}
impl Default for DepositWithdrawTransitionBatch {
    fn default() -> Self {
        Self(
            (0..BATCH_SIZE)
                .map(|_| DepositWithdrawTransition::default())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )
    }
}

#[derive(Debug, Default)]
pub struct DepositWithdrawCircuit {
    pub filled: bool,
    pub state: ZkScalar,                                  // Public
    pub transitions: Box<DepositWithdrawTransitionBatch>, // Secret :)
    pub next_state: ZkScalar,                             // Public
}
