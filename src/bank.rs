use crate::circuits::DepositWithdraw;
use crate::config;
use crate::{circuits, core};
use bazuka::zk::ZkScalar;
use bazuka::{
    config::blockchain::MPN_CONTRACT_ID,
    core::{Money, ZkHasher},
    crypto::jubjub::{PointAffine, PublicKey},
    db::KvStore,
    zk::{KvStoreStateManager, ZeroTransaction, ZkDataLocator, ZkStateModel},
};
use bellman::groth16;
use bellman::groth16::Parameters;
use bls12_381::Bls12;
use rand::rngs::OsRng;
use thiserror::Error;

lazy_static! {
    pub static ref STATE_MODEL: ZkStateModel = {
        ZkStateModel::List {
            log4_size: config::LOG4_TREE_SIZE,
            item_type: Box::new(ZkStateModel::Struct {
                field_types: vec![
                    ZkStateModel::Scalar, // Nonce
                    ZkStateModel::Scalar, // Pub-key X
                    ZkStateModel::Scalar, // Pub-key Y
                    ZkStateModel::Scalar, // Balance
                ],
            }),
        }
    };
}

pub fn get_account<K: KvStore>(db: &K, index: u32) -> core::Account {
    let nonce: u64 = KvStoreStateManager::<ZkHasher>::get_data(
        db,
        *MPN_CONTRACT_ID,
        &ZkDataLocator(vec![index, 0]),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let pub_x = KvStoreStateManager::<ZkHasher>::get_data(
        db,
        *MPN_CONTRACT_ID,
        &ZkDataLocator(vec![index, 1]),
    )
    .unwrap();
    let pub_y = KvStoreStateManager::<ZkHasher>::get_data(
        db,
        *MPN_CONTRACT_ID,
        &ZkDataLocator(vec![index, 2]),
    )
    .unwrap();
    let balance: u64 = KvStoreStateManager::<ZkHasher>::get_data(
        db,
        *MPN_CONTRACT_ID,
        &ZkDataLocator(vec![index, 3]),
    )
    .unwrap()
    .try_into()
    .unwrap();
    core::Account {
        nonce,
        balance: Money(balance),
        address: PointAffine(pub_x, pub_y),
    }
}

pub fn set_account<K: KvStore>(db: &mut K, index: u32, acc: core::Account, size_diff: &mut u32) {
    KvStoreStateManager::<ZkHasher>::set_data(
        db,
        *MPN_CONTRACT_ID,
        ZkDataLocator(vec![index, 0]),
        ZkScalar::from(acc.nonce),
        size_diff,
    )
    .unwrap();
    KvStoreStateManager::<ZkHasher>::set_data(
        db,
        *MPN_CONTRACT_ID,
        ZkDataLocator(vec![index, 1]),
        acc.address.0,
        size_diff,
    )
    .unwrap();
    KvStoreStateManager::<ZkHasher>::set_data(
        db,
        *MPN_CONTRACT_ID,
        ZkDataLocator(vec![index, 2]),
        acc.address.1,
        size_diff,
    )
    .unwrap();
    let balance: u64 = acc.balance.into();
    KvStoreStateManager::<ZkHasher>::set_data(
        db,
        *MPN_CONTRACT_ID,
        ZkDataLocator(vec![index, 3]),
        ZkScalar::from(balance),
        size_diff,
    )
    .unwrap();
}

#[derive(Error, Debug)]
pub enum BankError {
    #[error("cannot generate zk-snark proof!")]
    CannotProve,
    #[error("kv-store error: {0}")]
    KvStoreError(#[from] bazuka::db::KvStoreError),
}

pub struct Bank {
    update_params: Parameters<Bls12>,
    deposit_withdraw_params: Parameters<Bls12>,
}

pub fn extract_delta(ops: Vec<bazuka::db::WriteOp>) -> bazuka::zk::ZkDeltaPairs {
    let mut pairs = bazuka::zk::ZkDeltaPairs([].into());
    for op in ops {
        match op {
            bazuka::db::WriteOp::Put(k, v) => {
                let mut it = k.0.split("_s_");
                it.next();
                if let Some(loc) = it.next() {
                    pairs
                        .0
                        .insert(loc.parse().unwrap(), Some(v.try_into().unwrap()));
                }
            }
            bazuka::db::WriteOp::Remove(k) => {
                let mut it = k.0.split("_s_");
                it.next();
                if let Some(loc) = it.next() {
                    pairs.0.insert(loc.parse().unwrap(), None);
                }
            }
        }
    }
    pairs
}

impl Bank {
    pub fn balances<K: KvStore>(&self, db: &K) -> Vec<(u32, u64)> {
        let state = KvStoreStateManager::<ZkHasher>::get_full_state(db, *MPN_CONTRACT_ID).unwrap();
        let mut result = Vec::new();
        for (loc, val) in state.data.0 {
            if loc.0[1] == 3 {
                result.push((loc.0[0], val.try_into().unwrap()));
            }
        }
        result
    }
    pub fn new(
        update_params: Parameters<Bls12>,
        deposit_withdraw_params: Parameters<Bls12>,
    ) -> Self {
        Self {
            update_params,
            deposit_withdraw_params,
        }
    }

    pub fn deposit_withdraw<K: KvStore>(
        &self,
        db: &mut K,
        txs: Vec<DepositWithdraw>,
    ) -> Result<
        (
            bazuka::zk::ZkDeltaPairs,
            bazuka::zk::ZkCompressedState,
            bazuka::zk::groth16::Groth16Proof,
        ),
        BankError,
    > {
        let mut mirror = db.mirror();

        let mut transitions = Vec::new();
        let root = KvStoreStateManager::<ZkHasher>::root(db, *MPN_CONTRACT_ID).unwrap();

        let state = root.state_hash;
        let mut state_size = root.state_size;

        for tx in txs.iter() {
            let acc = get_account(&mirror, tx.index);
            let balance_u64: u64 = acc.balance.into();
            if acc.address != Default::default() && tx.pub_key != acc.address {
                continue;
            } else if tx.amount < 0 && balance_u64 as i64 + tx.amount < 0 {
                continue;
            } else {
                let updated_acc = core::Account {
                    address: tx.pub_key,
                    balance: ((balance_u64 as i64 + tx.amount) as u64).into(),
                    nonce: acc.nonce,
                };

                let proof = zeekit::merkle::Proof::<{ config::LOG4_TREE_SIZE }>(
                    KvStoreStateManager::<ZkHasher>::prove(
                        &mirror,
                        *MPN_CONTRACT_ID,
                        ZkDataLocator(vec![]),
                        tx.index,
                    )
                    .unwrap(),
                );

                set_account(&mut mirror, tx.index, updated_acc, &mut state_size);

                transitions.push(circuits::DepositWithdrawTransition {
                    enabled: true,
                    tx: tx.clone(),
                    before: acc,
                    proof,
                });
            }
        }
        let next_state = KvStoreStateManager::<ZkHasher>::get_data(
            &mirror,
            *MPN_CONTRACT_ID,
            &ZkDataLocator(vec![]),
        )
        .unwrap();

        let state_model = bazuka::zk::ZkStateModel::List {
            item_type: Box::new(bazuka::zk::CONTRACT_PAYMENT_STATE_MODEL.clone()),
            log4_size: config::LOG4_BATCH_SIZE as u8,
        };
        let mut state_builder =
            bazuka::zk::ZkStateBuilder::<bazuka::core::ZkHasher>::new(state_model.clone());
        for (i, trans) in transitions.iter().enumerate() {
            state_builder
                .batch_set(&bazuka::zk::ZkDeltaPairs(
                    [
                        (
                            bazuka::zk::ZkDataLocator(vec![i as u32, 0]),
                            Some(bazuka::zk::ZkScalar::from(trans.tx.index as u64)),
                        ),
                        (
                            bazuka::zk::ZkDataLocator(vec![i as u32, 1]),
                            Some(bazuka::zk::ZkScalar::from(trans.tx.amount as u64)),
                        ),
                        (
                            bazuka::zk::ZkDataLocator(vec![i as u32, 2]),
                            Some(bazuka::zk::ZkScalar::from(trans.tx.pub_key.0)),
                        ),
                        (
                            bazuka::zk::ZkDataLocator(vec![i as u32, 3]),
                            Some(bazuka::zk::ZkScalar::from(trans.tx.pub_key.1)),
                        ),
                    ]
                    .into(),
                ))
                .unwrap();
        }
        let aux_data = state_builder.compress().unwrap().state_hash;

        let circuit = circuits::DepositWithdrawCircuit {
            filled: true,
            state,
            aux_data,
            next_state,
            transitions: Box::new(circuits::DepositWithdrawTransitionBatch::new(transitions)),
        };

        let start = std::time::Instant::now();
        let proof = unsafe {
            std::mem::transmute::<bellman::groth16::Proof<Bls12>, bazuka::zk::groth16::Groth16Proof>(
                groth16::create_random_proof(circuit, &self.deposit_withdraw_params, &mut OsRng)
                    .unwrap(),
            )
        };
        println!(
            "Proving took: {}ms",
            (std::time::Instant::now() - start).as_millis()
        );

        if bazuka::zk::groth16::groth16_verify(
            &bazuka::config::blockchain::MPN_PAYMENT_VK,
            state,
            aux_data,
            next_state,
            &proof,
        ) {
            let ops = mirror.to_ops();
            db.update(&ops)?;
            Ok((
                extract_delta(ops),
                bazuka::zk::ZkCompressedState {
                    state_hash: next_state,
                    state_size,
                },
                proof,
            ))
        } else {
            Err(BankError::CannotProve)
        }
    }
    pub fn root<K: KvStore>(&self, db: &K) -> bazuka::zk::ZkCompressedState {
        KvStoreStateManager::<ZkHasher>::root(db, *MPN_CONTRACT_ID).unwrap()
    }
    pub fn change_state<K: KvStore>(
        &self,
        db: &mut K,
        txs: Vec<ZeroTransaction>,
    ) -> Result<
        (
            bazuka::zk::ZkDeltaPairs,
            bazuka::zk::ZkCompressedState,
            bazuka::zk::groth16::Groth16Proof,
        ),
        BankError,
    > {
        let mut transitions = Vec::new();

        let root = KvStoreStateManager::<ZkHasher>::root(db, *MPN_CONTRACT_ID).unwrap();

        let state = root.state_hash;
        let mut state_size = root.state_size;

        let mut mirror = db.mirror();

        for tx in txs.iter() {
            let src_before = get_account(&mirror, tx.src_index);
            if tx.nonce != src_before.nonce {
                continue;
            } else if !tx.verify(&PublicKey(src_before.address.compress())) {
                continue;
            } else if src_before.balance < tx.fee + tx.amount {
                continue;
            } else {
                let src_proof = zeekit::merkle::Proof::<{ config::LOG4_TREE_SIZE }>(
                    KvStoreStateManager::<ZkHasher>::prove(
                        &mirror,
                        *MPN_CONTRACT_ID,
                        ZkDataLocator(vec![]),
                        tx.src_index,
                    )
                    .unwrap(),
                );
                let src_after = core::Account {
                    address: src_before.address.clone(),
                    balance: src_before.balance - tx.fee - tx.amount,
                    nonce: src_before.nonce + 1,
                };
                set_account(&mut mirror, tx.src_index, src_after, &mut state_size);

                let dst_before = get_account(&mirror, tx.dst_index);
                let dst_proof = zeekit::merkle::Proof::<{ config::LOG4_TREE_SIZE }>(
                    KvStoreStateManager::<ZkHasher>::prove(
                        &mirror,
                        *MPN_CONTRACT_ID,
                        ZkDataLocator(vec![]),
                        tx.dst_index,
                    )
                    .unwrap(),
                );

                let dst_after = core::Account {
                    address: tx.dst_pub_key.0.decompress(),
                    balance: dst_before.balance + tx.amount,
                    nonce: dst_before.nonce,
                };
                set_account(&mut mirror, tx.dst_index, dst_after, &mut state_size);

                transitions.push(circuits::Transition {
                    enabled: true,
                    tx: tx.clone(),
                    src_before,
                    src_proof,
                    dst_before,
                    dst_proof,
                });
            }
        }

        let next_state = KvStoreStateManager::<ZkHasher>::get_data(
            &mirror,
            *MPN_CONTRACT_ID,
            &ZkDataLocator(vec![]),
        )
        .unwrap();
        let aux_data = ZkScalar::from(0);

        let circuit = circuits::UpdateCircuit {
            filled: true,
            state,
            aux_data,
            next_state,
            transitions: Box::new(circuits::TransitionBatch::new(transitions)),
        };

        let start = std::time::Instant::now();
        let proof = unsafe {
            std::mem::transmute::<bellman::groth16::Proof<Bls12>, bazuka::zk::groth16::Groth16Proof>(
                groth16::create_random_proof(circuit, &self.update_params, &mut OsRng).unwrap(),
            )
        };
        println!(
            "Proving took: {}ms",
            (std::time::Instant::now() - start).as_millis()
        );

        if bazuka::zk::groth16::groth16_verify(
            &bazuka::config::blockchain::MPN_UPDATE_VK,
            state,
            aux_data,
            next_state,
            &proof,
        ) {
            let ops = mirror.to_ops();
            db.update(&ops)?;
            Ok((
                extract_delta(ops),
                bazuka::zk::ZkCompressedState {
                    state_hash: next_state,
                    state_size,
                },
                proof,
            ))
        } else {
            Err(BankError::CannotProve)
        }
    }
}
