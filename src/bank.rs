use crate::circuits;
use crate::circuits::{Deposit, Withdraw};
use bazuka::zk::ZkScalar;
use bazuka::{
    blockchain::BlockchainConfig,
    core::{ContractId, ZkHasher},
    crypto::jubjub::PublicKey,
    db::KvStore,
    zk::{KvStoreStateManager, MpnAccount, MpnTransaction, ZkDataLocator},
};
use bellman::gpu::{Brand, Device};
use bellman::groth16;
use bellman::groth16::Backend;
use bellman::groth16::Parameters;
use bls12_381::Bls12;
use rand::rngs::OsRng;
use std::sync::{Arc, RwLock};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BankError {
    #[error("cannot generate zk-snark proof! Error: {0}")]
    CannotProve(#[from] bellman::SynthesisError),
    #[error("snark proof incorrect!")]
    IncorrectProof,
    #[error("kv-store error: {0}")]
    KvStoreError(#[from] bazuka::db::KvStoreError),
}

pub struct Bank<
    const LOG4_DEPOSIT_BATCH_SIZE: u8,
    const LOG4_WITHDRAW_BATCH_SIZE: u8,
    const LOG4_UPDATE_BATCH_SIZE: u8,
    const LOG4_TREE_SIZE: u8,
> {
    backend: Backend,
    mpn_contract_id: ContractId,
    update_params: Parameters<Bls12>,
    deposit_params: Parameters<Bls12>,
    withdraw_params: Parameters<Bls12>,
}

pub fn extract_delta(ops: Vec<bazuka::db::WriteOp>) -> bazuka::zk::ZkDeltaPairs {
    let mut pairs = bazuka::zk::ZkDeltaPairs([].into());
    for op in ops {
        match op {
            bazuka::db::WriteOp::Put(k, v) => {
                let mut it = k.0.split("-S-");
                it.next();
                if let Some(loc) = it.next() {
                    pairs
                        .0
                        .insert(loc.parse().unwrap(), Some(v.try_into().unwrap()));
                }
            }
            bazuka::db::WriteOp::Remove(k) => {
                let mut it = k.0.split("-S-");
                it.next();
                if let Some(loc) = it.next() {
                    pairs.0.insert(loc.parse().unwrap(), None);
                }
            }
        }
    }
    pairs
}

impl<
        const LOG4_DEPOSIT_BATCH_SIZE: u8,
        const LOG4_WITHDRAW_BATCH_SIZE: u8,
        const LOG4_UPDATE_BATCH_SIZE: u8,
        const LOG4_TREE_SIZE: u8,
    >
    Bank<LOG4_DEPOSIT_BATCH_SIZE, LOG4_WITHDRAW_BATCH_SIZE, LOG4_UPDATE_BATCH_SIZE, LOG4_TREE_SIZE>
{
    pub fn new(
        blockchain_config: BlockchainConfig,
        update_params: Parameters<Bls12>,
        deposit_params: Parameters<Bls12>,
        withdraw_params: Parameters<Bls12>,
        gpu: bool,
    ) -> Self {
        Self {
            backend: if gpu {
                Backend::Gpu(
                    Device::by_brand(Brand::Nvidia)
                        .unwrap()
                        .into_iter()
                        .map(|d| {
                            (
                                d,
                                bellman::gpu::OptParams {
                                    n_g1: 32 * 1024 * 1024,
                                    window_size_g1: 10,
                                    groups_g1: 807,
                                    n_g2: 16 * 1024 * 1024,
                                    window_size_g2: 9,
                                    groups_g2: 723,
                                },
                            )
                        })
                        .collect(),
                )
            } else {
                Backend::Cpu
            },
            mpn_contract_id: blockchain_config.mpn_contract_id,
            update_params,
            deposit_params,
            withdraw_params,
        }
    }

    pub fn withdraw<K: KvStore>(
        &self,
        db: &mut K,
        txs: Vec<Withdraw>,
        cancel: Arc<RwLock<bool>>,
    ) -> Result<
        (
            Vec<Withdraw>,
            Vec<Withdraw>,
            bazuka::zk::ZkCompressedState,
            bazuka::zk::groth16::Groth16Proof,
        ),
        BankError,
    > {
        let mut mirror = db.mirror();

        let mut transitions = Vec::new();
        let mut rejected = Vec::new();
        let mut accepted = Vec::new();
        let height = KvStoreStateManager::<ZkHasher>::height_of(db, self.mpn_contract_id).unwrap();
        let root = KvStoreStateManager::<ZkHasher>::root(db, self.mpn_contract_id).unwrap();

        let state = root.state_hash;
        let mut state_size = root.state_size;

        for tx in txs.into_iter() {
            if transitions.len() == 1 << (2 * LOG4_WITHDRAW_BATCH_SIZE) {
                break;
            }
            let acc = KvStoreStateManager::<ZkHasher>::get_mpn_account(
                &mirror,
                self.mpn_contract_id,
                tx.index,
            )
            .unwrap();

            // TODO: Check for wrong calldata
            // TODO: Check for wrong signature
            if (acc.address != Default::default() && tx.pub_key != acc.address)
                || tx.nonce != acc.nonce
                || tx.amount > acc.balance
            {
                rejected.push(tx.clone());
                continue;
            } else {
                let new_balance = acc.balance - tx.amount;
                let updated_acc = MpnAccount {
                    address: tx.pub_key,
                    balance: new_balance,
                    nonce: acc.nonce + 1,
                };

                let proof = zeekit::merkle::Proof::<{ LOG4_TREE_SIZE }>(
                    KvStoreStateManager::<ZkHasher>::prove(
                        &mirror,
                        self.mpn_contract_id,
                        ZkDataLocator(vec![]),
                        tx.index,
                    )
                    .unwrap(),
                );

                KvStoreStateManager::<ZkHasher>::set_mpn_account(
                    &mut mirror,
                    self.mpn_contract_id,
                    tx.index,
                    updated_acc,
                    &mut state_size,
                )
                .unwrap();

                transitions.push(circuits::WithdrawTransition {
                    enabled: true,
                    tx: tx.clone(),
                    before: acc,
                    proof,
                });
                accepted.push(tx);
            }
        }
        let next_state = KvStoreStateManager::<ZkHasher>::get_data(
            &mirror,
            self.mpn_contract_id,
            &ZkDataLocator(vec![]),
        )
        .unwrap();
        mirror
            .update(&[bazuka::db::WriteOp::Put(
                bazuka::db::keys::local_root(&self.mpn_contract_id),
                bazuka::zk::ZkCompressedState {
                    state_hash: next_state,
                    state_size,
                }
                .into(),
            )])
            .unwrap();

        let state_model = bazuka::zk::ZkStateModel::List {
            item_type: Box::new(bazuka::zk::ZkStateModel::Struct {
                field_types: vec![
                    bazuka::zk::ZkStateModel::Scalar, // Enabled
                    bazuka::zk::ZkStateModel::Scalar, // Amount
                    bazuka::zk::ZkStateModel::Scalar, // Fingerprint
                    bazuka::zk::ZkStateModel::Scalar, // Calldata
                ],
            }),
            log4_size: LOG4_WITHDRAW_BATCH_SIZE as u8,
        };
        let mut state_builder =
            bazuka::zk::ZkStateBuilder::<bazuka::core::ZkHasher>::new(state_model.clone());
        for (i, trans) in transitions.iter().enumerate() {
            use bazuka::zk::ZkHasher;
            let calldata = bazuka::core::ZkHasher::hash(&[
                bazuka::zk::ZkScalar::from(trans.tx.pub_key.0),
                bazuka::zk::ZkScalar::from(trans.tx.pub_key.1),
                bazuka::zk::ZkScalar::from(trans.tx.nonce as u64),
                bazuka::zk::ZkScalar::from(trans.tx.sig.r.0),
                bazuka::zk::ZkScalar::from(trans.tx.sig.r.1),
                bazuka::zk::ZkScalar::from(trans.tx.sig.s),
            ]);
            state_builder
                .batch_set(&bazuka::zk::ZkDeltaPairs(
                    [
                        (
                            bazuka::zk::ZkDataLocator(vec![i as u32, 0]),
                            Some(bazuka::zk::ZkScalar::from(1)),
                        ),
                        (
                            bazuka::zk::ZkDataLocator(vec![i as u32, 1]),
                            Some(bazuka::zk::ZkScalar::from(trans.tx.amount)),
                        ),
                        (
                            bazuka::zk::ZkDataLocator(vec![i as u32, 2]),
                            Some(trans.tx.fingerprint),
                        ),
                        (bazuka::zk::ZkDataLocator(vec![i as u32, 3]), Some(calldata)),
                    ]
                    .into(),
                ))
                .unwrap();
        }
        let aux_data = state_builder.compress().unwrap().state_hash;

        let circuit = circuits::WithdrawCircuit {
            height,
            state,
            aux_data,
            next_state,
            transitions: Box::new(circuits::WithdrawTransitionBatch::<
                LOG4_WITHDRAW_BATCH_SIZE,
                LOG4_TREE_SIZE,
            >::new(transitions)),
        };

        let proof = unsafe {
            std::mem::transmute::<bellman::groth16::Proof<Bls12>, bazuka::zk::groth16::Groth16Proof>(
                groth16::create_random_proof(
                    circuit,
                    &self.withdraw_params,
                    &mut OsRng,
                    self.backend.clone(),
                    Some(cancel),
                )?,
            )
        };

        if bazuka::zk::groth16::groth16_verify(
            &bazuka::config::blockchain::MPN_WITHDRAW_VK,
            height,
            state,
            aux_data,
            next_state,
            &proof,
        ) {
            let ops = mirror.to_ops();
            db.update(&ops)?;
            Ok((
                accepted,
                rejected,
                bazuka::zk::ZkCompressedState {
                    state_hash: next_state,
                    state_size,
                },
                proof,
            ))
        } else {
            Err(BankError::IncorrectProof)
        }
    }

    pub fn deposit<K: KvStore>(
        &self,
        db: &mut K,
        txs: Vec<Deposit>,
        cancel: Arc<RwLock<bool>>,
    ) -> Result<
        (
            Vec<Deposit>,
            Vec<Deposit>,
            bazuka::zk::ZkCompressedState,
            bazuka::zk::groth16::Groth16Proof,
        ),
        BankError,
    > {
        let mut mirror = db.mirror();

        let mut transitions = Vec::new();
        let mut rejected = Vec::new();
        let mut accepted = Vec::new();
        let height = KvStoreStateManager::<ZkHasher>::height_of(db, self.mpn_contract_id).unwrap();
        let root = KvStoreStateManager::<ZkHasher>::root(db, self.mpn_contract_id).unwrap();

        let state = root.state_hash;
        let mut state_size = root.state_size;

        for tx in txs.into_iter() {
            if transitions.len() == 1 << (2 * LOG4_DEPOSIT_BATCH_SIZE) {
                break;
            }
            let acc = KvStoreStateManager::<ZkHasher>::get_mpn_account(
                &mirror,
                self.mpn_contract_id,
                tx.index,
            )
            .unwrap();
            if acc.address != Default::default() && tx.pub_key != acc.address {
                rejected.push(tx.clone());
                continue;
            } else {
                let new_balance = acc.balance + tx.amount;
                let updated_acc = MpnAccount {
                    address: tx.pub_key,
                    balance: new_balance,
                    nonce: acc.nonce,
                };

                let proof = zeekit::merkle::Proof::<{ LOG4_TREE_SIZE }>(
                    KvStoreStateManager::<ZkHasher>::prove(
                        &mirror,
                        self.mpn_contract_id,
                        ZkDataLocator(vec![]),
                        tx.index,
                    )
                    .unwrap(),
                );

                KvStoreStateManager::<ZkHasher>::set_mpn_account(
                    &mut mirror,
                    self.mpn_contract_id,
                    tx.index,
                    updated_acc,
                    &mut state_size,
                )
                .unwrap();

                transitions.push(circuits::DepositTransition {
                    enabled: true,
                    tx: tx.clone(),
                    before: acc,
                    proof,
                });
                accepted.push(tx);
            }
        }
        let next_state = KvStoreStateManager::<ZkHasher>::get_data(
            &mirror,
            self.mpn_contract_id,
            &ZkDataLocator(vec![]),
        )
        .unwrap();
        mirror
            .update(&[bazuka::db::WriteOp::Put(
                bazuka::db::keys::local_root(&self.mpn_contract_id),
                bazuka::zk::ZkCompressedState {
                    state_hash: next_state,
                    state_size,
                }
                .into(),
            )])
            .unwrap();

        let state_model = bazuka::zk::ZkStateModel::List {
            item_type: Box::new(bazuka::zk::ZkStateModel::Struct {
                field_types: vec![
                    bazuka::zk::ZkStateModel::Scalar, // Enabled
                    bazuka::zk::ZkStateModel::Scalar, // Amount
                    bazuka::zk::ZkStateModel::Scalar, // Calldata
                ],
            }),
            log4_size: LOG4_DEPOSIT_BATCH_SIZE as u8,
        };
        let mut state_builder =
            bazuka::zk::ZkStateBuilder::<bazuka::core::ZkHasher>::new(state_model.clone());

        for (i, trans) in transitions.iter().enumerate() {
            use bazuka::zk::ZkHasher;
            let calldata = bazuka::core::ZkHasher::hash(&[
                bazuka::zk::ZkScalar::from(trans.tx.pub_key.0),
                bazuka::zk::ZkScalar::from(trans.tx.pub_key.1),
            ]);
            state_builder
                .batch_set(&bazuka::zk::ZkDeltaPairs(
                    [
                        (
                            bazuka::zk::ZkDataLocator(vec![i as u32, 0]),
                            Some(bazuka::zk::ZkScalar::from(1)),
                        ),
                        (
                            bazuka::zk::ZkDataLocator(vec![i as u32, 1]),
                            Some(bazuka::zk::ZkScalar::from(trans.tx.amount)),
                        ),
                        (
                            bazuka::zk::ZkDataLocator(vec![i as u32, 2]),
                            Some(bazuka::zk::ZkScalar::from(calldata)),
                        ),
                    ]
                    .into(),
                ))
                .unwrap();
        }
        let aux_data = state_builder.compress().unwrap().state_hash;

        let circuit = circuits::DepositCircuit {
            height,
            state,
            aux_data,
            next_state,
            transitions: Box::new(circuits::DepositTransitionBatch::<
                LOG4_DEPOSIT_BATCH_SIZE,
                LOG4_TREE_SIZE,
            >::new(transitions)),
        };

        let proof = unsafe {
            std::mem::transmute::<bellman::groth16::Proof<Bls12>, bazuka::zk::groth16::Groth16Proof>(
                groth16::create_random_proof(
                    circuit,
                    &self.deposit_params,
                    &mut OsRng,
                    self.backend.clone(),
                    Some(cancel),
                )?,
            )
        };

        if bazuka::zk::groth16::groth16_verify(
            &bazuka::config::blockchain::MPN_DEPOSIT_VK,
            height,
            state,
            aux_data,
            next_state,
            &proof,
        ) {
            let ops = mirror.to_ops();
            db.update(&ops)?;
            Ok((
                accepted,
                rejected,
                bazuka::zk::ZkCompressedState {
                    state_hash: next_state,
                    state_size,
                },
                proof,
            ))
        } else {
            Err(BankError::IncorrectProof)
        }
    }
    pub fn change_state<K: KvStore>(
        &self,
        db: &mut K,
        txs: Vec<MpnTransaction>,
        cancel: Arc<RwLock<bool>>,
    ) -> Result<
        (
            Vec<MpnTransaction>,
            Vec<MpnTransaction>,
            bazuka::zk::ZkCompressedState,
            bazuka::zk::groth16::Groth16Proof,
        ),
        BankError,
    > {
        let mut rejected = Vec::new();
        let mut accepted = Vec::new();
        let mut transitions = Vec::new();

        let root = KvStoreStateManager::<ZkHasher>::root(db, self.mpn_contract_id).unwrap();
        let height = KvStoreStateManager::<ZkHasher>::height_of(db, self.mpn_contract_id).unwrap();

        let state = root.state_hash;
        let mut state_size = root.state_size;

        let mut mirror = db.mirror();

        for tx in txs.into_iter() {
            if transitions.len() == 1 << (2 * LOG4_UPDATE_BATCH_SIZE) {
                break;
            }
            let src_before = KvStoreStateManager::<ZkHasher>::get_mpn_account(
                &mirror,
                self.mpn_contract_id,
                tx.src_index,
            )
            .unwrap();
            if tx.nonce != src_before.nonce
                || !tx.verify(&PublicKey(src_before.address.compress()))
                || src_before.balance < tx.fee + tx.amount
            {
                rejected.push(tx.clone());
                continue;
            } else {
                let src_proof = zeekit::merkle::Proof::<{ LOG4_TREE_SIZE }>(
                    KvStoreStateManager::<ZkHasher>::prove(
                        &mirror,
                        self.mpn_contract_id,
                        ZkDataLocator(vec![]),
                        tx.src_index,
                    )
                    .unwrap(),
                );
                let src_after = MpnAccount {
                    address: src_before.address.clone(),
                    balance: src_before.balance - tx.fee - tx.amount,
                    nonce: src_before.nonce + 1,
                };
                KvStoreStateManager::<ZkHasher>::set_mpn_account(
                    &mut mirror,
                    self.mpn_contract_id,
                    tx.src_index,
                    src_after,
                    &mut state_size,
                )
                .unwrap();

                let dst_before = KvStoreStateManager::<ZkHasher>::get_mpn_account(
                    &mirror,
                    self.mpn_contract_id,
                    tx.dst_index,
                )
                .unwrap();
                let dst_proof = zeekit::merkle::Proof::<{ LOG4_TREE_SIZE }>(
                    KvStoreStateManager::<ZkHasher>::prove(
                        &mirror,
                        self.mpn_contract_id,
                        ZkDataLocator(vec![]),
                        tx.dst_index,
                    )
                    .unwrap(),
                );

                let dst_after = MpnAccount {
                    address: tx.dst_pub_key.0.decompress(),
                    balance: dst_before.balance + tx.amount,
                    nonce: dst_before.nonce,
                };
                KvStoreStateManager::<ZkHasher>::set_mpn_account(
                    &mut mirror,
                    self.mpn_contract_id,
                    tx.dst_index,
                    dst_after,
                    &mut state_size,
                )
                .unwrap();

                transitions.push(circuits::Transition {
                    enabled: true,
                    tx: tx.clone(),
                    src_before,
                    src_proof,
                    dst_before,
                    dst_proof,
                });
                accepted.push(tx);
            }
        }

        let next_state = KvStoreStateManager::<ZkHasher>::get_data(
            &mirror,
            self.mpn_contract_id,
            &ZkDataLocator(vec![]),
        )
        .unwrap();
        mirror
            .update(&[bazuka::db::WriteOp::Put(
                bazuka::db::keys::local_root(&self.mpn_contract_id),
                bazuka::zk::ZkCompressedState {
                    state_hash: next_state,
                    state_size,
                }
                .into(),
            )])
            .unwrap();

        let aux_data = ZkScalar::from(
            accepted
                .iter()
                .map(|tx| Into::<u64>::into(tx.fee))
                .sum::<u64>(),
        );

        let circuit = circuits::UpdateCircuit {
            state,
            height,
            aux_data,
            next_state,
            transitions: Box::new(circuits::TransitionBatch::<
                LOG4_UPDATE_BATCH_SIZE,
                LOG4_TREE_SIZE,
            >::new(transitions)),
        };

        let proof = unsafe {
            std::mem::transmute::<bellman::groth16::Proof<Bls12>, bazuka::zk::groth16::Groth16Proof>(
                groth16::create_random_proof(
                    circuit,
                    &self.update_params,
                    &mut OsRng,
                    self.backend.clone(),
                    Some(cancel),
                )?,
            )
        };

        if bazuka::zk::groth16::groth16_verify(
            &bazuka::config::blockchain::MPN_UPDATE_VK,
            height,
            state,
            aux_data,
            next_state,
            &proof,
        ) {
            let ops = mirror.to_ops();
            db.update(&ops)?;
            Ok((
                accepted,
                rejected,
                bazuka::zk::ZkCompressedState {
                    state_hash: next_state,
                    state_size,
                },
                proof,
            ))
        } else {
            Err(BankError::IncorrectProof)
        }
    }
}
