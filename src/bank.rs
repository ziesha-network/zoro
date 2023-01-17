use crate::circuits;
use crate::circuits::{Deposit, DepositCircuit, UpdateCircuit, Withdraw, WithdrawCircuit};
use bazuka::zk::ZkScalar;
use bazuka::{
    core::{ContractId, Money, TokenId, ZkHasher},
    db::KvStore,
    zk::{KvStoreStateManager, MpnAccount, MpnTransaction, ZkDataLocator},
};
use bellman::gpu::{Brand, Device};
use bellman::groth16;
use bellman::groth16::Backend;
use bellman::groth16::Parameters;
use bellman::Circuit;
use bls12_381::Bls12;
use rand::rngs::OsRng;
use std::sync::{Arc, Mutex, RwLock};
use thiserror::Error;
use zeekit::BellmanFr;

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
    const LOG4_TOKENS_TREE_SIZE: u8,
> {
    backend: Backend,
    mpn_contract_id: ContractId,
    debug: bool,
}

pub struct SnarkWork<C: Circuit<BellmanFr> + Clone> {
    circuit: C,
    params: Parameters<Bls12>,
    backend: Backend,
    cancel: Option<Arc<RwLock<bool>>>,
    verifier: bazuka::zk::groth16::Groth16VerifyingKey,
    height: u64,
    state: ZkScalar,
    aux_data: ZkScalar,
    next_state: ZkScalar,
}
unsafe impl<C: Circuit<BellmanFr> + Clone> std::marker::Send for SnarkWork<C> {}
unsafe impl<C: Circuit<BellmanFr> + Clone> std::marker::Sync for SnarkWork<C> {}

pub trait Provable: std::marker::Send + std::marker::Sync {
    fn prove(&self) -> Result<bazuka::zk::groth16::Groth16Proof, BankError>;
}

impl<C: Circuit<BellmanFr> + Clone> Provable for SnarkWork<C> {
    fn prove(&self) -> Result<bazuka::zk::groth16::Groth16Proof, BankError> {
        let proof = unsafe {
            std::mem::transmute::<bellman::groth16::Proof<Bls12>, bazuka::zk::groth16::Groth16Proof>(
                groth16::create_random_proof(
                    self.circuit.clone(),
                    &self.params,
                    &mut OsRng,
                    self.backend.clone(),
                    self.cancel.clone(),
                )?,
            )
        };

        if bazuka::zk::groth16::groth16_verify(
            &self.verifier,
            self.height,
            self.state,
            self.aux_data,
            self.next_state,
            &proof,
        ) {
            Ok(proof)
        } else {
            Err(BankError::IncorrectProof)
        }
    }
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
        const LOG4_TOKENS_TREE_SIZE: u8,
    >
    Bank<
        LOG4_DEPOSIT_BATCH_SIZE,
        LOG4_WITHDRAW_BATCH_SIZE,
        LOG4_UPDATE_BATCH_SIZE,
        LOG4_TREE_SIZE,
        LOG4_TOKENS_TREE_SIZE,
    >
{
    pub fn new(mpn_contract_id: ContractId, gpu: bool, debug: bool) -> Self {
        Self {
            debug,
            backend: if gpu {
                Backend::Gpu(Arc::new(Mutex::new(
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
                )))
            } else {
                Backend::Cpu
            },
            mpn_contract_id,
        }
    }

    pub fn withdraw<K: KvStore>(
        &self,
        db: &mut K,
        params: Parameters<Bls12>,
        txs: Vec<Withdraw>,
        cancel: Arc<RwLock<bool>>,
    ) -> Result<
        (
            Vec<Withdraw>,
            Vec<Withdraw>,
            bazuka::zk::ZkCompressedState,
            SnarkWork<
                WithdrawCircuit<
                    { LOG4_WITHDRAW_BATCH_SIZE },
                    { LOG4_TREE_SIZE },
                    { LOG4_TOKENS_TREE_SIZE },
                >,
            >,
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

            let acc_token = if let Some(acc_token) = acc.tokens.get(&tx.token_index) {
                acc_token.clone()
            } else {
                rejected.push(tx.clone());
                continue;
            };

            // TODO: Check for wrong calldata
            // TODO: Check for wrong signature
            if (acc.address != Default::default() && tx.pub_key != acc.address)
                || tx.nonce != acc.nonce
                || tx.amount.token_id != acc_token.token_id
                || tx.amount.amount > acc_token.amount
                || tx.index > 0x3fffffff
            {
                rejected.push(tx.clone());
                continue;
            } else {
                let mut updated_acc = MpnAccount {
                    address: tx.pub_key,
                    tokens: acc.tokens.clone(),
                    nonce: acc.nonce + 1,
                };

                let before_token_hash = updated_acc.tokens_hash::<ZkHasher>(LOG4_TOKENS_TREE_SIZE);
                let token_balance_proof = zeekit::merkle::Proof::<{ LOG4_TOKENS_TREE_SIZE }>(
                    KvStoreStateManager::<ZkHasher>::prove(
                        &mirror,
                        self.mpn_contract_id,
                        ZkDataLocator(vec![tx.index, 3]),
                        tx.token_index,
                    )
                    .unwrap(),
                );

                updated_acc.tokens.get_mut(&tx.token_index).unwrap().amount -= tx.amount.amount;
                KvStoreStateManager::<ZkHasher>::set_mpn_account(
                    &mut mirror,
                    self.mpn_contract_id,
                    tx.index,
                    updated_acc.clone(),
                    &mut state_size,
                )
                .unwrap();

                let fee_balance_proof = zeekit::merkle::Proof::<{ LOG4_TOKENS_TREE_SIZE }>(
                    KvStoreStateManager::<ZkHasher>::prove(
                        &mirror,
                        self.mpn_contract_id,
                        ZkDataLocator(vec![tx.index, 3]),
                        tx.fee_token_index,
                    )
                    .unwrap(),
                );

                let acc_fee_token =
                    if let Some(src_fee_token) = updated_acc.tokens.get(&tx.fee_token_index) {
                        src_fee_token.clone()
                    } else {
                        rejected.push(tx.clone());
                        continue;
                    };
                if tx.fee.token_id != acc_fee_token.token_id || tx.fee.amount > acc_fee_token.amount
                {
                    rejected.push(tx.clone());
                    continue;
                }

                updated_acc
                    .tokens
                    .get_mut(&tx.fee_token_index)
                    .unwrap()
                    .amount -= tx.fee.amount;

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
                    before_token_balance: acc_token.clone(),
                    before_fee_balance: acc_fee_token.clone(),
                    proof,
                    token_balance_proof,
                    fee_balance_proof,
                    before_token_hash,
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
                    bazuka::zk::ZkStateModel::Scalar, // Amount token-id
                    bazuka::zk::ZkStateModel::Scalar, // Fee
                    bazuka::zk::ZkStateModel::Scalar, // Fee token-id
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
                            bazuka::zk::ZkDataLocator(vec![i as u64, 0]),
                            Some(bazuka::zk::ZkScalar::from(1)),
                        ),
                        (
                            bazuka::zk::ZkDataLocator(vec![i as u64, 1]),
                            Some(trans.tx.amount.token_id.into()),
                        ),
                        (
                            bazuka::zk::ZkDataLocator(vec![i as u64, 2]),
                            Some(trans.tx.amount.amount.into()),
                        ),
                        (
                            bazuka::zk::ZkDataLocator(vec![i as u64, 3]),
                            Some(trans.tx.fee.token_id.into()),
                        ),
                        (
                            bazuka::zk::ZkDataLocator(vec![i as u64, 4]),
                            Some(trans.tx.fee.amount.into()),
                        ),
                        (
                            bazuka::zk::ZkDataLocator(vec![i as u64, 5]),
                            Some(trans.tx.fingerprint),
                        ),
                        (bazuka::zk::ZkDataLocator(vec![i as u64, 6]), Some(calldata)),
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
                LOG4_TOKENS_TREE_SIZE,
            >::new(transitions)),
        };

        let ops = mirror.to_ops();
        db.update(&ops)?;
        Ok((
            accepted,
            rejected,
            bazuka::zk::ZkCompressedState {
                state_hash: next_state,
                state_size,
            },
            SnarkWork::<
                WithdrawCircuit<
                    { LOG4_WITHDRAW_BATCH_SIZE },
                    { LOG4_TREE_SIZE },
                    { LOG4_TOKENS_TREE_SIZE },
                >,
            > {
                circuit,
                params: params.clone(),
                backend: self.backend.clone(),
                cancel: Some(cancel),
                verifier: if self.debug {
                    unsafe {
                        std::mem::transmute::<
                            bellman::groth16::VerifyingKey<Bls12>,
                            bazuka::zk::groth16::Groth16VerifyingKey,
                        >(params.vk.clone())
                    }
                } else {
                    bazuka::config::blockchain::MPN_WITHDRAW_VK.clone()
                },
                height,
                state,
                aux_data,
                next_state,
            },
        ))
    }

    pub fn deposit<K: KvStore>(
        &self,
        db: &mut K,
        params: Parameters<Bls12>,
        txs: Vec<Deposit>,
        cancel: Arc<RwLock<bool>>,
    ) -> Result<
        (
            Vec<Deposit>,
            Vec<Deposit>,
            bazuka::zk::ZkCompressedState,
            SnarkWork<
                DepositCircuit<
                    { LOG4_DEPOSIT_BATCH_SIZE },
                    { LOG4_TREE_SIZE },
                    { LOG4_TOKENS_TREE_SIZE },
                >,
            >,
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
            if tx.index > 0x3fffffff {
                rejected.push(tx.clone());
                continue;
            }
            let acc = KvStoreStateManager::<ZkHasher>::get_mpn_account(
                &mirror,
                self.mpn_contract_id,
                tx.index,
            )
            .unwrap();
            let acc_token = acc.tokens.get(&tx.token_index).clone();
            if (acc.address != Default::default() && tx.pub_key != acc.address)
                || (acc_token.is_some() && acc_token.unwrap().token_id != tx.amount.token_id)
            {
                rejected.push(tx.clone());
                continue;
            } else {
                let mut updated_acc = MpnAccount {
                    address: tx.pub_key,
                    tokens: acc.tokens.clone(),
                    nonce: acc.nonce,
                };
                updated_acc
                    .tokens
                    .entry(tx.token_index)
                    .or_insert(Money::new(tx.amount.token_id, 0))
                    .amount += tx.amount.amount;

                let balance_proof = zeekit::merkle::Proof::<{ LOG4_TOKENS_TREE_SIZE }>(
                    KvStoreStateManager::<ZkHasher>::prove(
                        &mirror,
                        self.mpn_contract_id,
                        ZkDataLocator(vec![tx.index, 3]),
                        tx.token_index,
                    )
                    .unwrap(),
                );
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
                    before: acc.clone(),
                    before_balances_hash: acc.tokens_hash::<ZkHasher>(LOG4_TOKENS_TREE_SIZE),
                    before_balance: acc_token.cloned().unwrap_or_default(),
                    proof,
                    balance_proof,
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
                    bazuka::zk::ZkStateModel::Scalar, // Token-id
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
                            bazuka::zk::ZkDataLocator(vec![i as u64, 0]),
                            Some(bazuka::zk::ZkScalar::from(1)),
                        ),
                        (
                            bazuka::zk::ZkDataLocator(vec![i as u64, 1]),
                            Some(trans.tx.amount.token_id.into()),
                        ),
                        (
                            bazuka::zk::ZkDataLocator(vec![i as u64, 2]),
                            Some(trans.tx.amount.amount.into()),
                        ),
                        (
                            bazuka::zk::ZkDataLocator(vec![i as u64, 3]),
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
                LOG4_TOKENS_TREE_SIZE,
            >::new(transitions)),
        };

        let ops = mirror.to_ops();
        db.update(&ops)?;

        Ok((
            accepted,
            rejected,
            bazuka::zk::ZkCompressedState {
                state_hash: next_state,
                state_size,
            },
            SnarkWork::<
                DepositCircuit<
                    { LOG4_DEPOSIT_BATCH_SIZE },
                    { LOG4_TREE_SIZE },
                    { LOG4_TOKENS_TREE_SIZE },
                >,
            > {
                circuit,
                params: params.clone(),
                backend: self.backend.clone(),
                cancel: Some(cancel),
                verifier: if self.debug {
                    unsafe {
                        std::mem::transmute::<
                            bellman::groth16::VerifyingKey<Bls12>,
                            bazuka::zk::groth16::Groth16VerifyingKey,
                        >(params.vk.clone())
                    }
                } else {
                    bazuka::config::blockchain::MPN_DEPOSIT_VK.clone()
                },
                height,
                state,
                aux_data,
                next_state,
            },
        ))
    }
    pub fn change_state<K: KvStore>(
        &self,
        db: &mut K,
        params: Parameters<Bls12>,
        txs: Vec<MpnTransaction>,
        fee_token: TokenId,
        cancel: Arc<RwLock<bool>>,
    ) -> Result<
        (
            Vec<MpnTransaction>,
            Vec<MpnTransaction>,
            bazuka::zk::ZkCompressedState,
            SnarkWork<
                UpdateCircuit<
                    { LOG4_UPDATE_BATCH_SIZE },
                    { LOG4_TREE_SIZE },
                    { LOG4_TOKENS_TREE_SIZE },
                >,
            >,
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
            let dst_before = KvStoreStateManager::<ZkHasher>::get_mpn_account(
                &mirror,
                self.mpn_contract_id,
                tx.dst_index,
            )
            .unwrap();
            let src_token = if let Some(src_token) = src_before.tokens.get(&tx.src_token_index) {
                src_token.clone()
            } else {
                rejected.push(tx.clone());
                continue;
            };
            let dst_token = dst_before.tokens.get(&tx.dst_token_index);
            if tx.nonce != src_before.nonce
                || tx.fee.token_id != fee_token
                || tx.src_index > 0x3fffffff
                || tx.dst_index > 0x3fffffff
                || tx.src_index == tx.dst_index
                || !tx.src_pub_key.is_on_curve()
                || !tx.dst_pub_key.is_on_curve()
                || src_before.address != tx.src_pub_key.decompress()
                || (dst_before.address.is_on_curve()
                    && dst_before.address != tx.dst_pub_key.decompress())
                || !tx.verify()
                || dst_token.is_some() && (src_token.token_id != dst_token.unwrap().token_id)
                || src_token.token_id != tx.amount.token_id
                || src_token.amount < tx.amount.amount
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

                let mut src_after = MpnAccount {
                    address: src_before.address.clone(),
                    tokens: src_before.tokens.clone(),
                    nonce: src_before.nonce + 1,
                };

                let src_balance_proof = zeekit::merkle::Proof::<{ LOG4_TOKENS_TREE_SIZE }>(
                    KvStoreStateManager::<ZkHasher>::prove(
                        &mirror,
                        self.mpn_contract_id,
                        ZkDataLocator(vec![tx.src_index, 3]),
                        tx.src_token_index,
                    )
                    .unwrap(),
                );

                src_after
                    .tokens
                    .get_mut(&tx.src_token_index)
                    .unwrap()
                    .amount -= tx.amount.amount;
                KvStoreStateManager::<ZkHasher>::set_mpn_account(
                    &mut mirror,
                    self.mpn_contract_id,
                    tx.src_index,
                    src_after.clone(),
                    &mut state_size,
                )
                .unwrap();

                let src_fee_token =
                    if let Some(src_fee_token) = src_after.tokens.get(&tx.src_fee_token_index) {
                        src_fee_token.clone()
                    } else {
                        rejected.push(tx.clone());
                        continue;
                    };

                if src_fee_token.token_id != tx.fee.token_id || src_fee_token.amount < tx.fee.amount
                {
                    rejected.push(tx.clone());
                    continue;
                }

                let src_fee_balance_proof = zeekit::merkle::Proof::<{ LOG4_TOKENS_TREE_SIZE }>(
                    KvStoreStateManager::<ZkHasher>::prove(
                        &mirror,
                        self.mpn_contract_id,
                        ZkDataLocator(vec![tx.src_index, 3]),
                        tx.src_fee_token_index,
                    )
                    .unwrap(),
                );

                src_after
                    .tokens
                    .get_mut(&tx.src_fee_token_index)
                    .unwrap()
                    .amount -= tx.fee.amount;
                KvStoreStateManager::<ZkHasher>::set_mpn_account(
                    &mut mirror,
                    self.mpn_contract_id,
                    tx.src_index,
                    src_after,
                    &mut state_size,
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
                let dst_balance_proof = zeekit::merkle::Proof::<{ LOG4_TOKENS_TREE_SIZE }>(
                    KvStoreStateManager::<ZkHasher>::prove(
                        &mirror,
                        self.mpn_contract_id,
                        ZkDataLocator(vec![tx.dst_index, 3]),
                        tx.dst_token_index,
                    )
                    .unwrap(),
                );

                let mut dst_after = MpnAccount {
                    address: tx.dst_pub_key.0.decompress(),
                    tokens: dst_before.tokens.clone(),
                    nonce: dst_before.nonce,
                };
                dst_after
                    .tokens
                    .entry(tx.dst_token_index)
                    .or_insert(Money::new(tx.amount.token_id, 0))
                    .amount += tx.amount.amount;
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
                    src_before: src_before.clone(),
                    src_proof,
                    dst_before: dst_before.clone(),
                    dst_proof,
                    src_balance_proof,
                    src_fee_balance_proof,
                    dst_balance_proof,
                    src_before_balance: src_token.clone(),
                    src_before_fee_balance: src_fee_token.clone(),
                    dst_before_balance: dst_token.cloned().unwrap_or(Money::default()),
                    src_before_balances_hash: src_before
                        .tokens_hash::<ZkHasher>(LOG4_TOKENS_TREE_SIZE),
                    dst_before_balances_hash: dst_before
                        .tokens_hash::<ZkHasher>(LOG4_TOKENS_TREE_SIZE),
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

        let aux_data = {
            use bazuka::zk::ZkHasher;
            bazuka::core::ZkHasher::hash(&[
                fee_token.into(),
                ZkScalar::from(
                    accepted
                        .iter()
                        .map(|tx| Into::<u64>::into(tx.fee.amount))
                        .sum::<u64>(),
                ),
            ])
        };

        let circuit = circuits::UpdateCircuit {
            fee_token,
            state,
            height,
            aux_data,
            next_state,
            transitions: Box::new(circuits::TransitionBatch::<
                LOG4_UPDATE_BATCH_SIZE,
                LOG4_TREE_SIZE,
                LOG4_TOKENS_TREE_SIZE,
            >::new(transitions)),
        };
        let ops = mirror.to_ops();
        db.update(&ops)?;
        Ok((
            accepted,
            rejected,
            bazuka::zk::ZkCompressedState {
                state_hash: next_state,
                state_size,
            },
            SnarkWork::<
                UpdateCircuit<
                    { LOG4_UPDATE_BATCH_SIZE },
                    { LOG4_TREE_SIZE },
                    { LOG4_TOKENS_TREE_SIZE },
                >,
            > {
                circuit,
                params: params.clone(),
                backend: self.backend.clone(),
                cancel: Some(cancel),
                verifier: if self.debug {
                    unsafe {
                        std::mem::transmute::<
                            bellman::groth16::VerifyingKey<Bls12>,
                            bazuka::zk::groth16::Groth16VerifyingKey,
                        >(params.vk.clone())
                    }
                } else {
                    bazuka::config::blockchain::MPN_UPDATE_VK.clone()
                },
                height,
                state,
                aux_data,
                next_state,
            },
        ))
    }
}
