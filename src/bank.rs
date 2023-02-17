use crate::circuits;
use crate::circuits::{Deposit, Withdraw};
use bazuka::zk::ZkScalar;
use bazuka::{
    core::{Amount, ContractId, Money, TokenId, ZkHasher},
    db::KvStore,
    zk::{KvStoreStateManager, MpnAccount, MpnTransaction, ZkDataLocator},
};
use bellman::groth16;
use bellman::groth16::Backend;
use bls12_381::Bls12;
use rand::rngs::OsRng;
use rayon::prelude::*;
use std::collections::HashSet;
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
    const LOG4_TOKENS_TREE_SIZE: u8,
> {
    mpn_contract_id: ContractId,
    mpn_log4_account_capacity: u8,
}

#[derive(Clone)]
pub struct ZoroParams {
    pub deposit: groth16::Parameters<Bls12>,
    pub withdraw: groth16::Parameters<Bls12>,
    pub update: groth16::Parameters<Bls12>,
}

impl ZoroParams {
    fn verify_keys(&self) -> ZoroVerifyKeys {
        ZoroVerifyKeys {
            update: self.update.vk.clone().into(),
            deposit: self.deposit.vk.clone().into(),
            withdraw: self.withdraw.vk.clone().into(),
        }
    }
}

#[derive(Clone)]
pub struct ZoroVerifyKeys {
    pub deposit: bazuka::zk::groth16::Groth16VerifyingKey,
    pub withdraw: bazuka::zk::groth16::Groth16VerifyingKey,
    pub update: bazuka::zk::groth16::Groth16VerifyingKey,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ZoroWork<
    const LOG4_DEPOSIT_BATCH_SIZE: u8,
    const LOG4_WITHDRAW_BATCH_SIZE: u8,
    const LOG4_UPDATE_BATCH_SIZE: u8,
    const LOG4_TREE_SIZE: u8,
    const LOG4_TOKENS_TREE_SIZE: u8,
> {
    circuit: ZoroCircuit<
        LOG4_DEPOSIT_BATCH_SIZE,
        LOG4_WITHDRAW_BATCH_SIZE,
        LOG4_UPDATE_BATCH_SIZE,
        LOG4_TREE_SIZE,
        LOG4_TOKENS_TREE_SIZE,
    >,
    height: u64,
    state: ZkScalar,
    aux_data: ZkScalar,
    next_state: ZkScalar,
}

impl<
        const LOG4_DEPOSIT_BATCH_SIZE: u8,
        const LOG4_WITHDRAW_BATCH_SIZE: u8,
        const LOG4_UPDATE_BATCH_SIZE: u8,
        const LOG4_TREE_SIZE: u8,
        const LOG4_TOKENS_TREE_SIZE: u8,
    >
    ZoroWork<
        LOG4_DEPOSIT_BATCH_SIZE,
        LOG4_WITHDRAW_BATCH_SIZE,
        LOG4_UPDATE_BATCH_SIZE,
        LOG4_TREE_SIZE,
        LOG4_TOKENS_TREE_SIZE,
    >
{
    pub fn verify(
        &self,
        params: &ZoroVerifyKeys,
        proof: &bazuka::zk::groth16::Groth16Proof,
    ) -> bool {
        let verifier: bazuka::zk::groth16::Groth16VerifyingKey = match &self.circuit {
            ZoroCircuit::Deposit(_) => params.deposit.clone(),
            ZoroCircuit::Withdraw(_) => params.withdraw.clone(),
            ZoroCircuit::Update(_) => params.update.clone(),
        }
        .into();
        bazuka::zk::groth16::groth16_verify(
            &verifier,
            self.height,
            self.state,
            self.aux_data,
            self.next_state,
            proof,
        )
    }
    pub fn prove(
        &self,
        params: ZoroParams,
        backend: Backend,
        cancel: Option<Arc<RwLock<bool>>>,
    ) -> Result<bazuka::zk::groth16::Groth16Proof, BankError> {
        let proof = unsafe {
            std::mem::transmute::<bellman::groth16::Proof<Bls12>, bazuka::zk::groth16::Groth16Proof>(
                match &self.circuit {
                    ZoroCircuit::Deposit(circuit) => groth16::create_random_proof(
                        circuit.clone(),
                        &params.deposit.clone(),
                        &mut OsRng,
                        backend.clone(),
                        cancel.clone(),
                    )?,
                    ZoroCircuit::Withdraw(circuit) => groth16::create_random_proof(
                        circuit.clone(),
                        &params.withdraw.clone(),
                        &mut OsRng,
                        backend.clone(),
                        cancel.clone(),
                    )?,
                    ZoroCircuit::Update(circuit) => groth16::create_random_proof(
                        circuit.clone(),
                        &params.update.clone(),
                        &mut OsRng,
                        backend.clone(),
                        cancel.clone(),
                    )?,
                },
            )
        };
        let vks = params.verify_keys();

        if self.verify(&vks, &proof) {
            Ok(proof)
        } else {
            Err(BankError::IncorrectProof)
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ZoroCircuit<
    const LOG4_DEPOSIT_BATCH_SIZE: u8,
    const LOG4_WITHDRAW_BATCH_SIZE: u8,
    const LOG4_UPDATE_BATCH_SIZE: u8,
    const LOG4_TREE_SIZE: u8,
    const LOG4_TOKENS_TREE_SIZE: u8,
> {
    Deposit(
        circuits::DepositCircuit<
            { LOG4_DEPOSIT_BATCH_SIZE },
            { LOG4_TREE_SIZE },
            { LOG4_TOKENS_TREE_SIZE },
        >,
    ),
    Withdraw(
        circuits::WithdrawCircuit<
            { LOG4_WITHDRAW_BATCH_SIZE },
            { LOG4_TREE_SIZE },
            { LOG4_TOKENS_TREE_SIZE },
        >,
    ),
    Update(
        circuits::UpdateCircuit<
            { LOG4_UPDATE_BATCH_SIZE },
            { LOG4_TREE_SIZE },
            { LOG4_TOKENS_TREE_SIZE },
        >,
    ),
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
    pub fn new(mpn_log4_account_capacity: u8, mpn_contract_id: ContractId) -> Self {
        Self {
            mpn_contract_id,
            mpn_log4_account_capacity,
        }
    }

    pub fn withdraw<K: KvStore>(
        &self,
        db: &mut K,
        txs: Vec<Withdraw>,
    ) -> Result<
        (
            Vec<Withdraw>,
            Vec<Withdraw>,
            bazuka::zk::ZkCompressedState,
            ZoroWork<
                LOG4_DEPOSIT_BATCH_SIZE,
                LOG4_WITHDRAW_BATCH_SIZE,
                LOG4_UPDATE_BATCH_SIZE,
                LOG4_TREE_SIZE,
                LOG4_TOKENS_TREE_SIZE,
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
            ZoroWork {
                circuit: ZoroCircuit::Withdraw(circuit),
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
        txs: Vec<Deposit>,
    ) -> Result<
        (
            Vec<Deposit>,
            Vec<Deposit>,
            bazuka::zk::ZkCompressedState,
            ZoroWork<
                LOG4_DEPOSIT_BATCH_SIZE,
                LOG4_WITHDRAW_BATCH_SIZE,
                LOG4_UPDATE_BATCH_SIZE,
                LOG4_TREE_SIZE,
                LOG4_TOKENS_TREE_SIZE,
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
        let mut rejected_pub_keys = HashSet::new();

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
            let acc_token = acc.tokens.get(&tx.token_index).clone();
            let src_pub = tx.mpn_deposit.as_ref().unwrap().payment.src.clone();
            if rejected_pub_keys.contains(&src_pub)
                || (acc.address != Default::default() && tx.pub_key != acc.address)
                || (acc_token.is_some() && acc_token.unwrap().token_id != tx.amount.token_id)
            {
                rejected.push(tx.clone());
                rejected_pub_keys.insert(src_pub);
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
            ZoroWork {
                circuit: ZoroCircuit::Deposit(circuit),
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
        txs: Vec<MpnTransaction>,
        fee_token: TokenId,
    ) -> Result<
        (
            Vec<MpnTransaction>,
            Vec<MpnTransaction>,
            bazuka::zk::ZkCompressedState,
            ZoroWork<
                LOG4_DEPOSIT_BATCH_SIZE,
                LOG4_WITHDRAW_BATCH_SIZE,
                LOG4_UPDATE_BATCH_SIZE,
                LOG4_TREE_SIZE,
                LOG4_TOKENS_TREE_SIZE,
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

        let txs = txs
            .into_par_iter()
            .filter(|tx| {
                tx.fee.token_id == fee_token
                    && tx.src_pub_key.is_on_curve()
                    && tx.dst_pub_key.is_on_curve()
            })
            .collect::<Vec<_>>();

        for tx in txs.into_iter() {
            if transitions.len() == 1 << (2 * LOG4_UPDATE_BATCH_SIZE) {
                break;
            }
            let src_before = KvStoreStateManager::<ZkHasher>::get_mpn_account(
                &mirror,
                self.mpn_contract_id,
                tx.src_index(self.mpn_log4_account_capacity),
            )
            .unwrap();
            let dst_before = KvStoreStateManager::<ZkHasher>::get_mpn_account(
                &mirror,
                self.mpn_contract_id,
                tx.dst_index(self.mpn_log4_account_capacity),
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
                || src_before.address != tx.src_pub_key.decompress()
                || (dst_before.address.is_on_curve()
                    && dst_before.address != tx.dst_pub_key.decompress())
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
                        tx.src_index(self.mpn_log4_account_capacity),
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
                        ZkDataLocator(vec![tx.src_index(self.mpn_log4_account_capacity), 3]),
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
                    tx.src_index(self.mpn_log4_account_capacity),
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
                        ZkDataLocator(vec![tx.src_index(self.mpn_log4_account_capacity), 3]),
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
                    tx.src_index(self.mpn_log4_account_capacity),
                    src_after,
                    &mut state_size,
                )
                .unwrap();

                let dst_proof = zeekit::merkle::Proof::<{ LOG4_TREE_SIZE }>(
                    KvStoreStateManager::<ZkHasher>::prove(
                        &mirror,
                        self.mpn_contract_id,
                        ZkDataLocator(vec![]),
                        tx.dst_index(self.mpn_log4_account_capacity),
                    )
                    .unwrap(),
                );
                let dst_balance_proof = zeekit::merkle::Proof::<{ LOG4_TOKENS_TREE_SIZE }>(
                    KvStoreStateManager::<ZkHasher>::prove(
                        &mirror,
                        self.mpn_contract_id,
                        ZkDataLocator(vec![tx.dst_index(self.mpn_log4_account_capacity), 3]),
                        tx.dst_token_index,
                    )
                    .unwrap(),
                );

                let dst_before = KvStoreStateManager::<ZkHasher>::get_mpn_account(
                    &mirror,
                    self.mpn_contract_id,
                    tx.dst_index(self.mpn_log4_account_capacity),
                )
                .unwrap();
                let dst_token = dst_before.tokens.get(&tx.dst_token_index);

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
                    tx.dst_index(self.mpn_log4_account_capacity),
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
            ZoroWork {
                circuit: ZoroCircuit::Update(circuit),
                height,
                state,
                aux_data,
                next_state,
            },
        ))
    }
}
