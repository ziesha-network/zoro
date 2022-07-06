use crate::{circuits, core};
use bazuka::zk::ZkScalar;
use bazuka::{
    core::{ContractId, ZkHasher},
    crypto::jubjub::{PointAffine, PublicKey},
    db::KvStore,
    zk::{KvStoreStateManager, ZkDataLocator, ZkStateModel},
};
use bellman::groth16;
use bellman::groth16::Parameters;
use bls12_381::Bls12;
use rand::rngs::OsRng;
use std::str::FromStr;
use zeekit::merkle;

use std::collections::HashMap;

lazy_static! {
    pub static ref STATE_MODEL: ZkStateModel = {
        ZkStateModel::List {
            log4_size: 2,
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
    pub static ref CONTRACT_ID: ContractId = {
        ContractId::from_str(
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        .unwrap()
    };
}

pub fn get_account<K: KvStore>(db: &K, index: u32) -> core::Account {
    let nonce: u64 =
        KvStoreStateManager::<ZkHasher>::get_data(db, *CONTRACT_ID, &ZkDataLocator(vec![index, 0]))
            .unwrap()
            .try_into()
            .unwrap();
    let pub_x =
        KvStoreStateManager::<ZkHasher>::get_data(db, *CONTRACT_ID, &ZkDataLocator(vec![index, 1]))
            .unwrap();
    let pub_y =
        KvStoreStateManager::<ZkHasher>::get_data(db, *CONTRACT_ID, &ZkDataLocator(vec![index, 2]))
            .unwrap();
    let balance: u64 =
        KvStoreStateManager::<ZkHasher>::get_data(db, *CONTRACT_ID, &ZkDataLocator(vec![index, 3]))
            .unwrap()
            .try_into()
            .unwrap();
    core::Account {
        nonce,
        balance,
        address: PublicKey(PointAffine(pub_x, pub_y).compress()),
    }
}

pub fn set_account<K: KvStore>(db: &mut K, index: u32, acc: core::Account) {
    KvStoreStateManager::<ZkHasher>::set_data(
        db,
        *CONTRACT_ID,
        ZkDataLocator(vec![index, 0]),
        ZkScalar::from(acc.nonce),
    )
    .unwrap();
    KvStoreStateManager::<ZkHasher>::set_data(
        db,
        *CONTRACT_ID,
        ZkDataLocator(vec![index, 1]),
        acc.address.0.decompress().0,
    )
    .unwrap();
    KvStoreStateManager::<ZkHasher>::set_data(
        db,
        *CONTRACT_ID,
        ZkDataLocator(vec![index, 2]),
        acc.address.0.decompress().1,
    )
    .unwrap();
    KvStoreStateManager::<ZkHasher>::set_data(
        db,
        *CONTRACT_ID,
        ZkDataLocator(vec![index, 3]),
        ZkScalar::from(acc.balance),
    )
    .unwrap();
}

#[derive(Clone, Debug)]
pub enum BankError {
    BalanceInsufficient,
    InvalidNonce,
    InvalidSignature,
    InvalidPublicKey,
}

pub struct Bank<K: KvStore> {
    update_params: Parameters<Bls12>,
    deposit_withdraw_params: Parameters<Bls12>,
    database: K,
}

impl<K: KvStore> Bank<K> {
    pub fn balances(&self) -> Vec<(u64, u64)> {
        unimplemented!();
    }
    pub fn new(
        update_params: Parameters<Bls12>,
        deposit_withdraw_params: Parameters<Bls12>,
        database: K,
    ) -> Self {
        Self {
            update_params,
            deposit_withdraw_params,
            database,
        }
    }

    pub fn deposit_withdraw(&mut self, txs: Vec<core::DepositWithdraw>) -> Result<(), BankError> {
        let mut mirror = self.database.mirror();

        let mut transitions = Vec::new();
        let state = KvStoreStateManager::<ZkHasher>::get_data(
            &self.database,
            *CONTRACT_ID,
            &ZkDataLocator(vec![]),
        )
        .unwrap();
        for tx in txs.iter() {
            let acc = get_account(&mirror, tx.index);
            if acc.address != Default::default() && tx.pub_key != acc.address {
                return Err(BankError::InvalidPublicKey);
            } else if tx.withdraw && acc.balance < tx.amount {
                return Err(BankError::BalanceInsufficient);
            } else {
                let updated_acc = core::Account {
                    address: tx.pub_key.clone(),
                    balance: if tx.withdraw {
                        acc.balance - tx.amount
                    } else {
                        acc.balance + tx.amount
                    },
                    nonce: acc.nonce,
                };
                set_account(&mut mirror, tx.index, updated_acc);

                let proof = zeekit::merkle::Proof::<2>(
                    KvStoreStateManager::<ZkHasher>::prove(
                        &mirror,
                        *CONTRACT_ID,
                        ZkDataLocator(vec![]),
                        tx.index,
                    )
                    .unwrap(),
                );

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
            *CONTRACT_ID,
            &ZkDataLocator(vec![]),
        )
        .unwrap();

        let circuit = circuits::DepositWithdrawCircuit {
            filled: true,
            state,
            next_state,
            transitions: Box::new(circuits::DepositWithdrawTransitionBatch::new(transitions)),
        };

        let pvk = groth16::prepare_verifying_key(&self.deposit_withdraw_params.vk);

        let start = std::time::Instant::now();
        let proof =
            groth16::create_random_proof(circuit, &self.deposit_withdraw_params, &mut OsRng)
                .unwrap();
        println!(
            "Proving took: {}ms",
            (std::time::Instant::now() - start).as_millis()
        );

        let inputs = vec![state.into(), next_state.into()];

        println!(
            "Verify: {}",
            groth16::verify_proof(&pvk, &proof, &inputs).is_ok()
        );

        Ok(())
    }
    pub fn change_state(&mut self, txs: Vec<core::Transaction>) -> Result<(), BankError> {
        let mut transitions = Vec::new();

        let state = KvStoreStateManager::<ZkHasher>::get_data(
            &self.database,
            *CONTRACT_ID,
            &ZkDataLocator(vec![]),
        )
        .unwrap();

        let mut mirror = self.database.mirror();

        for tx in txs.iter() {
            let src_before = get_account(&mirror, tx.src_index);
            if tx.nonce != src_before.nonce {
                return Err(BankError::InvalidNonce);
            } else if !tx.verify(src_before.address.clone()) {
                return Err(BankError::InvalidSignature);
            } else if src_before.balance < tx.fee + tx.amount {
                return Err(BankError::BalanceInsufficient);
            } else {
                let src_proof = zeekit::merkle::Proof::<2>(
                    KvStoreStateManager::<ZkHasher>::prove(
                        &mirror,
                        *CONTRACT_ID,
                        ZkDataLocator(vec![]),
                        tx.src_index,
                    )
                    .unwrap(),
                );
                let src_after = core::Account {
                    address: src_before.address.clone(),
                    balance: src_before.balance - tx.fee + tx.amount,
                    nonce: src_before.nonce + 1,
                };
                set_account(&mut mirror, tx.src_index, src_after);

                let dst_before = get_account(&mirror, tx.dst_index);
                let dst_proof = zeekit::merkle::Proof::<2>(
                    KvStoreStateManager::<ZkHasher>::prove(
                        &mirror,
                        *CONTRACT_ID,
                        ZkDataLocator(vec![]),
                        tx.dst_index,
                    )
                    .unwrap(),
                );

                let dst_after = core::Account {
                    address: tx.dst_pub_key.clone(),
                    balance: dst_before.balance + tx.amount,
                    nonce: dst_before.nonce,
                };
                set_account(&mut mirror, tx.dst_index, dst_after);

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
            *CONTRACT_ID,
            &ZkDataLocator(vec![]),
        )
        .unwrap();

        let circuit = circuits::UpdateCircuit {
            filled: true,
            state,
            next_state,
            transitions: Box::new(circuits::TransitionBatch::new(transitions)),
        };

        let pvk = groth16::prepare_verifying_key(&self.update_params.vk);

        let start = std::time::Instant::now();
        let proof = groth16::create_random_proof(circuit, &self.update_params, &mut OsRng).unwrap();
        println!(
            "Proving took: {}ms",
            (std::time::Instant::now() - start).as_millis()
        );

        let inputs = vec![state.into(), next_state.into()];

        println!(
            "Verify: {}",
            groth16::verify_proof(&pvk, &proof, &inputs).is_ok()
        );

        Ok(())
    }
}
