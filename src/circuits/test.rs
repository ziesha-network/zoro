use super::*;
use crate::bank::{Provable, Bank};
use bazuka::core::ContractId;
use bazuka::db::{KvStore, RamKvStore};
use bazuka::zk::{ZkCompressedState, ZkContract, ZkStateModel};
use bellman::groth16;
use bls12_381::Bls12;
use rand::rngs::OsRng;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

fn fresh_db(log4_tree_size: u8, log4_token_size: u8) -> (RamKvStore, ContractId) {
    let state_model = ZkStateModel::List {
        log4_size: log4_tree_size,
        item_type: Box::new(ZkStateModel::Struct {
            field_types: vec![
                ZkStateModel::Scalar, // Nonce
                ZkStateModel::Scalar, // Pub-key X
                ZkStateModel::Scalar, // Pub-key Y
                ZkStateModel::List {
                    log4_size: log4_token_size,
                    item_type: Box::new(ZkStateModel::Struct {
                        field_types: vec![
                            ZkStateModel::Scalar, // Token-Id
                            ZkStateModel::Scalar, // Balance
                        ],
                    }),
                },
            ],
        }),
    };
    let mpn_contract_id =
        ContractId::from_str("0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
    let mut db = RamKvStore::new();
    db.update(&[bazuka::db::WriteOp::Put(
        bazuka::db::keys::contract(&mpn_contract_id),
        ZkContract {
            initial_state: ZkCompressedState::empty::<bazuka::core::ZkHasher>(state_model.clone())
                .into(),
            state_model: state_model,
            deposit_functions: vec![],
            withdraw_functions: vec![],
            functions: vec![],
        }
        .into(),
    )])
    .unwrap();
    (db, mpn_contract_id)
}

#[test]
fn test_update_empty() {
    let c = UpdateCircuit::<1, 1>::default();
    let _p = groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap();
}

#[test]
fn test_deposit_empty() {
    let (mut db, mpn_contract_id) = fresh_db(1, 1);
    let c = DepositCircuit::<1, 1>::default();
    let p = groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap();
    let b = Bank::<1, 0, 0, 1>::new(mpn_contract_id, false, true);
    b.deposit(&mut db, p.clone(), vec![], Arc::new(RwLock::new(false)))
        .unwrap().3.prove().unwrap();
}
