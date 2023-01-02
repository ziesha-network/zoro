use super::*;
use crate::bank::{Bank, Provable};
use bazuka::core::{ContractId, Money, MpnAddress, TokenId};
use bazuka::db::{KvStore, RamKvStore};
use bazuka::wallet::TxBuilder;
use bazuka::zk::KvStoreStateManager;
use bazuka::zk::ZkDataLocator;
use bazuka::zk::{ZkCompressedState, ZkContract, ZkScalar, ZkStateModel};
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
fn test_deposit_tx() {
    let tx_builder = TxBuilder::new(b"hi");
    let zk_addr = tx_builder.get_zk_address().decompress();
    let (mut db, mpn_contract_id) = fresh_db(1, 1);
    let c = DepositCircuit::<1, 1, 1>::default();
    let p = groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap();
    let b = Bank::<1, 0, 0, 1, 1>::new(mpn_contract_id, false, true);
    let d = Deposit {
        mpn_deposit: None,
        index: 2,
        token_index: 3,
        pub_key: zk_addr.clone(),
        amount: (TokenId::Custom(ZkScalar::from(123)), Money(10)),
    };
    let (acc, rej, _, work) = b
        .deposit(&mut db, p.clone(), vec![d], Arc::new(RwLock::new(false)))
        .unwrap();
    assert_eq!(acc.len(), 1);
    assert_eq!(rej.len(), 0);
    work.prove().unwrap();
    let state = KvStoreStateManager::<bazuka::core::ZkHasher>::get_full_state(&db, mpn_contract_id)
        .unwrap();
    assert_eq!(state.data.0.len(), 4);
    assert_eq!(
        state.data.0.get(&ZkDataLocator(vec![2, 1])),
        Some(&zk_addr.0)
    );
    assert_eq!(
        state.data.0.get(&ZkDataLocator(vec![2, 2])),
        Some(&zk_addr.1)
    );
    assert_eq!(
        state.data.0.get(&ZkDataLocator(vec![2, 3, 3, 0])),
        Some(&ZkScalar::from(123))
    );
    assert_eq!(
        state.data.0.get(&ZkDataLocator(vec![2, 3, 3, 1])),
        Some(&ZkScalar::from(10))
    );
}

#[test]
fn test_deposit_empty() {
    let (mut db, mpn_contract_id) = fresh_db(1, 1);
    let c = DepositCircuit::<1, 1, 1>::default();
    let p = groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap();
    let b = Bank::<1, 0, 0, 1, 1>::new(mpn_contract_id, false, true);
    b.deposit(&mut db, p.clone(), vec![], Arc::new(RwLock::new(false)))
        .unwrap()
        .3
        .prove()
        .unwrap();
}

#[test]
fn test_update_empty() {
    let (mut db, mpn_contract_id) = fresh_db(1, 1);
    let c = UpdateCircuit::<1, 1, 1>::default();
    let p = groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap();
    let b = Bank::<0, 0, 1, 1, 1>::new(mpn_contract_id, false, true);
    b.change_state(&mut db, p.clone(), vec![], Arc::new(RwLock::new(false)))
        .unwrap()
        .3
        .prove()
        .unwrap();
}

#[test]
fn test_update_tx() {
    let tx_builder = TxBuilder::new(b"hi");
    let zk_addr = tx_builder.get_zk_address().decompress();
    let (mut db, mpn_contract_id) = fresh_db(1, 1);
    let deposit_circ = DepositCircuit::<1, 1, 1>::default();
    let update_circ = UpdateCircuit::<1, 1, 1>::default();
    let param_deposit =
        groth16::generate_random_parameters::<Bls12, _, _>(deposit_circ, &mut OsRng).unwrap();
    let param_update =
        groth16::generate_random_parameters::<Bls12, _, _>(update_circ, &mut OsRng).unwrap();
    let b = Bank::<1, 0, 1, 1, 1>::new(mpn_contract_id, false, true);
    let d = Deposit {
        mpn_deposit: None,
        index: 2,
        token_index: 3,
        pub_key: zk_addr.clone(),
        amount: (TokenId::Custom(ZkScalar::from(123)), Money(10)),
    };
    let (acc, rej, _, work) = b
        .deposit(
            &mut db,
            param_deposit.clone(),
            vec![d],
            Arc::new(RwLock::new(false)),
        )
        .unwrap();
    assert_eq!(acc.len(), 1);
    assert_eq!(rej.len(), 0);
    work.prove().unwrap();
    let u = tx_builder.create_mpn_transaction(
        2,
        3,
        MpnAddress {
            pub_key: tx_builder.get_zk_address(),
            account_index: 1,
        },
        1,
        TokenId::Custom(ZkScalar::from(123)),
        Money(5),
        3,
        TokenId::Custom(ZkScalar::from(123)),
        Money(1),
        0,
    );
    let (acc, rej, _, work) = b
        .change_state(
            &mut db,
            param_update.clone(),
            vec![u],
            Arc::new(RwLock::new(false)),
        )
        .unwrap();
    assert_eq!(acc.len(), 1);
    assert_eq!(rej.len(), 0);
    work.prove().unwrap();
}

#[test]
fn test_withdraw_empty() {
    let (mut db, mpn_contract_id) = fresh_db(1, 1);
    let c = WithdrawCircuit::<1, 1, 1>::default();
    let p = groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap();
    let b = Bank::<0, 1, 0, 1, 1>::new(mpn_contract_id, false, true);
    b.withdraw(&mut db, p.clone(), vec![], Arc::new(RwLock::new(false)))
        .unwrap()
        .3
        .prove()
        .unwrap();
}
