use crate::{circuit, core, merkle};
use dusk_plonk::prelude::*;
use rand_core::OsRng;

#[derive(Clone, Debug)]
pub enum BankError {
    AddressNotFound,
    BalanceInsufficient,
    InvalidNonce,
    InvalidSignature,
}

pub struct Bank {
    tree: merkle::SparseTree,
    accounts: Vec<core::Account>,
}

impl Bank {
    pub fn balances(&self) -> Vec<(u64, u64)> {
        self.accounts
            .iter()
            .enumerate()
            .map(|(i, a)| (i as u64, a.balance))
            .collect()
    }
    pub fn new() -> Self {
        Self {
            tree: merkle::SparseTree::new(),
            accounts: Vec::new(),
        }
    }
    pub fn get_account(&self, index: u64) -> Option<core::Account> {
        self.accounts.get(index as usize).cloned()
    }
    pub fn add_account(&mut self, address: JubJubAffine, balance: u64) -> u64 {
        let acc = core::Account {
            address,
            balance,
            nonce: 0,
        };
        let ind = self.accounts.len();
        self.tree.set(ind as u64, acc.hash());
        self.accounts.push(acc);
        ind as u64
    }
    pub fn change_state(&mut self, txs: Vec<core::Transaction>) -> Result<(), BankError> {
        let state = self.tree.root();

        let mut transitions = Vec::new();
        for tx in txs.iter() {
            let src_acc = self.accounts[tx.src_index as usize].clone();
            if tx.nonce != src_acc.nonce {
                return Err(BankError::InvalidNonce);
            } else if !tx.verify(src_acc.address) {
                return Err(BankError::InvalidSignature);
            } else if src_acc.balance < tx.fee + tx.amount {
                return Err(BankError::BalanceInsufficient);
            } else {
                let src_before = self.accounts[tx.src_index as usize].clone();
                let src_proof = self.tree.prove(tx.src_index);
                self.accounts[tx.src_index as usize].nonce += 1;
                self.accounts[tx.src_index as usize].balance -= tx.fee + tx.amount;
                self.tree.set(
                    tx.src_index as u64,
                    self.accounts[tx.src_index as usize].hash(),
                );

                let dst_before = self.accounts[tx.dst_index as usize].clone();
                let dst_proof = self.tree.prove(tx.dst_index);
                self.accounts[tx.dst_index as usize].balance += tx.amount;
                self.tree.set(
                    tx.dst_index as u64,
                    self.accounts[tx.dst_index as usize].hash(),
                );

                transitions.push(circuit::Transition {
                    tx: tx.clone(),
                    src_before,
                    src_proof,
                    dst_before,
                    dst_proof,
                });
            }
        }

        let next_state = self.tree.root();

        let pp = PublicParameters::setup(1 << 15, &mut OsRng).unwrap();
        let mut circuit = circuit::MainCircuit::default();
        let (pk, vd) = circuit.compile(&pp).unwrap();

        let proof = {
            let mut circuit = circuit::MainCircuit {
                state,
                next_state,
                transitions: transitions,
            };
            circuit.prove(&pp, &pk, b"Test").unwrap()
        };

        let public_inputs: Vec<PublicInputValue> = vec![state.into(), next_state.into()];
        circuit::MainCircuit::verify(&pp, &vd, &proof, &public_inputs, b"Test").unwrap();

        Ok(())
    }
}
