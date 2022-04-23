use crate::{core, merkle};
use dusk_plonk::prelude::*;

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
        for tx in txs.iter() {
            let src_acc = self.accounts[tx.src_index as usize].clone();
            if tx.nonce != src_acc.nonce {
                return Err(BankError::InvalidNonce);
            }
            if !tx.verify(src_acc.address) {
                return Err(BankError::InvalidSignature);
            }
            if src_acc.balance < tx.fee + tx.amount {
                return Err(BankError::BalanceInsufficient);
            } else {
                self.accounts[tx.src_index as usize].nonce += 1;
                self.accounts[tx.src_index as usize].balance -= tx.fee + tx.amount;
                self.accounts[tx.dst_index as usize].balance += tx.amount;
            }
        }
        Ok(())
    }
}
