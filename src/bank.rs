use crate::{core, merkle};
use dusk_plonk::prelude::*;

pub enum BankError {
    AddressNotFound,
    BalanceInsufficient,
    InvalidNonce,
}

pub struct Bank {
    tree: merkle::SparseTree,
    accounts: Vec<core::Account>,
}

impl Bank {
    pub fn new() -> Self {
        Self {
            tree: merkle::SparseTree::new(),
            accounts: Vec::new(),
        }
    }
    pub fn find(&self, addr: &JubJubAffine) -> Option<usize> {
        self.accounts.iter().position(|a| a.address == *addr)
    }
    pub fn add_account(&mut self, address: JubJubAffine, balance: BlsScalar) {
        let acc = core::Account {
            address,
            balance,
            nonce: 0,
        };
        let ind = self.accounts.len();
        self.tree.set(ind as u64, acc.hash());
        self.accounts.push(acc);
    }
    pub fn change_state(&mut self, txs: Vec<core::Transaction>) -> Result<(), BankError> {
        for tx in txs {
            let src_ind = self.find(&tx.src).ok_or(BankError::AddressNotFound)?;
            let dst_ind = self.find(&tx.dst).ok_or(BankError::AddressNotFound)?;
            if tx.nonce != self.accounts[src_ind].nonce {
                return Err(BankError::InvalidNonce);
            }
            if self.accounts[src_ind].balance < tx.fee + tx.amount {
                return Err(BankError::BalanceInsufficient);
            } else {
                self.accounts[src_ind].nonce += 1;
                self.accounts[src_ind].balance -= tx.fee + tx.amount;
                self.accounts[dst_ind].balance += tx.amount;
            }
        }
        Ok(())
    }
}
