use crate::{eddsa, mimc};
use dusk_plonk::prelude::*;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Account {
    pub nonce: u64,
    pub address: JubJubAffine,
    pub balance: u64,
}

impl Account {
    pub fn hash(&self) -> BlsScalar {
        mimc::mimc(vec![
            BlsScalar::from(self.nonce),
            self.address.get_x(),
            self.address.get_y(),
            BlsScalar::from(self.balance),
        ])
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Transaction {
    pub nonce: u64,
    pub src_index: u64,
    pub dst_index: u64,
    pub amount: u64,
    pub fee: u64,
    pub sig: eddsa::Signature,
}

impl Transaction {
    pub fn verify(&self, addr: JubJubAffine) -> bool {
        eddsa::verify(addr, self.hash(), self.sig.clone())
    }
    pub fn sign(&mut self, sk: eddsa::PrivateKey) {
        self.sig = eddsa::sign(&sk, self.hash());
    }
    pub fn hash(&self) -> BlsScalar {
        mimc::mimc(vec![
            BlsScalar::from(self.nonce),
            BlsScalar::from(self.src_index),
            BlsScalar::from(self.dst_index),
            BlsScalar::from(self.amount),
            BlsScalar::from(self.fee),
        ])
    }
}
