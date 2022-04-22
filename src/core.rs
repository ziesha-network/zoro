use crate::{eddsa, mimc};
use dusk_plonk::prelude::*;

#[derive(Debug, Clone, PartialEq)]
pub struct Account {
    pub nonce: u64,
    pub address: JubJubAffine,
    pub balance: BlsScalar,
}

impl Account {
    pub fn hash(&self) -> BlsScalar {
        mimc::mimc(vec![
            BlsScalar::from(self.nonce),
            self.address.get_x(),
            self.address.get_y(),
            self.balance,
        ])
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Transaction {
    pub nonce: u64,
    pub src: JubJubAffine,
    pub dst: JubJubAffine,
    pub amount: BlsScalar,
    pub fee: BlsScalar,
    pub sig: eddsa::Signature,
}
