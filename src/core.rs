use bazuka::core::ZkHasher as ZkMainHasher;
use bazuka::crypto::{jubjub, ZkSignatureScheme};
use bazuka::zk::{ZkHasher, ZkScalar};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Account {
    pub nonce: u64,
    pub address: jubjub::PointAffine,
    pub balance: u64,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Transaction {
    pub nonce: u64,
    pub src_index: u32,
    pub dst_index: u32,
    pub dst_pub_key: jubjub::PublicKey,
    pub amount: u64,
    pub fee: u64,
    pub sig: jubjub::Signature,
}

impl Transaction {
    pub fn verify(&self, addr: jubjub::PublicKey) -> bool {
        jubjub::JubJub::<ZkMainHasher>::verify(&addr, self.hash(), &self.sig)
    }
    pub fn sign(&mut self, sk: jubjub::PrivateKey) {
        self.sig = jubjub::JubJub::<ZkMainHasher>::sign(&sk, self.hash());
    }
    pub fn hash(&self) -> ZkScalar {
        ZkMainHasher::hash(&[
            ZkScalar::from(self.nonce),
            ZkScalar::from(self.src_index as u64),
            ZkScalar::from(self.dst_index as u64),
            ZkScalar::from(self.amount),
            ZkScalar::from(self.fee),
        ])
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DepositWithdraw {
    pub index: u32,
    pub pub_key: jubjub::PublicKey,
    pub amount: u64,
    pub withdraw: bool,
}
