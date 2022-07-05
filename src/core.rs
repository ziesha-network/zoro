use bazuka::core::ZkHasher as ZkMainHasher;
use bazuka::crypto::{jubjub, ZkSignatureScheme};
use bazuka::zk::{ZkHasher, ZkScalar};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Account {
    pub nonce: u64,
    pub address: jubjub::PublicKey,
    pub balance: u64,
}

impl Account {
    pub fn hash(&self) -> ZkScalar {
        let pnt = self.address.0.decompress();
        ZkMainHasher::hash(&[
            ZkScalar::from(self.nonce),
            pnt.0,
            pnt.1,
            ZkScalar::from(self.balance),
        ])
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Transaction {
    pub nonce: u64,
    pub src_index: u64,
    pub dst_index: u64,
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
            ZkScalar::from(self.src_index),
            ZkScalar::from(self.dst_index),
            ZkScalar::from(self.amount),
            ZkScalar::from(self.fee),
        ])
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DepositWithdraw {
    pub index: u64,
    pub pub_key: jubjub::PublicKey,
    pub amount: u64,
    pub withdraw: bool,
}
