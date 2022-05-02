use zeekit::{eddsa, mimc, Fr};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Account {
    pub nonce: u64,
    pub address: eddsa::PublicKey,
    pub balance: u64,
}

impl Account {
    pub fn hash(&self) -> Fr {
        let pnt = self.address.0.decompress();
        mimc::mimc(vec![
            Fr::from(self.nonce),
            pnt.0,
            pnt.1,
            Fr::from(self.balance),
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
    pub fn verify(&self, addr: eddsa::PublicKey) -> bool {
        eddsa::verify(&addr, self.hash(), &self.sig)
    }
    pub fn sign(&mut self, sk: eddsa::PrivateKey) {
        self.sig = eddsa::sign(&sk, self.hash());
    }
    pub fn hash(&self) -> Fr {
        mimc::mimc(vec![
            Fr::from(self.nonce),
            Fr::from(self.src_index),
            Fr::from(self.dst_index),
            Fr::from(self.amount),
            Fr::from(self.fee),
        ])
    }
}
