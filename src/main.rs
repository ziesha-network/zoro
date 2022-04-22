#[macro_use]
extern crate lazy_static;

mod account;
mod eddsa;
mod merkle;
mod mimc;

use dusk_plonk::prelude::*;
use rand_core::OsRng;

pub struct Transfer {
    nonce: u64,
    src: JubJubAffine,
    dst: JubJubAffine,
    amount: BlsScalar,
    fee: BlsScalar,
    sig: (JubJubAffine, BlsScalar),
}

pub enum BankError {
    AddressNotFound,
    BalanceInsufficient,
    InvalidNonce,
}

pub struct Bank {
    tree: merkle::SparseTree,
    accounts: Vec<account::Account>,
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
        let acc = account::Account {
            address,
            balance,
            nonce: 0,
        };
        let ind = self.accounts.len();
        self.tree.set(ind as u64, acc.hash());
        self.accounts.push(acc);
    }
    pub fn change_state(&mut self, txs: Vec<Transfer>) -> Result<(), BankError> {
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

#[derive(Debug, Default)]
pub struct MimcCircuit {
    inp: BlsScalar,
    out: BlsScalar,
}

impl Circuit for MimcCircuit {
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];
    fn gadget(&mut self, composer: &mut TurboComposer) -> Result<(), Error> {
        let mut tree = merkle::SparseTree::new();
        tree.set(12345, BlsScalar::one());
        let prf = tree.prove(12345);
        let mut proof_wits = Vec::new();
        for b in prf.clone() {
            proof_wits.push(composer.append_witness(b));
        }
        merkle::SparseTree::verify(12345, BlsScalar::from(1), prf.clone(), tree.root());
        let index_wit = composer.append_witness(BlsScalar::from(12345));
        let val_wit = composer.append_witness(BlsScalar::from(1));
        let root_wit = composer.append_witness(tree.root());
        merkle::gadget::check_proof(composer, index_wit, val_wit, proof_wits, root_wit);

        let inp = composer.append_witness(self.inp);
        let out = mimc::gadget::mimc(composer, vec![inp]);
        let outp = composer.append_public_witness(self.out);
        composer.assert_equal(out, outp);
        Ok(())
    }

    fn public_inputs(&self) -> Vec<PublicInputValue> {
        vec![self.out.into()]
    }

    fn padded_gates(&self) -> usize {
        1 << 12
    }
}

fn main() {
    let pp = PublicParameters::setup(1 << 13, &mut OsRng).unwrap();
    let mut circuit = MimcCircuit::default();
    let (pk, vd) = circuit.compile(&pp).unwrap();

    let proof = {
        let mut circuit = MimcCircuit {
            inp: BlsScalar::from(20u64),
            out: BlsScalar::from(794794754447u64),
        };
        circuit.prove(&pp, &pk, b"Test").unwrap()
    };

    let public_inputs: Vec<PublicInputValue> = vec![BlsScalar::from(794794754447u64).into()];
    MimcCircuit::verify(&pp, &vd, &proof, &public_inputs, b"Test").unwrap();
}
