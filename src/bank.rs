use crate::{circuits, core};
use dusk_plonk::prelude::*;
use zeekit::{eddsa, merkle};

#[derive(Clone, Debug)]
pub enum BankError {
    AddressNotFound,
    BalanceInsufficient,
    InvalidNonce,
    InvalidSignature,
}

pub struct Bank {
    params: PublicParameters,
    update_circuit: (ProverKey, VerifierData),
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
    pub fn new(params: PublicParameters) -> Self {
        let start = std::time::Instant::now();
        let (update_pk, update_vd) = circuits::UpdateCircuit::default().compile(&params).unwrap();
        println!(
            "Compiling took: {}ms",
            (std::time::Instant::now() - start).as_millis()
        );
        Self {
            params,
            update_circuit: (update_pk, update_vd),
            tree: merkle::SparseTree::new(),
            accounts: Vec::new(),
        }
    }
    pub fn get_account(&self, index: u64) -> Result<core::Account, BankError> {
        self.accounts
            .get(index as usize)
            .cloned()
            .ok_or(BankError::AddressNotFound)
    }
    pub fn add_account(&mut self, address: eddsa::PublicKey, balance: u64) -> u64 {
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
        let mut transitions = Vec::new();

        let state = self.tree.root();

        for tx in txs.iter() {
            let src_acc = self.accounts[tx.src_index as usize].clone();
            if tx.nonce != src_acc.nonce {
                return Err(BankError::InvalidNonce);
            } else if !tx.verify(src_acc.address) {
                return Err(BankError::InvalidSignature);
            } else if src_acc.balance < tx.fee + tx.amount {
                return Err(BankError::BalanceInsufficient);
            } else {
                let src_before = self.get_account(tx.src_index)?;
                let src_proof = self.tree.prove(tx.src_index);
                self.accounts[tx.src_index as usize].nonce += 1;
                self.accounts[tx.src_index as usize].balance -= tx.fee + tx.amount;
                self.tree.set(
                    tx.src_index as u64,
                    self.accounts[tx.src_index as usize].hash(),
                );

                let dst_before = self.get_account(tx.dst_index)?;
                let dst_proof = self.tree.prove(tx.dst_index);
                self.accounts[tx.dst_index as usize].balance += tx.amount;
                self.tree.set(
                    tx.dst_index as u64,
                    self.accounts[tx.dst_index as usize].hash(),
                );

                transitions.push(circuits::Transition {
                    enabled: true,
                    tx: tx.clone(),
                    src_before,
                    src_proof,
                    dst_before,
                    dst_proof,
                });
            }
        }

        let next_state = self.tree.root();

        let start = std::time::Instant::now();
        let state_bls: BlsScalar = state.into();
        let next_state_bls: BlsScalar = next_state.into();
        let proof = {
            let mut circuit = circuits::UpdateCircuit {
                state: state_bls,
                next_state: next_state_bls,
                transitions: circuits::TransitionBatch::new(transitions),
            };
            circuit
                .prove(&self.params, &self.update_circuit.0, b"Test")
                .unwrap()
        };
        println!(
            "Proving took: {}ms",
            (std::time::Instant::now() - start).as_millis()
        );

        let public_inputs: Vec<PublicInputValue> = vec![state_bls.into(), next_state_bls.into()];
        circuits::UpdateCircuit::verify(
            &self.params,
            &self.update_circuit.1,
            &proof,
            &public_inputs,
            b"Test",
        )
        .unwrap();

        Ok(())
    }
}
