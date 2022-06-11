use crate::{circuits, core};
use bellman::groth16;
use bellman::groth16::Parameters;
use bls12_381::Bls12;
use rand::rngs::OsRng;
use std::fs::File;
use zeekit::merkle;

use std::collections::HashMap;

#[derive(Clone, Debug)]
pub enum BankError {
    AddressNotFound,
    BalanceInsufficient,
    InvalidNonce,
    InvalidSignature,
    InvalidPublicKey,
}

pub struct Bank {
    //params: PublicParameters,
    //update_circuit: (ProverKey, VerifierData),
    tree: merkle::SparseTree,
    accounts: HashMap<u64, core::Account>,
}

impl Bank {
    pub fn balances(&self) -> Vec<(u64, u64)> {
        self.accounts.iter().map(|(i, a)| (*i, a.balance)).collect()
    }
    pub fn new(/*params: PublicParameters*/) -> Self {
        /*let start = std::time::Instant::now();
        let (update_pk, update_vd) = circuits::UpdateCircuit::default().compile(&params).unwrap();
        println!(
            "Compiling took: {}ms",
            (std::time::Instant::now() - start).as_millis()
        );*/
        let mut tree = merkle::SparseTree::new();
        tree.set(0u64, Default::default());
        Self {
            //params,
            //update_circuit: (update_pk, update_vd),
            tree,
            accounts: HashMap::new(),
        }
    }
    pub fn get_account(&self, index: u64) -> core::Account {
        self.accounts.get(&index).cloned().unwrap_or_default()
    }
    pub fn deposit_withdraw(&mut self, txs: Vec<core::DepositWithdraw>) -> Result<(), BankError> {
        let mut transitions = Vec::new();
        let state = self.tree.root();
        for tx in txs.iter() {
            let acc = self.get_account(tx.index);
            if acc.address != Default::default() && tx.pub_key != acc.address {
                return Err(BankError::InvalidPublicKey);
            } else if tx.nonce != acc.nonce {
                return Err(BankError::InvalidNonce);
            } else if tx.withdraw && acc.balance < tx.amount {
                return Err(BankError::BalanceInsufficient);
            } else {
                let updated_acc = core::Account {
                    address: tx.pub_key.clone(),
                    balance: if tx.withdraw {
                        acc.balance - tx.amount
                    } else {
                        acc.balance + tx.amount
                    },
                    nonce: acc.nonce + 1,
                };
                self.tree.set(tx.index as u64, updated_acc.hash());
                self.accounts.insert(tx.index, updated_acc);

                let proof = self.tree.prove(tx.index);

                transitions.push(circuits::DepositWithdrawTransition {
                    enabled: true,
                    tx: tx.clone(),
                    before: acc,
                    proof,
                });
            }
        }
        let next_state = self.tree.root();

        let circuit = circuits::DepositWithdrawCircuit {
            filled: true,
            state,
            next_state,
            transitions: Box::new(circuits::DepositWithdrawTransitionBatch::new(transitions)),
        };

        let load_parameters = false;
        let parameters_path = "parameters_dw.dat";

        // Create parameters for our circuit
        let params = if load_parameters {
            let param_file = File::open(parameters_path).expect("Unable to open parameters file!");
            Parameters::<Bls12>::read(param_file, false /* false for better performance*/)
                .expect("Unable to read parameters file!")
        } else {
            let c = circuits::DepositWithdrawCircuit::default();

            let p = groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap();
            let param_file =
                File::create(parameters_path).expect("Unable to create parameters file!");
            p.write(param_file)
                .expect("Unable to write parameters file!");
            p
        };

        let pvk = groth16::prepare_verifying_key(&params.vk);

        let start = std::time::Instant::now();
        let proof = groth16::create_random_proof(circuit, &params, &mut OsRng).unwrap();
        println!(
            "Proving took: {}ms",
            (std::time::Instant::now() - start).as_millis()
        );

        let inputs = vec![state.into(), next_state.into()];

        println!(
            "Verify: {}",
            groth16::verify_proof(&pvk, &proof, &inputs).is_ok()
        );

        Ok(())
    }
    pub fn change_state(&mut self, txs: Vec<core::Transaction>) -> Result<(), BankError> {
        let mut transitions = Vec::new();

        let state = self.tree.root();

        for tx in txs.iter() {
            let src_acc = self.accounts[&tx.src_index].clone();
            if tx.nonce != src_acc.nonce {
                return Err(BankError::InvalidNonce);
            } else if !tx.verify(src_acc.address) {
                return Err(BankError::InvalidSignature);
            } else if src_acc.balance < tx.fee + tx.amount {
                return Err(BankError::BalanceInsufficient);
            } else {
                let src_before = self.get_account(tx.src_index);
                let src_proof = self.tree.prove(tx.src_index);
                self.accounts.get_mut(&tx.src_index).unwrap().nonce += 1;
                self.accounts.get_mut(&tx.src_index).unwrap().balance -= tx.fee + tx.amount;
                self.tree
                    .set(tx.src_index as u64, self.accounts[&tx.src_index].hash());

                let dst_before = self.get_account(tx.dst_index);
                let dst_proof = self.tree.prove(tx.dst_index);
                self.accounts.get_mut(&tx.dst_index).unwrap().balance += tx.amount;
                self.tree
                    .set(tx.dst_index as u64, self.accounts[&tx.dst_index].hash());

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

        let circuit = circuits::UpdateCircuit {
            filled: true,
            state,
            next_state,
            transitions: Box::new(circuits::TransitionBatch::new(transitions)),
        };

        let load_parameters = false;
        let parameters_path = "parameters.dat";

        // Create parameters for our circuit
        let params = if load_parameters {
            let param_file = File::open(parameters_path).expect("Unable to open parameters file!");
            Parameters::<Bls12>::read(param_file, false /* false for better performance*/)
                .expect("Unable to read parameters file!")
        } else {
            let c = circuits::UpdateCircuit::default();

            let p = groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap();
            let param_file =
                File::create(parameters_path).expect("Unable to create parameters file!");
            p.write(param_file)
                .expect("Unable to write parameters file!");
            p
        };

        let pvk = groth16::prepare_verifying_key(&params.vk);

        let start = std::time::Instant::now();
        let proof = groth16::create_random_proof(circuit, &params, &mut OsRng).unwrap();
        println!(
            "Proving took: {}ms",
            (std::time::Instant::now() - start).as_millis()
        );

        let inputs = vec![state.into(), next_state.into()];

        println!(
            "Verify: {}",
            groth16::verify_proof(&pvk, &proof, &inputs).is_ok()
        );

        /*let start = std::time::Instant::now();
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
        .unwrap();*/

        Ok(())
    }
}
