use bazuka::mpn::circuits;

use bazuka::zk::ZkScalar;
use bellman::groth16;
use bellman::groth16::Backend;
use bls12_381::Bls12;
use rand::rngs::OsRng;

use std::sync::{Arc, RwLock};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BankError {
    #[error("cannot generate zk-snark proof! Error: {0}")]
    CannotProve(#[from] bellman::SynthesisError),
    #[error("snark proof incorrect!")]
    IncorrectProof,
}
#[derive(Clone)]
pub struct ZoroParams {
    pub deposit: groth16::Parameters<Bls12>,
    pub withdraw: groth16::Parameters<Bls12>,
    pub update: groth16::Parameters<Bls12>,
}

impl ZoroParams {
    fn verify_keys(&self) -> ZoroVerifyKeys {
        ZoroVerifyKeys {
            update: self.update.vk.clone().into(),
            deposit: self.deposit.vk.clone().into(),
            withdraw: self.withdraw.vk.clone().into(),
        }
    }
}

#[derive(Clone)]
pub struct ZoroVerifyKeys {
    pub deposit: bazuka::zk::groth16::Groth16VerifyingKey,
    pub withdraw: bazuka::zk::groth16::Groth16VerifyingKey,
    pub update: bazuka::zk::groth16::Groth16VerifyingKey,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ZoroWork {
    pub circuit: ZoroCircuit,
    pub height: u64,
    pub state: ZkScalar,
    pub aux_data: ZkScalar,
    pub next_state: ZkScalar,
}

impl ZoroWork {
    pub fn verify(
        &self,
        params: &ZoroVerifyKeys,
        proof: &bazuka::zk::groth16::Groth16Proof,
    ) -> bool {
        let verifier: bazuka::zk::groth16::Groth16VerifyingKey = match &self.circuit {
            ZoroCircuit::Deposit(_) => params.deposit.clone(),
            ZoroCircuit::Withdraw(_) => params.withdraw.clone(),
            ZoroCircuit::Update(_) => params.update.clone(),
        }
        .into();
        bazuka::zk::groth16::groth16_verify(
            &verifier,
            self.height,
            self.state,
            self.aux_data,
            self.next_state,
            proof,
        )
    }
    pub fn prove(
        &self,
        params: ZoroParams,
        backend: Backend,
        cancel: Option<Arc<RwLock<bool>>>,
    ) -> Result<bazuka::zk::groth16::Groth16Proof, BankError> {
        let proof = unsafe {
            std::mem::transmute::<bellman::groth16::Proof<Bls12>, bazuka::zk::groth16::Groth16Proof>(
                match &self.circuit {
                    ZoroCircuit::Deposit(circuit) => groth16::create_random_proof_with_backend(
                        circuit.clone(),
                        &params.deposit.clone(),
                        &mut OsRng,
                        backend.clone(),
                        cancel.clone(),
                    )?,
                    ZoroCircuit::Withdraw(circuit) => groth16::create_random_proof_with_backend(
                        circuit.clone(),
                        &params.withdraw.clone(),
                        &mut OsRng,
                        backend.clone(),
                        cancel.clone(),
                    )?,
                    ZoroCircuit::Update(circuit) => groth16::create_random_proof_with_backend(
                        circuit.clone(),
                        &params.update.clone(),
                        &mut OsRng,
                        backend.clone(),
                        cancel.clone(),
                    )?,
                },
            )
        };
        let vks = params.verify_keys();

        if self.verify(&vks, &proof) {
            Ok(proof)
        } else {
            Err(BankError::IncorrectProof)
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ZoroCircuit {
    Deposit(circuits::DepositCircuit),
    Withdraw(circuits::WithdrawCircuit),
    Update(circuits::UpdateCircuit),
}
