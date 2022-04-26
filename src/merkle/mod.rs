pub mod gadget;

use dusk_plonk::prelude::*;

use super::config::LOG_TREE_SIZE;
use crate::mimc;
use std::collections::HashMap;

pub struct SparseTree {
    levels: Vec<HashMap<u64, BlsScalar>>,
}

#[derive(Debug, Clone)]
pub struct Proof(pub [BlsScalar; LOG_TREE_SIZE]);
impl Default for Proof {
    fn default() -> Self {
        Self([BlsScalar::zero(); LOG_TREE_SIZE])
    }
}

impl SparseTree {
    pub fn new() -> Self {
        Self {
            levels: vec![HashMap::new(); LOG_TREE_SIZE + 1],
        }
    }
    pub fn root(&self) -> BlsScalar {
        *self.levels[LOG_TREE_SIZE].get(&0).expect("Tree empty!")
    }
    fn get(&self, level: usize, index: u64) -> BlsScalar {
        self.levels[level]
            .get(&index)
            .cloned()
            .unwrap_or(BlsScalar::zero())
    }
    pub fn prove(&self, mut index: u64) -> Proof {
        let mut proof = [BlsScalar::zero(); LOG_TREE_SIZE];
        for level in 0..LOG_TREE_SIZE {
            let neigh = if index & 1 == 0 { index + 1 } else { index - 1 };
            proof[level] = self.get(level, neigh);
            index = index >> 1;
        }
        Proof(proof)
    }
    #[allow(dead_code)]
    pub fn verify(mut index: u64, mut value: BlsScalar, proof: Proof, root: BlsScalar) -> bool {
        for p in proof.0 {
            value = if index & 1 == 0 {
                mimc::mimc(vec![value, p])
            } else {
                mimc::mimc(vec![p, value])
            };
            index = index >> 1;
        }
        value == root
    }
    pub fn set(&mut self, mut index: u64, mut value: BlsScalar) {
        for level in 0..(LOG_TREE_SIZE + 1) {
            self.levels[level].insert(index, value);
            let neigh = if index & 1 == 0 { index + 1 } else { index - 1 };
            let neigh_val = self.get(level, neigh);
            value = mimc::mimc(if index & 1 == 0 {
                vec![value, neigh_val]
            } else {
                vec![neigh_val, value]
            });
            index = index >> 1;
        }
    }
}
