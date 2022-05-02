use dusk_plonk::prelude::*;

pub const LOG_BATCH_SIZE: usize = 3;
pub const BATCH_SIZE: usize = 1 << LOG_BATCH_SIZE;

lazy_static! {
    pub static ref MIMC_PARAMS: Vec<BlsScalar> = vec![BlsScalar::from(1u64), BlsScalar::from(2u64)];
}
