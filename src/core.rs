use bazuka::crypto::jubjub;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Account {
    pub nonce: u64,
    pub address: jubjub::PointAffine,
    pub balance: u64,
}
