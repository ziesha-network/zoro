use bazuka::crypto::jubjub;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Account {
    pub nonce: u64,
    pub address: jubjub::PointAffine,
    pub balance: u64,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DepositWithdraw {
    pub index: u32,
    pub pub_key: jubjub::PublicKey,
    pub amount: i64,
}
