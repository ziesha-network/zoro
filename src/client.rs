use bazuka::blockchain::ValidatorProof;
use bazuka::client::NodeError;
use std::future::Future;

#[derive(Clone)]
pub struct SyncClient {
    node: bazuka::client::PeerAddress,
    network: String,
    miner_token: String,
    sk: <bazuka::core::Signer as bazuka::crypto::SignatureScheme>::Priv,
}

impl SyncClient {
    pub fn new(node: bazuka::client::PeerAddress, network: &str, miner_token: String) -> Self {
        Self {
            node,
            network: network.to_string(),
            miner_token,
            sk: <bazuka::core::Signer as bazuka::crypto::SignatureScheme>::generate_keys(b"dummy")
                .1,
        }
    }
    async fn call<
        R,
        Fut: Future<Output = Result<R, NodeError>>,
        F: FnOnce(bazuka::client::BazukaClient) -> Fut,
    >(
        &self,
        f: F,
    ) -> Result<R, NodeError> {
        let (lp, client) = bazuka::client::BazukaClient::connect(
            self.sk.clone(),
            self.node,
            self.network.clone(),
            Some(self.miner_token.clone()),
        );

        let (res, _) = tokio::join!(
            async move { Ok::<_, bazuka::client::NodeError>(f(client).await) },
            lp
        );
        Ok(res??)
    }
    pub async fn is_outdated(&self) -> Result<bool, NodeError> {
        self.call(move |client| async move {
            Ok(!client.outdated_heights().await?.outdated_heights.is_empty())
        })
        .await
    }
    pub async fn transact(
        &self,
        tx: bazuka::core::TransactionAndDelta,
    ) -> Result<bazuka::client::messages::TransactResponse, NodeError> {
        self.call(move |client| async move { Ok(client.transact(tx).await?) })
            .await
    }
    pub async fn get_account(
        &self,
        address: bazuka::core::Address,
    ) -> Result<bazuka::client::messages::GetAccountResponse, NodeError> {
        self.call(move |client| async move { Ok(client.get_account(address).await?) })
            .await
    }
    pub async fn get_zero_mempool(
        &self,
    ) -> Result<bazuka::client::messages::GetZeroMempoolResponse, NodeError> {
        self.call(move |client| async move { Ok(client.get_zero_mempool().await?) })
            .await
    }
    pub async fn get_height(&self) -> Result<u64, NodeError> {
        self.call(move |client| async move { Ok(client.stats().await.map(|resp| resp.height)?) })
            .await
    }
    pub async fn validator_proof(&self) -> Result<Option<ValidatorProof>, NodeError> {
        self.call(move |client| async move {
            Ok(client.stats().await.map(|resp| resp.validator_proof)?)
        })
        .await
    }
    pub async fn get_header(&self, index: u64) -> Result<Option<bazuka::core::Header>, NodeError> {
        self.call(move |client| async move {
            Ok(client.get_headers(index, 1).await?.headers.first().cloned())
        })
        .await
    }
    pub async fn get_block(&self, index: u64) -> Result<Option<bazuka::core::Block>, NodeError> {
        self.call(move |client| async move {
            Ok(client.get_blocks(index, 1).await?.blocks.first().cloned())
        })
        .await
    }
    pub async fn get_mpn_account(
        &self,
        index: u64,
    ) -> Result<bazuka::client::messages::GetMpnAccountResponse, NodeError> {
        self.call(move |client| async move { Ok(client.get_mpn_account(index).await?) })
            .await
    }
    pub async fn transact_deposit(
        &self,
        tx: bazuka::core::MpnDeposit,
    ) -> Result<bazuka::client::messages::PostMpnDepositResponse, NodeError> {
        self.call(move |client| async move { Ok(client.transact_contract_deposit(tx).await?) })
            .await
    }
    pub async fn transact_zero(
        &self,
        tx: bazuka::zk::MpnTransaction,
    ) -> Result<bazuka::client::messages::PostMpnTransactionResponse, NodeError> {
        self.call(move |client| async move { Ok(client.zero_transact(tx).await?) })
            .await
    }
}
