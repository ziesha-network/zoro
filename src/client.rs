use crate::ZoroError;
use std::future::Future;

#[derive(Clone)]
pub struct SyncClient {
    node: bazuka::client::PeerAddress,
    network: String,
    sk: <bazuka::core::Signer as bazuka::crypto::SignatureScheme>::Priv,
}

impl SyncClient {
    pub fn new(node: bazuka::client::PeerAddress, network: &str) -> Self {
        Self {
            node,
            network: network.to_string(),
            sk: <bazuka::core::Signer as bazuka::crypto::SignatureScheme>::generate_keys(b"dummy")
                .1,
        }
    }
    fn call<
        R,
        Fut: Future<Output = Result<R, ZoroError>>,
        F: FnOnce(bazuka::client::BazukaClient) -> Fut,
    >(
        &self,
        f: F,
    ) -> Result<R, ZoroError> {
        Ok(tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let (lp, client) = bazuka::client::BazukaClient::connect(
                    self.sk.clone(),
                    self.node,
                    self.network.clone(),
                );

                let (res, _) = tokio::join!(
                    async move { Ok::<_, bazuka::client::NodeError>(f(client).await) },
                    lp
                );

                res
            })??)
    }
    pub fn is_outdated(&self) -> Result<bool, ZoroError> {
        self.call(move |client| async move {
            Ok(!client.outdated_heights().await?.outdated_heights.is_empty())
        })
    }
    pub fn transact(
        &self,
        tx: bazuka::core::TransactionAndDelta,
    ) -> Result<bazuka::client::messages::TransactResponse, ZoroError> {
        self.call(move |client| async move { Ok(client.transact(tx).await?) })
    }
    pub fn get_account(
        &self,
        address: bazuka::core::Address,
    ) -> Result<bazuka::client::messages::GetAccountResponse, ZoroError> {
        self.call(move |client| async move { Ok(client.get_account(address).await?) })
    }
    pub fn get_zero_mempool(
        &self,
    ) -> Result<bazuka::client::messages::GetZeroMempoolResponse, ZoroError> {
        self.call(move |client| async move { Ok(client.get_zero_mempool().await?) })
    }
    pub fn is_mining(&self) -> Result<bool, ZoroError> {
        self.call(move |client| async move {
            Ok(client
                .get_miner_puzzle()
                .await
                .map(|resp| resp.puzzle.is_some())?)
        })
    }
    pub fn get_height(&self) -> Result<u64, ZoroError> {
        self.call(move |client| async move { Ok(client.stats().await.map(|resp| resp.height)?) })
    }
}
