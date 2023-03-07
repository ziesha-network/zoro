use bazuka::client::messages::ValidatorClaim;
use bazuka::client::NodeError;

use std::collections::HashMap;
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
    pub async fn get_mpn_works(
        &self,
    ) -> Result<bazuka::client::messages::GetMpnWorkResponse, NodeError> {
        self.call(move |client| async move { Ok(client.get_mpn_works().await?) })
            .await
    }
    pub async fn post_mpn_solution(
        &self,
        reward_address: bazuka::core::MpnAddress,
        proofs: HashMap<usize, bazuka::zk::groth16::Groth16Proof>,
    ) -> Result<bazuka::client::messages::PostMpnSolutionResponse, NodeError> {
        self.call(
            move |client| async move { Ok(client.post_mpn_proof(reward_address, proofs).await?) },
        )
        .await
    }

    pub async fn validator_claim(&self) -> Result<Option<ValidatorClaim>, NodeError> {
        self.call(move |client| async move {
            Ok(client.stats().await.map(|resp| resp.validator_claim)?)
        })
        .await
    }
    #[allow(dead_code)]
    pub async fn get_mpn_account(
        &self,
        index: u64,
    ) -> Result<bazuka::client::messages::GetMpnAccountResponse, NodeError> {
        self.call(move |client| async move { Ok(client.get_mpn_account(index).await?) })
            .await
    }
}
