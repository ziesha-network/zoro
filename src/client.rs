use bazuka::client::{messages::ValidatorClaim, Limit, NodeError};
use bazuka::core::MpnAddress;

use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

#[derive(Clone)]
pub struct SyncClient {
    node: bazuka::client::PeerAddress,
    network: String,
    sk: <bazuka::core::Signer as bazuka::crypto::SignatureScheme>::Priv,
    timeout: Duration,
}

impl SyncClient {
    pub fn new(node: bazuka::client::PeerAddress, network: &str, timeout: Duration) -> Self {
        Self {
            node,
            network: network.to_string(),
            sk: <bazuka::core::Signer as bazuka::crypto::SignatureScheme>::generate_keys(b"dummy")
                .1,
            timeout,
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
            Some(Limit::default().time(self.timeout.as_millis().try_into().unwrap())),
        );

        let (res, _) = tokio::join!(
            async move { Ok::<_, bazuka::client::NodeError>(f(client).await) },
            lp
        );
        Ok(res??)
    }
    pub async fn post_mpn_worker(
        &self,
        reward_address: bazuka::core::MpnAddress,
    ) -> Result<bazuka::client::messages::PostMpnWorkerResponse, NodeError> {
        self.call(move |client| async move { Ok(client.post_mpn_worker(reward_address).await?) })
            .await
    }
    pub async fn get_mpn_works(
        &self,
        mpn_address: MpnAddress,
    ) -> Result<bazuka::client::messages::GetMpnWorkResponse, NodeError> {
        self.call(move |client| async move { Ok(client.get_mpn_works(mpn_address).await?) })
            .await
    }
    pub async fn post_mpn_solution(
        &self,
        proofs: HashMap<usize, bazuka::zk::ZkProof>,
    ) -> Result<bazuka::client::messages::PostMpnSolutionResponse, NodeError> {
        self.call(move |client| async move { Ok(client.post_mpn_proof(proofs).await?) })
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
        addr: MpnAddress,
    ) -> Result<bazuka::client::messages::GetMpnAccountResponse, NodeError> {
        self.call(move |client| async move { Ok(client.get_mpn_account(addr).await?) })
            .await
    }
}
