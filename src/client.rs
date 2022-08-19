use crate::ZoroError;

pub fn transact(
    node: bazuka::client::PeerAddress,
    tx: bazuka::core::TransactionAndDelta,
) -> Result<bazuka::client::messages::TransactResponse, ZoroError> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let sk =
                <bazuka::core::Signer as bazuka::crypto::SignatureScheme>::generate_keys(b"dummy")
                    .1;
            let (lp, client) = bazuka::client::BazukaClient::connect(sk, node, "mainnet".into());

            let (res, _) = tokio::join!(
                async move { Ok::<_, bazuka::client::NodeError>(client.transact(tx).await) },
                lp
            );

            res
        })??)
}

pub fn get_account(
    node: bazuka::client::PeerAddress,
    address: bazuka::core::Address,
) -> Result<bazuka::client::messages::GetAccountResponse, ZoroError> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let sk =
                <bazuka::core::Signer as bazuka::crypto::SignatureScheme>::generate_keys(b"dummy")
                    .1;
            let (lp, client) = bazuka::client::BazukaClient::connect(sk, node, "mainnet".into());

            let (res, _) = tokio::join!(
                async move { Ok::<_, bazuka::client::NodeError>(client.get_account(address).await) },
                lp
            );

            res
        })??)
}

pub fn get_zero_mempool(
    node: bazuka::client::PeerAddress,
) -> Result<bazuka::client::messages::GetZeroMempoolResponse, ZoroError> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let sk =
                <bazuka::core::Signer as bazuka::crypto::SignatureScheme>::generate_keys(b"dummy")
                    .1;
            let (lp, client) = bazuka::client::BazukaClient::connect(sk, node, "mainnet".into());

            let (res, _) = tokio::join!(
                async move { Ok::<_, bazuka::client::NodeError>(client.get_zero_mempool().await) },
                lp
            );

            res
        })??)
}

pub fn is_mining(node: bazuka::client::PeerAddress) -> Result<bool, ZoroError> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let sk =
                <bazuka::core::Signer as bazuka::crypto::SignatureScheme>::generate_keys(b"dummy")
                    .1;
            let (lp, client) = bazuka::client::BazukaClient::connect(sk, node, "mainnet".into());

            let (res, _) = tokio::join!(
                async move {
                    Ok::<_, bazuka::client::NodeError>(
                        client
                            .get_miner_puzzle()
                            .await
                            .map(|resp| resp.puzzle.is_some()),
                    )
                },
                lp
            );

            res
        })??)
}
