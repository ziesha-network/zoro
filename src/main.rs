mod bank;
mod circuits;
mod client;
mod config;

use circuits::{Deposit, Withdraw};

use bazuka::blockchain::BlockchainConfig;
use bazuka::config::blockchain::get_blockchain_config;
use bazuka::core::{Amount, Money, MpnDeposit, MpnWithdraw, TokenId};
use bazuka::db::KvStore;
use bazuka::db::ReadOnlyLevelDbKvStore;
use bazuka::zk::MpnTransaction;
use bellman::gpu::{Brand, Device};
use bellman::groth16::Backend;
use bellman::{groth16, Circuit};
use bls12_381::Bls12;
use client::SyncClient;
use colored::Colorize;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::Client;
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs::File;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::{Arc, RwLock};
use structopt::StructOpt;
use tokio::sync::RwLock as AsyncRwLock;
use zeekit::BellmanFr;

const LISTEN: &'static str = "0.0.0.0:8767";

#[derive(Debug, Clone, StructOpt)]
struct GenerateParamsOpt {
    #[structopt(long, default_value = "update_params.dat")]
    update_circuit_params: PathBuf,
    #[structopt(long, default_value = "deposit_params.dat")]
    deposit_circuit_params: PathBuf,
    #[structopt(long, default_value = "withdraw_params.dat")]
    withdraw_circuit_params: PathBuf,
}

#[derive(Debug, Clone, StructOpt)]
struct StartOpt {
    #[structopt(long, default_value = LISTEN)]
    listen: SocketAddr,
    #[structopt(long, default_value = LISTEN)]
    connect: SocketAddr,
    #[structopt(long)]
    seed: String,
    #[structopt(long)]
    node: String,
    #[structopt(long)]
    db: String,
    #[structopt(long, default_value = "update_params.dat")]
    update_circuit_params: PathBuf,
    #[structopt(long, default_value = "deposit_params.dat")]
    deposit_circuit_params: PathBuf,
    #[structopt(long, default_value = "withdraw_params.dat")]
    withdraw_circuit_params: PathBuf,
    #[structopt(long, default_value = "1")]
    deposit_batches: usize,
    #[structopt(long, default_value = "1")]
    withdraw_batches: usize,
    #[structopt(long, default_value = "1")]
    update_batches: usize,
    #[structopt(long)]
    gpu: bool,
    #[structopt(long, default_value = "")]
    miner_token: String,
}

#[derive(Debug, Clone, StructOpt)]
#[structopt(name = "Zoro", about = "Ziesha's MPN Executor")]
enum Opt {
    Start(StartOpt),
    GenerateParams(GenerateParamsOpt),
}

fn load_params<C: Circuit<BellmanFr> + Default, R: Rng>(
    path: PathBuf,
    rng: Option<R>,
) -> groth16::Parameters<Bls12> {
    if let Some(mut rng) = rng {
        println!("Generating {}...", path.to_string_lossy());
        let c = C::default();

        let p = groth16::generate_random_parameters::<Bls12, _, _>(c, &mut rng).unwrap();
        let param_file = File::create(path.clone()).expect("Unable to create parameters file!");
        p.write(param_file)
            .expect("Unable to write parameters file!");
        log::info!("VK of {}: {}", path.to_string_lossy(), vk_to_hex(&p.vk));
        p
    } else {
        println!("Loading {}...", path.to_string_lossy());
        let param_file = File::open(path.clone()).expect("Unable to open parameters file!");
        let p = groth16::Parameters::<Bls12>::read(
            param_file, false, /* false for better performance*/
        )
        .expect("Unable to read parameters file!");
        log::info!("VK of {}: {}", path.to_string_lossy(), vk_to_hex(&p.vk));
        p
    }
}

fn vk_to_hex(vk: &bellman::groth16::VerifyingKey<Bls12>) -> String {
    hex::encode(
        &bincode::serialize(&unsafe {
            std::mem::transmute::<
                bellman::groth16::VerifyingKey<Bls12>,
                bazuka::zk::groth16::Groth16VerifyingKey,
            >(vk.clone())
        })
        .unwrap(),
    )
}

fn db_shutter(path: &str) -> ReadOnlyLevelDbKvStore {
    ReadOnlyLevelDbKvStore::read_only(std::path::Path::new(path), 64).unwrap()
}

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZoroError {
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("node error: {0}")]
    NodeError(#[from] bazuka::client::NodeError),
    #[error("bank error: {0}")]
    BankError(#[from] bank::BankError),
    #[error("async task join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),
    #[error("http server error: {0}")]
    HttpServerError(#[from] hyper::Error),
    #[error("http client error: {0}")]
    HttpError(#[from] hyper::http::Error),
    #[error("bincode error: {0}")]
    BincodeError(#[from] bincode::Error),
    #[error("json error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("someone else found a block sooner than you!")]
    Aborted,
}

type ZoroWork = bank::ZoroWork<
    { config::LOG4_DEPOSIT_BATCH_SIZE },
    { config::LOG4_WITHDRAW_BATCH_SIZE },
    { config::LOG4_UPDATE_BATCH_SIZE },
    { config::LOG4_TREE_SIZE },
    { config::LOG4_TOKENS_TREE_SIZE },
>;

fn process_deposits<K: bazuka::db::KvStore>(
    conf: &BlockchainConfig,
    mempool: &[MpnDeposit],
    b: &bank::Bank<
        { config::LOG4_DEPOSIT_BATCH_SIZE },
        { config::LOG4_WITHDRAW_BATCH_SIZE },
        { config::LOG4_UPDATE_BATCH_SIZE },
        { config::LOG4_TREE_SIZE },
        { config::LOG4_TOKENS_TREE_SIZE },
    >,
    db_mirror: &mut bazuka::db::RamMirrorKvStore<K>,
) -> Result<(bazuka::core::ContractUpdate, ZoroWork), ZoroError> {
    let mut mpn_deposits = mempool
        .iter()
        .filter(|dw| dw.payment.contract_id == conf.mpn_contract_id)
        .map(|dw| Deposit {
            mpn_deposit: Some(dw.clone()),
            index: dw.zk_address_index(conf.mpn_log4_account_capacity),
            token_index: dw.zk_token_index,
            pub_key: dw.zk_address.0.decompress(),
            amount: dw.payment.amount,
        })
        .collect::<Vec<_>>();
    mpn_deposits.sort_unstable_by_key(|t| t.mpn_deposit.as_ref().unwrap().payment.nonce);
    let mut deposits = Vec::new();
    let mut nonces: HashMap<bazuka::core::Address, u32> = HashMap::new();
    for d in mpn_deposits {
        let pay = d.mpn_deposit.clone().unwrap().payment;
        if let Some(prev_nonce) = nonces.get(&pay.src) {
            if pay.nonce != prev_nonce + 1 {
                continue;
            }
        }
        nonces.insert(pay.src.clone(), pay.nonce);
        deposits.push(d);
    }

    let (accepted, _rejected, new_root, proof) = b.deposit(db_mirror, deposits)?;
    println!("Processed {} deposits!", accepted.len());

    //for tx in accepted.iter().chain(rejected.iter()) {
    //    mempool.remove(&tx.mpn_deposit.as_ref().unwrap());
    //}

    Ok((
        bazuka::core::ContractUpdate::Deposit {
            deposit_circuit_id: 0,
            deposits: accepted
                .into_iter()
                .map(|dw| dw.mpn_deposit.unwrap().payment)
                .collect(),
            next_state: new_root,
            proof: bazuka::zk::ZkProof::Groth16(Box::new(Default::default())),
        },
        proof,
    ))
}

fn process_withdraws<K: bazuka::db::KvStore>(
    conf: &BlockchainConfig,
    mempool: &[MpnWithdraw],
    b: &bank::Bank<
        { config::LOG4_DEPOSIT_BATCH_SIZE },
        { config::LOG4_WITHDRAW_BATCH_SIZE },
        { config::LOG4_UPDATE_BATCH_SIZE },
        { config::LOG4_TREE_SIZE },
        { config::LOG4_TOKENS_TREE_SIZE },
    >,
    db_mirror: &mut bazuka::db::RamMirrorKvStore<K>,
) -> Result<(bazuka::core::ContractUpdate, ZoroWork), ZoroError> {
    let mut withdraws = mempool
        .iter()
        .filter(|dw| dw.payment.contract_id == conf.mpn_contract_id)
        .map(|dw| Withdraw {
            mpn_withdraw: Some(dw.clone()),
            index: dw.zk_address_index(conf.mpn_log4_account_capacity),
            token_index: dw.zk_token_index,
            fee_token_index: dw.zk_fee_token_index,
            pub_key: dw.zk_address.0.decompress(),
            fingerprint: dw.payment.fingerprint(),
            nonce: dw.zk_nonce,
            sig: dw.zk_sig.clone(),
            amount: dw.payment.amount,
            fee: dw.payment.fee,
        })
        .collect::<Vec<_>>();
    withdraws.sort_unstable_by_key(|t| t.nonce);

    let (accepted, _rejected, new_root, proof) = b.withdraw(db_mirror, withdraws)?;
    println!("Processed {} withdrawals!", accepted.len());

    //for tx in accepted.iter().chain(rejected.iter()) {
    //    mempool.remove(&tx.mpn_withdraw.as_ref().unwrap());
    //}

    Ok((
        bazuka::core::ContractUpdate::Withdraw {
            withdraw_circuit_id: 0,
            withdraws: accepted
                .into_iter()
                .map(|dw| dw.mpn_withdraw.unwrap().payment)
                .collect(),
            next_state: new_root,
            proof: bazuka::zk::ZkProof::Groth16(Box::new(Default::default())),
        },
        proof,
    ))
}

fn process_updates<K: bazuka::db::KvStore>(
    mempool: &[MpnTransaction],
    b: &bank::Bank<
        { config::LOG4_DEPOSIT_BATCH_SIZE },
        { config::LOG4_WITHDRAW_BATCH_SIZE },
        { config::LOG4_UPDATE_BATCH_SIZE },
        { config::LOG4_TREE_SIZE },
        { config::LOG4_TOKENS_TREE_SIZE },
    >,
    db_mirror: &mut bazuka::db::RamMirrorKvStore<K>,
) -> Result<(bazuka::core::ContractUpdate, ZoroWork), ZoroError> {
    let mut txs: Vec<_> = mempool.iter().cloned().collect();
    txs.sort_unstable_by_key(|t| t.nonce);
    let fee_token = TokenId::Ziesha;
    let (accepted, _rejected, new_root, proof) = b.change_state(db_mirror, txs, fee_token)?;

    println!("Processed {} transactions!", accepted.len());
    // WARN: Will fail if accepted transactions have different fee tokens
    let fee_sum = accepted
        .iter()
        .map(|tx| Into::<u64>::into(tx.fee.amount))
        .sum::<u64>();
    //for tx in accepted.into_iter().chain(rejected.into_iter()) {
    //    mempool.remove(&tx);
    //}

    Ok((
        bazuka::core::ContractUpdate::FunctionCall {
            fee: Money::new(fee_token, fee_sum),
            function_id: 0,
            next_state: new_root,
            proof: bazuka::zk::ZkProof::Groth16(Box::new(Default::default())),
        },
        proof,
    ))
}

fn alice_shuffle() {
    println!(
        "{} {} {}",
        bazuka::config::SYMBOL.bright_red(),
        "Alice is shuffling the balls...".bright_cyan(),
        bazuka::config::SYMBOL.bright_red()
    );
}

struct ZoroContext {
    params: bank::ZoroParams,
    height: Option<u64>,
    works: HashMap<usize, ZoroWork>,
    submissions: HashMap<usize, bazuka::zk::groth16::Groth16Proof>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct GetWorkRequest {}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct GetWorkResponse {
    height: Option<u64>,
    works: HashMap<usize, ZoroWork>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct GetStatsRequest {}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct GetStatsResponse {
    height: Option<u64>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct PostProofRequest {
    height: u64,
    proofs: HashMap<usize, bazuka::zk::groth16::Groth16Proof>,
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct PostProofResponse {}

async fn process_request(
    context: Arc<AsyncRwLock<ZoroContext>>,
    request: Request<Body>,
    _client: Option<SocketAddr>,
    opt: StartOpt,
) -> Result<Response<Body>, ZoroError> {
    let url = request.uri().path().to_string();
    Ok(match &url[..] {
        "/stats" => {
            let resp = GetStatsResponse {
                height: context.read().await.height,
            };
            Response::new(Body::from(serde_json::to_vec(&resp)?))
        }
        "/get" => {
            let ctx = context.read().await;
            let resp = GetWorkResponse {
                height: ctx.height,
                works: ctx.works.clone(),
            };
            Response::new(Body::from(bincode::serialize(&resp)?))
        }
        "/post" => {
            let body = request.into_body();
            let body_bytes = hyper::body::to_bytes(body).await?;
            let req: PostProofRequest = bincode::deserialize(&body_bytes)?;
            let mut ctx = context.write().await;
            if ctx.height == Some(req.height) {
                for (id, p) in req.proofs {
                    if let Some(w) = ctx.works.get(&id) {
                        if w.verify(&ctx.params, &p) {
                            ctx.submissions.insert(id, p);
                            ctx.works.remove(&id);
                        }
                    }
                }
            }
            Response::new(Body::empty())
        }
        _ => {
            let mut resp = Response::new(Body::empty());
            *resp.status_mut() = StatusCode::NOT_FOUND;
            resp
        }
    })
}

#[tokio::main]
async fn main() {
    env_logger::init();
    println!(
        "{} v{} - A CPU/GPU-based MPN Executor for Ziesha Cryptocurrency",
        "Zoro!".bright_green(),
        env!("CARGO_PKG_VERSION")
    );
    let opt = Opt::from_args();

    match opt {
        Opt::GenerateParams(opt) => {
            let rng = Some(ChaCha20Rng::seed_from_u64(123456));

            load_params::<
                circuits::DepositCircuit<
                    { config::LOG4_DEPOSIT_BATCH_SIZE },
                    { config::LOG4_TREE_SIZE },
                    { config::LOG4_TOKENS_TREE_SIZE },
                >,
                _,
            >(opt.deposit_circuit_params, rng.clone());

            load_params::<
                circuits::WithdrawCircuit<
                    { config::LOG4_WITHDRAW_BATCH_SIZE },
                    { config::LOG4_TREE_SIZE },
                    { config::LOG4_TOKENS_TREE_SIZE },
                >,
                _,
            >(opt.withdraw_circuit_params, rng.clone());

            load_params::<
                circuits::UpdateCircuit<
                    { config::LOG4_UPDATE_BATCH_SIZE },
                    { config::LOG4_TREE_SIZE },
                    { config::LOG4_TOKENS_TREE_SIZE },
                >,
                _,
            >(opt.update_circuit_params, rng.clone());
        }

        Opt::Start(opt) => {
            let deposit_params =
                load_params::<
                    circuits::DepositCircuit<
                        { config::LOG4_DEPOSIT_BATCH_SIZE },
                        { config::LOG4_TREE_SIZE },
                        { config::LOG4_TOKENS_TREE_SIZE },
                    >,
                    _,
                >(opt.deposit_circuit_params.clone(), None::<ChaCha20Rng>);

            let withdraw_params =
                load_params::<
                    circuits::WithdrawCircuit<
                        { config::LOG4_WITHDRAW_BATCH_SIZE },
                        { config::LOG4_TREE_SIZE },
                        { config::LOG4_TOKENS_TREE_SIZE },
                    >,
                    _,
                >(opt.withdraw_circuit_params.clone(), None::<ChaCha20Rng>);

            let update_params =
                load_params::<
                    circuits::UpdateCircuit<
                        { config::LOG4_UPDATE_BATCH_SIZE },
                        { config::LOG4_TREE_SIZE },
                        { config::LOG4_TOKENS_TREE_SIZE },
                    >,
                    _,
                >(opt.update_circuit_params.clone(), None::<ChaCha20Rng>);

            let zoro_params = bank::ZoroParams {
                update: update_params.clone(),
                deposit: deposit_params.clone(),
                withdraw: withdraw_params.clone(),
            };

            let context = Arc::new(AsyncRwLock::new(ZoroContext {
                params: zoro_params.clone(),
                height: None,
                works: HashMap::new(),
                submissions: HashMap::new(),
            }));

            // Construct our SocketAddr to listen on...
            let addr = SocketAddr::from(opt.listen);

            // And a MakeService to handle each connection...
            let ctx_server = Arc::clone(&context);
            let opt_server = opt.clone();
            let make_service = make_service_fn(move |conn: &AddrStream| {
                let client = conn.remote_addr();
                let opt = opt_server.clone();
                let ctx = Arc::clone(&ctx_server);
                async move {
                    let opt = opt.clone();
                    let ctx = Arc::clone(&ctx);
                    Ok::<_, ZoroError>(service_fn(move |req: Request<Body>| {
                        let opt = opt.clone();
                        let ctx = Arc::clone(&ctx);
                        async move {
                            let resp = process_request(ctx, req, Some(client), opt).await?;
                            Ok::<_, ZoroError>(resp)
                        }
                    }))
                }
            });
            let server_fut = async {
                Server::bind(&addr)
                    .http1_only(true)
                    .http1_keepalive(false)
                    .serve(make_service)
                    .await?;
                Ok::<(), ZoroError>(())
            };

            let backend = if opt.gpu {
                Backend::Gpu(Arc::new(Mutex::new(
                    Device::by_brand(Brand::Nvidia)
                        .unwrap()
                        .into_iter()
                        .map(|d| {
                            (
                                d,
                                bellman::gpu::OptParams {
                                    n_g1: 32 * 1024 * 1024,
                                    window_size_g1: 10,
                                    groups_g1: 807,
                                    n_g2: 16 * 1024 * 1024,
                                    window_size_g2: 9,
                                    groups_g2: 723,
                                },
                            )
                        })
                        .collect(),
                )))
            } else {
                Backend::Cpu
            };

            let exec_wallet = bazuka::wallet::TxBuilder::new(&opt.seed.as_bytes().to_vec());
            let node_addr = bazuka::client::PeerAddress(opt.node.parse().unwrap());
            let client = SyncClient::new(node_addr, "mainnet", opt.miner_token.clone());

            let conf = get_blockchain_config();

            let mut last_height = None;

            let prover_loop = async {
                loop {
                    if let Err(e) = async {
                        let cancel = Arc::new(RwLock::new(false));
                        let req = Request::builder()
                            .method(Method::GET)
                            .uri(format!("http://{}/get", opt.connect))
                            .body(Body::empty())?;
                        let client = Client::new();
                        let resp =
                            hyper::body::to_bytes(client.request(req).await?.into_body()).await?;
                        let work_resp: GetWorkResponse = bincode::deserialize(&resp)?;
                        if let Some(height) = work_resp.height {
                            let (cancel_controller_tx, mut cancel_controller_rx) =
                                tokio::sync::mpsc::unbounded_channel::<()>();
                            let cancel_cloned = cancel.clone();
                            let cancel_controller = tokio::task::spawn(async move {
                                loop {
                                    match cancel_controller_rx.try_recv() {
                                        Ok(_)
                                        | Err(
                                            tokio::sync::mpsc::error::TryRecvError::Disconnected,
                                        ) => {
                                            break;
                                        }
                                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                                            let req = Request::builder()
                                                .method(Method::GET)
                                                .uri(format!("http://{}/stats", opt.connect))
                                                .body(Body::empty())?;
                                            let client = Client::new();
                                            let resp = hyper::body::to_bytes(
                                                client.request(req).await?.into_body(),
                                            )
                                            .await?;
                                            let resp: GetStatsResponse =
                                                serde_json::from_slice(&resp)?;
                                            if resp.height != Some(height) {
                                                *cancel_cloned.write().unwrap() = true;
                                            }
                                        }
                                    }
                                    std::thread::sleep(std::time::Duration::from_millis(2000));
                                }
                                Ok::<(), ZoroError>(())
                            });
                            let start = std::time::Instant::now();
                            let proofs: HashMap<usize, bazuka::zk::groth16::Groth16Proof> =
                                work_resp
                                    .works
                                    .into_par_iter()
                                    .map(|(id, p)| {
                                        p.prove(
                                            zoro_params.clone(),
                                            backend.clone(),
                                            Some(cancel.clone()),
                                        )
                                        .map(|p| (id, p))
                                    })
                                    .collect::<Result<
                                        HashMap<usize, bazuka::zk::groth16::Groth16Proof>,
                                        bank::BankError,
                                    >>()?;
                            println!(
                                "{} {}ms",
                                "Proving took:".bright_green(),
                                (std::time::Instant::now() - start).as_millis()
                            );
                            let req = Request::builder()
                                .method(Method::POST)
                                .uri(format!("http://{}/post", opt.connect))
                                .body(Body::from(bincode::serialize(&PostProofRequest {
                                    height,
                                    proofs,
                                })?))?;
                            let client = Client::new();
                            client.request(req).await?;

                            let _ = cancel_controller_tx.send(());
                            cancel_controller.await??;
                        }
                        Ok::<(), ZoroError>(())
                    }
                    .await
                    {
                        println!("Error while proving: {}", e);
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                    }
                }
                Ok::<(), ZoroError>(())
            };

            let packager_loop = async {
                loop {
                    if let Err(e) = async {

                    let mut ctx = context.write().await;
                    ctx.works.clear();
                    ctx.height=None;
                    drop(ctx);

                    // Wait till mine is done
                    if client.is_mining().await? {
                        log::info!("Nothing to mine!");
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                        return Ok::<(), ZoroError>(());
                    }

                    // Wait till chain gets updated
                    if client.is_outdated().await? {
                        log::info!("Chain is outdated!");
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                        return Ok::<(), ZoroError>(());
                    }

                    let curr_height = client.get_height().await?;

                    if Some(curr_height) == last_height {
                        log::info!("Proof already generated for height {}!", curr_height);
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                        return Ok::<(), ZoroError>(());
                    } else {
                        last_height = Some(curr_height);
                    }

                    println!("Started on height: {}", curr_height);

                    let acc = client.get_account(exec_wallet.get_address()).await?.account;

                    let mempool = client.get_zero_mempool().await?;
                    let task_conf = conf.clone();
                    let task_opt_db = opt.db.clone();
                    let (mut updates, provers, ops) = tokio::task::spawn_blocking(move || -> Result<(Vec< bazuka::core::ContractUpdate>,Vec<ZoroWork>, Vec<bazuka::db::WriteOp>),ZoroError > {
                        let db_shutter = db_shutter(&task_opt_db);
                        let db = db_shutter.snapshot();
                        let mut db_mirror = db.mirror();
                        let b = bank::Bank::new(
                            conf.mpn_log4_account_capacity,
                            conf.mpn_contract_id,
                            Some(Amount(1000000000)),
                        );

                        let mut updates = Vec::new();

                        for i in 0..opt.deposit_batches {
                            println!(
                                "{} Deposit-Transactions ({}/{})...",
                                "Processing:".bright_yellow(),
                                i + 1,
                                opt.deposit_batches
                            );
                            updates.push(process_deposits(
                                &task_conf,
                                &mempool.deposits,
                                &b,
                                &mut db_mirror,
                            )?);
                        }

                        for i in 0..opt.withdraw_batches {
                            println!(
                                "{} Withdraw-Transactions ({}/{})...",
                                "Processing:".bright_yellow(),
                                i + 1,
                                opt.withdraw_batches
                            );
                            updates.push(process_withdraws(
                                &task_conf,
                                &mempool.withdraws,
                                &b,
                                &mut db_mirror,
                            )?);
                        }

                        for i in 0..opt.update_batches {
                            println!(
                                "{} Zero-Transactions ({}/{})...",
                                "Processing:".bright_yellow(),
                                i + 1,
                                opt.update_batches
                            );
                            updates.push(process_updates(
                                &mempool.updates,
                                &b,
                                &mut db_mirror,
                            )?);
                        }

                        let (updates, provers): (
                            Vec<bazuka::core::ContractUpdate>,
                            Vec<ZoroWork>,
                        ) = updates.into_iter().unzip();
                        let ops = db_mirror.to_ops();
                        Ok((updates, provers, ops))
                    }).await??;

                    let mut ctx = context.write().await;
                    ctx.works = provers.iter().enumerate().map(|(i, w)| (i, w.clone())).collect();
                    ctx.height = Some(curr_height);
                    drop(ctx);

                    alice_shuffle();

                    while context.read().await.works.len() > 0 {
                        let remote_height = client.get_height().await?;
                        if remote_height != curr_height {
                            return Err(ZoroError::Aborted);
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                    }

                    let ctx = context.read().await;
                    for (i, upd) in updates.iter_mut().enumerate() {
                        let p = ctx.submissions.get(&i).unwrap().clone();
                        match upd {
                            bazuka::core::ContractUpdate::Deposit { proof, .. } => {
                                *proof = bazuka::zk::ZkProof::Groth16(Box::new(p));
                            }
                            bazuka::core::ContractUpdate::Withdraw { proof, .. } => {
                                *proof = bazuka::zk::ZkProof::Groth16(Box::new(p));
                            }
                            bazuka::core::ContractUpdate::FunctionCall { proof, .. } => {
                                *proof = bazuka::zk::ZkProof::Groth16(Box::new(p));
                            }
                        }
                    }
                    drop(ctx);

                    let mut update = bazuka::core::Transaction {
                        memo: String::new(),
                        src: Some(exec_wallet.get_address()),
                        nonce: acc.nonce + 1,
                        fee: Money::ziesha(0),
                        data: bazuka::core::TransactionData::UpdateContract {
                            contract_id: conf.mpn_contract_id.clone(),
                            updates,
                        },
                        sig: bazuka::core::Signature::Unsigned,
                    };
                    exec_wallet.sign_tx(&mut update);


                    let delta = bank::extract_delta(ops);

                    let tx_delta = bazuka::core::TransactionAndDelta {
                        tx: update,
                        state_delta: Some(delta),
                    };

                    client.transact(tx_delta).await?;

                    Ok(())
                }
                .await
                {
                    println!("Error while packaging: {}", e);
                    std::thread::sleep(std::time::Duration::from_millis(1000));
                }
                }
                Ok::<(), ZoroError>(())
            };

            tokio::try_join!(server_fut, packager_loop, prover_loop).unwrap();
        }
    }
}
