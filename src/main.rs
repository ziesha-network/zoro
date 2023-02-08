mod bank;
mod circuits;
mod client;
mod config;

use circuits::{Deposit, Withdraw};

use bazuka::blockchain::{BlockchainConfig, ValidatorProof};
use bazuka::config::blockchain::get_blockchain_config;
use bazuka::core::{
    Amount, ChainSourcedTx, Header, Money, MpnAddress, MpnDeposit, MpnSourcedTx, MpnWithdraw,
    TokenId,
};
use bazuka::db::KvStore;
use bazuka::db::ReadOnlyLevelDbKvStore;
use bazuka::wallet::{TxBuilder, Wallet};
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
use rand::seq::IteratorRandom;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::{Arc, RwLock};
use std::time::Duration;
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
struct ProveOpt {
    #[structopt(long)]
    address: MpnAddress,
    #[structopt(long)]
    connect: Vec<SocketAddr>,
    #[structopt(long, default_value = "update_params.dat")]
    update_circuit_params: PathBuf,
    #[structopt(long, default_value = "deposit_params.dat")]
    deposit_circuit_params: PathBuf,
    #[structopt(long, default_value = "withdraw_params.dat")]
    withdraw_circuit_params: PathBuf,
    #[structopt(long)]
    gpu: bool,
    #[structopt(long, default_value = "1")]
    workers: usize,
}

#[derive(Debug, Clone, StructOpt)]
struct PackOpt {
    #[structopt(long, default_value = LISTEN)]
    listen: SocketAddr,
    #[structopt(long)]
    seed: String,
    #[structopt(long)]
    node: String,
    #[structopt(long)]
    db: String,
    #[structopt(long, default_value = "1")]
    deposit_batches: usize,
    #[structopt(long, default_value = "1")]
    withdraw_batches: usize,
    #[structopt(long, default_value = "1")]
    update_batches: usize,
    #[structopt(long, default_value = "")]
    miner_token: String,
    #[structopt(long, default_value = "1")]
    work_per_ip: usize,
    #[structopt(long, default_value = "10")]
    reward_delay: u64,
}

#[derive(Debug, Clone, StructOpt)]
#[structopt(name = "Zoro", about = "Ziesha's MPN Executor")]
enum Opt {
    Pack(PackOpt),
    Prove(ProveOpt),
    GenerateParams(GenerateParamsOpt),
}

const MAXIMUM_PROVING_TIME: Duration = Duration::from_secs(50);

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
    #[error("you are not the validator anymore!")]
    NotValidator,
    #[error("http request timed out!")]
    HttpTimeout(#[from] tokio::time::error::Elapsed),
    #[error("from-hex error happened: {0}")]
    FromHexError(#[from] hex::FromHexError),
    #[error("mpn-address parse error happened: {0}")]
    MpnAddressError(#[from] bazuka::core::ParseMpnAddressError),
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
    verif_keys: bank::ZoroVerifyKeys,
    height: Option<u64>,
    works: HashMap<usize, ZoroWork>,
    sent: HashMap<SocketAddr, HashSet<usize>>,
    remaining_works: HashSet<usize>,
    submissions: HashMap<usize, bazuka::zk::groth16::Groth16Proof>,
    rewards: HashMap<MpnAddress, usize>,
    validator_proof: Option<ValidatorProof>,
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
    validator_proof: Option<ValidatorProof>,
    version: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct PostProofRequest {
    height: u64,
    proofs: HashMap<usize, bazuka::zk::groth16::Groth16Proof>,
    address: MpnAddress,
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct PostProofResponse {
    accepted: usize,
}

fn create_tx(
    wallet: &mut Wallet,
    memo: String,
    entries: HashMap<MpnAddress, Amount>,
    remote_nonce: u32,
    remote_mpn_nonce: u64,
) -> Result<(bazuka::core::MpnDeposit, Vec<MpnTransaction>), ZoroError> {
    let mpn_id = bazuka::config::blockchain::get_blockchain_config().mpn_contract_id;
    let tx_builder = TxBuilder::new(&wallet.seed());
    let new_nonce = wallet.new_r_nonce().unwrap_or(remote_nonce + 1);
    let pool_mpn_address = MpnAddress {
        pub_key: tx_builder.get_zk_address(),
    };
    let new_mpn_nonce = wallet
        .new_z_nonce(&pool_mpn_address)
        .unwrap_or(remote_mpn_nonce);
    let sum_all = entries
        .iter()
        .map(|(_, m)| Into::<u64>::into(*m))
        .sum::<u64>();
    let tx = tx_builder.deposit_mpn(
        memo,
        mpn_id,
        pool_mpn_address.clone(),
        0,
        new_nonce,
        Money::ziesha(sum_all),
        Money::ziesha(0),
    );
    wallet.add_deposit(tx.clone());
    let mut ztxs = Vec::new();
    for (i, (addr, mon)) in entries.iter().enumerate() {
        if *addr != pool_mpn_address {
            let tx = tx_builder.create_mpn_transaction(
                0,
                addr.clone(),
                0,
                Money::ziesha((*mon).into()),
                0,
                Money::ziesha(0),
                new_mpn_nonce + i as u64,
            );
            wallet.add_zsend(tx.clone());
            ztxs.push(tx);
        }
    }
    Ok((tx, ztxs))
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct History {
    solved: HashMap<Header, HashMap<MpnAddress, Amount>>,
    sent: HashMap<Header, (MpnDeposit, Vec<MpnTransaction>)>,
}

fn save_history(h: &History) -> Result<(), ZoroError> {
    let history_path = home::home_dir().unwrap().join(Path::new(".zoro-history"));
    File::create(history_path)?.write_all(&bincode::serialize(h)?)?;
    Ok(())
}

fn get_history() -> Result<History, ZoroError> {
    let history_path = home::home_dir().unwrap().join(Path::new(".zoro-history"));
    Ok(if let Ok(mut f) = File::open(history_path.clone()) {
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)?;
        drop(f);
        bincode::deserialize(&bytes)?
    } else {
        History {
            solved: HashMap::new(),
            sent: HashMap::new(),
        }
    })
}

async fn process_request(
    context: Arc<AsyncRwLock<ZoroContext>>,
    request: Request<Body>,
    client: Option<SocketAddr>,
    opt: PackOpt,
) -> Result<Response<Body>, ZoroError> {
    let url = request.uri().path().to_string();
    Ok(match &url[..] {
        "/stats" => {
            let ctx = context.read().await;
            let resp = GetStatsResponse {
                height: ctx.height,
                validator_proof: ctx.validator_proof.clone(),
                version: env!("CARGO_PKG_VERSION").into(),
            };
            Response::new(Body::from(serde_json::to_vec(&resp)?))
        }
        "/get" => {
            if let Some(client) = client {
                let mut ctx = context.write().await;
                let already_sent = ctx.sent.get(&client).cloned().unwrap_or_default();
                if already_sent.len() >= opt.work_per_ip {
                    let resp = GetWorkResponse {
                        height: ctx.height,
                        works: Default::default(),
                    };
                    return Ok(Response::new(Body::from(bincode::serialize(&resp)?)));
                }
                if ctx.remaining_works.is_empty() {
                    ctx.remaining_works = ctx.works.keys().cloned().collect();
                    println!("Resending works!");
                }
                let remaining_works: HashSet<usize> = ctx.remaining_works.iter().cloned().collect();
                let sendable: Vec<usize> =
                    remaining_works.difference(&already_sent).cloned().collect();
                let work_ids = sendable
                    .iter()
                    .cloned()
                    .choose_multiple(&mut rand::thread_rng(), opt.work_per_ip);
                for id in work_ids.iter() {
                    ctx.remaining_works.remove(id);
                }
                let works: HashMap<usize, ZoroWork> = work_ids
                    .into_iter()
                    .filter_map(|id| {
                        if let Some(w) = ctx.works.get(&id) {
                            Some((id, w.clone()))
                        } else {
                            None
                        }
                    })
                    .collect();
                for id in works.keys() {
                    println!("Posted work-id {} to client {}", id, client);
                    ctx.sent.entry(client).or_default().insert(*id);
                }
                let resp = GetWorkResponse {
                    height: ctx.height,
                    works,
                };
                Response::new(Body::from(bincode::serialize(&resp)?))
            } else {
                Response::new(Body::empty())
            }
        }
        "/post" => {
            let mut accepted = 0;
            if let Some(client) = client {
                let body = request.into_body();
                let body_bytes = hyper::body::to_bytes(body).await?;
                let req: PostProofRequest = bincode::deserialize(&body_bytes)?;
                let mut ctx = context.write().await;
                if ctx.height == Some(req.height) {
                    for (id, p) in req.proofs {
                        if let Some(w) = ctx.works.get(&id) {
                            if w.verify(&ctx.verif_keys, &p) {
                                println!("Client {} sent the solution for work-id {}", client, id);
                                ctx.submissions.insert(id, p);
                                *ctx.rewards.entry(req.address.clone()).or_default() += 1;
                                ctx.works.remove(&id);
                                accepted += 1;
                            }
                        }
                    }
                }
            }
            Response::new(Body::from(bincode::serialize(&PostProofResponse {
                accepted,
            })?))
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

        Opt::Prove(opt) => {
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

            let new_worker = || async {
                let backend = backend.clone();
                let zoro_params = zoro_params.clone();
                let opt = opt.clone();
                loop {
                    let backend = backend.clone();
                    let zoro_params = zoro_params.clone();
                    let opt = opt.clone();
                    if let Err(e) = async move {
                        for connect in opt.connect.clone() {
                            println!("Checking {}...", connect);
                            let backend = backend.clone();
                            let zoro_params = zoro_params.clone();
                            let opt = opt.clone();
                            let cancel = Arc::new(RwLock::new(false));

                            let req = Request::builder()
                                .method(Method::GET)
                                .uri(format!("http://{}/stats", connect))
                                .body(Body::empty())?;
                            let client = Client::new();
                                if let Ok(res) = tokio::time::timeout(Duration::from_millis(2000), async {
                                        hyper::body::to_bytes(client.request(req).await?.into_body()).await
                                    }).await {
                                        if let Ok(res) = res {
                                            let resp :Result<GetStatsResponse,_>=  serde_json::from_slice(&res);
                                            if let Ok(resp) = resp {
                                                if resp.height.is_none() {
                                                    println!("Remote is not a validator!");
                                                    continue;
                                                }
                                            } else {
                                                println!("Error parsing");
                                                continue;
                                            }
                                        } else {
                                            println!("Error while getting");
                                            continue;
                                        }
                                    } else {
                                        println!("Timed out");
                                        continue;
                                    };
                            println!("Remote is a validator! Getting work...");

                            let req = Request::builder()
                                .method(Method::GET)
                                .uri(format!("http://{}/get", connect))
                                .body(Body::empty())?;
                            let client = Client::new();
                            let resp =
                                if let Ok(res) = tokio::time::timeout(Duration::from_millis(15000), async {
                                        hyper::body::to_bytes(client.request(req).await?.into_body()).await
                                    }).await {
                                        if let Ok(res) = res {
                                            res
                                        } else {
                                            println!("Error getting work!");
                                            continue;
                                        }
                                    } else {
                                        println!("Timed out!");
                                        continue;
                                    };
                            let work_resp: GetWorkResponse = bincode::deserialize(&resp)?;
                            if let Some(height) = work_resp.height {
                                println!("Work found! Starting...");
                                let (cancel_controller_tx, mut cancel_controller_rx) =
                                    tokio::sync::mpsc::unbounded_channel::<()>();
                                let cancel_cloned = cancel.clone();
                                let cancel_controller =
                                    tokio::task::spawn(async move {
                                        loop {
                                            match cancel_controller_rx.try_recv() {
                                        Ok(_)
                                        | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                                            break;
                                        }
                                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                                            let req = Request::builder()
                                                .method(Method::GET)
                                                .uri(format!("http://{}/stats", connect))
                                                .body(Body::empty())?;
                                            let client = Client::new();
                                            let resp = hyper::body::to_bytes(
                                                client.request(req).await?.into_body(),
                                            )
                                            .await?;
                                            let resp: GetStatsResponse = serde_json::from_slice(&resp)?;
                                            if resp.height != Some(height) || resp.validator_proof.is_none() {
                                                *cancel_cloned.write().unwrap() = true;
                                            }
                                        }
                                    }
                                            std::thread::sleep(std::time::Duration::from_millis(3000));
                                        }
                                        Ok::<(), ZoroError>(())
                                    });
                                println!("Got {} SNARK-works to solve...", work_resp.works.len());
                                let start = std::time::Instant::now();
                                let pool = rayon::ThreadPoolBuilder::new()
                                    .num_threads(32)
                                    .build()
                                    .unwrap();
                                let proofs = tokio::task::spawn_blocking(move || {
                                    pool.install(|| -> Result<
                                    HashMap<usize, bazuka::zk::groth16::Groth16Proof>,
                                    bank::BankError,
                                > {
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
                                        .collect()
                                })
                                })
                                .await??;
                                println!(
                                    "{} {}ms",
                                    "Proving took:".bright_green(),
                                    start.elapsed().as_millis()
                                );
                                if start.elapsed() > MAXIMUM_PROVING_TIME {
                                    println!("{} {}", "WARNING:".bright_red(), "Your proving time is too high! You will most probably not win any rewards with this latency.");
                                }

                                let req = Request::builder()
                                    .method(Method::POST)
                                    .uri(format!("http://{}/post", connect))
                                    .body(Body::from(bincode::serialize(&PostProofRequest {
                                        address: opt.address,
                                        height,
                                        proofs,
                                    })?))?;
                                let client = Client::new();

                                if let Ok(res) = tokio::time::timeout(std::time::Duration::from_millis(5000), async {
                                        hyper::body::to_bytes(client.request(req).await?.into_body()).await
                                    }).await
                                    {
                                    if let Ok(res) = res {
                                        let resp :Result<PostProofResponse,_>=  serde_json::from_slice(&res);
                                        if let Ok(resp) = resp {
                                            println!("{} of your proofs were accepted!", resp.accepted);
                                        } else {
                                            println!("Error parsing response");
                                            continue;
                                        }
                                    } else {
                                        println!("Error while sending solution");
                                        continue;
                                    }
                                }
                                else {
                                    println!("Timed out when sending solution!");
                                    continue;
                                }

                                let _ = cancel_controller_tx.send(());
                                cancel_controller.await??;
                            } else {
                                println!("No work to do!");
                            }
                        }
                        Ok::<(), ZoroError>(())
                    }
                    .await
                    {
                        println!("Error while proving: {}", e);
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                    }
                }
            };
            let workers: Vec<_> = (0..opt.workers).map(|_| new_worker()).collect();
            futures::future::join_all(workers).await;
        }

        Opt::Pack(opt) => {
            let verif_keys = bank::ZoroVerifyKeys {
                update: bazuka::config::blockchain::MPN_UPDATE_VK.clone(),
                deposit: bazuka::config::blockchain::MPN_DEPOSIT_VK.clone(),
                withdraw: bazuka::config::blockchain::MPN_WITHDRAW_VK.clone(),
            };

            let context = Arc::new(AsyncRwLock::new(ZoroContext {
                verif_keys: verif_keys.clone(),
                height: None,
                validator_proof: None,
                works: HashMap::new(),
                remaining_works: HashSet::new(),
                submissions: HashMap::new(),
                rewards: HashMap::new(),
                sent: HashMap::new(),
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

            let exec_wallet = bazuka::wallet::TxBuilder::new(&opt.seed.as_bytes().to_vec());
            let node_addr = bazuka::client::PeerAddress(opt.node.parse().unwrap());
            let client = SyncClient::new(node_addr, "mainnet", opt.miner_token.clone());

            let conf = get_blockchain_config();

            let opt_reward_sender = opt.clone();
            let client_reward_sender = client.clone();
            let reward_sender_loop = {
                let opt = opt_reward_sender.clone();
                let client = client_reward_sender.clone();
                async move {
                    loop {
                        let opt = opt.clone();
                        let client = client.clone();
                        if let Err(e) = async move {
                            let mpn_log4_acc_cap =
                                bazuka::config::blockchain::get_blockchain_config()
                                    .mpn_log4_account_capacity;

                            let mut hist = get_history()?;
                            let curr_height = client.get_height().await?;
                            let wallet_path =
                                home::home_dir().unwrap().join(Path::new(".bazuka-wallet"));
                            let mut wallet = Wallet::open(wallet_path.clone()).unwrap().unwrap();
                            let pool_mpn_address = MpnAddress {
                                pub_key: TxBuilder::new(&wallet.seed()).get_zk_address(),
                            };
                            let curr_nonce = client
                                .get_account(TxBuilder::new(&wallet.seed()).get_address())
                                .await?
                                .account
                                .nonce;
                            let curr_mpn_nonce = client
                                .get_mpn_account(pool_mpn_address.account_index(mpn_log4_acc_cap))
                                .await?
                                .account
                                .nonce;
                            for (h, entries) in hist.solved.clone().into_iter() {
                                if let Some(actual_header) = client.get_header(h.number).await? {
                                    if curr_height - h.number >= opt.reward_delay {
                                        hist.solved.remove(&h);
                                        if actual_header == h {
                                            let (tx, ztxs) = create_tx(
                                                &mut wallet,
                                                format!("Pool-Reward, block #{}", h.number).into(),
                                                entries,
                                                curr_nonce,
                                                curr_mpn_nonce,
                                            )?;
                                            wallet.save(wallet_path.clone()).unwrap();
                                            println!(
                                                "Tx with nonce {} created...",
                                                tx.payment.nonce
                                            );
                                            hist.sent.insert(h, (tx, ztxs));
                                        }
                                        save_history(&hist)?;
                                    }
                                }
                            }
                            println!("Current nonce: {}", curr_nonce);

                            println!("Resending unprocessed transactions...");
                            for tx in wallet.chain_sourced_txs.iter() {
                                if tx.nonce() > curr_nonce {
                                    match tx {
                                        ChainSourcedTx::MpnDeposit(tx) => {
                                            client.transact_deposit(tx.clone()).await?;
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            for tx in wallet
                                .mpn_sourced_txs
                                .get(&pool_mpn_address)
                                .cloned()
                                .unwrap_or_default()
                                .iter()
                            {
                                if tx.nonce() >= curr_mpn_nonce {
                                    match tx {
                                        MpnSourcedTx::MpnTransaction(tx) => {
                                            client.transact_zero(tx.clone()).await?;
                                        }
                                        _ => {}
                                    }
                                }
                            }

                            Ok::<_, ZoroError>(())
                        }
                        .await
                        {
                            log::error!("Error: {}", e);
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    }

                    Ok::<(), ZoroError>(())
                }
            };

            let mut last_solved_height = None;

            let packager_loop = async {
                loop {
                    if let Err(e) = async {

                    let mut ctx = context.write().await;
                    ctx.works.clear();
                    ctx.submissions.clear();
                    ctx.rewards.clear();
                    ctx.remaining_works.clear();
                    ctx.sent.clear();
                    ctx.height = None;
                    ctx.validator_proof = None;
                    drop(ctx);

                    let validator_proof = client.validator_proof().await?;

                    // Wait till mine is done
                    if let Some(validator_proof) = validator_proof {
                        context.write().await.validator_proof=Some(validator_proof);
                    } else {
                        log::info!("You are not the selected validator!");
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
                    if Some(curr_height) == last_solved_height {
                       log::info!("Proof already generated for height {}!", curr_height);
                       std::thread::sleep(std::time::Duration::from_millis(1000));
                       return Ok::<(), ZoroError>(());
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
                            Some(Amount(0)),
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

                    let start = std::time::Instant::now();
                    while context.read().await.works.len() > 0 {
                        let remote_height = client.get_height().await?;
                        if remote_height != curr_height {
                            return Err(ZoroError::Aborted);
                        }
                        if client.validator_proof().await?.is_none() {
                            return Err(ZoroError::NotValidator);
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                    }
                    println!(
                        "{} {}ms",
                        "Proving took:".bright_green(),
                        start.elapsed().as_millis()
                    );

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
                    last_solved_height = Some(curr_height);
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

            tokio::try_join!(server_fut, packager_loop, reward_sender_loop).unwrap();
        }
    }
}
