mod bank;
mod circuits;
mod client;
mod config;

use bazuka::client::PeerAddress;

use bazuka::core::{MpnAddress, TokenId};

use bazuka::mpn::{MpnWork, MpnWorkData};

use bellman::gpu::{Brand, Device};
use bellman::groth16::Backend;
use bellman::{groth16, Circuit};
use bls12_381::Bls12;
use client::SyncClient;
use colored::Colorize;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs::File;

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use structopt::StructOpt;

use zeekit::BellmanFr;

#[derive(Debug, Clone, StructOpt)]
struct GenerateParamsOpt {
    #[structopt(long, default_value = "super_update_params.dat")]
    super_update_circuit_params: PathBuf,
    #[structopt(long, default_value = "update_params.dat")]
    update_circuit_params: PathBuf,
    #[structopt(long, default_value = "deposit_params.dat")]
    deposit_circuit_params: PathBuf,
    #[structopt(long, default_value = "withdraw_params.dat")]
    withdraw_circuit_params: PathBuf,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Optimization {
    n_g1: usize,
    window_size_g1: usize,
    groups_g1: usize,
    n_g2: usize,
    window_size_g2: usize,
    groups_g2: usize,
}

impl Into<bellman::gpu::OptParams> for Optimization {
    fn into(self) -> bellman::gpu::OptParams {
        bellman::gpu::OptParams {
            n_g1: self.n_g1,
            window_size_g1: self.window_size_g1,
            groups_g1: self.groups_g1,
            n_g2: self.n_g2,
            window_size_g2: self.window_size_g2,
            groups_g2: self.groups_g2,
        }
    }
}

#[derive(Debug, Clone, StructOpt)]
struct ProveOpt {
    #[structopt(long)]
    network: String,
    #[structopt(long)]
    connect: PeerAddress,
    #[structopt(long, default_value = "super_update_params.dat")]
    super_update_circuit_params: PathBuf,
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
    #[structopt(long)]
    address: MpnAddress,
}

#[derive(Debug, Clone, StructOpt)]
#[structopt(name = "Zoro", about = "Ziesha's MPN Executor")]
enum Opt {
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
    #[error("kv-store error happened: {0}")]
    KvStoreError(#[from] bazuka::db::KvStoreError),
}

type ZoroWork = bank::ZoroWork<
    { config::LOG4_DEPOSIT_BATCH_SIZE },
    { config::LOG4_WITHDRAW_BATCH_SIZE },
    { config::LOG4_UPDATE_BATCH_SIZE },
    { config::LOG4_TREE_SIZE },
    { config::LOG4_TOKENS_TREE_SIZE },
>;

fn to_zoro_work(work: MpnWork) -> ZoroWork {
    ZoroWork {
        height: work.public_inputs.height.into(),
        state: work.public_inputs.state,
        aux_data: work.public_inputs.aux_data,
        next_state: work.public_inputs.next_state,
        circuit: match &work.data {
            MpnWorkData::Deposit(deposits) => {
                println!("{} deposits", deposits.len());
                bank::ZoroCircuit::Deposit(circuits::DepositCircuit {
                    height: work.public_inputs.height.into(),
                    state: work.public_inputs.state,
                    aux_data: work.public_inputs.aux_data,
                    next_state: work.public_inputs.next_state,
                    transitions: Box::new(circuits::DepositTransitionBatch::new(deposits.clone())),
                })
            }
            MpnWorkData::Withdraw(withdraws) => {
                println!("{} withdraws", withdraws.len());
                bank::ZoroCircuit::Withdraw(circuits::WithdrawCircuit {
                    height: work.public_inputs.height.into(),
                    state: work.public_inputs.state,
                    aux_data: work.public_inputs.aux_data,
                    next_state: work.public_inputs.next_state,
                    transitions: Box::new(circuits::WithdrawTransitionBatch::new(
                        withdraws.clone(),
                    )),
                })
            }
            MpnWorkData::Update(updates) => {
                println!("{} updates", updates.len());
                bank::ZoroCircuit::Update(circuits::UpdateCircuit {
                    height: work.public_inputs.height.into(),
                    state: work.public_inputs.state,
                    aux_data: work.public_inputs.aux_data,
                    next_state: work.public_inputs.next_state,
                    fee_token: TokenId::Ziesha,
                    transitions: Box::new(circuits::TransitionBatch::new(updates.clone())),
                })
            }
        },
    }
}

fn alice_shuffle() {
    println!(
        "{} {} {}",
        bazuka::config::SYMBOL.bright_red(),
        "Alice is shuffling the balls...".bright_cyan(),
        bazuka::config::SYMBOL.bright_red()
    );
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
            let verif_keys = bank::ZoroVerifyKeys {
                update: bazuka::config::blockchain::MPN_UPDATE_VK.clone(),
                deposit: bazuka::config::blockchain::MPN_DEPOSIT_VK.clone(),
                withdraw: bazuka::config::blockchain::MPN_WITHDRAW_VK.clone(),
            };

            let deposit_params =
                load_params::<
                    circuits::DepositCircuit<
                        { config::LOG4_DEPOSIT_BATCH_SIZE },
                        { config::LOG4_TREE_SIZE },
                        { config::LOG4_TOKENS_TREE_SIZE },
                    >,
                    _,
                >(opt.deposit_circuit_params.clone(), None::<ChaCha20Rng>);
            if Into::<bazuka::zk::groth16::Groth16VerifyingKey>::into(deposit_params.vk.clone())
                != verif_keys.deposit
            {
                panic!("Incorrect deposit-params! Regenerate params via: zoro generate-params");
            }

            let withdraw_params =
                load_params::<
                    circuits::WithdrawCircuit<
                        { config::LOG4_WITHDRAW_BATCH_SIZE },
                        { config::LOG4_TREE_SIZE },
                        { config::LOG4_TOKENS_TREE_SIZE },
                    >,
                    _,
                >(opt.withdraw_circuit_params.clone(), None::<ChaCha20Rng>);
            if Into::<bazuka::zk::groth16::Groth16VerifyingKey>::into(withdraw_params.vk.clone())
                != verif_keys.withdraw
            {
                panic!("Incorrect withdraw-params! Regenerate params via: zoro generate-params");
            }

            let update_params =
                load_params::<
                    circuits::UpdateCircuit<
                        { config::LOG4_UPDATE_BATCH_SIZE },
                        { config::LOG4_TREE_SIZE },
                        { config::LOG4_TOKENS_TREE_SIZE },
                    >,
                    _,
                >(opt.update_circuit_params.clone(), None::<ChaCha20Rng>);
            if Into::<bazuka::zk::groth16::Groth16VerifyingKey>::into(update_params.vk.clone())
                != verif_keys.update
            {
                panic!("Incorrect update-params! Regenerate params via: zoro generate-params");
            }

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
                        let backend = backend.clone();
                        let zoro_params = zoro_params.clone();
                        let opt = opt.clone();
                        let cancel = Arc::new(RwLock::new(false));

                        println!("Finding the validator...");
                        let client = SyncClient::new(opt.connect, &opt.network);
                        let validator_claim = client.validator_claim().await?;

                        if let Some(claim) = validator_claim.clone() {
                            println!("{} is validator!", claim.node);
                            let client = SyncClient::new(claim.node, &opt.network);

                            let works = client.get_mpn_works(opt.address.clone()).await?;

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
                                        let client = SyncClient::new(opt.connect, &opt.network);
                                        let new_claim = client.validator_claim().await?;
                                        if new_claim!= validator_claim {
                                            *cancel_cloned.write().unwrap() = true;
                                        }
                                    }
                                }
                                        std::thread::sleep(std::time::Duration::from_millis(3000));
                                    }
                                    Ok::<(), ZoroError>(())
                                });
                                if !works.works.is_empty() {
                                println!("Got {} SNARK-works to solve...", works.works.len());
                                alice_shuffle();
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
                                    works
                                        .works
                                        .into_par_iter()
                                        .map(|(id, p)| {
                                            to_zoro_work(p).prove(
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

                                let resp = client.post_mpn_solution(proofs).await?;
                                println!("{} of your proofs were accepted!", resp.accepted);

                                let _ = cancel_controller_tx.send(());
                                cancel_controller.await??;
                            }
                            else {
                                println!("No work to do!");
                            }
                        } else {
                            std::thread::sleep(std::time::Duration::from_millis(1000));
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
    }
}
