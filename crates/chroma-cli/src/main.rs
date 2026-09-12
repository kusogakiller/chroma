use clap::{Parser, Subcommand};
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use zeroize::Zeroize;

#[derive(Parser)]
#[command(name = "chroma", version = env!("CARGO_PKG_VERSION"), about = "Chroma blockchain node and wallet")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Node {
        #[arg(short, long, default_value = "127.0.0.1:8333")]
        listen: SocketAddr,
        #[arg(short, long)]
        connect: Vec<SocketAddr>,
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long, conflicts_with = "testnet")]
        regtest: bool,
        #[arg(long, conflicts_with = "regtest")]
        testnet: bool,
        #[arg(long)]
        miner_address: Option<String>,
        #[arg(long)]
        log_level: Option<String>,
        #[arg(long)]
        rpc_listen: Option<SocketAddr>,
        #[arg(long, env = "CHROMA_RPC_API_KEY", hide_env_values = true)]
        rpc_api_key: Option<String>,
        /// DANGEROUS test/debug only: speak plaintext to peers instead of
        /// Noise XX. Refused on mainnet. Never enable in production.
        #[arg(long)]
        insecure_plaintext_peers: bool,
    },
    Wallet {
        #[command(subcommand)]
        command: WalletCommands,
    },
    Block {
        #[command(subcommand)]
        command: BlockCommands,
    },
    Mnemonic {
        #[arg(short, long, default_value = "default")]
        name: String,
    },
}

#[derive(Subcommand)]
enum WalletCommands {
    Create {
        #[arg(short, long)]
        name: String,
    },
    Import {
        #[arg(short, long)]
        name: String,
        #[arg(long, conflicts_with = "key_stdin")]
        keystore: Option<PathBuf>,
        #[arg(long)]
        key_stdin: bool,
    },
    Export {
        #[arg(short, long)]
        name: String,
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    List {
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    Address {
        #[arg(short, long)]
        name: String,
    },
    Send {
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        to: String,
        #[arg(short, long)]
        amount: String,
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        rpc_url: Option<String>,
        #[arg(long, conflicts_with = "testnet")]
        regtest: bool,
        #[arg(long, conflicts_with = "regtest")]
        testnet: bool,
    },
    Balance {
        #[arg(short, long)]
        address: String,
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum BlockCommands {
    Height {
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
}

fn default_data_dir(network: &str) -> PathBuf {
    match network {
        "regtest" => PathBuf::from("chroma_regtest_data"),
        "testnet" => PathBuf::from("chroma_testnet_data"),
        _ => PathBuf::from("chroma_data"),
    }
}

fn address_to_bech32(addr: &chroma_core::types::Address) -> String {
    chroma_crypto::address::AddressString::from_hash160(&addr.as_hash160(), None)
        .map(|a| a.0)
        .unwrap_or_else(|| format!("{}", addr))
}

fn bech32_to_address(s: &str) -> Option<chroma_core::types::Address> {
    if s.starts_with("chr1") {
        let addr_str = chroma_crypto::address::AddressString(s.to_string());
        let h = addr_str.to_hash160()?;
        Some(chroma_core::types::Address::from_hash160(h))
    } else {
        let hex_str = s.trim_start_matches("0x");
        let bytes = hex::decode(hex_str).ok()?;
        if bytes.len() != 20 {
            return None;
        }
        let mut h = [0u8; 20];
        h.copy_from_slice(&bytes);
        Some(chroma_core::types::Address::from_hash160(
            chroma_core::hash::Hash160(h),
        ))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Node {
            listen,
            connect,
            data_dir,
            regtest,
            testnet,
            miner_address,
            log_level,
            rpc_listen,
            rpc_api_key,
            insecure_plaintext_peers,
        } => {
            let env_filter =
                tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                    let level = log_level.as_deref().unwrap_or("info");
                    tracing_subscriber::EnvFilter::new(level)
                });
            tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .with_target(false)
                .init();

            let network_kind = if regtest {
                chroma_consensus::NetworkKind::Regtest
            } else if testnet {
                chroma_consensus::NetworkKind::Testnet
            } else {
                chroma_consensus::NetworkKind::Mainnet
            };
            let network = if regtest {
                chroma_p2p::NetworkConfig::regtest()
            } else if testnet {
                chroma_p2p::NetworkConfig::testnet()
            } else {
                chroma_p2p::NetworkConfig::mainnet()
            };

            let data_dir = data_dir.unwrap_or_else(|| default_data_dir(&network.network_name));
            let network_name = network.network_name.clone();

            tracing::info!(
                "Starting Chroma node on {} [{}]",
                listen,
                network.network_name
            );
            tracing::info!("Data directory: {}", data_dir.display());
            if !connect.is_empty() {
                tracing::info!("Connecting to: {:?}", connect);
            }

            let genesis = chroma_consensus::build_genesis_for_network(&network_kind);
            let genesis_hash = genesis.hash();
            tracing::info!("Genesis hash: {}", genesis_hash.to_hex());

            // Mainnet P2P is Noise-only with no downgrade path.
            if insecure_plaintext_peers && !regtest && !testnet {
                eprintln!(
                    "Error: --insecure-plaintext-peers is refused on mainnet. \
                     Mainnet peer traffic is always Noise-encrypted."
                );
                std::process::exit(1);
            }
            if insecure_plaintext_peers {
                tracing::warn!(
                    "INSECURE: plaintext peer transport enabled. \
                     For test/debug inspection only. Never use in production."
                );
            }

            let mut config = chroma_p2p::NodeConfig::new(listen, genesis_hash)
                .with_data_dir(data_dir)
                .with_connect_addrs(connect)
                .with_network(network);
            if insecure_plaintext_peers {
                config = config.with_plaintext_peers_allowed();
            }

            if let Some(addr_str) = miner_address {
                let addr_str = addr_str.trim();
                match addr_str.parse::<chroma_core::types::Address>() {
                    Ok(addr) => {
                        tracing::info!("Miner address: {}", addr);
                        config = config.with_miner_address(addr);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Invalid miner address '{}': {}, using default",
                            addr_str,
                            e
                        );
                    }
                }
            }

            let mut node = chroma_p2p::Node::new(config);
            let mut event_rx = node.event_rx().expect("event_rx already taken");

            if let Some(rpc_addr) = rpc_listen {
                let rpc_state = chroma_rpc::RpcState {
                    storage: node.storage_arc(),
                    chain_state: node.chain_state().clone(),
                    mempool: node.mempool().clone(),
                    peer_manager: node.peer_manager().clone(),
                    node_id: format!("{}:{}", listen.ip(), listen.port()),
                    listen_addr: rpc_addr,
                    network_name: network_name.clone(),
                    start_time: std::time::Instant::now(),
                    api_key: rpc_api_key.clone(),
                };
                let rpc_shutdown_rx = node.shutdown_tx_subscriber();
                tokio::spawn(async move {
                    if let Err(e) =
                        chroma_rpc::start_rpc_server(rpc_addr, rpc_state, rpc_shutdown_rx).await
                    {
                        tracing::error!("RPC server error: {}", e);
                    }
                });
                tracing::info!("RPC server started on {}", rpc_addr);
            }

            tokio::spawn(async move {
                while let Some(event) = event_rx.recv().await {
                    match event {
                        chroma_p2p::NodeEvent::PeerConnected(addr) => {
                            tracing::info!("[PEER] Connected: {}", addr);
                        }
                        chroma_p2p::NodeEvent::PeerDisconnected(addr) => {
                            tracing::info!("[PEER] Disconnected: {}", addr);
                        }
                        chroma_p2p::NodeEvent::BlockReceived(hash, height) => {
                            tracing::info!(
                                "[BLOCK] Received: height={} hash={}",
                                height,
                                &hash.to_hex()[..16]
                            );
                        }
                        chroma_p2p::NodeEvent::BlockMined(hash, height) => {
                            tracing::info!(
                                "[BLOCK] Mined: height={} hash={}",
                                height,
                                &hash.to_hex()[..16]
                            );
                        }
                        chroma_p2p::NodeEvent::Reorg {
                            old_height,
                            old_hash,
                            new_height,
                            new_hash,
                            depth,
                        } => {
                            tracing::warn!(
                                "[CHAIN] Reorg: old_tip={} old_hash={} new_tip={} new_hash={} depth={}",
                                old_height,
                                &old_hash.to_hex()[..16],
                                new_height,
                                &new_hash.to_hex()[..16],
                                depth
                            );
                        }
                        chroma_p2p::NodeEvent::TxReceived(hash) => {
                            tracing::info!("[TX] Received: {}", &hash.to_hex()[..16]);
                        }
                        chroma_p2p::NodeEvent::SyncComplete => {
                            tracing::info!("[SYNC] Complete");
                        }
                        chroma_p2p::NodeEvent::SyncTimeout(addr) => {
                            tracing::warn!("[SYNC] Timeout from peer: {}", addr);
                        }
                        chroma_p2p::NodeEvent::Error(e) => {
                            tracing::error!("[ERROR] {}", e);
                        }
                    }
                }
            });
            node.run().await?;
            tokio::signal::ctrl_c().await?;
            node.shutdown();
            tracing::info!("Shutting down...");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        Commands::Wallet { command } => match command {
            WalletCommands::Create { name } => {
                let password = rpassword::prompt_password("Set wallet password: ").unwrap();
                let confirm = rpassword::prompt_password("Confirm password: ").unwrap();
                if password != confirm {
                    eprintln!("Error: passwords do not match");
                    std::process::exit(1);
                }
                let wallet = chroma_wallet::Wallet::generate(&name);
                let dir = std::path::Path::new("wallets");
                std::fs::create_dir_all(dir).ok();
                let path = dir.join(format!("{}.json", name));
                wallet.save(&path, &password).unwrap();
                println!("Wallet '{}' created and encrypted.", name);
                println!("Address: {}", address_to_bech32(&wallet.address()));
                println!("Saved to: {}", path.display());
            }
            WalletCommands::Import {
                name,
                keystore,
                key_stdin,
            } => {
                if keystore.is_none() && !key_stdin {
                    eprintln!("Error: provide --keystore or --key-stdin");
                    eprintln!("  --keystore <path>     Load from encrypted keystore file");
                    eprintln!("  --key-stdin           Read hex key from stdin (no shell history)");
                    std::process::exit(1);
                }
                let password = rpassword::prompt_password("Wallet password: ").unwrap();
                let wallet = if let Some(keystore_path) = keystore {
                    chroma_wallet::Wallet::load(&keystore_path, &password, &name).unwrap_or_else(
                        |e| {
                            eprintln!("Error loading keystore: {}", e);
                            std::process::exit(1);
                        },
                    )
                } else if key_stdin {
                    eprint!("Enter hex-encoded private key (32 bytes): ");
                    std::io::stderr().flush().unwrap();
                    let mut key_input = String::new();
                    std::io::stdin()
                        .read_line(&mut key_input)
                        .unwrap_or_else(|e| {
                            eprintln!("Error reading key: {}", e);
                            std::process::exit(1);
                        });
                    let key_hex = key_input.trim().to_string();
                    key_input.zeroize();
                    let key_bytes = hex::decode(&key_hex).unwrap_or_else(|e| {
                        eprintln!("Error: invalid hex key: {}", e);
                        std::process::exit(1);
                    });
                    if key_bytes.len() != 32 {
                        eprintln!("Error: key must be 32 bytes");
                        std::process::exit(1);
                    }
                    let mut buf = [0u8; 32];
                    buf.copy_from_slice(&key_bytes);
                    drop(key_hex);
                    drop(key_bytes);
                    let sk =
                        chroma_crypto::schnorr::SecretKey32::from_bytes(buf).unwrap_or_else(|e| {
                            eprintln!("Error: invalid key: {}", e);
                            std::process::exit(1);
                        });
                    buf.zeroize();
                    chroma_wallet::Wallet::from_secret_key(&name, sk).unwrap_or_else(|e| {
                        eprintln!("Error: {}", e);
                        std::process::exit(1)
                    })
                } else {
                    eprintln!("Error: provide --keystore or --key-stdin");
                    eprintln!("  --keystore <path>     Load from encrypted keystore file");
                    eprintln!("  --key-stdin           Read hex key from stdin (no shell history)");
                    std::process::exit(1);
                };
                let dir = std::path::Path::new("wallets");
                std::fs::create_dir_all(dir).ok();
                let path = dir.join(format!("{}.json", name));
                wallet.save(&path, &password).unwrap();
                println!("Wallet '{}' imported and encrypted.", name);
                println!("Address: {}", address_to_bech32(&wallet.address()));
                println!("Saved to: {}", path.display());
            }
            WalletCommands::Export { name, data_dir } => {
                let password = rpassword::prompt_password("Wallet password: ").unwrap();
                let dir = data_dir.unwrap_or_else(|| std::path::PathBuf::from("wallets"));
                let path = dir.join(format!("{}.json", name));
                let wallet =
                    chroma_wallet::Wallet::load(&path, &password, &name).unwrap_or_else(|e| {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    });
                println!("Wallet: {}", name);
                println!("Address: {}", address_to_bech32(&wallet.address()));
                println!("WARNING: The secret key will be displayed. Do not share it.");
                let confirm =
                    rpassword::prompt_password("Type 'yes' to reveal secret key: ").unwrap();
                if confirm == "yes" {
                    let key_hex = hex::encode(wallet.secret_bytes());
                    println!("Secret key: {}", key_hex);
                } else {
                    println!("Aborted.");
                }
            }
            WalletCommands::List { data_dir } => {
                let dir = data_dir.unwrap_or_else(|| std::path::PathBuf::from("wallets"));
                if !dir.exists() {
                    println!(
                        "No wallets found (directory {} does not exist)",
                        dir.display()
                    );
                    return Ok(());
                }
                let mut found = false;
                for entry in std::fs::read_dir(&dir).unwrap() {
                    let entry = entry.unwrap();
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("json") {
                        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                            println!("  {}", stem);
                            found = true;
                        }
                    }
                }
                if !found {
                    println!("No wallets found in {}", dir.display());
                }
            }
            WalletCommands::Address { name } => {
                let dir = std::path::PathBuf::from("wallets");
                let path = dir.join(format!("{}.json", name));
                if !path.exists() {
                    eprintln!("Wallet '{}' not found at {}", name, path.display());
                    std::process::exit(1);
                }
                let password = rpassword::prompt_password("Wallet password: ").unwrap();
                let wallet =
                    chroma_wallet::Wallet::load(&path, &password, &name).unwrap_or_else(|e| {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    });
                println!("Wallet '{}':", name);
                println!("  Address: {}", address_to_bech32(&wallet.address()));
            }
            WalletCommands::Send {
                name,
                to,
                amount,
                data_dir,
                rpc_url,
                regtest,
                testnet,
            } => {
                let recipient = match bech32_to_address(&to) {
                    Some(a) => a,
                    None => {
                        eprintln!("Invalid recipient address: expected chr1... or 0x-prefixed hex");
                        std::process::exit(1);
                    }
                };
                let amount_chr = amount.trim().parse::<f64>().unwrap_or_else(|e| {
                    eprintln!("Invalid amount '{}': {}", amount, e);
                    std::process::exit(1);
                });
                let amount_units = (amount_chr * 1_000_000.0) as u64;
                if amount_units == 0 {
                    eprintln!("Error: amount must be greater than zero");
                    std::process::exit(1);
                }
                let dir = data_dir.unwrap_or_else(|| std::path::PathBuf::from("wallets"));
                let path = dir.join(format!("{}.json", name));
                if !path.exists() {
                    eprintln!("Wallet '{}' not found at {}", name, path.display());
                    std::process::exit(1);
                }

                let password = rpassword::prompt_password("Wallet password: ").unwrap();
                let wallet =
                    chroma_wallet::Wallet::load(&path, &password, &name).unwrap_or_else(|e| {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    });
                drop(password);

                let network_magic = if regtest {
                    chroma_core::constants::REGTEST_MAGIC
                } else if testnet {
                    chroma_core::constants::TESTNET_MAGIC
                } else {
                    chroma_core::constants::MAINNET_MAGIC
                };
                let wallet = wallet.with_network_magic(network_magic);

                let rpc_url = rpc_url.unwrap_or_else(|| "http://127.0.0.1:8334".to_string());

                let result = wallet
                    .send(
                        &rpc_url,
                        recipient,
                        chroma_core::types::Amount(amount_units),
                    )
                    .await
                    .unwrap_or_else(|e| {
                        eprintln!("Transaction failed: {}", e);
                        std::process::exit(1);
                    });
                println!("Transaction submitted successfully.");
                println!("  TxID: {}", result.tx_hash);
                println!("  From: {}", address_to_bech32(&result.from));
                println!("  To:   {}", address_to_bech32(&result.to));
                println!("  Amount: {} CHR", amount_chr);
                println!("  Nonce: {}", result.nonce.0);
            }
            WalletCommands::Balance { address, data_dir } => {
                let addr = match bech32_to_address(&address) {
                    Some(a) => a,
                    None => {
                        eprintln!("Invalid address: expected bech32m (chr1...) or 0x-prefixed hex");
                        std::process::exit(1);
                    }
                };
                let data_dir = data_dir.unwrap_or_else(|| default_data_dir("mainnet"));
                match chroma_storage::Storage::open(&data_dir) {
                    Ok(storage) => match storage.get_account(&addr) {
                        Ok(Some(account)) => {
                            let chr = account.balance as f64 / 1_000_000.0;
                            println!("Balance: {} CHR ({} units)", chr, account.balance);
                            println!("Nonce: {}", account.nonce);
                        }
                        Ok(None) => {
                            println!("Balance: 0 CHR (account not found)");
                        }
                        Err(e) => {
                            eprintln!("Error reading account: {}", e);
                            std::process::exit(1);
                        }
                    },
                    Err(e) => {
                        eprintln!("Failed to open database at {}: {}", data_dir.display(), e);
                        std::process::exit(1);
                    }
                }
            }
        },
        Commands::Block { command } => match command {
            BlockCommands::Height { data_dir } => {
                let data_dir = data_dir.unwrap_or_else(|| default_data_dir("mainnet"));
                match chroma_storage::Storage::open(&data_dir) {
                    Ok(storage) => match storage.get_tip() {
                        Ok(Some(tip)) => {
                            println!("Block height: {}", tip.height);
                            println!("Chain tip: {}", tip.hash.to_hex());
                            let supply_chr = tip.supply as f64 / 1_000_000.0;
                            println!("Supply: {} CHR ({} units)", supply_chr, tip.supply);
                        }
                        Ok(None) => {
                            println!("No chain found. Start the node to initialize.");
                        }
                        Err(e) => {
                            eprintln!("Error reading chain tip: {}", e);
                            std::process::exit(1);
                        }
                    },
                    Err(e) => {
                        eprintln!("Failed to open database at {}: {}", data_dir.display(), e);
                        std::process::exit(1);
                    }
                }
            }
        },
        Commands::Mnemonic { name } => {
            let phrase = chroma_wallet::generate_seed_phrase();
            let wallet = chroma_wallet::wallet_from_seed_phrase(&name, &phrase)?;
            println!("Generated mnemonic for '{}':", name);
            println!("  {}", phrase.join(" "));
            println!("Address: {}", address_to_bech32(&wallet.address()));
        }
    }

    Ok(())
}
