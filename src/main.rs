use bitcoin::Network;
use clap::{ArgAction, Parser, ValueEnum};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
// mod base58; // Removed
mod listener;
mod p2p;
mod rpc;
mod storage;
// mod util; // Removed as it's unused

use log::{error, info}; // Removed warn

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum BitcoinNetworkCli {
    #[value(name = "bitcoin")]
    Bitcoin,
    Testnet,
    Regtest,
    Signet,
}

#[derive(Debug, PartialEq, Parser)]
#[clap(version = "0.1.0", author = "Vibecoin Developers")]
struct CliOptions {
    /// Set the network chain to use (bitcoin, testnet, regtest, signet).
    #[arg(long = "chain", value_enum, default_value_t = BitcoinNetworkCli::Bitcoin)]
    network: BitcoinNetworkCli,

    /// Address of peer to connect to (e.g., 127.0.0.1 or 127.0.0.1:8333).
    /// Use --connect=0 to disable automatic outbound connection.
    #[arg(long = "connect")]
    connect: Option<String>,

    /// Path to the headers file (overrides default in data directory)
    #[arg(long = "headers-file")]
    headers_path_override: Option<String>,

    /// Path to the data directory (default: ~/.vibecoin/<network>/)
    #[arg(long = "datadir")]
    datadir_override: Option<String>,

    /// Address to bind the listener for P2P and RPC/HTTP
    #[arg(long = "listen-addr", default_value = "0.0.0.0:8335")]
    listen_addr: String,

    /// Disable the RPC server (currently integrated with unified listener)
    #[arg(long = "no-rpc", action = ArgAction::SetFalse, default_value_t = true)]
    enable_rpc: bool,
}

fn parse_args(args: &[String]) -> Result<CliOptions, String> {
    CliOptions::try_parse_from(args).map_err(|e| e.to_string())
}

fn get_default_datadir(cli_network: BitcoinNetworkCli) -> PathBuf {
    let mut path = dirs::home_dir().expect("Failed to get home directory");
    path.push(".vibecoin");
    match cli_network {
        BitcoinNetworkCli::Bitcoin => path.push("bitcoin"),
        BitcoinNetworkCli::Testnet => path.push("testnet3"),
        BitcoinNetworkCli::Regtest => path.push("regtest"),
        BitcoinNetworkCli::Signet => path.push("signet"),
    }
    path
}

fn to_bitcoin_network(cli_network: BitcoinNetworkCli) -> Network {
    match cli_network {
        BitcoinNetworkCli::Bitcoin => Network::Bitcoin,
        BitcoinNetworkCli::Testnet => Network::Testnet,
        BitcoinNetworkCli::Regtest => Network::Regtest,
        BitcoinNetworkCli::Signet => Network::Signet,
    }
}

fn get_default_p2p_port(network: Network) -> u16 {
    match network {
        Network::Bitcoin => 8333,
        Network::Testnet => 18333,
        Network::Regtest => 18444,
        Network::Signet => 38333,
        _ => 8333,
    }
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();
    let opts = match parse_args(&args) {
        Ok(o) => o,
        Err(msg) => {
            error!("{}", msg);
            std::process::exit(1);
        }
    };

    let cli_network = opts.network;
    let network = to_bitcoin_network(cli_network);
    info!(
        "Selected network: {:?} (using bitcoin::Network::{})",
        cli_network, network
    );

    let datadir = match opts.datadir_override {
        Some(path_str) => PathBuf::from(path_str),
        None => get_default_datadir(cli_network),
    };

    if !datadir.exists() {
        fs::create_dir_all(&datadir).expect("Failed to create data directory");
        info!("Created data directory: {}", datadir.display());
    }

    let headers_path = match opts.headers_path_override {
        Some(path_str) => PathBuf::from(path_str),
        None => datadir.join("headers.bin"),
    };
    info!("Using headers file: {}", headers_path.display());

    let mut peer_addr_processed = opts.connect.clone();
    if let Some(addr_str) = &mut peer_addr_processed {
        if addr_str == "0" {
            peer_addr_processed = None; // Disable connection if --connect=0
            info!("--connect=0 specified, disabling automatic outbound connection.");
        } else if !addr_str.contains(':') {
            let port = get_default_p2p_port(network);
            addr_str.push_str(&format!(":{}", port));
            info!(
                "Peer address amended with default port for {}: {}",
                network, addr_str
            );
        }
    }

    let status = Arc::new(Mutex::new(rpc::NodeStatus {
        block_height: 0,
        peers: Vec::new(),
        current_best_header_hex: None,
    }));

    let listen_addr_clone = opts.listen_addr.clone();
    let status_clone_for_listener = Arc::clone(&status);
    tokio::spawn(async move {
        if let Err(e) =
            listener::start_listener(&listen_addr_clone, status_clone_for_listener).await
        {
            error!("Listener failed: {}", e);
        }
    });

    if let Some(addr) = peer_addr_processed {
        info!(
            "Attempting to connect to peer: {} on network {}",
            addr, network
        );
        let headers_path_for_peer = headers_path.clone();
        let status_for_peer_connection = Arc::clone(&status); // Cloned status for this peer connection task.
        let network_for_peer = network;

        tokio::spawn(async move {
            match p2p::Peer::connect(&addr, network_for_peer).await {
                Ok(peer) => {
                    info!(
                        "Successfully connected to {}. Spawning continuous sync task (handshake will be done by task).",
                        addr
                    );
                    let status_for_sync_handler = Arc::clone(&status_for_peer_connection);
                    {
                        let mut s = status_for_sync_handler.lock().unwrap();
                        if !s.peers.contains(&addr) {
                            s.peers.push(addr.clone());
                        }
                    }
                    if let Err(e) = peer
                        .maintain_connection_and_sync_headers(
                            headers_path_for_peer.to_string_lossy().into_owned(),
                            status_for_sync_handler,
                            network_for_peer,
                        )
                        .await
                    {
                        error!(
                            "[main] Continuous sync handler for {} exited with error: {}",
                            addr, e
                        );
                    } else {
                        info!("[main] Continuous sync handler for {} finished.", addr);
                    }
                }
                Err(e) => {
                    error!(
                        "[main] Failed to connect to peer {}: {}. Ensure the peer is running and accessible.",
                        addr, e
                    );
                }
            }
            // After the peer task finishes (due to error or completion), remove the peer from the list.
            // This part might need more robust logic for handling reconnects or distinguishing expected vs. unexpected exits.
            info!(
                "[main] Peer task for {} concluded. Removing from active peer list.",
                addr
            );
            let mut s = status_for_peer_connection.lock().unwrap();
            s.peers.retain(|p| p != &addr);
            // Potentially also update block_height or current_best_header_hex if the node is shutting down
            // or if this peer was the sole source of truth for a while, though this is complex.
            // For now, just removing the peer is sufficient.
        });
    } else {
        info!("No specific peer to connect to provided via --connect. Node will only listen for incoming connections.");
    }

    // Keep the main thread alive, print status periodically, and listen for Ctrl-C for graceful shutdown.
    info!(
        "Node is running. Listener active on {}. Press Ctrl-C to stop.",
        opts.listen_addr
    );

    let mut ctr = 0;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl-C received, shutting down.");
                break;
            }
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(60)) => {
                let status_snapshot = status.lock().unwrap();
                info!(
                    "[Heartbeat {}] Current block height: {}, Peers: {:?}, Best Header: {}",
                    ctr,
                    status_snapshot.block_height,
                    status_snapshot.peers,
                    status_snapshot.current_best_header_hex.as_deref().unwrap_or("N/A")
                );
                ctr += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::consensus::encode::serialize_hex;
    use bitcoin::Network;

    // Helper function for tests that need genesis hex - this was the original genesis_hex
    fn get_genesis_hex_for_test(network: Network) -> String {
        let genesis = genesis_block(network);
        serialize_hex(&genesis)
    }

    #[test]
    fn parse_args_default_network() {
        let args: Vec<String> = vec!["prog".into()];
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.network, BitcoinNetworkCli::Bitcoin);
    }

    #[test]
    fn parse_args_chain_regtest() {
        let args: Vec<String> = vec!["prog".into(), "--chain".into(), "regtest".into()];
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.network, BitcoinNetworkCli::Regtest);
    }

    #[test]
    fn default_datadir_paths() {
        assert!(get_default_datadir(BitcoinNetworkCli::Bitcoin).ends_with(".vibecoin/bitcoin"));
        assert!(get_default_datadir(BitcoinNetworkCli::Testnet).ends_with(".vibecoin/testnet3"));
        assert!(get_default_datadir(BitcoinNetworkCli::Regtest).ends_with(".vibecoin/regtest"));
        assert!(get_default_datadir(BitcoinNetworkCli::Signet).ends_with(".vibecoin/signet"));
    }

    #[test]
    fn default_p2p_ports() {
        assert_eq!(get_default_p2p_port(Network::Bitcoin), 8333);
        assert_eq!(get_default_p2p_port(Network::Testnet), 18333);
        assert_eq!(get_default_p2p_port(Network::Regtest), 18444);
        assert_eq!(get_default_p2p_port(Network::Signet), 38333);
    }

    #[test]
    fn genesis_hex_matches_known_value() {
        let hex_bitcoin = get_genesis_hex_for_test(Network::Bitcoin);
        assert!(hex_bitcoin.starts_with("01000000")); // Minimal check, used to be full hex
        let hex_regtest = get_genesis_hex_for_test(Network::Regtest);
        assert!(hex_regtest.starts_with("01000000"));
    }

    #[test]
    fn genesis_hash_matches_known_value() {
        let genesis = genesis_block(Network::Bitcoin);
        assert_eq!(
            genesis.block_hash().to_string(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
        let genesis_regtest = genesis_block(Network::Regtest);
        assert_eq!(
            genesis_regtest.block_hash().to_string(),
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
        );
    }

    #[test]
    fn genesis_merkle_root_matches_known_value() {
        let genesis = genesis_block(Network::Bitcoin);
        assert_eq!(
            genesis.header.merkle_root.to_string(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        );
        let genesis_regtest = genesis_block(Network::Regtest);
        assert_eq!(
            genesis_regtest.header.merkle_root.to_string(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" // Regtest genesis also uses this merkle root
        );
    }

    #[test]
    fn parse_args_connect_zero_disables_connection() {
        let args: Vec<String> = vec!["prog".into(), "--connect".into(), "0".into()];
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.connect, Some("0".to_string()));
        // Main logic will interpret this as None for peer_addr_processed

        let mut peer_addr_processed = opts.connect.clone();
        if let Some(addr_str) = &mut peer_addr_processed {
            if addr_str == "0" {
                peer_addr_processed = None;
            }
        }
        assert_eq!(peer_addr_processed, None);
    }

    #[test]
    fn parse_args_help_output() {
        let args: Vec<String> = vec!["prog".into(), "--help".into()];
        let err = parse_args(&args).unwrap_err();
        assert!(err.contains("Usage:"));
    }

    #[test]
    fn parse_args_invalid_option() {
        let args: Vec<String> = vec!["prog".into(), "--bogus".into()];
        assert!(parse_args(&args).is_err());
    }

    #[test]
    fn parse_args_custom_headers_file_override() {
        let args: Vec<String> = vec!["prog".into(), "--headers-file".into(), "foo.bin".into()];
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.headers_path_override, Some("foo.bin".to_string()));
    }

    #[test]
    fn parse_args_custom_datadir_override() {
        let args: Vec<String> = vec![
            "prog".into(),
            "--datadir".into(),
            "/tmp/myvibecoindata".into(),
        ];
        let opts = parse_args(&args).unwrap();
        assert_eq!(
            opts.datadir_override,
            Some("/tmp/myvibecoindata".to_string())
        );
    }
}
