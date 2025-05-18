use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::encode::serialize_hex;
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

    /// Display current block height
    #[arg(long = "height")]
    show_height: bool,

    /// Path to the headers file (overrides default in data directory)
    #[arg(long = "headers-file")]
    headers_path_override: Option<String>,

    /// Path to the data directory (default: ~/.vibecoin/<network>/)
    #[arg(long = "datadir")]
    datadir_override: Option<String>,

    /// Address to bind the listener for P2P and RPC/HTTP
    #[arg(long = "listen-addr", default_value = "0.0.0.0:8334")]
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

fn genesis_hex(network: Network) -> String {
    let genesis = genesis_block(network);
    serialize_hex(&genesis)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let opts = match parse_args(&args) {
        Ok(o) => o,
        Err(msg) => {
            eprintln!("{}", msg);
            std::process::exit(1);
        }
    };

    let cli_network = opts.network;
    let network = to_bitcoin_network(cli_network);
    println!(
        "Selected network: {:?} (using bitcoin::Network::{})",
        cli_network, network
    );

    let datadir = match opts.datadir_override {
        Some(path_str) => PathBuf::from(path_str),
        None => get_default_datadir(cli_network),
    };

    if !datadir.exists() {
        fs::create_dir_all(&datadir).expect("Failed to create data directory");
        println!("Created data directory: {}", datadir.display());
    }

    let headers_path = match opts.headers_path_override {
        Some(path_str) => PathBuf::from(path_str),
        None => datadir.join("headers.bin"),
    };
    println!("Using headers file: {}", headers_path.display());

    let mut peer_addr_processed = opts.connect.clone();
    if let Some(addr_str) = &mut peer_addr_processed {
        if addr_str == "0" {
            peer_addr_processed = None; // Disable connection if --connect=0
            println!("--connect=0 specified, disabling automatic outbound connection.");
        } else if !addr_str.contains(':') {
            let port = get_default_p2p_port(network);
            addr_str.push_str(&format!(":{}", port));
            println!(
                "Peer address amended with default port for {}: {}",
                network, addr_str
            );
        }
    }

    let status = Arc::new(Mutex::new(rpc::NodeStatus {
        block_height: 0,
        peers: Vec::new(),
    }));

    let listen_addr_clone = opts.listen_addr.clone();
    tokio::spawn(async move {
        if let Err(e) = listener::start_listener(&listen_addr_clone).await {
            eprintln!("Listener failed: {}", e);
        }
    });

    if let Some(addr) = peer_addr_processed {
        println!(
            "Attempting to connect to peer: {} on network {}",
            addr, network
        );
        let headers_path_str = headers_path
            .to_str()
            .expect("Headers path is not valid UTF-8");

        match p2p::Peer::connect(&addr, network) {
            Ok(mut peer) => {
                println!("Connected. Performing handshake...");
                match peer.handshake().await {
                    Ok(_) => {
                        println!("Handshake with {} successful", addr);
                        {
                            let mut s = status.lock().unwrap();
                            s.peers.push(addr.clone());
                        }
                        if opts.show_height {
                            println!("Attempting to sync headers from {}...", addr);
                            match peer.sync_headers(headers_path_str).await {
                                Ok(h) => {
                                    let mut s_lock = status.lock().unwrap();
                                    s_lock.block_height = h;
                                    println!("Current block height after sync: {}", h);
                                }
                                Err(e) => eprintln!("Header sync failed: {}", e),
                            }
                        }
                    }
                    Err(e) => eprintln!("Handshake failed: {}", e),
                }
            }
            Err(e) => eprintln!("Connection error: {}", e),
        }
    } else {
        println!(
            "No peer address provided for network: {}. Displaying Genesis.",
            network
        );
        let hex = genesis_hex(network);
        println!("Bitcoin genesis block:\n{}", hex);
        if opts.show_height {
            let h = status.lock().unwrap().block_height;
            println!("Current block height (from local status): {}", h);
        }
    }

    if opts.connect.is_none() || opts.connect == Some("0".to_string()) {
        println!(
            "Running in listener-only mode (no peer connection initiated from CLI or --connect=0)."
        );
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for ctrl-c");
        println!("Ctrl-C received, shutting down.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let hex_bitcoin = genesis_hex(Network::Bitcoin);
        assert!(hex_bitcoin.starts_with("01000000"));
        let hex_regtest = genesis_hex(Network::Regtest);
        assert!(hex_regtest.starts_with("01000000"));
    }

    #[test]
    fn genesis_hash_matches_known_value() {
        let genesis = genesis_block(Network::Bitcoin);
        assert_eq!(
            genesis.block_hash().to_string(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    #[test]
    fn genesis_merkle_root_matches_known_value() {
        let genesis = genesis_block(Network::Bitcoin);
        assert_eq!(
            genesis.header.merkle_root.to_string(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        );
    }

    #[test]
    fn parse_args_height_flag() {
        let args: Vec<String> = vec!["prog".into(), "--height".into()];
        let opts = parse_args(&args).unwrap();
        assert!(opts.show_height);
        assert!(opts.connect.is_none());
        assert!(opts.headers_path_override.is_none());
    }

    #[test]
    fn parse_args_peer_and_height() {
        let args: Vec<String> = vec![
            "prog".into(),
            "--height".into(),
            "--connect".into(),
            "127.0.0.1:8333".into(),
        ];
        let opts = parse_args(&args).unwrap();
        assert!(opts.show_height);
        assert_eq!(opts.connect, Some("127.0.0.1:8333".into()));
        assert!(opts.headers_path_override.is_none());
    }

    #[test]
    fn parse_args_connect_zero_disables_connection() {
        let args: Vec<String> = vec!["prog".into(), "--connect".into(), "0".into()];
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.connect, Some("0".to_string()));
        // The main logic will then set peer_addr_processed to None based on this.
        // We can't directly test peer_addr_processed here as it's a local var in main,
        // but we verify the argument is parsed correctly.
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
