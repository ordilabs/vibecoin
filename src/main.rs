use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::Network;
use clap::{ArgAction, Parser, ValueEnum};
use std::sync::{Arc, Mutex};
// mod base58; // Removed as the file is deleted
mod p2p;
mod rpc;
mod storage;
mod util;

#[derive(Debug, PartialEq, Parser)]
struct CliOptions {
    /// Disable the RPC server
    #[arg(long = "no-rpc", action = ArgAction::SetFalse, default_value_t = true)]
    enable_rpc: bool,

    /// Address of peer to connect to. Use "0" for no connection.
    #[arg(long = "connect")]
    connect: Option<String>,

    /// Display current block height
    #[arg(long)]
    show_height: bool,

    /// Path to the headers file
    #[arg(long = "headers-file", default_value = "headers.bin")]
    headers_path: String,

    /// Address to bind the RPC server
    #[arg(long = "rpc-addr", default_value = "127.0.0.1:8080")]
    rpc_addr: String,

    /// Network to use (mainnet, testnet, regtest)
    #[arg(long, value_enum, default_value_t = BitcoinNetwork::Mainnet)]
    network: BitcoinNetwork,
}

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq)]
enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

impl From<BitcoinNetwork> for Network {
    fn from(val: BitcoinNetwork) -> Self {
        match val {
            BitcoinNetwork::Mainnet => Network::Bitcoin,
            BitcoinNetwork::Testnet => Network::Testnet,
            BitcoinNetwork::Regtest => Network::Regtest,
        }
    }
}

fn parse_args(args: &[String]) -> Result<CliOptions, String> {
    CliOptions::try_parse_from(args).map_err(|e| e.to_string())
}

fn genesis_hex(network: Network) -> String {
    let genesis = genesis_block(network);
    serialize_hex(&genesis)
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let args: Vec<String> = std::env::args().collect();
    let opts = match parse_args(&args) {
        Ok(o) => o,
        Err(msg) => {
            println!("{}", msg);
            std::process::exit(0);
        }
    };
    let enable_rpc = opts.enable_rpc;
    let mut peer_connect_addr = opts.connect.clone();

    // Handle --connect=0 to mean no connection
    if let Some(addr) = &peer_connect_addr {
        if addr == "0" {
            peer_connect_addr = None;
        }
    }

    let network: Network = opts.network.into();

    let status = Arc::new(Mutex::new(rpc::NodeStatus {
        block_height: 0,
        peers: Vec::new(),
    }));
    let _rpc_handle = if enable_rpc {
        match rpc::start(&opts.rpc_addr, Arc::clone(&status)).await {
            Ok(h) => Some(h),
            Err(e) => {
                eprintln!("Failed to start RPC server: {}", e);
                None
            }
        }
    } else {
        None
    };

    if let Some(addr) = peer_connect_addr {
        println!("Connecting to {} on {} network...", addr, network);
        match p2p::Peer::connect(&addr, network) {
            Ok(mut peer) => match peer.handshake().await {
                Ok(_) => {
                    println!("Handshake with {} successful", addr);
                    let mut s = status.lock().unwrap();
                    s.peers.push(addr.clone());
                    if opts.show_height {
                        match peer.sync_headers(&opts.headers_path, network).await {
                            Ok(h) => {
                                s.block_height = h;
                                println!("Current block height: {}", h);
                            }
                            Err(e) => eprintln!("Header sync failed: {}", e),
                        }
                    }
                }
                Err(e) => eprintln!("Handshake failed: {}", e),
            },
            Err(e) => eprintln!("Connection error: {}", e),
        }
    } else {
        let hex = genesis_hex(network);
        println!("Bitcoin genesis block ({}):\\n{}", network, hex);
        if opts.show_height {
            let h = status.lock().unwrap().block_height;
            println!("Current block height: {}", h);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_hex_matches_known_value() {
        let hex = genesis_hex(Network::Bitcoin);
        assert!(hex.starts_with("01000000"));
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
        let args = vec!["prog".into(), "--height".into()];
        let opts = parse_args(&args).unwrap();
        assert!(opts.show_height);
        assert!(opts.connect.is_none());
        assert!(opts.enable_rpc);
        assert_eq!(opts.headers_path, "headers.bin");
        assert_eq!(opts.rpc_addr, "127.0.0.1:8080");
        assert_eq!(opts.network, BitcoinNetwork::Mainnet);
    }

    #[test]
    fn parse_args_peer_and_height() {
        let args = vec![
            "prog".into(),
            "--height".into(),
            "--connect".into(),
            "127.0.0.1:8333".into(),
        ];
        let opts = parse_args(&args).unwrap();
        assert!(opts.show_height);
        assert_eq!(opts.connect, Some("127.0.0.1:8333".into()));
        assert!(opts.enable_rpc);
        assert_eq!(opts.headers_path, "headers.bin");
        assert_eq!(opts.rpc_addr, "127.0.0.1:8080");
        assert_eq!(opts.network, BitcoinNetwork::Mainnet);
    }

    #[test]
    fn parse_args_help_output() {
        let args = vec!["prog".into(), "--help".into()];
        let err = parse_args(&args).unwrap_err();
        assert!(err.contains("Usage:"));
    }

    #[test]
    fn parse_args_invalid_option() {
        let args = vec!["prog".into(), "--bogus".into()];
        assert!(parse_args(&args).is_err());
    }

    #[test]
    fn parse_args_custom_headers_file() {
        let args = vec!["prog".into(), "--headers-file".into(), "foo.bin".into()];
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.headers_path, "foo.bin");
        assert_eq!(opts.rpc_addr, "127.0.0.1:8080");
    }

    #[test]
    fn parse_args_custom_rpc_addr() {
        let args = vec!["prog".into(), "--rpc-addr".into(), "0.0.0.0:9999".into()];
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.rpc_addr, "0.0.0.0:9999");
    }

    #[test]
    fn parse_args_network_regtest() {
        let args = vec!["prog".into(), "--network".into(), "regtest".into()];
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.network, BitcoinNetwork::Regtest);
    }

    #[test]
    fn parse_args_connect_0_means_no_connection() {
        let args_with_connect_0 = vec!["prog".into(), "--connect".into(), "0".into()];
        let opts_connect_0 = parse_args(&args_with_connect_0).unwrap();

        // We need to check the logic within main, parse_args just gives us the Some("0")
        // This test verifies that CliOptions parses it correctly.
        assert_eq!(opts_connect_0.connect, Some("0".to_string()));

        // To test the actual behavior of not connecting, we'd need a more involved test
        // or check the `peer_connect_addr` variable after the logic in `main`.
        // For now, this test just ensures the arg is parsed.
    }
}
