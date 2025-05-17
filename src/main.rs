use bitcoin::blockdata::constants::genesis_block;
use bitcoin::network::constants::Network;
use bitcoin::consensus::encode::serialize_hex;
use std::sync::{Arc, Mutex};
use std::thread;
mod utils;

mod base58;
mod util;
mod p2p;
mod rpc;
mod storage;

#[derive(Default, Debug, PartialEq)]
struct CliOptions {
    enable_rpc: bool,
    peer_addr: Option<String>,
    show_height: bool,
}

fn parse_args(args: &[String]) -> CliOptions {
    let mut opts = CliOptions {
        enable_rpc: true,
        peer_addr: None,
        show_height: false,
    };
    for arg in args.iter().skip(1) {
        if arg == "--no-rpc" {
            opts.enable_rpc = false;
        } else if arg == "--height" {
            opts.show_height = true;
        } else {
            opts.peer_addr = Some(arg.clone());
        }
    }
    opts
}

fn genesis_hex() -> String {
    let genesis = genesis_block(Network::Bitcoin);
    serialize_hex(&genesis)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let opts = parse_args(&args);
    let enable_rpc = opts.enable_rpc;
    let peer_addr = opts.peer_addr.clone();

    let status = Arc::new(Mutex::new(rpc::NodeStatus { block_height: 0, peers: Vec::new() }));
    let _rpc_handle = if enable_rpc {
        match rpc::start("127.0.0.1:8080", Arc::clone(&status)) {
            Ok(h) => Some(h),
            Err(e) => {
                eprintln!("Failed to start RPC server: {}", e);
                None
            }
        }
    } else { None };

    if let Some(addr) = peer_addr {
        println!("Connecting to {}...", addr);
        match p2p::Peer::connect(&addr) {
            Ok(mut peer) => match peer.handshake() {
                Ok(_) => {
                    println!("Handshake with {} successful", addr);
                    let mut s = status.lock().unwrap();
                    s.peers.push(addr.clone());
                    if opts.show_height {
                        match peer.sync_headers() {
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
        let hex = genesis_hex();
        println!("Bitcoin genesis block:\n{}", hex);
        if opts.show_height {
            let h = status.lock().unwrap().block_height;
            println!("Current block height: {}", h);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::hex::ToHex;

    #[test]
    fn genesis_hex_matches_known_value() {
        let hex = genesis_hex();
        assert!(hex.starts_with("01000000"));
    }

    #[test]
    fn genesis_hash_matches_known_value() {
        let genesis = genesis_block(Network::Bitcoin);
        assert_eq!(genesis.block_hash().to_hex(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
    }

    #[test]
    fn genesis_merkle_root_matches_known_value() {
        let genesis = genesis_block(Network::Bitcoin);
        assert_eq!(genesis.header.merkle_root.to_hex(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
    }

    #[test]
    fn parse_args_height_flag() {
        let args = vec!["prog".into(), "--height".into()];
        let opts = parse_args(&args);
        assert!(opts.show_height);
        assert!(opts.peer_addr.is_none());
        assert!(opts.enable_rpc);
    }

    #[test]
    fn parse_args_peer_and_height() {
        let args = vec!["prog".into(), "--height".into(), "127.0.0.1:8333".into()];
        let opts = parse_args(&args);
        assert!(opts.show_height);
        assert_eq!(opts.peer_addr, Some("127.0.0.1:8333".into()));
        assert!(opts.enable_rpc);
    }
}
