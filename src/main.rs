use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::Network;
use std::sync::{Arc, Mutex};
mod base58;
mod p2p;
mod rpc;
mod storage;
mod util;

#[derive(Debug, PartialEq)]
struct CliOptions {
    enable_rpc: bool,
    peer_addr: Option<String>,
    show_height: bool,
    headers_path: String,
}

impl Default for CliOptions {
    fn default() -> Self {
        CliOptions {
            enable_rpc: true,
            peer_addr: None,
            show_height: false,
            headers_path: "headers.dat".into(),
        }
    }
}

fn usage(prog: &str) -> String {
    format!(
        "Usage: {prog} [--no-rpc] [--height] [--headers-file <path>] [peer_addr]\n    -h, --help    Show this message",
        prog = prog
    )
}

fn parse_args(args: &[String]) -> Result<CliOptions, String> {
    let mut opts = CliOptions::default();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--no-rpc" => opts.enable_rpc = false,
            "--height" => opts.show_height = true,
            "--headers-file" => {
                i += 1;
                if i >= args.len() {
                    return Err(usage(&args[0]));
                }
                opts.headers_path = args[i].clone();
            }
            "-h" | "--help" => return Err(usage(&args[0])),
            opt if opt.starts_with('-') => return Err(usage(&args[0])),
            addr => opts.peer_addr = Some(addr.to_string()),
        }
        i += 1;
    }
    Ok(opts)
}

fn genesis_hex() -> String {
    let genesis = genesis_block(Network::Bitcoin);
    serialize_hex(&genesis)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let opts = match parse_args(&args) {
        Ok(o) => o,
        Err(msg) => {
            println!("{}", msg);
            std::process::exit(0);
        }
    };
    let enable_rpc = opts.enable_rpc;
    let peer_addr = opts.peer_addr.clone();

    let status = Arc::new(Mutex::new(rpc::NodeStatus {
        block_height: 0,
        peers: Vec::new(),
    }));
    let _rpc_handle = if enable_rpc {
        match rpc::start("127.0.0.1:8080", Arc::clone(&status)) {
            Ok(h) => Some(h),
            Err(e) => {
                eprintln!("Failed to start RPC server: {}", e);
                None
            }
        }
    } else {
        None
    };

    if let Some(addr) = peer_addr {
        println!("Connecting to {}...", addr);
        match p2p::Peer::connect(&addr) {
            Ok(mut peer) => match peer.handshake().await {
                Ok(_) => {
                    println!("Handshake with {} successful", addr);
                    let mut s = status.lock().unwrap();
                    s.peers.push(addr.clone());
                    if opts.show_height {
                        match peer.sync_headers(&opts.headers_path).await {
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

    #[test]
    fn genesis_hex_matches_known_value() {
        let hex = genesis_hex();
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
        assert!(opts.peer_addr.is_none());
        assert!(opts.enable_rpc);
        assert_eq!(opts.headers_path, "headers.dat");
    }

    #[test]
    fn parse_args_peer_and_height() {
        let args = vec!["prog".into(), "--height".into(), "127.0.0.1:8333".into()];
        let opts = parse_args(&args).unwrap();
        assert!(opts.show_height);
        assert_eq!(opts.peer_addr, Some("127.0.0.1:8333".into()));
        assert!(opts.enable_rpc);
        assert_eq!(opts.headers_path, "headers.dat");
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
        let args = vec![
            "prog".into(),
            "--headers-file".into(),
            "foo.dat".into(),
        ];
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.headers_path, "foo.dat");
    }
}
