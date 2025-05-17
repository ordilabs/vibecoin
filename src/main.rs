use bitcoin::blockdata::constants::genesis_block;
use bitcoin::network::constants::Network;
use bitcoin::consensus::encode::serialize_hex;
mod utils;

mod base58;
mod util;
mod p2p;

fn genesis_hex() -> String {
    let genesis = genesis_block(Network::Bitcoin);
    serialize_hex(&genesis)
}

/// Command line arguments after parsing.
#[derive(Debug, PartialEq)]
struct Args {
    /// Optional peer address to connect to.
    addr: Option<String>,
    /// Whether to display the synced block height.
    show_height: bool,
}

/// Parse command line arguments. The first non-flag argument is treated as the
/// peer address. Currently only a single `--height` flag is supported.
fn parse_args(args: &[String]) -> Args {
    let mut show_height = false;
    let mut addr = None;
    for arg in args.iter().skip(1) {
        if arg == "--height" {
            show_height = true;
        } else if addr.is_none() {
            addr = Some(arg.clone());
        }
    }
    Args { addr, show_height }
}

/// Placeholder for future header synchronization. Returns the current best
/// height, which is zero for now.
fn sync_headers(_peer: &mut p2p::Peer) -> Result<u64, Box<dyn std::error::Error>> {
    // TODO: implement real header synchronization.
    Ok(0)
}

fn main() {
    let raw_args: Vec<String> = std::env::args().collect();
    let args = parse_args(&raw_args);

    if let Some(addr) = args.addr.as_ref() {
        println!("Connecting to {}...", addr);
        match p2p::Peer::connect(addr) {
            Ok(mut peer) => match peer.handshake() {
                Ok(_) => {
                    println!("Handshake with {} successful", addr);
                    if args.show_height {
                        match sync_headers(&mut peer) {
                            Ok(height) => println!("Current block height: {}", height),
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
    fn parse_args_height_and_addr() {
        let args = vec!["prog".into(), "--height".into(), "127.0.0.1".into()];
        let parsed = parse_args(&args);
        assert_eq!(parsed.show_height, true);
        assert_eq!(parsed.addr, Some("127.0.0.1".into()));
    }

    #[test]
    fn parse_args_addr_only() {
        let args = vec!["prog".into(), "127.0.0.1".into()];
        let parsed = parse_args(&args);
        assert_eq!(parsed.show_height, false);
        assert_eq!(parsed.addr, Some("127.0.0.1".into()));
    }

    #[test]
    fn parse_args_no_options() {
        let args = vec!["prog".into()];
        let parsed = parse_args(&args);
        assert_eq!(parsed.show_height, false);
        assert_eq!(parsed.addr, None);
    }
}
