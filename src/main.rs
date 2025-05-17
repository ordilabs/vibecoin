use bitcoin::blockdata::constants::genesis_block;
use bitcoin::network::constants::Network;
use bitcoin::consensus::encode::serialize_hex;
mod utils;

mod base58;
mod util;

fn genesis_hex() -> String {
    let genesis = genesis_block(Network::Bitcoin);
    serialize_hex(&genesis)
}

fn main() {
    let hex = genesis_hex();
    println!("Bitcoin genesis block:\n{}", hex);
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
}
