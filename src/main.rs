use bitcoin::blockdata::constants::genesis_block;
use bitcoin::network::constants::Network;
use bitcoin::consensus::encode::serialize_hex;

fn main() {
    let genesis = genesis_block(Network::Bitcoin);
    let hex = serialize_hex(&genesis);
    println!("Bitcoin genesis block:\n{}", hex);
}
