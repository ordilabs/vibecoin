use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::consensus::encode::{serialize, deserialize};
use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hash_types::{BlockHash, TxMerkleNode};
use bitcoin::network::address::Address;
use bitcoin::network::constants::{Network, ServiceFlags, PROTOCOL_VERSION};
use bitcoin::network::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::network::message_network::VersionMessage;
use bitcoin::network::message_blockdata::{GetHeadersMessage, HeadersMessage};
use bitcoin::util::uint::Uint256;

/// Simple in-memory header chain tracking the best tip.
pub struct HeaderChain {
    tip: BlockHeader,
    height: u32,
}

impl HeaderChain {
    /// Create a new header chain starting from the network genesis block.
    pub fn new(network: Network) -> Self {
        let genesis = genesis_block(network).header;
        HeaderChain { tip: genesis, height: 0 }
    }

    pub fn tip(&self) -> &BlockHeader {
        &self.tip
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    /// Apply a set of new headers extending the current tip.
    pub fn apply(&mut self, headers: &[BlockHeader]) -> Result<(), String> {
        for h in headers {
            if h.prev_blockhash != self.tip.block_hash() {
                return Err("prev block mismatch".into());
            }
            if !check_pow(h) {
                return Err("invalid pow".into());
            }
            self.tip = h.clone();
            self.height += 1;
        }
        Ok(())
    }
}

fn target_from_bits(bits: u32) -> Uint256 {
    let exponent = bits >> 24;
    let mantissa = bits & 0x007f_ffff;
    let mut target = Uint256::from_u64(mantissa as u64);
    if exponent <= 3 {
        target >>= 8 * (3 - exponent);
    } else {
        target <<= 8 * (exponent - 3);
    }
    target
}

fn check_pow(header: &BlockHeader) -> bool {
    let target = target_from_bits(header.bits);
    let hash = Uint256::from_be_bytes(header.block_hash().into_inner());
    hash <= target
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::network::constants::Network;

    fn build_header(prev: &BlockHeader) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_blockhash: prev.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: prev.time + 1,
            bits: 0x207fffff,
            nonce: 0,
        }
    }

    #[test]
    fn valid_chain_updates_tip() {
        let mut chain = HeaderChain::new(Network::Bitcoin);
        let h = build_header(chain.tip());
        chain.apply(&[h.clone()]).unwrap();
        assert_eq!(chain.height(), 1);
        assert_eq!(chain.tip().block_hash(), h.block_hash());
    }

    #[test]
    fn invalid_pow_rejected() {
        let mut chain = HeaderChain::new(Network::Bitcoin);
        let mut h = build_header(chain.tip());
        h.bits = 0;
        assert!(chain.apply(&[h]).is_err());
    }
}

/// Simple peer connection that performs a version handshake.
pub struct Peer {
    stream: TcpStream,
    headers: HeaderChain,
}

impl Peer {
    /// Connect to the given address (host:port) and perform version handshake.
    pub fn connect(addr: &str) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        Ok(Peer {
            stream,
            headers: HeaderChain::new(Network::Bitcoin),
        })
    }

    /// Perform the Bitcoin version handshake.
    pub fn handshake(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let local = self.stream.local_addr()?;
        let remote = self.stream.peer_addr()?;

        let version = VersionMessage {
            version: PROTOCOL_VERSION as i32,
            services: ServiceFlags::NONE,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs() as i64,
            receiver: Address::new(&remote, ServiceFlags::NONE),
            sender: Address::new(&local, ServiceFlags::NONE),
            nonce: rand::random(),
            user_agent: "/vibecoin:0.1.0/".into(),
            start_height: 0,
            relay: false,
        };

        let msg = RawNetworkMessage {
            magic: Network::Bitcoin.magic(),
            payload: NetworkMessage::Version(version),
        };
        let bytes = serialize(&msg);
        self.stream.write_all(&bytes)?;

        // Read remote version message
        let mut buf = vec![0u8; 1024];
        let n = self.stream.read(&mut buf)?;
        let incoming: RawNetworkMessage = deserialize(&buf[..n])?;
        match incoming.payload {
            NetworkMessage::Version(_) => {
                // Send verack
                let verack = RawNetworkMessage {
                    magic: Network::Bitcoin.magic(),
                    payload: NetworkMessage::Verack,
                };
                let bytes = serialize(&verack);
                self.stream.write_all(&bytes)?;

                // Request headers starting from our tip
                let locator = vec![self.headers.tip().block_hash()];
                let getheaders = RawNetworkMessage {
                    magic: Network::Bitcoin.magic(),
                    payload: NetworkMessage::GetHeaders(GetHeadersMessage {
                        locator_hashes: locator,
                        stop_hash: BlockHash::all_zeros(),
                    }),
                };
                let bytes = serialize(&getheaders);
                self.stream.write_all(&bytes)?;

                self.receive_headers()?;
                Ok(())
            }
            _ => Err("unexpected message".into()),
        }
    }

    /// Current best header height.
    pub fn tip_height(&self) -> u32 {
        self.headers.height()
    }

    fn receive_headers(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = vec![0u8; 4096];
        let n = self.stream.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        let incoming: RawNetworkMessage = deserialize(&buf[..n])?;
        if let NetworkMessage::Headers(HeadersMessage { headers }) = incoming.payload {
            self.headers.apply(&headers).map_err(|e| e.into())?;
        }
        Ok(())
    }
}
