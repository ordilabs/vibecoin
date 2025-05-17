use std::fs::{self, OpenOptions};
use std::io::{self, Write};

use bitcoin::blockdata::block::BlockHeader;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::util::uint::Uint256;

/// Verify that a block header satisfies its proof-of-work requirement.
pub fn header_pow_valid(header: &BlockHeader) -> bool {
    let hash = Uint256::from_be_bytes(header.block_hash().into_inner());
    hash <= header.target()
}

/// Simple on-disk header store using hex encoded headers, one per line.
pub struct HeaderStore {
    path: String,
    headers: Vec<BlockHeader>,
}

impl HeaderStore {
    /// Load headers from the given file, if it exists.
    pub fn open(path: &str) -> io::Result<Self> {
        let mut headers = Vec::new();
        if let Ok(data) = fs::read_to_string(path) {
            for line in data.lines() {
                let bytes = Vec::from_hex(line).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                })?;
                let header: BlockHeader = deserialize(&bytes).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                })?;
                headers.push(header);
            }
        }
        Ok(HeaderStore { path: path.to_string(), headers })
    }

    /// Current height of the stored chain.
    pub fn height(&self) -> u64 {
        self.headers.len() as u64
    }

    /// Return the latest header if available.
    pub fn tip(&self) -> Option<&BlockHeader> {
        self.headers.last()
    }

    /// Append validated headers to the store.
    pub fn append(&mut self, new_headers: &[BlockHeader]) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        for header in new_headers {
            if let Some(prev) = self.headers.last() {
                if header.prev_blockhash != prev.block_hash() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "header does not connect",
                    ));
                }
            }
            if !header_pow_valid(header) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid proof-of-work",
                ));
            }
            let hex = serialize(header).to_hex();
            writeln!(file, "{}", hex)?;
            self.headers.push(header.clone());
        }
        Ok(())
    }

    /// Build a locator list for getheaders messages.
    pub fn locator_hashes(&self) -> Vec<bitcoin::BlockHash> {
        self.headers
            .iter()
            .rev()
            .take(10)
            .map(|h| h.block_hash())
            .collect()
    }
}
