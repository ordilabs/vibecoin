use std::fs::{self, OpenOptions};
use std::io::{self, Write};

use bitcoin::blockdata::block::Header as BlockHeader;
use bitcoin::consensus::encode::{deserialize, serialize_hex};
use bitcoin::hex::FromHex;

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
                let bytes = Vec::from_hex(line)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                let header: BlockHeader = deserialize(&bytes)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                headers.push(header);
            }
        }
        Ok(HeaderStore {
            path: path.to_string(),
            headers,
        })
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
            if let Err(e) = header.validate_pow(header.target()) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
            }
            let hex = serialize_hex(header);
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

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::Network;

    fn temp_file() -> String {
        let dir = std::env::temp_dir();
        let name = format!("test_headers_{}.dat", rand::random::<u64>());
        dir.join(name).to_str().unwrap().to_string()
    }

    #[test]
    fn append_valid_header() {
        let path = temp_file();
        let mut store = HeaderStore::open(&path).unwrap();
        let genesis = genesis_block(Network::Bitcoin);
        store.append(&[genesis.header]).unwrap();
        assert_eq!(store.height(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn reject_invalid_pow() {
        let path = temp_file();
        let mut store = HeaderStore::open(&path).unwrap();
        let mut genesis = genesis_block(Network::Bitcoin).header;
        genesis.nonce = 0;
        assert!(store.append(&[genesis]).is_err());
        let _ = std::fs::remove_file(path);
    }
}
