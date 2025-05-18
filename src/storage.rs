use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use bitcoin::blockdata::block::Header as BlockHeader;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::Network;

/// Simple on-disk header store using length-prefixed binary headers.
pub struct HeaderStore {
    path: String, // Keep path as String if TempDir usage is tricky with lifetimes
    headers: Vec<BlockHeader>,
    network: Network, // Ensured network field is present
}

impl HeaderStore {
    /// Load headers from the given file, if it exists.
    pub fn open(path: &Path, network: Network) -> io::Result<Self> {
        let mut headers = Vec::new();
        if path.exists() {
            let mut data = File::open(path)?;
            let mut len_buf = [0u8; 4];
            loop {
                match data.read_exact(&mut len_buf) {
                    Ok(()) => {
                        let len = u32::from_le_bytes(len_buf) as usize;
                        let mut buf = vec![0u8; len];
                        data.read_exact(&mut buf)?;
                        let header: BlockHeader = deserialize(&buf).map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                        })?;
                        headers.push(header);
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(HeaderStore {
            path: path.to_str().unwrap().to_string(), // Store path as String for simplicity here
            headers,
            network, // Ensure network is assigned
        })
    }

    /// Current height of the stored chain (0-indexed).
    pub fn height(&self) -> io::Result<u64> {
        if self.headers.is_empty() {
            Ok(0)
        } else {
            Ok((self.headers.len() - 1) as u64)
        }
    }

    #[allow(dead_code)]
    pub fn get_header_by_height(&self, height: u64) -> io::Result<Option<BlockHeader>> {
        Ok(self.headers.get(height as usize).cloned())
    }

    /// Return the latest header if available.
    #[allow(dead_code)] // Kept from Stashed changes
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
                if header.block_hash() == prev.block_hash() {
                    continue;
                }
                if header.prev_blockhash != prev.block_hash() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "header {} (prev: {}) does not connect to current tip {} (hash: {})",
                            header.block_hash(),
                            header.prev_blockhash,
                            prev.block_hash(),
                            prev.block_hash()
                        ),
                    ));
                }
            } else {
                let network_genesis_header = genesis_block(self.network).header;
                if header.block_hash() != network_genesis_header.block_hash() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "first header {} (prev: {}) is not genesis {} (prev: {}) for network {}",
                            header.block_hash(),
                            header.prev_blockhash,
                            network_genesis_header.block_hash(),
                            network_genesis_header.prev_blockhash,
                            self.network
                        )
                    ));
                }
            }

            if let Err(e) = header.validate_pow(header.target()) {
                println!(
                    "[Append PoW Fail] header_bits: {:x}, header_target: {:?}, block_hash: {}, error: {}",
                    header.bits.to_consensus(), header.target(), header.block_hash(), e
                );
                return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
            }
            let bytes = serialize(header);
            let len = bytes.len() as u32;
            file.write_all(&len.to_le_bytes())?;
            file.write_all(&bytes)?;
            self.headers.push(*header);
        }
        Ok(())
    }

    /// Build a locator list for getheaders messages.
    pub fn locator_hashes(&self) -> Vec<bitcoin::BlockHash> {
        if self.headers.is_empty() {
            vec![genesis_block(self.network).header.block_hash()]
        } else {
            let mut hashes = Vec::new();
            let mut step = 1;
            let mut count = 0;
            let mut index = self.headers.len() as i64 - 1;
            while index >= 0 {
                hashes.push(self.headers[index as usize].block_hash());
                count += 1;
                if count >= 10 && index > 0 {
                    index -= step;
                    step *= 2;
                } else {
                    index -= 1;
                }
            }
            hashes
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::hashes::{sha256d, Hash as BitcoinHash};
    use bitcoin::TxMerkleNode;
    use bitcoin::{BlockHash, CompactTarget};
    use tempfile::TempDir;

    fn civiles_merkle_root_from_index(idx: u32) -> TxMerkleNode {
        let mut data = [0u8; 32];
        let bytes = idx.to_le_bytes();
        data[0..bytes.len()].copy_from_slice(&bytes);
        TxMerkleNode::from_raw_hash(sha256d::Hash::from_slice(&data).unwrap())
    }

    fn solve_pow_for_header(header: &mut BlockHeader) {
        let mut attempts = 0u64;
        loop {
            attempts += 1;
            if attempts % 1_000_000 == 0 {
                // println!("PoW attempts: {}M for target {:x}", attempts / 1_000_000, header.bits.to_consensus());
            }
            let pow_hash = header.validate_pow(header.target());
            match pow_hash {
                Ok(_work) => {
                    break;
                }
                Err(_) => {
                    header.nonce += 1;
                    if header.nonce == 0 {
                        header.time += 1;
                    }
                }
            }
        }
    }

    #[test]
    fn append_valid_header() -> Result<(), Box<dyn std::error::Error>> {
        let network = Network::Regtest;
        let temp_dir = TempDir::new()?;
        let path = temp_dir.path().join("headers.dat");
        let mut store = HeaderStore::open(&path, network)?;
        let genesis_hdr = genesis_block(network).header;
        store.append(&[genesis_hdr])?;
        assert_eq!(store.height()?, 0);
        Ok(())
    }

    #[test]
    fn reject_invalid_pow() -> Result<(), Box<dyn std::error::Error>> {
        let network = Network::Regtest;
        let temp_dir = TempDir::new()?;
        let path = temp_dir.path().join("headers.dat");
        let mut store = HeaderStore::open(&path, network)?;
        let genesis_hdr_clone = genesis_block(network).header;
        store.append(&[genesis_hdr_clone])?;

        let mut invalid_header = genesis_hdr_clone;
        invalid_header.prev_blockhash = genesis_hdr_clone.block_hash();
        invalid_header.merkle_root = civiles_merkle_root_from_index(1);
        invalid_header.time = genesis_hdr_clone.time + 1;
        invalid_header.bits = CompactTarget::from_consensus(0x01000001);
        invalid_header.nonce = 0;

        assert!(
            store.append(&[invalid_header]).is_err(),
            "append should fail with an extremely difficult target and unsolved PoW"
        );
        Ok(())
    }

    #[test]
    fn append_multiple_headers() -> Result<(), Box<dyn std::error::Error>> {
        let network = Network::Regtest;
        let genesis_hdr = genesis_block(network).header;
        let temp_dir = TempDir::new()?;
        let path = temp_dir.path().join("headers.dat");

        let mut store = HeaderStore::open(&path, network)?;
        store.append(&[genesis_hdr])?;
        assert_eq!(store.height()?, 0);

        let easiest_bits_compact = network.params().max_attainable_target.to_compact_lossy();

        let mut h2 = genesis_hdr;
        h2.prev_blockhash = genesis_hdr.block_hash();
        h2.merkle_root = civiles_merkle_root_from_index(2);
        h2.time = genesis_hdr.time + 1;
        h2.bits = easiest_bits_compact;
        h2.nonce = 0;
        solve_pow_for_header(&mut h2);
        store.append(&[h2])?;
        assert_eq!(store.height()?, 1);

        let mut h3 = h2;
        h3.prev_blockhash = h2.block_hash();
        h3.merkle_root = civiles_merkle_root_from_index(3);
        h3.time = h2.time + 1;
        h3.bits = easiest_bits_compact;
        h3.nonce = 0;
        solve_pow_for_header(&mut h3);
        store.append(&[h3])?;
        assert_eq!(store.height()?, 2);
        Ok(())
    }

    #[test]
    fn reject_disconnected_header() -> Result<(), Box<dyn std::error::Error>> {
        let network = Network::Regtest;
        let temp_dir = TempDir::new()?;
        let path = temp_dir.path().join("headers.dat");
        let mut store = HeaderStore::open(&path, network)?;
        let genesis_hdr = genesis_block(network).header;
        store.append(&[genesis_hdr])?;

        let mut disconnected_header = genesis_hdr;
        disconnected_header.prev_blockhash = BlockHash::all_zeros();
        disconnected_header.merkle_root = civiles_merkle_root_from_index(99);
        disconnected_header.time = genesis_hdr.time + 100;
        disconnected_header.bits = network.params().max_attainable_target.to_compact_lossy();
        solve_pow_for_header(&mut disconnected_header);

        assert!(store.append(&[disconnected_header]).is_err());
        Ok(())
    }

    #[test]
    fn append_to_existing_store() -> Result<(), Box<dyn std::error::Error>> {
        let network = Network::Regtest;
        let genesis_hdr = genesis_block(network).header;
        let temp_dir = TempDir::new()?;
        let path = temp_dir.path().join("headers.dat");

        // Create and populate a store
        {
            let mut store = HeaderStore::open(&path, network)?;
            store.append(&[genesis_hdr])?;
            assert_eq!(store.height()?, 0);

            let mut h2 = genesis_hdr;
            h2.prev_blockhash = genesis_hdr.block_hash();
            h2.merkle_root = civiles_merkle_root_from_index(10);
            h2.time = genesis_hdr.time + 1;
            h2.bits = network.params().max_attainable_target.to_compact_lossy();
            solve_pow_for_header(&mut h2);
            store.append(&[h2])?;
            assert_eq!(store.height()?, 1);
        }

        // Re-open and append
        {
            let mut store = HeaderStore::open(&path, network)?;
            assert_eq!(store.height()?, 1);
            let current_tip = store.tip().unwrap();

            let mut h3 = genesis_hdr; // Incorrect, should be based on current_tip
            h3.prev_blockhash = current_tip.block_hash();
            h3.merkle_root = civiles_merkle_root_from_index(11);
            h3.time = current_tip.time + 1;
            h3.bits = network.params().max_attainable_target.to_compact_lossy();
            solve_pow_for_header(&mut h3);
            store.append(&[h3])?;
            assert_eq!(store.height()?, 2);
        }
        Ok(())
    }

    #[test]
    fn locator_hashes_empty_store() -> Result<(), Box<dyn std::error::Error>> {
        let network = Network::Regtest;
        let temp_dir = TempDir::new()?;
        let path = temp_dir.path().join("headers.dat");
        let store = HeaderStore::open(&path, network)?;
        let locators = store.locator_hashes();
        assert_eq!(locators.len(), 1);
        assert_eq!(locators[0], genesis_block(network).header.block_hash());
        Ok(())
    }

    #[test]
    fn locator_hashes_few_headers() -> Result<(), Box<dyn std::error::Error>> {
        let network = Network::Regtest;
        let genesis_hdr = genesis_block(network).header;
        let temp_dir = TempDir::new()?;
        let path = temp_dir.path().join("headers.dat");
        let mut store = HeaderStore::open(&path, network)?;

        store.append(&[genesis_hdr])?;

        let mut h2 = genesis_hdr;
        h2.prev_blockhash = genesis_hdr.block_hash();
        h2.merkle_root = civiles_merkle_root_from_index(30);
        h2.time = genesis_hdr.time + 1;
        h2.bits = network.params().max_attainable_target.to_compact_lossy();
        solve_pow_for_header(&mut h2);
        store.append(&[h2])?;

        let mut h3 = genesis_hdr;
        h3.prev_blockhash = h2.block_hash();
        h3.merkle_root = civiles_merkle_root_from_index(31);
        h3.time = h2.time + 1;
        h3.bits = network.params().max_attainable_target.to_compact_lossy();
        solve_pow_for_header(&mut h3);
        store.append(&[h3])?;

        let locators = store.locator_hashes();
        // Expected: [h3_hash, h2_hash, genesis_hash]
        assert_eq!(locators.len(), 3);
        assert_eq!(locators[0], h3.block_hash());
        assert_eq!(locators[1], h2.block_hash());
        assert_eq!(locators[2], genesis_hdr.block_hash());
        Ok(())
    }

    #[test]
    fn locator_hashes_many_headers() -> Result<(), Box<dyn std::error::Error>> {
        let network = Network::Regtest;
        let genesis_hdr = genesis_block(network).header;
        let temp_dir = TempDir::new()?;
        let path = temp_dir.path().join("headers.dat");
        let mut store = HeaderStore::open(&path, network)?;

        let mut headers_appended = vec![genesis_hdr];
        store.append(&[genesis_hdr])?;

        for i in 1u32..=20u32 {
            // Create 20 more headers (total 21)
            let prev_header = *headers_appended.last().unwrap();
            let mut next_header = genesis_hdr;
            next_header.prev_blockhash = prev_header.block_hash();
            next_header.merkle_root = civiles_merkle_root_from_index(100 + i);
            next_header.time = prev_header.time + i;
            next_header.bits = network.params().max_attainable_target.to_compact_lossy();
            next_header.nonce = i; // Simpler nonce for test, ensure solve_pow respects it.
            solve_pow_for_header(&mut next_header);
            store.append(&[next_header])?;
            headers_appended.push(next_header);
        }
        assert_eq!(store.height()?, 20);

        let locators = store.locator_hashes();

        assert_eq!(locators.len(), 13);
        for i in 0..10 {
            assert_eq!(
                locators[i],
                headers_appended[20 - i].block_hash(),
                "Mismatch in first 10: index {}",
                i
            );
        }
        assert_eq!(
            locators[10],
            headers_appended[10].block_hash(),
            "Mismatch at locator[10]"
        );
        assert_eq!(
            locators[11],
            headers_appended[8].block_hash(),
            "Mismatch at locator[11]"
        );
        assert_eq!(
            locators[12],
            headers_appended[4].block_hash(),
            "Mismatch at locator[12]"
        );

        Ok(())
    }
}
