use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use bitcoin::blockdata::block::BlockHeader;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hash_types::BlockHash;

/// Simple on-disk store for block headers.
pub struct HeaderStore {
    path: PathBuf,
    chain: Vec<BlockHeader>,
}

impl HeaderStore {
    /// Load headers from the given path, creating directories if needed.
    pub fn load(path: PathBuf) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut chain = Vec::new();
        if path.exists() {
            let mut file = File::open(&path)?;
            let mut data = Vec::new();
            file.read_to_end(&mut data)?;
            let mut cursor = std::io::Cursor::new(data);
            while (cursor.position() as usize) < cursor.get_ref().len() {
                match deserialize::<BlockHeader>(&mut cursor) {
                    Ok(h) => chain.push(h),
                    Err(_) => break,
                }
            }
        }
        Ok(HeaderStore { path, chain })
    }

    /// Load headers from the default location `~/.vibecoin/headers.dat`.
    pub fn load_default() -> io::Result<Self> {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        let path = PathBuf::from(home).join(".vibecoin").join("headers.dat");
        Self::load(path)
    }

    /// Current chain height (-1 if no headers loaded).
    pub fn height(&self) -> i32 {
        self.chain.len() as i32 - 1
    }

    /// Hash of the current best block.
    pub fn best_hash(&self) -> Option<BlockHash> {
        self.chain.last().map(|h| h.block_hash())
    }

    /// Append or reorganize when a new header is received.
    pub fn add_header(&mut self, header: BlockHeader) -> io::Result<()> {
        if self.chain.is_empty() {
            self.chain.push(header);
            return self.save();
        }
        let prev = header.prev_blockhash;
        if let Some(pos) = self
            .chain
            .iter()
            .position(|h| h.block_hash() == prev)
        {
            // Remove headers after the parent if needed (reorg)
            if pos + 1 != self.chain.len() {
                self.chain.truncate(pos + 1);
            }
            self.chain.push(header);
            self.save()
        } else {
            // Unknown parent, ignore
            Ok(())
        }
    }

    fn save(&self) -> io::Result<()> {
        let mut file = File::create(&self.path)?;
        for h in &self.chain {
            let bytes = serialize(h);
            file.write_all(&bytes)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::network::constants::Network;
    use bitcoin::hash_types::TxMerkleNode;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(name)
    }

    fn dummy_header(prev: BlockHash) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::default(),
            time: 1,
            bits: 0x1d00ffff,
            nonce: 0,
        }
    }

    #[test]
    fn write_and_reload() {
        let path = temp_path("headers_test.dat");
        let genesis = genesis_block(Network::Bitcoin).header;
        {
            let mut store = HeaderStore::load(path.clone()).unwrap();
            store.add_header(genesis.clone()).unwrap();
            assert_eq!(store.height(), 0);
        }
        {
            let store = HeaderStore::load(path.clone()).unwrap();
            assert_eq!(store.height(), 0);
            assert_eq!(store.best_hash().unwrap(), genesis.block_hash());
        }
        let _ = fs::remove_file(path);
    }

    #[test]
    fn reorg() {
        let path = temp_path("headers_reorg.dat");
        let genesis = genesis_block(Network::Bitcoin).header;
        let h1 = dummy_header(genesis.block_hash());
        let h2 = dummy_header(genesis.block_hash());
        {
            let mut store = HeaderStore::load(path.clone()).unwrap();
            store.add_header(genesis.clone()).unwrap();
            store.add_header(h1).unwrap();
            assert_eq!(store.height(), 1);
            store.add_header(h2.clone()).unwrap();
            assert_eq!(store.height(), 1);
            assert_eq!(store.best_hash().unwrap(), h2.block_hash());
        }
        let _ = fs::remove_file(path);
    }
}

