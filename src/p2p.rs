use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::storage::HeaderStore;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message_blockdata::GetHeadersMessage;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{message::NetworkMessage, message::RawNetworkMessage};
use bitcoin::p2p::{ServiceFlags, PROTOCOL_VERSION};
use bitcoin::{BlockHash, Network};
use std::io::{self};
use std::path::Path; // For explicit genesis handling

/// Simple peer connection that performs a version handshake.
pub struct Peer {
    stream: TcpStream,
    network: Network,
}

impl Peer {
    /// Connect to the given address (host:port).
    pub fn connect(addr: &str, network: Network) -> std::io::Result<Self> {
        let std_stream = std::net::TcpStream::connect(addr)?;
        std_stream.set_nonblocking(true)?;
        let stream = TcpStream::from_std(std_stream)?;
        Ok(Peer { stream, network })
    }

    /// Read a full network message from the stream assembling multiple reads.
    async fn read_message(&mut self) -> Result<RawNetworkMessage, Box<dyn std::error::Error>> {
        let mut header = [0u8; 24];
        self.stream.read_exact(&mut header).await?;
        let payload_len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; payload_len];
        self.stream.read_exact(&mut payload).await?;

        let mut full = Vec::with_capacity(24 + payload_len);
        full.extend_from_slice(&header);
        full.extend_from_slice(&payload);
        Ok(deserialize(&full)?)
    }

    /// Perform the Bitcoin version handshake.
    pub async fn handshake(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let local = self.stream.local_addr()?;
        let remote = self.stream.peer_addr()?;

        let version = VersionMessage {
            version: PROTOCOL_VERSION,
            services: ServiceFlags::NONE,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64,
            receiver: Address::new(&remote, ServiceFlags::NONE),
            sender: Address::new(&local, ServiceFlags::NONE),
            nonce: rand::random(),
            user_agent: "/vibecoin:0.1.0/".into(),
            start_height: 0,
            relay: false,
        };

        let msg = RawNetworkMessage::new(self.network.magic(), NetworkMessage::Version(version));
        let bytes = serialize(&msg);
        self.stream.write_all(&bytes).await?;

        // Read remote version message
        let incoming = self.read_message().await?;
        match incoming.payload() {
            NetworkMessage::Version(_) => {
                // Send verack
                let verack = RawNetworkMessage::new(self.network.magic(), NetworkMessage::Verack);
                let bytes = serialize(&verack);
                self.stream.write_all(&bytes).await?;

                // Wait for peer verack
                let reply = self.read_message().await?;
                match reply.payload() {
                    NetworkMessage::Verack => Ok(()),
                    _ => Err("unexpected message".into()),
                }
            }
            _ => Err("unexpected message".into()),
        }
    }

    /// Synchronize block headers with the connected peer.
    /// Load existing headers from disk and fetch new ones from the peer.
    pub async fn sync_headers(
        &mut self,
        headers_path_str: &str,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let path = Path::new(headers_path_str);
        let mut store = HeaderStore::open(path, self.network)?;

        // Ensure genesis block is in the store if it's empty or doesn't have the correct genesis
        let network_genesis_header = genesis_block(self.network).header;
        let mut store_needs_genesis = true;
        if let Some(tip) = store.tip() {
            if tip.block_hash() == network_genesis_header.block_hash() {
                store_needs_genesis = false;
            } else if store.height()? > 0 {
                // Store has content but tip is not genesis. This is an invalid state for p2p sync starting from genesis.
                // For simplicity, we might choose to clear the store or error.
                // Or, if we trust the existing store, we sync from its tip.
                // Current logic: if store is not empty AND tip is not genesis, we still try to append genesis if height is 0,
                // which is contradictory. Let's refine: only append genesis if store is TRULY empty.
                // If store has content but not genesis, `locator_hashes` will handle it.
                store_needs_genesis = false; // Don't force genesis if store has other things.
            }
        }

        if store_needs_genesis {
            println!(
                "[Sync] Store is empty or tip is not correct genesis, appending genesis: {}",
                network_genesis_header.block_hash()
            );
            // It's critical that append itself handles the "store is empty, first must be genesis" rule.
            // And if store is NOT empty, it should connect.
            // If we append genesis here, store.append must be okay with it.
            store.append(&[network_genesis_header])?;
        }

        loop {
            let locator = store.locator_hashes();
            // println!("[Sync] Sending getheaders with locator count: {}. First: {:?}, Last: {:?}", locator.len(), locator.first(), locator.last());

            let get_headers_msg = GetHeadersMessage::new(locator.clone(), BlockHash::all_zeros());
            let req = RawNetworkMessage::new(
                self.network.magic(),
                NetworkMessage::GetHeaders(get_headers_msg),
            );
            let bytes = serialize(&req);
            self.stream.write_all(&bytes).await?;
            // println!("[Sync] Sent getheaders message.");

            match self.read_message().await {
                Ok(incoming) => {
                    match incoming.payload() {
                        NetworkMessage::Headers(headers_payload) => {
                            if headers_payload.is_empty() {
                                println!("[Sync] Received empty headers message (0 headers), assuming sync complete based on locator.");
                                break;
                            }
                            // println!("[Sync] Received {} headers from peer.", headers_payload.len());

                            let mut headers_to_append = headers_payload.clone();

                            if let Some(current_tip_header) = store.tip() {
                                if let Some(first_received_header) = headers_to_append.first() {
                                    if first_received_header.block_hash()
                                        == current_tip_header.block_hash()
                                    {
                                        // println!(
                                        //     "[Sync] First received header {} is same as current tip {}, removing from batch.",
                                        //     first_received_header.block_hash(),
                                        //     current_tip_header.block_hash()
                                        // );
                                        headers_to_append.remove(0);
                                    }
                                }
                            }

                            if headers_to_append.is_empty() {
                                // println!("[Sync] Batch became empty after removing duplicate tip (if any). Peer might have sent only known tip.");
                                // This often means we are synced up to the point the peer knows from our locator.
                                // If the original headers_payload was also empty, we'd have broken above.
                                // If it wasn't, but became empty, means peer only sent back our own tip.
                                // Consider this sync complete for this round.
                                println!("[Sync] No new headers to append after filtering. Assuming sync complete for this iteration.");
                                break;
                            }

                            // println!("[Sync] Attempting to append {} headers to store.", headers_to_append.len());
                            match store.append(&headers_to_append) {
                                Ok(_) => {
                                    // println!("[Sync] Appended {} headers. New height: {}", headers_to_append.len(), store.height()?);
                                    if headers_payload.len() < 2000 {
                                        // Check original payload length
                                        // println!("[Sync] Received less than max headers in original batch ({}), assuming sync complete.", headers_payload.len());
                                        break;
                                    }
                                    // If we received a full batch originally, loop again to get more.
                                }
                                Err(e) => {
                                    eprintln!("[SyncError] Header sync append failed: {}. Tip: {:?}, First new: {:?}", e, store.tip().map(|h| h.block_hash()), headers_to_append.first().map(|h| (h.block_hash(), h.prev_blockhash)));
                                    return Err(Box::new(std::io::Error::other(format!(
                                        "Header sync append failed: {}",
                                        e
                                    ))));
                                }
                            }
                        }
                        NetworkMessage::Inv(_inv_msg) => {
                            // println!("[Sync] Received Inv message with {} items. Ignoring in header sync phase.", _inv_msg.len());
                        }
                        _other_msg => {
                            // println!("[Sync] Received other message type: {:?}. Ignoring.", _other_msg.message_name());
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[SyncError] Failed to read message from peer: {}", e);
                    return Err(e);
                }
            }
        }
        store.height().map_err(Box::from)
    }

    pub fn _latest_known_header_height(&self) -> io::Result<u64> {
        // Placeholder: In a real scenario, this might come from a shared HeaderStore
        // or be managed more dynamically if the Peer struct has its own small store.
        // For now, assuming the main store passed during construction is the source of truth.
        let path_str = "./data/headers_p2p_placeholder.dat"; // Example path, should align with Peer's construction
        let path = Path::new(path_str);
        let store = HeaderStore::open(path, self.network)?;
        Ok(store.height()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    // Helper to create a Peer instance for tests, assuming Bitcoin network for simplicity
    fn test_peer(addr: &str) -> Peer {
        Peer::connect(addr, Network::Bitcoin).unwrap()
    }

    #[tokio::test]
    async fn handshake_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_network = Network::Bitcoin; // Ensure server uses same network
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
            if let NetworkMessage::Version(v) = msg.payload() {
                let resp = RawNetworkMessage::new(
                    server_network.magic(),
                    NetworkMessage::Version(v.clone()),
                );
                socket.write_all(&serialize(&resp)).await.unwrap();
                let n = socket.read(&mut buf).await.unwrap();
                let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
                assert!(matches!(msg.payload(), NetworkMessage::Verack));
                let resp = RawNetworkMessage::new(server_network.magic(), NetworkMessage::Verack);
                socket.write_all(&serialize(&resp)).await.unwrap();
            } else {
                panic!("unexpected message");
            }
        });

        let mut peer = test_peer(&addr.to_string()); // Use helper
        peer.handshake().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn sync_headers_empty() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_network = Network::Bitcoin; // Ensure server uses same network
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            // Handle Handshake part first
            let n = socket.read(&mut buf).await.unwrap(); // Version from client
            let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
            if let NetworkMessage::Version(v) = msg.payload() {
                let resp = RawNetworkMessage::new(
                    server_network.magic(),
                    NetworkMessage::Version(v.clone()),
                );
                socket.write_all(&serialize(&resp)).await.unwrap(); // Server Version back
                let _ = socket.read(&mut buf).await.unwrap(); // Verack from client
                let resp = RawNetworkMessage::new(server_network.magic(), NetworkMessage::Verack);
                socket.write_all(&serialize(&resp)).await.unwrap(); // Server Verack back
            } else {
                panic!("Expected Version message during handshake simulation");
            }

            // Handle GetHeaders part
            let n = socket.read(&mut buf).await.unwrap();
            let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
            if matches!(msg.payload(), NetworkMessage::GetHeaders(_)) {
                let resp = RawNetworkMessage::new(
                    server_network.magic(),
                    NetworkMessage::Headers(vec![]), // Send empty headers
                );
                socket.write_all(&serialize(&resp)).await.unwrap();
            } else {
                panic!("Expected GetHeaders message after handshake");
            }
        });

        let mut peer = test_peer(&addr.to_string()); // Use helper
        peer.handshake().await.unwrap();
        // Create a dummy headers file for the test, as sync_headers tries to open it.
        let dummy_headers_path = "./test_headers_sync_empty.bin";
        std::fs::File::create(dummy_headers_path).unwrap(); // Create empty file

        let h = peer.sync_headers(dummy_headers_path).await.unwrap();
        assert_eq!(h, 0);
        server.await.unwrap();
        std::fs::remove_file(dummy_headers_path).unwrap(); // Clean up
    }

    #[tokio::test]
    async fn handshake_requires_verack() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_network = Network::Bitcoin; // Ensure server uses same network
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
            if let NetworkMessage::Version(v) = msg.payload() {
                let resp = RawNetworkMessage::new(
                    server_network.magic(),
                    NetworkMessage::Version(v.clone()),
                );
                socket.write_all(&serialize(&resp)).await.unwrap();
                let _ = socket.read(&mut buf).await.unwrap(); // Client Verack
                                                              // send ping instead of verack
                let resp = RawNetworkMessage::new(server_network.magic(), NetworkMessage::Ping(0));
                socket.write_all(&serialize(&resp)).await.unwrap();
            }
        });

        let mut peer = test_peer(&addr.to_string()); // Use helper
        assert!(peer.handshake().await.is_err());
        // We don't join the server here as it might panic if client disconnects early
        // or test might finish before server does, which is fine for this error case.
        let _ = server.await; // Allow server to finish or error out
    }

    #[tokio::test]
    async fn handshake_multi_read() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
            if let NetworkMessage::Version(v) = msg.payload() {
                let resp = RawNetworkMessage::new(
                    Network::Bitcoin.magic(),
                    NetworkMessage::Version(v.clone()),
                );
                let bytes = serialize(&resp);
                socket.write_all(&bytes[..10]).await.unwrap();
                socket.write_all(&bytes[10..]).await.unwrap();

                let n = socket.read(&mut buf).await.unwrap();
                let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
                assert!(matches!(msg.payload(), NetworkMessage::Verack));
                let resp = RawNetworkMessage::new(Network::Bitcoin.magic(), NetworkMessage::Verack);
                let bytes = serialize(&resp);
                socket.write_all(&bytes[..14]).await.unwrap();
                socket.write_all(&bytes[14..]).await.unwrap();
            }
        });

        let mut peer = Peer::connect(&addr.to_string(), Network::Bitcoin).unwrap();
        peer.handshake().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn sync_headers_multi_read() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
            if let NetworkMessage::Version(v) = msg.payload() {
                let resp = RawNetworkMessage::new(
                    Network::Bitcoin.magic(),
                    NetworkMessage::Version(v.clone()),
                );
                socket.write_all(&serialize(&resp)).await.unwrap();
                let n = socket.read(&mut buf).await.unwrap();
                let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
                assert!(matches!(msg.payload(), NetworkMessage::Verack));
                let resp = RawNetworkMessage::new(Network::Bitcoin.magic(), NetworkMessage::Verack);
                let bytes = serialize(&resp);
                socket.write_all(&bytes[..8]).await.unwrap();
                socket.write_all(&bytes[8..]).await.unwrap();
            }

            let mut buf = vec![0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
            if matches!(msg.payload(), NetworkMessage::GetHeaders(_)) {
                let resp = RawNetworkMessage::new(
                    Network::Bitcoin.magic(),
                    NetworkMessage::Headers(vec![]),
                );
                let bytes = serialize(&resp);
                socket.write_all(&bytes[..5]).await.unwrap();
                socket.write_all(&bytes[5..20]).await.unwrap();
                socket.write_all(&bytes[20..]).await.unwrap();
            }
        });

        let mut peer = Peer::connect(&addr.to_string(), Network::Bitcoin).unwrap();
        peer.handshake().await.unwrap();
        let h = peer.sync_headers("headers_multi.bin").await.unwrap();
        assert_eq!(h, 0);
        server.await.unwrap();
    }
}
