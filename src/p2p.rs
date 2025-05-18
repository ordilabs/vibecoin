use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::rpc;
use crate::storage::HeaderStore;

use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::encode::{deserialize, serialize, serialize_hex};
use bitcoin::hashes::Hash;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::ServiceFlags;

use bitcoin::{BlockHash, Network};
use log::{debug, error, info, warn};

/// Simple peer connection that performs a version handshake.
#[derive(Debug)]
pub struct Peer {
    stream: TcpStream,
    network: Network,
}

impl Peer {
    /// Connect to the given address (host:port).
    pub async fn connect(addr: &str, network: Network) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        Ok(Peer { stream, network })
    }

    /// Read a full network message from the stream assembling multiple reads.
    async fn read_message(
        &mut self,
    ) -> Result<RawNetworkMessage, Box<dyn std::error::Error + Send + Sync>> {
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
    pub async fn handshake(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let local = self.stream.local_addr()?;
        let remote = self.stream.peer_addr()?;
        debug!(
            "[p2p] Performing handshake. Local: {}, Remote: {}",
            local, remote
        );

        let version = VersionMessage {
            version: bitcoin::p2p::PROTOCOL_VERSION,
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
        debug!("[p2p] Sent Version message to {}", remote);

        let incoming_raw = self.read_message().await?;
        debug!(
            "[p2p] Received message from {}: {}",
            remote,
            incoming_raw.command()
        );
        match incoming_raw.payload() {
            NetworkMessage::Version(_) => {
                let verack = RawNetworkMessage::new(self.network.magic(), NetworkMessage::Verack);
                let bytes = serialize(&verack);
                self.stream.write_all(&bytes).await?;
                debug!("[p2p] Sent Verack message to {}", remote);

                let reply_raw = self.read_message().await?;
                debug!(
                    "[p2p] Received message from {}: {}",
                    remote,
                    reply_raw.command()
                );
                match reply_raw.payload() {
                    NetworkMessage::Verack => {
                        info!("[p2p] Handshake with {} successful.", remote);
                        Ok(())
                    }
                    _unexpected_payload => {
                        warn!(
                            "[p2p] Handshake with {} failed. Expected Verack, got {}.",
                            remote,
                            reply_raw.command()
                        );
                        Err(format!(
                            "unexpected message: expected Verack, got {}",
                            reply_raw.command()
                        )
                        .into())
                    }
                }
            }
            _unexpected_payload => {
                warn!(
                    "[p2p] Handshake with {} failed. Expected Version, got {}.",
                    remote,
                    incoming_raw.command()
                );
                Err(format!(
                    "unexpected message: expected Version, got {}",
                    incoming_raw.command()
                )
                .into())
            }
        }
    }

    /// Synchronize block headers with the connected peer.
    /// Load existing headers from disk and fetch new ones from the peer.
    pub async fn sync_headers(
        &mut self,
        headers_path_str: &str,
        status: Arc<Mutex<rpc::NodeStatus>>,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        info!(
            "[p2p] Starting header sync. Headers file: {}",
            headers_path_str
        );
        let path = Path::new(headers_path_str);
        let mut store = HeaderStore::open(path, self.network)?;

        if store.height()? == 0 {
            info!("[p2p] Header store is empty or at height 0. Appending genesis block for network: {:?}.", self.network);
            let network_genesis_header = genesis_block(self.network).header;
            store.append(&[network_genesis_header])?;
            debug!(
                "[p2p] Genesis block appended. Store height: {}",
                store.height()?
            );
        }

        // Outer loop: continues as long as we get full batches of headers
        'outer_sync_loop: loop {
            let locator = store.locator_hashes();
            debug!(
                "[p2p] Sending GetHeaders with {} locator hashes. First: {:?}, Last: {:?}",
                locator.len(),
                locator.first(),
                locator.last()
            );

            let get_headers_msg = GetHeadersMessage::new(locator.clone(), BlockHash::all_zeros());
            let req = RawNetworkMessage::new(
                self.network.magic(),
                NetworkMessage::GetHeaders(get_headers_msg),
            );
            let bytes = serialize(&req);
            self.stream.write_all(&bytes).await?;

            const MAX_NON_HEADER_MESSAGES_BEFORE_ERROR: usize = 5;
            let mut non_header_messages_count = 0;

            // Inner loop: tries to read the Headers message corresponding to the GetHeaders sent
            'inner_read_loop: loop {
                if non_header_messages_count >= MAX_NON_HEADER_MESSAGES_BEFORE_ERROR {
                    error!("[p2p] Too many non-Headers messages received after GetHeaders. Aborting sync.");
                    return Err("Too many non-Headers messages received after GetHeaders".into());
                }

                match self.read_message().await {
                    // This returns RawNetworkMessage
                    Ok(incoming_raw) => {
                        match incoming_raw.payload() {
                            NetworkMessage::Headers(headers_payload) => {
                                if headers_payload.is_empty() {
                                    info!("[p2p] Received empty Headers message. Header sync complete.");
                                    break 'outer_sync_loop; // Sync is done
                                }
                                debug!(
                                    "[p2p] Received {} headers from peer.",
                                    headers_payload.len()
                                );

                                let mut headers_to_append = headers_payload.clone();
                                if let Some(current_tip_header) = store.tip() {
                                    if let Some(first_received_header) = headers_to_append.first() {
                                        if first_received_header.block_hash()
                                            == current_tip_header.block_hash()
                                        {
                                            debug!("[p2p] First received header {} matches current tip. Removing it from batch.", first_received_header.block_hash());
                                            headers_to_append.remove(0);
                                        }
                                    }
                                }

                                if headers_to_append.is_empty() {
                                    info!("[p2p] No new headers to append after filtering known tip. Header sync likely complete.");
                                    break 'outer_sync_loop; // Sync is done
                                }
                                debug!(
                                    "[p2p] Attempting to append {} new headers.",
                                    headers_to_append.len()
                                );

                                match store.append(&headers_to_append) {
                                    Ok(_) => {
                                        let new_height = store.height()?;
                                        let new_tip_header = store.tip();
                                        info!("[p2p] Successfully appended {} headers. New height: {}", headers_to_append.len(), new_height);

                                        {
                                            let mut s_lock = status.lock().unwrap();
                                            s_lock.block_height = new_height;
                                            if let Some(header) = new_tip_header {
                                                s_lock.current_best_header_hex =
                                                    Some(serialize_hex(&header));
                                                debug!("[p2p] Updated shared status: height={}, tip_hex={}", new_height, s_lock.current_best_header_hex.as_deref().unwrap_or("N/A"));
                                            } else {
                                                s_lock.current_best_header_hex = None;
                                                warn!("[p2p] Store tip is None after append; this should not happen if append was successful with non-empty headers.");
                                            }
                                        }

                                        if headers_payload.len() < 2000 {
                                            info!("[p2p] Received less than 2000 headers ({}), assuming sync is complete for this batch.", headers_payload.len());
                                            break 'outer_sync_loop; // Sync is done
                                        } else {
                                            // Got a full batch, break inner loop to send another GetHeaders
                                            break 'inner_read_loop;
                                        }
                                    }
                                    Err(e) => {
                                        error!("[p2p] Header sync append failed: {}. Current tip: {:?}, First new header: {:?}", e, store.tip().map(|h| h.block_hash()), headers_to_append.first().map(|h| (h.block_hash(), h.prev_blockhash)));
                                        return Err(Box::new(e)); // Propagate storage error
                                    }
                                }
                            }
                            // Handle other message types received while expecting Headers
                            NetworkMessage::Inv(inv_msg) => {
                                debug!("[p2p] Received Inv message ({} items) while expecting Headers. Ignoring and continuing to wait for Headers.", inv_msg.len());
                                non_header_messages_count += 1;
                                // Do not break 'inner_read_loop', continue waiting for Headers
                            }
                            NetworkMessage::Ping(nonce) => {
                                debug!("[p2p] Received Ping({}) while expecting Headers. Responding and continuing to wait for Headers.", nonce);
                                let pong_msg = RawNetworkMessage::new(
                                    self.network.magic(),
                                    NetworkMessage::Pong(*nonce),
                                );
                                if let Err(e) = self.stream.write_all(&serialize(&pong_msg)).await {
                                    error!("[p2p] Failed to send Pong during sync_headers: {}. Aborting sync.", e);
                                    return Err(Box::new(e));
                                }
                                non_header_messages_count += 1;
                            }
                            // Catch-all for other unexpected messages during this specific state
                            other_payload => {
                                warn!("[p2p] Received unexpected message {} while expecting Headers. Ignoring and continuing to wait. Count: {}", incoming_raw.command(), non_header_messages_count + 1);
                                non_header_messages_count += 1;
                                // Do not break 'inner_read_loop', continue waiting for Headers
                            }
                        }
                    }
                    Err(e) => {
                        error!("[p2p] Failed to read message from peer during header sync: {}. Aborting sync.", e);
                        return Err(e); // Network or deserialization error
                    }
                }
            } // End 'inner_read_loop'
        } // End 'outer_sync_loop'

        let final_height = store.height()?;
        let final_tip_header = store.tip();
        info!(
            "[p2p] Finalizing header sync. Final height: {}, Tip: {:?}",
            final_height,
            final_tip_header.map(|h| h.block_hash())
        );
        {
            let mut s_lock = status.lock().unwrap();
            s_lock.block_height = final_height;
            if let Some(header) = final_tip_header {
                s_lock.current_best_header_hex = Some(serialize_hex(&header));
            } else {
                s_lock.current_best_header_hex = None;
            }
        }
        Ok(final_height)
    }

    pub async fn maintain_connection_and_sync_headers(
        mut self,
        headers_path_str: String,
        status: Arc<Mutex<rpc::NodeStatus>>,
        network: Network,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let peer_log_addr = self
            .stream
            .peer_addr()
            .map_or_else(|_| "unknown_peer".to_string(), |a| a.to_string());
        info!("[p2p] ({}) Maintain: Performing handshake.", peer_log_addr);
        self.handshake().await?;

        info!(
            "[p2p] ({}) Maintain: Starting initial header sync.",
            peer_log_addr
        );
        match self
            .sync_headers(&headers_path_str, Arc::clone(&status))
            .await
        {
            Ok(height) => {
                info!(
                    "[p2p] ({}) Maintain: Initial sync completed. Height: {}",
                    peer_log_addr, height
                );
            }
            Err(e) => {
                error!(
                    "[p2p] ({}) Maintain: Initial sync failed: {}. Disconnecting.",
                    peer_log_addr, e
                );
                return Err(e);
            }
        }

        let mut store = HeaderStore::open(Path::new(&headers_path_str), network)?;
        info!("[p2p] ({}) Maintain: Entering message loop.", peer_log_addr);

        loop {
            match self.read_message().await {
                Ok(raw_message) => {
                    debug!(
                        "[p2p] ({}) Maintain: Received message: {}",
                        peer_log_addr,
                        raw_message.command()
                    );
                    match raw_message.payload() {
                        NetworkMessage::Inv(inv_items) => {
                            info!(
                                "[p2p] ({}) Maintain: Received Inv with {} items.",
                                peer_log_addr,
                                inv_items.len()
                            );
                            let mut new_block_hashes_to_request = Vec::<BlockHash>::new();
                            for inventory_item in inv_items {
                                match inventory_item {
                                    Inventory::Block(block_hash)
                                    | Inventory::WitnessBlock(block_hash) => {
                                        new_block_hashes_to_request.push(*block_hash);
                                    }
                                    Inventory::Error => {
                                        debug!(
                                            "[p2p] ({}) Maintain: Received Error inventory item.",
                                            peer_log_addr
                                        );
                                    }
                                    Inventory::Transaction(_)
                                    | Inventory::WTx(_)
                                    | Inventory::WitnessTransaction(_)
                                    | Inventory::CompactBlock(_) => {
                                        debug!("[p2p] ({}) Maintain: Received other known inventory type: {:?}. Ignoring.", peer_log_addr, inventory_item);
                                    }
                                    Inventory::Unknown { inv_type, hash } => {
                                        debug!("[p2p] ({}) Maintain: Received Unknown inventory type: {} with hash (first 4 bytes): {:02x?}", peer_log_addr, inv_type, &hash[..4]);
                                    }
                                }
                            }

                            if !new_block_hashes_to_request.is_empty() {
                                info!("[p2p] ({}) Maintain: Inv contained {} relevant block type(s). Requesting headers.", peer_log_addr, new_block_hashes_to_request.len());
                                let locator = store.locator_hashes();
                                let get_headers_msg =
                                    GetHeadersMessage::new(locator, BlockHash::all_zeros());
                                let req = RawNetworkMessage::new(
                                    network.magic(),
                                    NetworkMessage::GetHeaders(get_headers_msg),
                                );
                                if let Err(e) = self.stream.write_all(&serialize(&req)).await {
                                    error!("[p2p] ({}) Maintain: Failed to send GetHeaders: {}. Disconnecting.", peer_log_addr, e);
                                    return Err(Box::new(e));
                                }
                                debug!(
                                    "[p2p] ({}) Maintain: Sent GetHeaders for INV items.",
                                    peer_log_addr
                                );
                            }
                        }
                        NetworkMessage::Headers(headers_payload) => {
                            if headers_payload.is_empty() {
                                debug!("[p2p] ({}) Maintain: Received empty Headers message. No action needed.", peer_log_addr);
                                continue;
                            }
                            info!(
                                "[p2p] ({}) Maintain: Received {} headers.",
                                peer_log_addr,
                                headers_payload.len()
                            );

                            let mut headers_to_append = headers_payload.clone();
                            if let Some(current_tip_header) = store.tip() {
                                if let Some(first_received_header) = headers_to_append.first() {
                                    if first_received_header.block_hash()
                                        == current_tip_header.block_hash()
                                    {
                                        debug!("[p2p] ({}) Maintain: First received header matches current tip. Removing.", peer_log_addr);
                                        headers_to_append.remove(0);
                                    }
                                }
                            }

                            if headers_to_append.is_empty() {
                                debug!("[p2p] ({}) Maintain: No new headers to append after filtering known tip.", peer_log_addr);
                                continue;
                            }

                            match store.append(&headers_to_append) {
                                Ok(_) => {
                                    let new_height = store.height().map_err(|e| {
                                        error!("[p2p] ({}) Maintain: Failed to get store height after append: {}", peer_log_addr, e);
                                        Box::new(e) as Box<dyn std::error::Error + Send + Sync>
                                    })?;
                                    let new_tip_header = store.tip();
                                    {
                                        let mut s_lock = status.lock().unwrap();
                                        s_lock.block_height = new_height;
                                        if let Some(header) = new_tip_header {
                                            s_lock.current_best_header_hex =
                                                Some(serialize_hex(&header));
                                            info!("[p2p] ({}) Maintain: Updated NodeStatus: height={}, new_tip={}", peer_log_addr, new_height, header.block_hash());
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        "[p2p] ({}) Maintain: Error appending headers: {}",
                                        peer_log_addr, e
                                    );
                                }
                            }
                        }
                        NetworkMessage::Ping(nonce) => {
                            info!(
                                "[p2p] ({}) Maintain: Received Ping({}), sending Pong.",
                                peer_log_addr, nonce
                            );
                            let pong_msg = RawNetworkMessage::new(
                                network.magic(),
                                NetworkMessage::Pong(*nonce),
                            );
                            if let Err(e) = self.stream.write_all(&serialize(&pong_msg)).await {
                                error!(
                                    "[p2p] ({}) Maintain: Failed to send Pong: {}. Disconnecting.",
                                    peer_log_addr, e
                                );
                                return Err(Box::new(e));
                            }
                        }
                        NetworkMessage::Addr(addresses) => {
                            debug!("[p2p] ({}) Maintain: Received Addr message with {} addresses. (Not processed yet)", peer_log_addr, addresses.len());
                        }
                        NetworkMessage::FeeFilter(feerate) => {
                            debug!("[p2p] ({}) Maintain: Received FeeFilter message: {}. (Not processed yet)", peer_log_addr, feerate);
                        }
                        _ => {
                            debug!(
                                "[p2p] ({}) Maintain: Received unhandled message type: {}",
                                peer_log_addr,
                                raw_message.command()
                            );
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "[p2p] ({}) Maintain: Error reading message: {}. Disconnecting.",
                        peer_log_addr, e
                    );
                    return Err(e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::NodeStatus;
    use bitcoin::blockdata::block::Header as BlockHeader;
    use bitcoin::hashes::Hash;
    use bitcoin::TxMerkleNode;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;
    use tokio::net::TcpListener;

    // Helper functions
    fn civiles_merkle_root_from_index(idx: u32) -> TxMerkleNode {
        let mut data = [0u8; 32];
        let bytes = idx.to_le_bytes();
        data[0..bytes.len()].copy_from_slice(&bytes);
        TxMerkleNode::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_slice(&data).unwrap())
    }

    fn solve_pow_for_header(header: &mut BlockHeader) {
        let mut attempts = 0u64;
        loop {
            attempts += 1;
            if attempts % 10_000_000 == 0 {
                // println!(
                //     "PoW attempts: {}M for target {:x} (block: {})
                //     ",
                //     attempts / 1_000_000,
                //     header.bits.to_consensus(),
                //     header.block_hash()
                // );
            }
            let pow_hash = header.validate_pow(header.target());
            match pow_hash {
                Ok(_work) => {
                    // println!(
                    //     "Solved PoW for {}: nonce {}, time {}, hash {}",
                    //     header.block_hash(),
                    //     header.nonce,
                    //     header.time,
                    //     _work
                    // );
                    break;
                }
                Err(_) => {
                    header.nonce = header.nonce.wrapping_add(1);
                    if header.nonce == 0 {
                        header.time = header.time.wrapping_add(1);
                    }
                }
            }
        }
    }

    // Helper to create a Peer instance for tests, assuming Bitcoin network for simplicity
    async fn test_peer(addr: &str) -> Peer {
        Peer::connect(addr, Network::Bitcoin).await.unwrap()
    }

    /// Tests that a basic version handshake completes successfully.
    /// The client initiates the handshake, and the server responds correctly.
    #[tokio::test]
    async fn handshake_succeeds() {
        println!("[Test: handshake_succeeds] Starting...");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        println!("[Test: handshake_succeeds] Listener bound to {}", addr);

        let server_network = Network::Bitcoin; // Ensure server uses same network
        let server = tokio::spawn(async move {
            println!("[Test Server: handshake_succeeds] Waiting for connection...");
            let (mut socket, client_addr) = listener.accept().await.unwrap();
            println!(
                "[Test Server: handshake_succeeds] Accepted connection from {}",
                client_addr
            );
            let mut buf = vec![0u8; 1024];
            println!("[Test Server: handshake_succeeds] Reading Version...");
            let n = socket.read(&mut buf).await.unwrap();
            println!("[Test Server: handshake_succeeds] Read {} bytes.", n);
            let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
            if let NetworkMessage::Version(v) = msg.payload() {
                println!("[Test Server: handshake_succeeds] Received Version. Sending Version...");
                let resp = RawNetworkMessage::new(
                    server_network.magic(),
                    NetworkMessage::Version(v.clone()),
                );
                socket.write_all(&serialize(&resp)).await.unwrap();
                println!("[Test Server: handshake_succeeds] Sent Version. Reading Verack...");
                let n = socket.read(&mut buf).await.unwrap(); // Client Verack
                println!(
                    "[Test Server: handshake_succeeds] Read {} bytes for Verack.",
                    n
                );
                let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
                assert!(matches!(msg.payload(), NetworkMessage::Verack));
                println!("[Test Server: handshake_succeeds] Received Verack. Sending Verack...");
                let resp = RawNetworkMessage::new(server_network.magic(), NetworkMessage::Verack);
                socket.write_all(&serialize(&resp)).await.unwrap();
                println!("[Test Server: handshake_succeeds] Sent Verack. Server task finished.");
            } else {
                println!("[Test Server: handshake_succeeds] Received unexpected message.");
                panic!("unexpected message");
            }
        });

        let mut peer = test_peer(&addr.to_string()).await; // Use helper and await
        println!(
            "[Test: handshake_succeeds] Client connecting to {} and performing handshake...",
            addr
        );
        peer.handshake().await.unwrap();
        println!("[Test: handshake_succeeds] Handshake successful. Waiting for server task...");
        server.await.unwrap();
        println!("[Test: handshake_succeeds] Server task finished. Test complete.");
    }

    /// Tests that the handshake fails if the server does not send a Verack message
    /// after the version exchange. Instead, it sends a Ping.
    #[tokio::test]
    async fn handshake_requires_verack() {
        println!("[Test: handshake_requires_verack] Starting...");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        println!(
            "[Test: handshake_requires_verack] Listener bound to {}",
            addr
        );

        let server_network = Network::Bitcoin; // Ensure server uses same network
        let server = tokio::spawn(async move {
            println!("[Test Server: handshake_requires_verack] Waiting for connection...");
            let (mut socket, client_addr) = listener.accept().await.unwrap();
            println!(
                "[Test Server: handshake_requires_verack] Accepted connection from {}",
                client_addr
            );
            let mut buf = vec![0u8; 1024];
            println!("[Test Server: handshake_requires_verack] Reading Version...");
            let n = socket.read(&mut buf).await.unwrap();
            println!("[Test Server: handshake_requires_verack] Read {} bytes.", n);
            let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
            if let NetworkMessage::Version(v) = msg.payload() {
                println!(
                    "[Test Server: handshake_requires_verack] Received Version. Sending Version..."
                );
                let resp = RawNetworkMessage::new(
                    server_network.magic(),
                    NetworkMessage::Version(v.clone()),
                );
                socket.write_all(&serialize(&resp)).await.unwrap();
                println!("[Test Server: handshake_requires_verack] Sent Version. Reading client response...");
                let _ = socket.read(&mut buf).await.unwrap(); // Client Verack
                println!("[Test Server: handshake_requires_verack] Received client response (expecting Verack).");
                // send ping instead of verack
                println!(
                    "[Test Server: handshake_requires_verack] Sending Ping instead of Verack..."
                );
                let resp = RawNetworkMessage::new(server_network.magic(), NetworkMessage::Ping(0));
                socket.write_all(&serialize(&resp)).await.unwrap();
                println!(
                    "[Test Server: handshake_requires_verack] Sent Ping. Server task finished."
                );
            }
        });

        let mut peer = test_peer(&addr.to_string()).await; // Use helper and await
        println!("[Test: handshake_requires_verack] Client connecting to {} and performing handshake (expecting failure)...", addr);
        let handshake_result = peer.handshake().await;
        println!(
            "[Test: handshake_requires_verack] Client handshake finished. Result: {:?}",
            handshake_result
        );
        assert!(handshake_result.is_err());
        println!("[Test: handshake_requires_verack] Assertion passed. Waiting for server task...");
        // We don't join the server here as it might panic if client disconnects early
        // or test might finish before server does, which is fine for this error case.
        let _ = server.await; // Allow server to finish or error out
        println!("[Test: handshake_requires_verack] Server task finished. Test complete.");
    }

    /// Tests that the handshake can handle messages (Version, Verack)
    /// sent in multiple TCP segments.
    #[tokio::test]
    async fn handshake_multi_read() {
        println!("[Test: handshake_multi_read] Starting...");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        println!("[Test: handshake_multi_read] Listener bound to {}", addr);

        let server = tokio::spawn(async move {
            println!("[Test Server: handshake_multi_read] Waiting for connection...");
            let (mut socket, client_addr) = listener.accept().await.unwrap();
            println!(
                "[Test Server: handshake_multi_read] Accepted connection from {}",
                client_addr
            );
            let mut buf = vec![0u8; 1024];
            println!("[Test Server: handshake_multi_read] Reading Version...");
            let n = socket.read(&mut buf).await.unwrap();
            println!("[Test Server: handshake_multi_read] Read {} bytes.", n);
            let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
            if let NetworkMessage::Version(v) = msg.payload() {
                println!("[Test Server: handshake_multi_read] Received Version. Sending Version in parts...");
                let resp = RawNetworkMessage::new(
                    Network::Bitcoin.magic(),
                    NetworkMessage::Version(v.clone()),
                );
                let bytes = serialize(&resp);
                socket.write_all(&bytes[..10]).await.unwrap();
                socket.write_all(&bytes[10..]).await.unwrap();
                println!(
                    "[Test Server: handshake_multi_read] Sent Version in parts. Reading Verack..."
                );

                let n = socket.read(&mut buf).await.unwrap();
                println!(
                    "[Test Server: handshake_multi_read] Read {} bytes for Verack.",
                    n
                );
                let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
                assert!(matches!(msg.payload(), NetworkMessage::Verack));
                println!("[Test Server: handshake_multi_read] Received Verack. Sending Verack in parts...");
                let resp = RawNetworkMessage::new(Network::Bitcoin.magic(), NetworkMessage::Verack);
                let bytes = serialize(&resp);
                socket.write_all(&bytes[..14]).await.unwrap();
                socket.write_all(&bytes[14..]).await.unwrap();
                println!("[Test Server: handshake_multi_read] Sent Verack in parts. Server task finished.");
            }
        });

        let mut peer = Peer::connect(&addr.to_string(), Network::Bitcoin)
            .await
            .unwrap();
        println!("[Test: handshake_multi_read] Client connecting to {} and performing handshake with multi-read expectation...", addr);
        peer.handshake().await.unwrap();
        println!("[Test: handshake_multi_read] Handshake successful. Waiting for server task...");
        server.await.unwrap();
        println!("[Test: handshake_multi_read] Server task finished. Test complete.");
    }

    /// Tests header synchronization when the peer has no new headers to offer.
    /// The client should connect, handshake, request headers, and receive an empty headers message.
    #[tokio::test]
    async fn sync_headers_empty() {
        println!("[Test: sync_headers_empty] Starting...");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap().to_string();
        println!(
            "[Test: sync_headers_empty] Listener bound to {}",
            server_addr
        );

        // Server task: accepts one connection, performs handshake, and sends headers
        let server_handle = tokio::spawn(async move {
            println!(
                "[Test Server: sync_headers_empty] Server task started. Waiting for connection..."
            );
            let (socket, _client_addr) = listener.accept().await.expect("server accept failed");
            println!("[Test Server: sync_headers_empty] Accepted connection.");

            // Perform handshake (reads version, sends version+verack, reads verack)
            let mut peer = Peer {
                stream: socket,
                network: Network::Regtest,
            };
            peer.handshake().await.expect("server handshake failed");
            println!("[Test Server: sync_headers_empty] Handshake complete.");

            // Expect GetHeaders, respond with empty Headers
            println!("[Test Server: sync_headers_empty] Reading client GetHeaders...");
            let get_headers_msg = peer
                .read_message()
                .await
                .expect("server failed to read GetHeaders");
            match get_headers_msg.payload() {
                NetworkMessage::GetHeaders(_) => {
                    println!("[Test Server: sync_headers_empty] Received GetHeaders.");
                }
                _ => {
                    panic!("Test Server: sync_headers_empty received unexpected message after handshake: {:?}", get_headers_msg.payload());
                }
            }

            println!("[Test Server: sync_headers_empty] Sending empty Headers...");
            let empty_headers_msg = NetworkMessage::Headers(Vec::new());
            let raw_empty_headers =
                RawNetworkMessage::new(Network::Regtest.magic(), empty_headers_msg);
            peer.stream
                .write_all(&serialize(&raw_empty_headers))
                .await
                .expect("server send empty headers failed");
            println!("[Test Server: sync_headers_empty] Sent empty Headers. Server task finished.");

            // Keep the connection open briefly before dropping
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            println!("[Test Server: sync_headers_empty] Server socket dropped.");
        });

        let _network = Network::Regtest;
        let temp_dir = TempDir::new().unwrap();
        let headers_path = temp_dir.path().join("test_sync_empty.bin");
        let headers_path_str = headers_path.to_str().unwrap().to_string();
        println!(
            "[Test: sync_headers_empty] Using headers file: {}",
            headers_path_str
        );

        let mut client_peer = Peer::connect(&server_addr, Network::Regtest)
            .await
            .expect("client connect failed");
        println!("[Test: sync_headers_empty] Client peer connected.");

        // Perform handshake before syncing headers
        client_peer
            .handshake()
            .await
            .expect("client handshake failed");
        println!("[Test: sync_headers_empty] Client handshake complete.");

        let status = Arc::new(Mutex::new(NodeStatus {
            block_height: 0,
            peers: Vec::new(),
            current_best_header_hex: None,
        }));
        let status_clone = Arc::clone(&status);
        println!("[Test: sync_headers_empty] Client status initialized.");

        let client_handle = tokio::spawn(async move {
            println!("[Test Client: sync_headers_empty] Client task started. Syncing headers...");
            // sync_headers does not perform handshake internally
            let result = client_peer
                .sync_headers(&headers_path_str, status_clone)
                .await
                .expect("sync_headers failed in test"); // Use expect to unwrap the inner result
            println!(
                "[Test Client: sync_headers_empty] sync_headers finished. Result: {:?}",
                result
            );
            result
        });

        println!("[Test: sync_headers_empty] Waiting for client and server tasks to complete...");
        // Wait for both client and server tasks to complete or timeout
        let results = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            // Increased timeout to 5 seconds
            // Create a new async block (a future) to pass to timeout
            let client_result = client_handle.await;
            let server_result = server_handle.await;
            (client_result, server_result) // Return the tuple of Results
        })
        .await
        .expect("sync_headers_empty test timed out");

        let (client_result_outer, server_task_result) = results;

        assert!(
            client_result_outer.is_ok(),
            "Client task failed: {:?}",
            client_result_outer.err()
        );
        assert!(
            server_task_result.is_ok(),
            "Server task failed: {:?}",
            server_task_result.err()
        );

        let client_inner_result = client_result_outer.unwrap(); // This should be the u64 height
        assert_eq!(client_inner_result, 0); // Adjusted expectation for 0-indexed height

        println!("[Test: sync_headers_empty] Assertions passed. Test complete.");
    }

    /// Tests header synchronization when the peer offers one new header.
    /// The client should connect, handshake, request headers, receive one header, store it,
    /// and then receive an empty headers message on the next request.
    #[tokio::test]
    async fn sync_headers_multi_read() {
        println!("[Test: sync_headers_multi_read] Starting...");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap().to_string();
        println!(
            "[Test: sync_headers_multi_read] Listener bound to {}",
            server_addr
        );

        // Server task: accepts one connection, performs handshake, and sends headers
        let server_handle = tokio::spawn(async move {
            println!("[Test Server: sync_headers_multi_read] Server task started. Waiting for connection...");
            let (socket, _client_addr) = listener.accept().await.unwrap();
            println!("[Test Server: sync_headers_multi_read] Accepted connection.");

            // Perform handshake
            let mut peer = Peer {
                stream: socket,
                network: Network::Regtest,
            };
            peer.handshake().await.expect("server handshake failed");
            println!("[Test Server: sync_headers_multi_read] Handshake complete.");

            // Read the client's initial GetHeaders message
            println!("[Test Server: sync_headers_multi_read] Reading client GetHeaders...");
            let get_headers_msg = peer
                .read_message()
                .await
                .expect("server failed to read initial GetHeaders");
            match get_headers_msg.payload() {
                NetworkMessage::GetHeaders(_) => {
                    println!("[Test Server: sync_headers_multi_read] Received initial GetHeaders.");
                }
                _ => {
                    panic!("Test Server: sync_headers_multi_read received unexpected message after handshake: {:?}", get_headers_msg.payload());
                }
            }

            let network = Network::Regtest;
            let genesis = genesis_block(network).header;
            let mut h1 = genesis;
            h1.prev_blockhash = genesis.block_hash();
            h1.merkle_root = civiles_merkle_root_from_index(1);
            h1.time = genesis.time + 1;
            h1.bits = network.params().max_attainable_target.to_compact_lossy();
            h1.nonce = 0;
            solve_pow_for_header(&mut h1);

            // Send first Headers message (1 header)
            println!("[Test Server: sync_headers_multi_read] Sending first Headers (1 header)...");
            let headers_msg1 = NetworkMessage::Headers(vec![h1]);
            let raw_headers1 = RawNetworkMessage::new(Network::Regtest.magic(), headers_msg1);
            peer.stream
                .write_all(&serialize(&raw_headers1))
                .await
                .expect("server send first headers failed");
            println!("[Test Server: sync_headers_multi_read] Sent first Headers.");

            // Send empty Headers message
            println!("[Test Server: sync_headers_multi_read] Sending empty Headers...");
            let empty_headers_msg = NetworkMessage::Headers(Vec::new());
            let raw_empty_headers =
                RawNetworkMessage::new(Network::Regtest.magic(), empty_headers_msg);
            peer.stream
                .write_all(&serialize(&raw_empty_headers))
                .await
                .expect("server send empty headers failed");
            println!(
                "[Test Server: sync_headers_multi_read] Sent empty Headers. Server task finished."
            );

            // Keep the connection open briefly before dropping
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            println!("[Test Server: sync_headers_multi_read] Server socket dropped.");
        });

        let network = Network::Regtest;
        let temp_dir = TempDir::new().unwrap();
        let headers_path = temp_dir.path().join("test_sync_multi.bin");
        let headers_path_str = headers_path.to_str().unwrap().to_string();
        println!(
            "[Test: sync_headers_multi_read] Using headers file: {}",
            headers_path_str
        );

        let mut client_peer = Peer::connect(&server_addr, network)
            .await
            .expect("client connect failed");
        println!("[Test: sync_headers_multi_read] Client peer connected.");

        // Perform handshake before syncing headers
        client_peer
            .handshake()
            .await
            .expect("client handshake failed");
        println!("[Test: sync_headers_multi_read] Client handshake complete.");

        let status = Arc::new(Mutex::new(NodeStatus {
            block_height: 0, // Initial height
            peers: Vec::new(),
            current_best_header_hex: None,
        }));
        let status_clone = Arc::clone(&status);
        println!("[Test: sync_headers_multi_read] Client peer created, status initialized.");

        let client_handle = tokio::spawn(async move {
            println!(
                "[Test Client: sync_headers_multi_read] Client task started. Syncing headers..."
            );
            // sync_headers does not perform handshake internally
            let result = client_peer
                .sync_headers(&headers_path_str, status_clone)
                .await
                .expect("sync_headers failed in test"); // Use expect to unwrap the inner result
            println!(
                "[Test Client: sync_headers_multi_read] sync_headers finished. Result: {:?}",
                result
            );
            result
        });

        println!(
            "[Test: sync_headers_multi_read] Waiting for client and server tasks to complete..."
        );
        // Wait for both client and server tasks to complete or timeout
        let results = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            // Increased timeout to 5 seconds
            // Create a new async block (a future) to pass to timeout
            let client_result = client_handle.await;
            let server_result = server_handle.await;
            (client_result, server_result) // Return the tuple of Results
        })
        .await
        .expect("sync_headers_multi_read test timed out");

        let (client_result_outer, server_task_result) = results;

        assert!(
            client_result_outer.is_ok(),
            "Client task failed: {:?}",
            client_result_outer.err()
        );
        assert!(
            server_task_result.is_ok(),
            "Server task failed: {:?}",
            server_task_result.err()
        );

        let height_result = client_result_outer.unwrap(); // This should be the u64 height
                                                          // Genesis (height 0) + h1 (height 1). So, final height is 1.
        assert_eq!(height_result, 1);

        println!("[Test: sync_headers_multi_read] Assertions passed. Test complete.");
    }

    /// Tests the `maintain_connection_and_sync_headers` function for basic operation.
    /// It checks that the initial handshake and header sync (which should result in no new headers)
    /// complete, and that the client and server tasks finish cleanly.
    #[tokio::test]
    async fn maintain_connection_and_sync_headers_logic() {
        println!("[Test: maintain_connection_and_sync_headers_logic] Starting...");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap().to_string();
        println!(
            "[Test: maintain_connection_and_sync_headers_logic] Listener bound to {}",
            server_addr
        );

        // Server task: accepts one connection, performs handshake, and handles messages
        let server_handle = tokio::spawn(async move {
            println!("[Test Server: maintain_connection_and_sync_headers_logic {}] Waiting for connection...", listener.local_addr().unwrap());
            let (socket, _client_addr) = listener.accept().await.expect("server accept failed");
            println!("[Test Server: maintain_connection_and_sync_headers_logic {}] Accepted connection from {}", listener.local_addr().unwrap(), _client_addr);

            // Perform handshake
            let mut peer = Peer {
                stream: socket,
                network: Network::Regtest,
            };
            peer.handshake().await.expect("server handshake failed");
            println!(
                "[Test Server: maintain_connection_and_sync_headers_logic {}] Handshake complete.",
                peer.stream.local_addr().unwrap()
            );

            // Handle messages in a loop (expect GetHeaders, send empty Headers, then break)
            match peer.read_message().await {
                Ok(raw_msg) => {
                    println!("[Test Server: maintain_connection_and_sync_headers_logic {}] Received message: {}", peer.stream.local_addr().unwrap(), raw_msg.command());
                    match raw_msg.payload() {
                        NetworkMessage::GetHeaders(_get_headers) => {
                            println!("[Test Server: maintain_connection_and_sync_headers_logic {}] Received GetHeaders.", peer.stream.local_addr().unwrap());
                            println!("[Test Server: maintain_connection_and_sync_headers_logic {}] Sending empty Headers...", peer.stream.local_addr().unwrap());
                            let empty_headers_msg = NetworkMessage::Headers(Vec::new());
                            let raw_empty_headers =
                                RawNetworkMessage::new(Network::Regtest.magic(), empty_headers_msg);
                            peer.stream
                                .write_all(&serialize(&raw_empty_headers))
                                .await
                                .expect("server send empty headers failed");
                            println!("[Test Server: maintain_connection_and_sync_headers_logic {}] Sent empty Headers.", peer.stream.local_addr().unwrap());
                        }
                        _other_msg => {
                            panic!("[Test Server: maintain_connection_and_sync_headers_logic {}] Received unexpected message type after handshake: {:?}", peer.stream.local_addr().unwrap(), _other_msg);
                        }
                    }
                }
                Err(e) => {
                    panic!("[Test Server: maintain_connection_and_sync_headers_logic {}] Error reading message after handshake: {}", peer.stream.local_addr().unwrap(), e);
                }
            }

            println!("[Test Server: maintain_connection_and_sync_headers_logic {}] Server task finished.", peer.stream.local_addr().unwrap());
            Ok(())
        });

        let network = Network::Regtest;
        let temp_dir = TempDir::new().unwrap();
        let headers_path_str = temp_dir
            .path()
            .join("headers_maintain.bin")
            .to_string_lossy()
            .into_owned();
        println!(
            "[Test: maintain_connection_and_sync_headers_logic] Using headers file: {}",
            headers_path_str
        );

        let status = Arc::new(Mutex::new(NodeStatus {
            block_height: 0, // Initial height
            peers: Vec::new(),
            current_best_header_hex: None,
        }));
        let _status_clone = Arc::clone(&status);
        println!("[Test: maintain_connection_and_sync_headers_logic] Client status initialized.");

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        println!("[Test: maintain_connection_and_sync_headers_logic] Client starting connection and maintenance task.");

        let client_handle = tokio::spawn(async move {
            println!(
                "[Test Client: maintain_connection_and_sync_headers_logic] Client task started."
            );
            let peer = Peer::connect(&server_addr, network)
                .await
                .expect("client connect failed");
            println!(
                "[Test Client: maintain_connection_and_sync_headers_logic] Connected to {}.",
                server_addr
            );
            // maintain_connection_and_sync_headers performs its own handshake internally
            println!("[Test Client: maintain_connection_and_sync_headers_logic] Calling maintain_connection_and_sync_headers...");
            let result = peer
                .maintain_connection_and_sync_headers(headers_path_str, status, network)
                .await;
            println!("[Test Client: maintain_connection_and_sync_headers_logic] maintain_connection_and_sync_headers returned with result: {:?}.", result);
            result
        });

        println!("[Test: maintain_connection_and_sync_headers_logic] Waiting for client task to complete...");
        let client_task_result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client_handle,
        )
        .await
        .expect(
            "maintain_connection_and_sync_headers_logic test timed out waiting for client task",
        );

        let _client_join_result = client_task_result.expect("Client task panicked");

        println!("[Test: maintain_connection_and_sync_headers_logic] Waiting for server task to complete...");
        let server_task_result = tokio::time::timeout(std::time::Duration::from_secs(5), server_handle).await.expect("maintain_connection_and_sync_headers_logic server task timed out waiting for server task");

        let server_join_result: Result<(), Box<dyn std::error::Error + Send + Sync>> =
            server_task_result.expect("Server task panicked");
        server_join_result.expect("Server task returned an error");

        println!("[Test: maintain_connection_and_sync_headers_logic] Test complete.");
    }
}
