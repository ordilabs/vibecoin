use log::{debug, error, info, trace, warn};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::storage::HeaderStore;
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message_blockdata::GetHeadersMessage;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::{message::NetworkMessage, message::RawNetworkMessage};
use bitcoin::Network;

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
        trace!("Reading message header (24 bytes)...");
        let mut header_buf = [0u8; 24];
        self.stream.read_exact(&mut header_buf).await?;
        let magic = u32::from_le_bytes(header_buf[0..4].try_into().unwrap());
        let command_bytes: [u8; 12] = header_buf[4..16].try_into().unwrap();
        let command = std::str::from_utf8(&command_bytes)?.trim_end_matches('\0');
        let payload_len = u32::from_le_bytes(header_buf[16..20].try_into().unwrap()) as usize;
        let checksum = u32::from_le_bytes(header_buf[20..24].try_into().unwrap());
        debug!(
            "Received message header: magic=0x{:08x}, command='{}', len={}, checksum=0x{:08x}",
            magic, command, payload_len, checksum
        );

        trace!("Reading message payload ({} bytes)...", payload_len);
        let mut payload = vec![0u8; payload_len];
        self.stream.read_exact(&mut payload).await?;
        trace!("Read payload ({} bytes). Deserializing...", payload_len);

        let mut full_message_bytes = Vec::with_capacity(24 + payload_len);
        full_message_bytes.extend_from_slice(&header_buf);
        full_message_bytes.extend_from_slice(&payload);

        // TODO: Add checksum verification here if needed bitcoin::util::hash::bitcoin_checksum

        match bitcoin::consensus::encode::deserialize::<RawNetworkMessage>(&full_message_bytes) {
            Ok(raw_msg) => {
                debug!(
                    "Successfully deserialized message: {:?}",
                    raw_msg.payload().command()
                );
                Ok(raw_msg)
            }
            Err(e) => {
                error!("Failed to deserialize message: {}", e);
                Err(e.into())
            }
        }
    }

    /// Perform the Bitcoin version handshake.
    pub async fn handshake(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!(
            "Initiating handshake with peer: {}",
            self.stream.peer_addr()?
        );
        let local = self.stream.local_addr()?;
        let remote = self.stream.peer_addr()?;

        let local_addr = local;
        let peer_original_addr = remote;

        // Protocol version 70016 is used for compatibility with modern bitcoind nodes (e.g., v0.21+).
        // The `bitcoin` crate (v0.32.6) defaults to an older protocol version (70001)
        // which can lead to issues like receiving unexpected 'alert' messages or handshake failures.
        // TODO: Consider making this configurable or dynamically chosen based on network type or capabilities.
        let version_to_send = 70016;
        debug!(
            "Overriding protocol version for outgoing Version message to: {}",
            version_to_send
        );

        let version_payload = VersionMessage {
            version: version_to_send,
            services: ServiceFlags::NETWORK,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64,
            receiver: Address::new(&peer_original_addr, ServiceFlags::NONE),
            sender: Address::new(&local_addr, ServiceFlags::NONE),
            nonce: rand::random(),
            user_agent: "/vibecoin:0.1.0/".into(),
            start_height: 0,
            relay: false,
        };

        let msg = RawNetworkMessage::new(
            self.network.magic(),
            NetworkMessage::Version(version_payload),
        );
        debug!("Sending Version message: {:?}", msg.payload());
        let bytes = serialize(&msg);
        self.stream.write_all(&bytes).await?;

        // Read remote version message
        debug!("Waiting for peer's Version message...");
        let incoming = self.read_message().await?;
        match incoming.payload() {
            NetworkMessage::Version(peer_version) => {
                debug!("Received Version message from peer: {:?}", peer_version);
                // Send verack
                let verack = RawNetworkMessage::new(self.network.magic(), NetworkMessage::Verack);
                debug!("Sending Verack message.");
                let bytes = serialize(&verack);
                self.stream.write_all(&bytes).await?;

                // Wait for peer verack, possibly skipping other messages
                debug!("Waiting for peer's Verack message, potentially skipping other messages like wtxidrelay...");
                loop {
                    let reply = self.read_message().await?;
                    match reply.payload() {
                        NetworkMessage::Verack => {
                            info!(
                                "Handshake successful with peer: {}",
                                self.stream.peer_addr()?
                            );
                            return Ok(()); // Handshake complete
                        }
                        NetworkMessage::WtxidRelay => {
                            debug!("Received and ignored WtxidRelay message from peer.");
                            // If vibecoin were to support WTXID relay, it might send its own WtxidRelay here.
                        }
                        NetworkMessage::SendAddrV2 => {
                            // BIP155
                            debug!("Received and ignored SendAddrV2 message from peer.");
                            // If vibecoin were to support SendAddrV2, it would process this.
                        }
                        NetworkMessage::FeeFilter(feerate) => {
                            // BIP133
                            debug!(
                                "Received and ignored FeeFilter message: feerate={:?}",
                                feerate
                            );
                        }
                        NetworkMessage::GetHeaders(get_headers_payload) => {
                            // Peer is requesting headers from us. This can happen.
                            // We are currently focused on syncing *from* the peer, so we ignore this for now.
                            debug!(
                                "Received and ignored GetHeaders message from peer: {:?}",
                                get_headers_payload
                            );
                        }
                        // Potentially handle other non-essential messages here if they appear
                        unexpected_msg => {
                            warn!(
                                "Unexpected message during handshake (expected Verack, got {:?}): {:?}",
                                unexpected_msg.command(),
                                unexpected_msg
                            );
                            return Err(format!(
                                "unexpected message {:?} while waiting for Verack",
                                unexpected_msg.command()
                            )
                            .into());
                        }
                    }
                }
            }
            unexpected_msg => {
                warn!(
                    "Unexpected message during handshake (expected Version): {:?}",
                    unexpected_msg.command()
                );
                Err("unexpected message during handshake (expected Version)".into())
            }
        }
    }

    /// Synchronize block headers with the connected peer.
    /// Load existing headers from disk and fetch new ones from the peer.
    pub async fn sync_headers(
        &mut self,
        path: &str,
        network: Network,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        info!(
            "Starting header sync from peer: {}",
            self.stream.peer_addr()?
        );
        let mut store = HeaderStore::open(path, network)?;
        info!(
            "Header store opened. Current height: {}. Path: {}",
            store.height(),
            path
        );
        let mut locator = store.locator_hashes();
        debug!(
            "Initial locator hashes: {:?}",
            locator.iter().map(|h| h.to_string()).collect::<Vec<_>>()
        );

        // Using protocol version 70016 for GetHeaders message, consistent with the main handshake version.
        let get_headers_protocol_version = 70016;

        // Outer loop for fetching batches of headers
        loop {
            debug!(
                "Using protocol version for outgoing GetHeaders message: {}",
                get_headers_protocol_version
            );
            let get_headers_msg_payload = GetHeadersMessage {
                version: get_headers_protocol_version, // Use overridden version
                locator_hashes: locator.clone(),
                stop_hash: bitcoin::BlockHash::all_zeros(),
            };
            let req_msg = RawNetworkMessage::new(
                self.network.magic(),
                NetworkMessage::GetHeaders(get_headers_msg_payload),
            );
            debug!(
                "Sending GetHeaders message with {} locators. First locator: {:?}, Stop hash: {:?}",
                locator.len(),
                locator.first().map(|h| h.to_string()),
                bitcoin::BlockHash::all_zeros().to_string()
            );
            trace!("GetHeaders message details: {:?}", req_msg.payload());
            let bytes = serialize(&req_msg);
            self.stream.write_all(&bytes).await?;

            // Inner loop to read messages until we get Headers for the current request or a definitive end/error
            loop {
                debug!("Waiting for Headers response or other messages (e.g., sendcmpct, ping, feefilter)...");
                let incoming = self.read_message().await?;
                match incoming.payload() {
                    NetworkMessage::Headers(headers) => {
                        info!("Received Headers message with {} headers.", headers.len());

                        if headers.is_empty() {
                            info!("Received 0 headers, sync considered complete.");
                            info!("Header sync finished. Final height: {}", store.height());
                            return Ok(store.height()); // Exit sync_headers entirely
                        }
                        debug!("Appending {} headers to store...", headers.len());
                        match store.append(&headers) {
                            Ok(_) => {
                                info!(
                                    "Successfully appended {} headers. New store height: {}",
                                    headers.len(),
                                    store.height()
                                );
                                locator = store.locator_hashes();
                                debug!(
                                    "Updated locator hashes. First locator: {:?}",
                                    locator.first().map(|h| h.to_string())
                                );
                                break; // Break from inner message loop to send next GetHeaders with new locator
                            }
                            Err(e) => {
                                error!("Error appending headers to store: {}", e);
                                return Err(e.into());
                            }
                        }
                    }
                    NetworkMessage::SendCmpct(send_cmpct_payload) => {
                        // BIP152
                        debug!(
                            "Received and ignored SendCmpct message: {:?}",
                            send_cmpct_payload
                        );
                    }
                    NetworkMessage::Ping(nonce) => {
                        // Handle Ping messages
                        debug!("Received Ping(nonce={}), sending Pong.", nonce);
                        let pong_msg = RawNetworkMessage::new(
                            self.network.magic(),
                            NetworkMessage::Pong(*nonce),
                        );
                        let bytes = serialize(&pong_msg);
                        if let Err(e) = self.stream.write_all(&bytes).await {
                            warn!("Error sending Pong: {}. Continuing header sync.", e);
                        }
                    }
                    NetworkMessage::FeeFilter(feerate) => {
                        // BIP133
                        debug!(
                            "Received and ignored FeeFilter message: feerate={:?}",
                            feerate
                        );
                    }
                    NetworkMessage::GetHeaders(get_headers_payload) => {
                        // Peer is requesting headers from us. This can happen.
                        // We are currently focused on syncing *from* the peer, so we ignore this for now.
                        debug!(
                            "Received and ignored GetHeaders message from peer: {:?}",
                            get_headers_payload
                        );
                    }
                    // Add other messages to explicitly ignore if they commonly appear post-handshake before headers
                    // e.g., Addr, Inv, NotFound, etc. For now, these will fall into unexpected_msg.
                    unexpected_msg => {
                        warn!(
                            "Unexpected message while waiting for Headers (got {:?}): {:?}. Potential stall or error.",
                            unexpected_msg.command(),
                            unexpected_msg
                        );
                        // Decide if this is a hard error. Some unexpected messages might be ignorable.
                        // For now, we error out, as we strictly expect Headers or known ignorable messages.
                        return Err(format!(
                            "unexpected message {:?} while waiting for Headers",
                            unexpected_msg.command()
                        )
                        .into());
                    }
                }
            } // End of inner message-reading loop
              // If we break from inner loop, it means we processed a non-empty batch of headers
              // and the outer loop will continue to send another GetHeaders request.
        } // End of outer loop (for fetching batches of headers)
          // Code here should ideally be unreachable if sync completes successfully via the return in Headers(empty) case.
          // info!("Header sync finished. Final height: {}", store.height());
          // Ok(store.height())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::encode::deserialize;
    use tokio::net::TcpListener;

    // Helper function for tests
    fn test_network() -> Network {
        Network::Regtest // Or any other network suitable for tests
    }

    #[tokio::test]
    async fn handshake_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let network = test_network();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
            if let NetworkMessage::Version(v) = msg.payload() {
                assert_eq!(*msg.magic(), network.magic());
                let resp =
                    RawNetworkMessage::new(network.magic(), NetworkMessage::Version(v.clone()));
                socket.write_all(&serialize(&resp)).await.unwrap();
                let n = socket.read(&mut buf).await.unwrap();
                let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
                assert!(matches!(msg.payload(), NetworkMessage::Verack));
                assert_eq!(*msg.magic(), network.magic());
                let resp = RawNetworkMessage::new(network.magic(), NetworkMessage::Verack);
                socket.write_all(&serialize(&resp)).await.unwrap();
            } else {
                panic!("unexpected message");
            }
        });

        let mut peer = Peer::connect(&addr.to_string(), network).unwrap();
        peer.handshake().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn sync_headers_empty() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let network = test_network();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
            if let NetworkMessage::Version(v) = msg.payload() {
                assert_eq!(*msg.magic(), network.magic());
                let resp =
                    RawNetworkMessage::new(network.magic(), NetworkMessage::Version(v.clone()));
                socket.write_all(&serialize(&resp)).await.unwrap();
                let _ = socket.read(&mut buf).await.unwrap();
                let verack_resp = RawNetworkMessage::new(network.magic(), NetworkMessage::Verack);
                socket.write_all(&serialize(&verack_resp)).await.unwrap();
            }

            let mut buf = vec![0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
            if matches!(msg.payload(), NetworkMessage::GetHeaders(_)) {
                assert_eq!(*msg.magic(), network.magic());
                let resp = RawNetworkMessage::new(network.magic(), NetworkMessage::Headers(vec![]));
                socket.write_all(&serialize(&resp)).await.unwrap();
            }
        });

        let mut peer = Peer::connect(&addr.to_string(), network).unwrap();
        peer.handshake().await.unwrap();
        let h = peer
            .sync_headers("headers_sync_empty.bin", network)
            .await
            .unwrap();
        assert_eq!(h, 0);
        let _ = std::fs::remove_file("headers_sync_empty.bin");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_requires_verack() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let network = test_network();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
            if let NetworkMessage::Version(v) = msg.payload() {
                assert_eq!(*msg.magic(), network.magic());
                let resp =
                    RawNetworkMessage::new(network.magic(), NetworkMessage::Version(v.clone()));
                socket.write_all(&serialize(&resp)).await.unwrap();
                let _ = socket.read(&mut buf).await.unwrap();
                let ping_resp = RawNetworkMessage::new(network.magic(), NetworkMessage::Ping(0));
                socket.write_all(&serialize(&ping_resp)).await.unwrap();
            }
        });

        let mut peer = Peer::connect(&addr.to_string(), network).unwrap();
        assert!(peer.handshake().await.is_err());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_multi_read() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let network = test_network();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
            if let NetworkMessage::Version(v) = msg.payload() {
                assert_eq!(*msg.magic(), network.magic());
                let resp =
                    RawNetworkMessage::new(network.magic(), NetworkMessage::Version(v.clone()));
                let bytes = serialize(&resp);
                socket.write_all(&bytes[..10]).await.unwrap();
                socket.write_all(&bytes[10..]).await.unwrap();

                let n = socket.read(&mut buf).await.unwrap();
                let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
                assert!(matches!(msg.payload(), NetworkMessage::Verack));
                assert_eq!(*msg.magic(), network.magic());
                let verack_resp = RawNetworkMessage::new(network.magic(), NetworkMessage::Verack);
                let bytes_verack = serialize(&verack_resp);
                socket.write_all(&bytes_verack[..14]).await.unwrap();
                socket.write_all(&bytes_verack[14..]).await.unwrap();
            }
        });

        let mut peer = Peer::connect(&addr.to_string(), network).unwrap();
        peer.handshake().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn sync_headers_multi_read() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let network = test_network();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
            if let NetworkMessage::Version(v) = msg.payload() {
                assert_eq!(*msg.magic(), network.magic());
                let resp =
                    RawNetworkMessage::new(network.magic(), NetworkMessage::Version(v.clone()));
                socket.write_all(&serialize(&resp)).await.unwrap();
                let n = socket.read(&mut buf).await.unwrap();
                let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
                assert!(matches!(msg.payload(), NetworkMessage::Verack));
                assert_eq!(*msg.magic(), network.magic());
                let resp = RawNetworkMessage::new(network.magic(), NetworkMessage::Verack);
                let bytes = serialize(&resp);
                socket.write_all(&bytes[..8]).await.unwrap();
                socket.write_all(&bytes[8..]).await.unwrap();
            }

            let mut buf = vec![0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
            if matches!(msg.payload(), NetworkMessage::GetHeaders(_)) {
                assert_eq!(*msg.magic(), network.magic());
                let resp = RawNetworkMessage::new(network.magic(), NetworkMessage::Headers(vec![]));
                let bytes = serialize(&resp);
                socket.write_all(&bytes[..5]).await.unwrap();
                socket.write_all(&bytes[5..20]).await.unwrap();
                socket.write_all(&bytes[20..]).await.unwrap();
            }
        });

        let mut peer = Peer::connect(&addr.to_string(), network).unwrap();
        peer.handshake().await.unwrap();
        let h = peer
            .sync_headers("headers_multi.bin", network)
            .await
            .unwrap();
        assert_eq!(h, 0);
        server.await.unwrap();
    }
}
