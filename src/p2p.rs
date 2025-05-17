use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::consensus::encode::{serialize, deserialize};
use bitcoin::network::address::Address;
use bitcoin::network::constants::{Network, ServiceFlags, PROTOCOL_VERSION};
use bitcoin::network::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::network::message_network::VersionMessage;
use bitcoin::network::message_blockdata::GetHeadersMessage;
use bitcoin::BlockHash;
use crate::storage::{HeaderStore, header_pow_valid};

/// Simple peer connection that performs a version handshake.
pub struct Peer {
    stream: TcpStream,
}

impl Peer {
    /// Connect to the given address (host:port).
    pub fn connect(addr: &str) -> std::io::Result<Self> {
        let std_stream = std::net::TcpStream::connect(addr)?;
        std_stream.set_nonblocking(true)?;
        let stream = TcpStream::from_std(std_stream)?;
        Ok(Peer { stream })
    }

    /// Perform the Bitcoin version handshake.
    pub async fn handshake(&mut self) -> Result<(), Box<dyn std::error::Error>> {
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
        self.stream.write_all(&bytes).await?;

        // Read remote version message
        let mut buf = vec![0u8; 1024];
        let n = self.stream.read(&mut buf).await?;
        let incoming: RawNetworkMessage = deserialize(&buf[..n])?;
        match incoming.payload {
            NetworkMessage::Version(_) => {
                // Send verack
                let verack = RawNetworkMessage {
                    magic: Network::Bitcoin.magic(),
                    payload: NetworkMessage::Verack,
                };
                let bytes = serialize(&verack);
                self.stream.write_all(&bytes).await?;
                Ok(())
            }
            _ => Err("unexpected message".into()),
        }
    }

    /// Synchronize block headers with the connected peer.
    /// Load existing headers from disk and fetch new ones from the peer.
    pub async fn sync_headers(&mut self) -> Result<u64, Box<dyn std::error::Error>> {
        let mut store = HeaderStore::open("headers.dat")?;
        let mut locator = store.locator_hashes();

        loop {
            let get = GetHeadersMessage {
                version: PROTOCOL_VERSION as i32,
                locator_hashes: locator.clone(),
                stop_hash: BlockHash::default(),
            };
            let req = RawNetworkMessage {
                magic: Network::Bitcoin.magic(),
                payload: NetworkMessage::GetHeaders(get),
            };
            let bytes = serialize(&req);
            self.stream.write_all(&bytes).await?;

            let mut buf = vec![0u8; 4096];
            let n = self.stream.read(&mut buf).await?;
            let incoming: RawNetworkMessage = deserialize(&buf[..n])?;
            match incoming.payload {
                NetworkMessage::Headers(headers) => {
                    if headers.is_empty() {
                        break;
                    }
                    let mut valid = Vec::new();
                    for h in headers {
                        if header_pow_valid(&h) {
                            valid.push(h);
                        } else {
                            eprintln!(
                                "rejecting header {}: invalid proof-of-work",
                                h.block_hash()
                            );
                        }
                    }
                    if valid.is_empty() {
                        break;
                    }
                    store.append(&valid)?;
                    locator = store.locator_hashes();
                }
                _ => {}
            }
        }

        Ok(store.height())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use bitcoin::blockdata::block::BlockHeader;

    #[tokio::test]
    async fn handshake_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
            if let NetworkMessage::Version(v) = msg.payload {
                let resp = RawNetworkMessage {
                    magic: Network::Bitcoin.magic(),
                    payload: NetworkMessage::Version(v),
                };
                socket.write_all(&serialize(&resp)).await.unwrap();
                let n = socket.read(&mut buf).await.unwrap();
                let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
                assert!(matches!(msg.payload, NetworkMessage::Verack));
            } else {
                panic!("unexpected message");
            }
        });

        let mut peer = Peer::connect(&addr.to_string()).unwrap();
        peer.handshake().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn sync_headers_empty() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
            if let NetworkMessage::Version(v) = msg.payload {
                let resp = RawNetworkMessage {
                    magic: Network::Bitcoin.magic(),
                    payload: NetworkMessage::Version(v),
                };
                socket.write_all(&serialize(&resp)).await.unwrap();
                let _ = socket.read(&mut buf).await.unwrap();
            }

            let mut buf = vec![0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
            if matches!(msg.payload, NetworkMessage::GetHeaders(_)) {
                let resp = RawNetworkMessage {
                    magic: Network::Bitcoin.magic(),
                    payload: NetworkMessage::Headers(vec![]),
                };
                socket.write_all(&serialize(&resp)).await.unwrap();
            }
        });

        let mut peer = Peer::connect(&addr.to_string()).unwrap();
        peer.handshake().await.unwrap();
        let h = peer.sync_headers().await.unwrap();
        assert_eq!(h, 0);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn sync_headers_invalid_pow() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
            if let NetworkMessage::Version(v) = msg.payload {
                let resp = RawNetworkMessage {
                    magic: Network::Bitcoin.magic(),
                    payload: NetworkMessage::Version(v),
                };
                socket.write_all(&serialize(&resp)).await.unwrap();
                let _ = socket.read(&mut buf).await.unwrap();
            }

            let mut buf = vec![0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
            if matches!(msg.payload, NetworkMessage::GetHeaders(_)) {
                let header = BlockHeader {
                    version: 0,
                    prev_blockhash: BlockHash::default(),
                    merkle_root: Default::default(),
                    time: 0,
                    bits: 0x01003456,
                    nonce: 0,
                };
                let resp = RawNetworkMessage {
                    magic: Network::Bitcoin.magic(),
                    payload: NetworkMessage::Headers(vec![header]),
                };
                socket.write_all(&serialize(&resp)).await.unwrap();
            }
        });

        let mut peer = Peer::connect(&addr.to_string()).unwrap();
        peer.handshake().await.unwrap();
        let h = peer.sync_headers().await.unwrap();
        assert_eq!(h, 0);
        server.await.unwrap();
    }
}
