use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::storage::HeaderStore;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message_blockdata::GetHeadersMessage;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{message::NetworkMessage, message::RawNetworkMessage};
use bitcoin::p2p::{ServiceFlags, PROTOCOL_VERSION};
use bitcoin::Network;

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

        let msg =
            RawNetworkMessage::new(Network::Bitcoin.magic(), NetworkMessage::Version(version));
        let bytes = serialize(&msg);
        self.stream.write_all(&bytes).await?;

        // Read remote version message
        let incoming = self.read_message().await?;
        match incoming.payload() {
            NetworkMessage::Version(_) => {
                // Send verack
                let verack =
                    RawNetworkMessage::new(Network::Bitcoin.magic(), NetworkMessage::Verack);
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
    pub async fn sync_headers(&mut self, path: &str) -> Result<u64, Box<dyn std::error::Error>> {
        let mut store = HeaderStore::open(path)?;
        let mut locator = store.locator_hashes();

        loop {
            let get = GetHeadersMessage {
                version: PROTOCOL_VERSION,
                locator_hashes: locator.clone(),
                stop_hash: bitcoin::BlockHash::all_zeros(),
            };
            let req =
                RawNetworkMessage::new(Network::Bitcoin.magic(), NetworkMessage::GetHeaders(get));
            let bytes = serialize(&req);
            self.stream.write_all(&bytes).await?;

            let incoming = self.read_message().await?;
            match incoming.payload() {
                NetworkMessage::Headers(headers) => {
                    if headers.is_empty() {
                        break;
                    }
                    store.append(&headers)?;
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

    #[tokio::test]
    async fn handshake_succeeds() {
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
                socket.write_all(&serialize(&resp)).await.unwrap();
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
            if let NetworkMessage::Version(v) = msg.payload() {
                let resp = RawNetworkMessage::new(
                    Network::Bitcoin.magic(),
                    NetworkMessage::Version(v.clone()),
                );
                socket.write_all(&serialize(&resp)).await.unwrap();
                let _ = socket.read(&mut buf).await.unwrap();
                let resp = RawNetworkMessage::new(Network::Bitcoin.magic(), NetworkMessage::Verack);
                socket.write_all(&serialize(&resp)).await.unwrap();
            }

            let mut buf = vec![0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            let msg: RawNetworkMessage = deserialize(&buf[..n]).unwrap();
            if matches!(msg.payload(), NetworkMessage::GetHeaders(_)) {
                let resp = RawNetworkMessage::new(
                    Network::Bitcoin.magic(),
                    NetworkMessage::Headers(vec![]),
                );
                socket.write_all(&serialize(&resp)).await.unwrap();
            }
        });

        let mut peer = Peer::connect(&addr.to_string()).unwrap();
        peer.handshake().await.unwrap();
        let h = peer.sync_headers("headers.dat").await.unwrap();
        assert_eq!(h, 0);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_requires_verack() {
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
                let _ = socket.read(&mut buf).await.unwrap();
                // send ping instead of verack
                let resp =
                    RawNetworkMessage::new(Network::Bitcoin.magic(), NetworkMessage::Ping(0));
                socket.write_all(&serialize(&resp)).await.unwrap();
            }
        });

        let mut peer = Peer::connect(&addr.to_string()).unwrap();
        assert!(peer.handshake().await.is_err());
        server.await.unwrap();
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

        let mut peer = Peer::connect(&addr.to_string()).unwrap();
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

        let mut peer = Peer::connect(&addr.to_string()).unwrap();
        peer.handshake().await.unwrap();
        let h = peer.sync_headers("headers_multi.dat").await.unwrap();
        assert_eq!(h, 0);
        server.await.unwrap();
    }
}
