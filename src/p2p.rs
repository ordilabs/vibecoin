use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::consensus::encode::{serialize, deserialize};
use bitcoin::network::address::Address;
use bitcoin::network::constants::{Network, ServiceFlags, PROTOCOL_VERSION};
use bitcoin::network::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::network::message_network::VersionMessage;

/// Simple peer connection that performs a version handshake.
pub struct Peer {
    stream: TcpStream,
}

impl Peer {
    /// Connect to the given address (host:port) and perform version handshake.
    pub fn connect(addr: &str) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        Ok(Peer { stream })
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
                Ok(())
            }
            _ => Err("unexpected message".into()),
        }
    }

    /// Synchronize block headers with the connected peer.
    ///
    /// This is currently a placeholder that returns height 0.
    pub fn sync_headers(&mut self) -> Result<u64, Box<dyn std::error::Error>> {
        // TODO: implement header synchronization using `getheaders`/`headers` messages
        Ok(0)
    }
}
