// use std::sync::{Arc, Mutex}; // These are no longer used in this file
// use tokio::io::{AsyncReadExt, AsyncWriteExt}; // No longer needed for this file directly
// use tokio::net::{TcpListener, TcpStream}; // No longer needed for this file directly
// use tokio::task::{self, JoinHandle}; // No longer needed for this file directly
use serde::Serialize; // Added for deriving Serialize

#[derive(Clone, Debug, Serialize)] // Added Serialize
pub struct NodeStatus {
    pub block_height: u64,
    pub peers: Vec<String>,
    pub current_best_header_hex: Option<String>,
}

// pub async fn start( // Old RPC start, removed
//     address: &str,
//     status: Arc<Mutex<NodeStatus>>,
// ) -> std::io::Result<JoinHandle<()>> {
//     let listener = TcpListener::bind(address).await?;
//     Ok(task::spawn(async move {
//         loop {
//             match listener.accept().await {
//                 Ok((mut s, _)) => {
//                     handle_connection(&mut s, &status).await.ok();
//                 }
//                 Err(e) => {
//                     eprintln!("RPC accept error: {}", e);
//                 }
//             }
//         }
//     }))
// }

// async fn handle_connection( // Old RPC connection handler, removed
//     stream: &mut TcpStream,
//     status: &Arc<Mutex<NodeStatus>>,
// ) -> std::io::Result<()> {
//     let mut buf = [0u8; 1024];
//     let n = stream.read(&mut buf).await?;
//     let req = String::from_utf8_lossy(&buf[..n]);
//     let response = {
//         let status = status.lock().unwrap();
//         handle_request(&req, &status)
//     };
//     stream.write_all(response.as_bytes()).await?;
//     Ok(())
// }

// pub fn handle_request(req: &str, status: &NodeStatus) -> String { // This logic is now in listener.rs
//     if req.starts_with("GET /status") {
//         let peers = format!(
//             "[{}]",
//             status
//                 .peers
//                 .iter()
//                 .map(|p| format!("\"{}\"", p))
//                 .collect::<Vec<_>>()
//                 .join(",")
//         );
//         let body = format!(
//             "{{\"block_height\":{},\"peers\":{}}}",
//             status.block_height, peers
//         );
//         format!(
//             "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
//             body.len(),
//             body
//         )
//     } else if req.starts_with("GET /peers") { // /peers endpoint not yet in new listener
//         let body = format!(
//             "[{}]",
//             status
//                 .peers
//                 .iter()
//                 .map(|p| format!("\"{}\"", p))
//                 .collect::<Vec<_>>()
//                 .join(",")
//         );
//         format!(
//             "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
//             body.len(),
//             body
//         )
//     } else {
//         let body = "Not Found".to_string();
//         format!(
//             "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\n\r\n{}",
//             body.len(),
//             body
//         )
//     }
// }

#[cfg(test)]
mod tests {
    // use super::*; // This was the only change needed for the warning.
    // The lines below were erroneously re-added by a previous edit attempt and should remain commented or removed
    // if they are not actually used by any current tests in this module.
    // use crate::rpc::handle_request;
    // use http_body_util::BodyExt;

    // Imports for tests that might have used old handle_request or handle_connection directly
    // use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // use tokio::net::{TcpListener, TcpStream};

    // The existing tests in rpc.rs were testing the old `handle_request` and `handle_connection`.
    // `handle_request`'s logic (for /status) has been moved to `listener.rs` and is tested there.
    // The `/peers` endpoint is not currently implemented in the new listener's HTTP handler.
    // The `handle_connection` test was for the old raw TCP RPC.
    // For now, I will remove these tests as their functionality is either covered elsewhere or deprecated.
    // If specific RPC logic beyond simple HTTP requests is needed later, new tests should be added.

    // #[test]
    // fn status_ok() { ... } // Covered by listener::tests::test_http_status_endpoint

    // #[test]
    // fn peers_ok() { ... } // /peers endpoint not in new listener yet

    // #[test]
    // fn not_found() { ... } // Covered by listener::tests::test_http_status_endpoint (testing /notfound)

    // #[tokio::test]
    // async fn handle_connection_status() { ... } // Old RPC raw TCP test
}
