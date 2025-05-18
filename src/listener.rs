use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response, StatusCode};
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use crate::rpc;
use log::{debug, error, info, warn};

// Placeholder for P2P connection handling
async fn handle_p2p_connection(mut stream: TcpStream, initial_bytes: Vec<u8>) {
    let peer_addr = stream
        .peer_addr()
        .map_or_else(|_| "unknown_peer".to_string(), |a| a.to_string());
    info!(
        "[listener] P2P connection detected from {}. Initial bytes (first {}) len: {}",
        peer_addr,
        initial_bytes.len().min(8),
        initial_bytes.len()
    );
    // Send a simple acknowledgment to confirm this handler was called
    if let Err(e) = stream.write_all(b"P2P_ACK").await {
        warn!("[listener] Failed to send P2P_ACK to {}: {}", peer_addr, e);
    }
    // Attempt a graceful shutdown
    if let Err(e) = stream.shutdown().await {
        warn!(
            "[listener] Failed to shutdown P2P stream from {} gracefully: {}",
            peer_addr, e
        );
    }
    debug!("[listener] P2P handler for {} finished.", peer_addr);
    // Stream is dropped when the function scope ends
}

async fn http_request_handler(
    req: Request<Body>,
    status: Arc<Mutex<rpc::NodeStatus>>,
) -> Result<Response<Body>, Infallible> {
    let peer_addr_str = req
        .extensions()
        .get::<std::net::SocketAddr>()
        .map_or_else(|| "unknown_peer".to_string(), |s| s.to_string());
    info!(
        "[listener] HTTP request from {}: {} {}",
        peer_addr_str,
        req.method(),
        req.uri().path()
    );
    match (req.method(), req.uri().path()) {
        (&hyper::Method::GET, "/status") => {
            let status_lock = status.lock().unwrap();
            // Serialize the NodeStatus struct to JSON
            match serde_json::to_string(&*status_lock) {
                Ok(json_body) => Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(hyper::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json_body))
                    .unwrap()),
                Err(e) => {
                    error!(
                        "[listener] Error serializing status for {}: {}",
                        peer_addr_str, e
                    );
                    Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from("Error serializing status"))
                        .unwrap())
                }
            }
        }
        _ => {
            warn!(
                "[listener] HTTP 404 for {} {}: Path not found.",
                req.method(),
                req.uri().path()
            );
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body("Not Found".into())
                .unwrap())
        }
    }
}

async fn handle_http_connection(stream: TcpStream, status: Arc<Mutex<rpc::NodeStatus>>) {
    let peer_addr_for_log = stream
        .peer_addr()
        .map_or_else(|_| "unknown_peer".to_string(), |a| a.to_string());
    info!(
        "[listener] HTTP connection detected from {}, serving with Hyper.",
        peer_addr_for_log
    );

    // Get peer_addr before stream is moved, and clone it for the closure.
    let peer_addr_for_handler = stream.peer_addr().ok();

    let service = service_fn(move |mut req: Request<Body>| {
        // Insert the cloned peer_addr into request extensions.
        if let Some(addr) = peer_addr_for_handler {
            req.extensions_mut().insert(addr);
        }
        http_request_handler(req, Arc::clone(&status))
    });

    if let Err(e) = Http::new()
        .http1_only(true)
        .http1_keep_alive(true)
        .serve_connection(stream, service)
        .await
    {
        // Differentiate between connection errors and hyper service errors if possible
        // Some errors (like BrokenPipe) are normal if client disconnects early.
        if e.is_incomplete_message()
            || format!("{}", e).contains("connection reset")
            || format!("{}", e).contains("broken pipe")
        {
            debug!(
                "[listener] HTTP connection from {} ended (client disconnect?): {}",
                peer_addr_for_log, e
            );
        } else {
            error!(
                "[listener] Error serving HTTP connection from {}: {}",
                peer_addr_for_log, e
            );
        }
    }
    debug!(
        "[listener] HTTP connection handler for {} finished.",
        peer_addr_for_log
    );
}

pub async fn start_listener(
    addr: &str,
    status: Arc<Mutex<rpc::NodeStatus>>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("[listener] Listening on: {} for P2P and HTTP/RPC", addr);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        info!("[listener] Accepted connection from: {}", peer_addr);
        let status_clone = Arc::clone(&status);

        let mut buf = [0u8; 8];
        match stream.peek(&mut buf).await {
            Ok(n) => {
                let peeked_bytes = &buf[..n];
                if n >= 4
                    && (peeked_bytes.starts_with(b"GET ")
                        || peeked_bytes.starts_with(b"POST")
                        || peeked_bytes.starts_with(b"PUT ")
                        || peeked_bytes.starts_with(b"HEAD")
                        || peeked_bytes.starts_with(b"HTTP"))
                {
                    debug!(
                        "[listener] Peeked {} bytes from {}, identified as HTTP.",
                        n, peer_addr
                    );
                    tokio::spawn(async move {
                        handle_http_connection(stream, status_clone).await;
                    });
                } else {
                    debug!(
                        "[listener] Peeked {} bytes from {}, identified as P2P. First few: {:?}",
                        n,
                        peer_addr,
                        &peeked_bytes[..n.min(8)]
                    );
                    let initial_data = peeked_bytes.to_vec();
                    tokio::spawn(async move {
                        handle_p2p_connection(stream, initial_data).await;
                    });
                }
            }
            Err(e) => {
                warn!(
                    "[listener] Failed to peek stream from {}: {}; dropping connection",
                    peer_addr, e
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::NodeStatus;
    use log::info;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    async fn find_free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[tokio::test]
    async fn test_http_status_endpoint() {
        let port = find_free_port().await;
        let addr = format!("127.0.0.1:{}", port);

        // Create a dummy NodeStatus for testing
        let test_status = Arc::new(Mutex::new(NodeStatus {
            block_height: 123,
            peers: vec!["1.2.3.4:8333".to_string()],
            current_best_header_hex: Some("001122aabbcc".to_string()),
        }));

        // Start the listener in a background task
        let listener_addr = addr.clone();
        let status_clone_for_listener = Arc::clone(&test_status);
        tokio::spawn(async move {
            // Pass the dummy status to the listener
            if let Err(e) = start_listener(&listener_addr, status_clone_for_listener).await {
                error!("[Test Listener] Listener failed: {}", e);
            }
        });

        // Give the listener a moment to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Test /status endpoint
        let mut stream_status = TcpStream::connect(&addr)
            .await
            .expect("Failed to connect for /status");
        stream_status
            .write_all(b"GET /status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("Failed to write /status request");

        let mut response_status_buf = Vec::new();
        stream_status
            .read_to_end(&mut response_status_buf)
            .await
            .expect("Failed to read /status response");
        let response_status_str = String::from_utf8_lossy(&response_status_buf);

        info!(
            "[Test Listener] Response for /status:\n{}",
            response_status_str
        );

        assert!(response_status_str.starts_with("HTTP/1.1 200 OK"));
        assert!(response_status_str.contains("content-type: application/json"));
        // Update expected JSON body
        let expected_body = serde_json::to_string(&*test_status.lock().unwrap()).unwrap();
        assert!(response_status_str.ends_with(&expected_body));

        // Test a non-existent endpoint (status arc doesn't matter here as much)
        let mut stream_notfound = TcpStream::connect(&addr)
            .await
            .expect("Failed to connect for /notfound");
        stream_notfound
            .write_all(b"GET /notfound HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("Failed to write /notfound request");

        let mut response_notfound_buf = Vec::new();
        stream_notfound
            .read_to_end(&mut response_notfound_buf)
            .await
            .expect("Failed to read /notfound response");
        let response_notfound_str = String::from_utf8_lossy(&response_notfound_buf);

        info!(
            "[Test Listener] Response for /notfound:\n{}",
            response_notfound_str
        );

        assert!(response_notfound_str.starts_with("HTTP/1.1 404 Not Found"));
        assert!(response_notfound_str.ends_with("Not Found"));
    }

    #[tokio::test]
    async fn test_p2p_connection_detection() {
        let port = find_free_port().await;
        let addr = format!("127.0.0.1:{}", port);

        // Start the listener in a background task
        let listener_addr = addr.clone();
        // Create a default status for this test
        let test_status_p2p = Arc::new(Mutex::new(NodeStatus {
            block_height: 0,
            peers: Vec::new(),
            current_best_header_hex: None,
        }));
        tokio::spawn(async move {
            if let Err(e) = start_listener(&listener_addr, test_status_p2p).await {
                // Pass the default status
                error!("[Test Listener] Test P2P listener failed: {}", e);
            }
        });

        // Give the listener a moment to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect and send some non-HTTP data
        let mut stream = TcpStream::connect(&addr)
            .await
            .expect("Failed to connect for P2P test");
        stream
            .write_all(b"p2p_magic_bytes")
            .await
            .expect("Failed to write P2P data");

        // Read the response, expecting "P2P_ACK"
        let mut response_buf = [0u8; 7]; // Length of P2P_ACK
        stream
            .read_exact(&mut response_buf)
            .await
            .expect("Failed to read P2P ACK");

        assert_eq!(&response_buf, b"P2P_ACK");

        // Check if the server closed the connection after ACK
        let mut extra_buf = [0u8; 1];
        match stream.read(&mut extra_buf).await {
            Ok(0) => { /* EOF, connection closed gracefully, good */ }
            Ok(n) => panic!("Expected EOF or connection close, but got {} more bytes", n),
            Err(e) => match e.kind() {
                std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof => {
                    // These errors also indicate the server side is done with the connection.
                    info!("[Test Listener] P2P connection closed with error: {:?}, considering test passed for P2P handler invocation.", e.kind());
                }
                _ => panic!("Error after P2P_ACK: {:?}", e), // Panic on other errors
            },
        }
    }
}
