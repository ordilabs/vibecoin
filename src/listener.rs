use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response, StatusCode};
use std::convert::Infallible;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

// Placeholder for P2P connection handling
async fn handle_p2p_connection(mut stream: TcpStream, initial_bytes: Vec<u8>) {
    println!(
        "P2P connection detected. Initial bytes (first 8) len: {}",
        initial_bytes.len()
    );
    // Send a simple acknowledgment to confirm this handler was called
    if let Err(e) = stream.write_all(b"P2P_ACK").await {
        eprintln!("Failed to send P2P_ACK: {}", e);
    }
    // Attempt a graceful shutdown
    if let Err(e) = stream.shutdown().await {
        eprintln!("Failed to shutdown P2P stream gracefully: {}", e);
    }
    // Stream is dropped when the function scope ends
}

async fn http_request_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    match (req.method(), req.uri().path()) {
        (&hyper::Method::GET, "/status") => {
            let body = Body::from("{\"status\": \"ok\"}");
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(body)
                .unwrap())
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body("Not Found".into())
            .unwrap()),
    }
}

async fn handle_http_connection(stream: TcpStream) {
    println!("HTTP connection detected, serving with Hyper.");
    if let Err(e) = Http::new()
        .http1_only(true)
        .http1_keep_alive(true)
        .serve_connection(stream, service_fn(http_request_handler))
        .await
    {
        eprintln!("Error serving HTTP connection: {}", e);
    }
}

pub async fn start_listener(addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on: {} for P2P and HTTP/RPC", addr);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        println!("Accepted connection from: {}", peer_addr);

        // Important: We need a way to "give back" the peeked bytes to the stream
        // if it's not HTTP, or ensure the P2P handler can prepend them.
        // Tokio's `peek()` doesn't consume the bytes from the underlying stream for other readers,
        // but our P2P handler might expect to read them itself.
        // A more robust solution might involve a small state machine or a wrapper around the stream.

        // For HTTP, hyper will read from the stream directly.
        // For P2P, if our `p2p::Peer` expects to read the magic bytes itself,
        // `peek()` is fine. If it expects a "fresh" stream, this is more complex.

        let mut buf = [0u8; 8]; // Peek a smaller amount, just enough for HTTP method or P2P magic.
        match stream.peek(&mut buf).await {
            Ok(n) => {
                let peeked_bytes = &buf[..n];
                // Basic HTTP method check
                if n >= 4
                    && (
                        peeked_bytes.starts_with(b"GET ")
                            || peeked_bytes.starts_with(b"POST")
                            || peeked_bytes.starts_with(b"PUT ")
                            || peeked_bytes.starts_with(b"HEAD")
                            || peeked_bytes.starts_with(b"HTTP")
                        // Some clients might send HTTP/1.1 directly
                    )
                {
                    tokio::spawn(async move {
                        handle_http_connection(stream).await;
                    });
                } else {
                    // Assume P2P and pass the peeked bytes for the handler to decide.
                    // The P2P handler will need to be adapted to potentially use these bytes
                    // instead of reading them again, or this peek must be non-consuming for it.
                    // Since peek() is non-consuming from the TcpStream's perspective for other awaiters,
                    // this should be okay if the P2P handler reads from the original stream.
                    let initial_data = peeked_bytes.to_vec();
                    tokio::spawn(async move {
                        handle_p2p_connection(stream, initial_data).await;
                    });
                }
            }
            Err(e) => {
                eprintln!(
                    "Failed to peek stream from {}: {}; dropping connection",
                    peer_addr, e
                );
                // stream is dropped here
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*; // Imports start_listener, handle_http_connection, etc.
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

        // Start the listener in a background task
        let listener_addr = addr.clone();
        tokio::spawn(async move {
            if let Err(e) = start_listener(&listener_addr).await {
                eprintln!("Test listener failed: {}", e); // Use eprintln for test output
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

        println!("Response for /status:\n{}", response_status_str); // Debug output

        assert!(response_status_str.starts_with("HTTP/1.1 200 OK"));
        assert!(response_status_str.contains("content-type: application/json"));
        assert!(response_status_str.ends_with("{\"status\": \"ok\"}"));

        // Test a non-existent endpoint
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

        println!("Response for /notfound:\n{}", response_notfound_str); // Debug output

        assert!(response_notfound_str.starts_with("HTTP/1.1 404 Not Found"));
        assert!(response_notfound_str.ends_with("Not Found"));
    }

    #[tokio::test]
    async fn test_p2p_connection_detection() {
        let port = find_free_port().await;
        let addr = format!("127.0.0.1:{}", port);

        // Start the listener in a background task
        let listener_addr = addr.clone();
        tokio::spawn(async move {
            if let Err(e) = start_listener(&listener_addr).await {
                eprintln!("Test P2P listener failed: {}", e);
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
                    println!("P2P connection closed with error: {:?}, considering test passed for P2P handler invocation.", e.kind());
                }
                _ => panic!("Error after P2P_ACK: {:?}", e), // Panic on other errors
            },
        }
    }
}
