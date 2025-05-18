use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{self, JoinHandle};

#[derive(Clone, Debug)]
pub struct NodeStatus {
    pub block_height: u64,
    pub peers: Vec<String>,
}

pub async fn start(
    address: &str,
    status: Arc<Mutex<NodeStatus>>,
) -> std::io::Result<JoinHandle<()>> {
    let listener = TcpListener::bind(address).await?;
    Ok(task::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut s, _)) => {
                    handle_connection(&mut s, &status).await.ok();
                }
                Err(e) => {
                    eprintln!("RPC accept error: {}", e);
                }
            }
        }
    }))
}

async fn handle_connection(
    stream: &mut TcpStream,
    status: &Arc<Mutex<NodeStatus>>,
) -> std::io::Result<()> {
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await?;
    let req = String::from_utf8_lossy(&buf[..n]);
    let response = {
        let status = status.lock().unwrap();
        handle_request(&req, &status)
    };
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

pub fn handle_request(req: &str, status: &NodeStatus) -> String {
    if req.starts_with("GET /status") {
        let peers = format!(
            "[{}]",
            status
                .peers
                .iter()
                .map(|p| format!("\"{}\"", p))
                .collect::<Vec<_>>()
                .join(",")
        );
        let body = format!(
            "{{\"block_height\":{},\"peers\":{}}}",
            status.block_height, peers
        );
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
    } else if req.starts_with("GET /peers") {
        let body = format!(
            "[{}]",
            status
                .peers
                .iter()
                .map(|p| format!("\"{}\"", p))
                .collect::<Vec<_>>()
                .join(",")
        );
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
    } else {
        let body = "Not Found".to_string();
        format!(
            "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_ok() {
        let status = NodeStatus {
            block_height: 42,
            peers: vec!["127.0.0.1:8333".to_string()],
        };
        let req = "GET /status HTTP/1.1\r\n\r\n";
        let resp = handle_request(req, &status);
        assert!(resp.starts_with("HTTP/1.1 200"));
        assert!(resp.contains("\"block_height\":42"));
    }

    #[test]
    fn peers_ok() {
        let status = NodeStatus {
            block_height: 0,
            peers: vec!["10.0.0.1:8333".to_string(), "8.8.8.8:8333".to_string()],
        };
        let req = "GET /peers HTTP/1.1\r\n\r\n";
        let resp = handle_request(req, &status);
        assert!(resp.starts_with("HTTP/1.1 200"));
        let body = resp.split("\r\n\r\n").nth(1).unwrap();
        assert_eq!(body, "[\"10.0.0.1:8333\",\"8.8.8.8:8333\"]");
    }

    #[test]
    fn not_found() {
        let status = NodeStatus {
            block_height: 0,
            peers: vec![],
        };
        let req = "GET /other HTTP/1.1\r\n\r\n";
        let resp = handle_request(req, &status);
        assert!(resp.starts_with("HTTP/1.1 404"));
    }

    #[tokio::test]
    async fn handle_connection_status() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let status = Arc::new(Mutex::new(NodeStatus {
            block_height: 1,
            peers: vec![],
        }));

        let server = tokio::spawn({
            let status = Arc::clone(&status);
            async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                handle_connection(&mut socket, &status).await.unwrap();
            }
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET /status HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut resp = vec![0u8; 1024];
        let n = client.read(&mut resp).await.unwrap();
        let body = String::from_utf8_lossy(&resp[..n]);
        assert!(body.starts_with("HTTP/1.1 200"));

        server.await.unwrap();
    }
}
