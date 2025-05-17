use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Clone, Debug)]
pub struct NodeStatus {
    pub block_height: u64,
    pub peers: Vec<String>,
}

pub fn start(address: &str, status: Arc<Mutex<NodeStatus>>) -> std::io::Result<thread::JoinHandle<()>> {
    let listener = TcpListener::bind(address)?;
    Ok(thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(mut s) = stream {
                handle_connection(&mut s, &status).ok();
            }
        }
    }))
}

fn handle_connection(stream: &mut TcpStream, status: &Arc<Mutex<NodeStatus>>) -> std::io::Result<()> {
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf)?;
    let req = String::from_utf8_lossy(&buf[..n]);
    let response = {
        let status = status.lock().unwrap();
        handle_request(&req, &status)
    };
    stream.write_all(response.as_bytes())?;
    Ok(())
}

pub fn handle_request(req: &str, status: &NodeStatus) -> String {
    if req.starts_with("GET /status") {
        let peers = format!("[{}]", status.peers.iter().map(|p| format!("\"{}\"", p)).collect::<Vec<_>>().join(","));
        let body = format!("{{\"block_height\":{},\"peers\":{}}}", status.block_height, peers);
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
        let status = NodeStatus { block_height: 42, peers: vec!["127.0.0.1:8333".to_string()] };
        let req = "GET /status HTTP/1.1\r\n\r\n";
        let resp = handle_request(req, &status);
        assert!(resp.starts_with("HTTP/1.1 200"));
        assert!(resp.contains("\"block_height\":42"));
    }

    #[test]
    fn not_found() {
        let status = NodeStatus { block_height: 0, peers: vec![] };
        let req = "GET /other HTTP/1.1\r\n\r\n";
        let resp = handle_request(req, &status);
        assert!(resp.starts_with("HTTP/1.1 404"));
    }
}
