# Vibecoin Roadmap

The project aims to reimplement core Bitcoin functionality in Rust. Below are the immediate milestones needed to reach a minimal viable product (MVP).

## Completed
- **Hello World**: Print the Bitcoin genesis block using the `bitcoin` crate.
- **Network Handshake**: Implemented peer connections over TCP, exchange of `version` and `verack` messages.
- **Basic RPC**: Exposed `/status` endpoint via HTTP.
- **Unified Listener**: Node listens on a single port, differentiating P2P and HTTP/RPC traffic based on initial bytes.
- **Header Storage**: Headers can be stored on disk and loaded. Proof-of-Work is validated on append. Locator hashes can be generated.
- **Header Synchronization (P2P Integration)**:
    - `p2p::sync_headers` fully integrated into the main application flow via CLI.
    - `HeaderStore` used for persistent header storage during P2P sync.
    - `listener.rs` dispatches to P2P handling, which then uses `Peer` methods for CLI-initiated connections.
- **CLI Enhancements**:
    - `--connect` option initiates P2P connection and header sync.
    - `--height` option, when used with `--connect`, displays synced block height.
    - Network selection (`--chain`) and data directory management implemented.

## Next Steps Towards MVP
1.  **Integrate P2P into Listener Fully**:
    - Currently, `listener.rs` has a placeholder `handle_p2p_connection`. This needs to be updated to actually instantiate a `Peer` from the accepted `TcpStream` and run the P2P protocol (handshake, then potentially other interactions like responding to `getheaders`, etc.). The CLI currently initiates outgoing P2P connections, but incoming P2P connections via the listener are not yet fully processed beyond detection.
2.  **Block Download and Basic Validation**:
    - Implement `getblocks` and `block` message handling.
    - Store and validate downloaded blocks (at least PoW and connection to previous block).
3.  **More Robust Peer Management**:
    - Handle multiple outgoing/incoming peer connections.
    - Basic peer scoring or retry logic.

## Future Work
- Full transaction download and verification.
- More comprehensive RPC endpoints (e.g., `getblockheader`, `getpeerinfo`, `getblock`).
- Wallet functionality (basic key management, transaction creation).
- Handling chain reorgs more robustly.
- Peer discovery mechanisms (DNS seeds, `addr` messages).
- Comprehensive test coverage for all new P2P and RPC interactions.
