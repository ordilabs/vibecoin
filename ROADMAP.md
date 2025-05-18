# Vibecoin Roadmap

The project aims to reimplement core Bitcoin functionality in Rust.

## Completed
- **Hello World**: print the Bitcoin genesis block using the `bitcoin` crate.
- **Network Handshake**: Implemented peer connections over TCP and exchange of `version` and `verack` messages.
- **Header Synchronization**: Implemented `getheaders` and `headers` message exchange. Validates proof-of-work and maintains the best chain tip.
- **Header Persistence**: Headers are persisted to disk.

## Version 0.1 Goals (MVP)
1.  **CLI Reporting**
    - Provide a command-line interface that displays the current synchronized block height and other relevant node status.
    - **Status**: Current synchronized block height is displayed via `--show-height` after successful header sync. Further enhancements for comprehensive node status can be future work.
2.  **Block Download & Persistence**
    - Download full blocks (after headers are synced) via `getdata`/`block` messages.
    - Persist block data to disk.
    - Basic block validation (e.g., Merkle root, consistency with header).
3.  **HTTP API for Data Exposure**
    - Expose an HTTP API to retrieve synchronized headers and blocks.
    - Support multiple formats for data retrieval (e.g., JSON, CSV, raw binary).
4.  **Handle Chain Reorganizations (Headers)**
    - Implement logic in `HeaderStore` to detect and handle basic block chain reorganizations.
5.  **Peer Management (Basic)**
    - Implement discovery and management of multiple peer connections (e.g., connect to a few hardcoded or CLI-provided peers).

## Version 0.2 Ideas
- **Full Block Validation**: Implement more comprehensive block validation rules.
- **Transaction Relay & Mempool**:
    - Handle `tx` messages.
    - Implement a basic mempool.
    - Relay valid transactions to peers.
- **Advanced Peer Management**: More robust peer discovery (DNS seeds, `addr` messages) and management.
- **Enhanced RPC/HTTP API**: More query capabilities, node control.

## Deprioritized / Future
- ~~Download and verify full blocks and transactions.~~ (Moved to 0.1)
- ~~Expose basic RPC endpoints for status queries.~~ (Expanded and moved to 0.1)
