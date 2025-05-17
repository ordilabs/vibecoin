# Vibecoin Roadmap

The project aims to reimplement core Bitcoin functionality in Rust. Below are the immediate milestones needed to reach a minimal viable product (MVP).

## Completed
- **Hello World**: print the Bitcoin genesis block using the `bitcoin` crate.

## Next Steps Towards MVP
1. **Network Handshake**
   - Implement peer connections over TCP using an async runtime (e.g. `tokio`).
   - Exchange `version` and `verack` messages as defined in Bitcoin Core `protocol.h`.
2. **Header Synchronization**
   - Send `getheaders` and process incoming `headers` messages.
   - Validate proof-of-work for each header and maintain the best chain tip in memory.
3. **CLI Reporting**
   - Provide a command-line interface that displays the current synchronized block height.

## Future Work
- Persist headers to disk and handle reorgs.
- Download and verify full blocks and transactions.
- Expose basic RPC endpoints for status queries.
