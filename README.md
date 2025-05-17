# Vibecoin

Vibecoin is an experiment to reimplement Bitcoin in Rust using modern tooling while remaining compatible with the current P2P network. This repository starts with a simple Rust "hello world" that prints the Bitcoin genesis block using the [`bitcoin`](https://crates.io/crates/bitcoin) crate.

## Building

```bash
cargo run
```

The initial code requires Rust and will fetch dependencies automatically. When
run with an argument like `cargo run -- 127.0.0.1:8333` it will attempt a simple
`version` handshake with the specified peer.

## Development Plan

The project will progress in several stages:

### Hello World Stage
- Create a basic Rust binary using `bitcoin` crate v0.32.6.
- Display the Bitcoin genesis block in hex.
- Include the Bitcoin Core source (tag `v29.0`) in a subfolder `bitcoin-cpp/` as reference. This folder can be added via submodule or manual download and is not required for building the Rust code.

### MVP Stage
- Implement minimal networking to connect to peers and exchange version messages.
- Parse and validate block headers.
- Provide simple CLI to show synced block height.
- Persist block headers to `~/.vibecoin/headers.dat` and reload them on startup.

### 0.1 Stage
- Validate and store blocks to disk using a simplified chain state.
- Relay and verify transactions, but without full script validation.
- Provide RPC endpoints for basic status queries.

### Further Steps
- Complete script and transaction validation.
- Implement mempool and mining logic.
- Achieve full compatibility with the Bitcoin P2P protocol.

These milestones are subject to change as development progresses.
