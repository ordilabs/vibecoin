This directory is intended to hold the Bitcoin Core source code (tag v29.0) as reference for the Rust reimplementation. The sources are not required to build vibecoin and may be added via git submodule or manual download.

## Checkpoint Notes

Two snapshots of Bitcoin Core are included here:

- **v0.1.5**: the original 2009 codebase. It uses WinSock networking, stores blocks via Berkeley DB and relies on IRC for peer discovery. The design is monolithic with global state.
- **v29.0**: the modern reference implementation with a modular code layout, descriptor wallets and a robust P2P stack defined in `src/protocol.h`.

For the Rust MVP we will study the simple message flow from `v0.1.5` (version handshake and header download) while referencing `v29.0` for current protocol details. The goal is to replicate the minimal features needed to join the network and sync headers before expanding further.
