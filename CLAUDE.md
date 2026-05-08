# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Constellation Mesh** is a Rust workspace for decentralized ESP32 mesh networking with a shared protocol core, bare-metal firmware host, and desktop simulator.

### Workspace Members

- `routing-core/` — Reusable no-std protocol/routing/crypto/behavior layer. All routing decisions live here.
- `firmware/` — ESP32 firmware using Embassy, esp-hal, trouble-host BLE, and flash persistence.
- `sim/` — Desktop simulator with Embassy-on-thread + ratatui TUI. **Primary routing-core experiment harness.**

## Build & Run Commands

```bash
# Build the workspace
cargo build

# Check individual crates
cargo check -p routing-core
cargo check -p sim
cargo check -p firmware  # requires esp toolchain

# Test
cargo test -p routing-core    # 30+ unit tests
cargo test -p sim             # 11 integration tests

# Run the simulator
cargo run -p sim

# Format and lint
cargo fmt --all
cargo clippy -p routing-core
cargo clippy -p sim

# Firmware (ESP32-C6 target)
cd firmware && cargo check --no-default-features --features=esp32c6
cargo esp32c6    # alias: release flash + monitor
```

## Architecture

- **Runtime**: Embassy async executor — all tasks are `async`
- **Shared layer**: `#![no_std]`, uses `heapless` collections and explicit capacities
- **BLE stack**: `esp-wifi` (controller) + `trouble-host` (host with GATT/L2CAP)
- **Crypto**: `ed25519-dalek` for signing, `x25519-dalek` + `chacha20poly1305` for encryption
- **Storage**: `esp-storage` + `embedded-storage` traits for flash persistence
- **Simulator**: Embassy runs on a background thread, ratatui owns the main thread, shared state crosses via `Arc<Mutex<_>>` + mpsc

## Key Constraints

- `routing-core` is `#![no_std]` — prefer `heapless` collections, explicit capacities, and static allocation
- Shared mutable state uses `Mutex` + `StaticCell` in firmware, `Arc<Mutex<_>>` in sim
- Transport abstraction is real: `H2hInitiator`/`H2hResponder` traits are implemented separately by firmware BLE and simulator shims
- Capability flags drive node roles; prefer expressing participation through bitfields instead of hard-coded role branches
- Build fingerprints are intentional: both `build.rs` files hash key sources so nodes can compare firmware equivalence
- `trouble-host` is pinned to the upstream `main` branch; several esp-hal family crates are patched to a specific git revision
- Several crates are pinned via `[patch.crates-io]` in the workspace `Cargo.toml` — check before updating dependencies
- The top-level `src/` tree and `build.rs` are **pre-workspace legacy** — treat them cautiously

## Documentation

- **[Protocol Specification](docs/spec/protocol.md)** — High-level mesh and low-level BLE protocol details.
- **[BLE Integration Guide](docs/guides/ble-integration.md)** — BLE transport layer status and development guide.
- **[Hardware Testing](docs/guides/hardware-testing.md)** — Flashing and testing on ESP32-C6 boards.
- **[Archive](docs/archive/)** — Historical summaries and plans.
