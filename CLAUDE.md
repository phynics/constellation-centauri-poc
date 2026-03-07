# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**y-wood** (`ble-connect`) is a `#![no_std]` embedded Rust firmware for ESP32 microcontrollers. It targets BLE connectivity and display output (ILI9486 via SPI) using the async Embassy framework on bare metal (no OS). Part of the broader "constellation-project" — a hybrid mesh networking system for ESP32.

## Build & Run Commands

The project uses the ESP Rust toolchain (`channel = "esp"` via `espup`). Default target is **ESP32-C6** (`riscv32imac-unknown-none-elf`).

```bash
# Build (default: esp32c6)
cargo build

# Build and flash to a connected device (uses espflash as runner)
cargo run --release

# Target a specific chip using cargo aliases:
cargo esp32c6    # default
cargo esp32c3
cargo esp32c2
cargo esp32h2
cargo esp32      # Xtensa
cargo esp32s3    # Xtensa
```

Each cargo alias runs `--release --no-default-features --features=<chip> --target=<arch>`. The runner is `espflash flash --monitor`, so `cargo run` flashes the device and opens a serial monitor.

## Toolchain Setup

- **Nix users**: `nix develop` sets up the full environment (espup, rustup, espflash, etc.)
- **Non-Nix**: Install `espup`, run `espup install`, then `source export-esp.sh` to set toolchain paths
- Xtensa targets (esp32, esp32s3) require `build-std` (configured in `[unstable]` in `.cargo/config.toml`)

## Architecture

- **Runtime**: Embassy async executor (`embassy-executor`, `esp-hal-embassy`) — all tasks are `async`
- **BLE stack**: `esp-wifi` (BLE controller) + `trouble-host` (BLE host with GATT/peripheral/security support)
- **Crypto**: `ed25519-dalek` for signing/key exchange
- **Storage**: `esp-storage` + `embedded-storage` traits for flash persistence
- **Display**: `mipidsi` driver for ILI9486 SPI display
- **Heap**: `esp-alloc` with a 72KB heap allocation

## Documentation

The project documentation is organized in the `docs/` directory:

- **[Project Spec](docs/spec/protocol.md)**: High-level protocol and BLE layer specifications.
- **[Testing Guide](docs/guides/hardware-testing.md)**: Steps to flash and test on ESP32-C6 hardware.
- **[BLE Integration Status](docs/guides/ble-integration.md)**: Status and roadmap for the BLE transport.
- **[Archive](docs/archive/)**: Historical design documents and summaries.

## Key Constraints

- `#![no_std]` + `#![no_main]` — no standard library, no OS, no dynamic allocation outside `esp-alloc`
- Dev builds use `opt-level = "s"` because debug is too slow on embedded
- Several crates are pinned to a specific esp-hal git revision via `[patch.crates-io]` — check `Cargo.toml` before updating dependencies
- `trouble-host` is pinned to the `main` branch of the upstream git repo
- Log level controlled by `ESP_LOG=info` env var (set in `.cargo/config.toml`)
