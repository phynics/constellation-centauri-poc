# Constellation Mesh

A decentralized mesh communication protocol for ESP32 microcontrollers.

Constellation nodes communicate via asymmetric-key authenticated and encrypted messages, with network routing derived from heartbeat-based topology discovery.

## Project Structure

- `routing-core/` — Core protocol logic (no-std, transport-agnostic). Routing table, H2H exchange, bloom filters, forwarding, crypto, and behavior loops.
- `firmware/` — ESP32-C6 firmware using Embassy, esp-hal, trouble-host BLE, and flash persistence.
- `sim/` — Desktop simulator with Embassy-on-thread + ratatui TUI. **Primary routing-core experiment harness.**
- `docs/` — Project documentation.

## Quick Start

```bash
# Build the workspace
cargo build

# Run the simulator
cargo run -p sim

# Run routing-core tests (30+ tests)
cargo test -p routing-core

# Run simulator tests
cargo test -p sim

# Check firmware (ESP32-C6 target)
cd firmware && cargo check --no-default-features --features=esp32c6
```

## Simulator

The simulator is the primary tool for debugging routing-core behavior. It runs the same shared protocol logic as the firmware, exposed through a ratatui TUI with:

- **Trace debugger** — hop-by-hop message propagation traces with per-hop event timelines
- **Node editor** — live capability, behavior, and type editing per node
- **Link editor** — toggle links and adjust drop probability
- **Spatial map** — coordinate-based node layout with connector paths
- **Scenario presets** — `Default`, `Minimal`, `PartitionedBridge`, `FieldDeployment`
- **Broadcast support** — send to `*` or `all` for broadcast fan-out traces

### Simulator Controls

| Key | Action |
|-----|--------|
| `N` | Cycle view modes (Trace / Nodes / Links) |
| `F` | Cycle trace filter (All / Directed / Broadcast) |
| `M` | Send manual message (directed or broadcast) |
| `R` | Switch scenario preset |
| `↑↓` | Navigate trace/node/link list |
| `Tab` | Cycle bottom tabs (Timeline / Graph / Packet / Logs) |
| `?` | Help overlay |

## Documentation

- **[Protocol Specification](docs/spec/protocol.md)** — High-level mesh and low-level BLE protocol details.
- **[BLE Integration Guide](docs/guides/ble-integration.md)** — BLE transport layer status and development guide.
- **[Hardware Testing](docs/guides/hardware-testing.md)** — Flashing and testing on ESP32-C6 boards.
- **[Archive](docs/archive/)** — Historical summaries and plans.

## Architecture

### Workspace Layout

```
routing-core/          # Shared no-std protocol layer
  src/
    lib.rs             # Module boundary
    config.rs          # Constants (MAX_NODES, TTL, etc.)
    behavior.rs        # Shared initiator/responder/heartbeat loops
    crypto/
      identity.rs      # NodeIdentity, ShortAddr, ed25519 signing
      encryption.rs    # ECDH + ChaCha20-Poly1305
    protocol/
      h2h.rs           # H2H payload, slot scheduling, initiator selection
      packet.rs        # Packet builder, header serialization
      dedup.rs         # SeenMessages ring buffer
    routing/
      table.rs         # RoutingTable, forwarding_candidates, bloom, decay
      bloom.rs         # BloomFilter (256-bit, 3 hash functions)
    network.rs         # H2hInitiator/H2hResponder traits, NetworkError
    transport.rs       # TransportAddr
    node/
      roles.rs         # Capabilities bitfield

firmware/              # ESP32 bare-metal host
  src/
    main.rs            # Embassy startup, BLE stack wiring, task orchestration
    transport/
      ble_network.rs   # trouble-host BLE: advertise, scan, L2CAP H2H

sim/                   # Desktop simulator host
  src/
    main.rs            # Simulator boot, static node setup, Embassy background thread
    network.rs         # SimInitiator/SimResponder (in-process transport shims)
    behavior.rs        # Sim-specific behavior loops (runtime capability lookup)
    scenario.rs        # Built-in scenario presets
    message_task.rs    # Hop-by-hop message propagation using routing-core
    command_task.rs    # TUI command dispatch (send, reset, scenario, etc.)
    snapshot_task.rs   # Embassy -> TUI state bridge (1s tick)
    medium.rs          # SimMedium channels and serialization
    sim_state.rs       # Shared state: TuiState, SimConfig, traces, events
    tui/
      mod.rs           # TUI entry point, crossterm + ratatui loop
      app.rs           # App state, key handling, input modes
      ui.rs            # Trace-centric rendering
```

### Routing Model

- **Direct peers**: discovered via scan, updated via `update_peer_compact()` with `TRUST_DIRECT`
- **Indirect peers**: learned from H2H exchange, stored with `learned_from` pointing to the direct partner, `TRUST_INDIRECT`
- **Forwarding**: `forwarding_candidates(dst)` resolves in order:
  1. Direct destination with usable transport
  2. Indirect destination via `learned_from` (the partner that taught us about this destination)
  3. Bloom-route candidates (neighbors whose bloom filter claims the destination)
- **Decay**: peers not refreshed within `max_age_ticks` are demoted to `TRUST_EXPIRED`; removed at 3x

### Capability System

Nodes opt into network functions via bitfield flags:

| Flag | Meaning |
|------|---------|
| `ROUTE` | Forwards messages for others |
| `STORE` | Store-and-forward for LE nodes |
| `BRIDGE` | Bridges to IP / other networks |
| `APPLICATION` | Runs application services |
| `LOW_ENERGY` | Battery-powered, does not route |
| `MOBILE` | Mobile device |

## License

TBD
