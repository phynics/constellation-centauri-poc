# Constellation Mesh

A decentralized mesh communication protocol for ESP32 microcontrollers.

Constellation nodes communicate via asymmetric-key authenticated and encrypted messages, with network routing derived from heartbeat-based topology discovery.

## Project Structure

- `routing-core/` — Core protocol logic (no-std, transport-agnostic). Routing table, H2H exchange, bloom filters, forwarding, crypto, onboarding, facade, and behavior loops.
- `firmware/` — ESP32-C6 firmware using Embassy, esp-hal, trouble-host BLE, and flash persistence with a dedicated partition table.
- `sim/` — Desktop simulator with Embassy-on-thread + ratatui TUI. **Primary routing-core experiment harness.**
- `companion/` — macOS BLE peer node with interactive TUI (discovery, enrollment, mesh routing, and event log) via `blew` (CoreBluetooth).
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

# Build companion (macOS)
cargo build -p companion
```

## Simulator

The simulator is the primary tool for debugging routing-core behavior. It runs the same shared protocol logic as the firmware, exposed through a ratatui TUI with:

- **Trace debugger** — hop-by-hop message propagation traces with per-hop event timelines
- **Delayed-delivery traces** — low-power wake/sync, retained-delivery, and fallback-router trace events
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

## Companion

The companion is a macOS application that serves as a mesh peer and onboarding operator:

- **Discovery** — scans for Constellation devices via BLE, parses manufacturer data (short_addr, capabilities, network_addr)
- **Inspection** — bounded GATT reads for full peer details (pubkey, network marker, capabilities)
- **Enrollment** — issues node certificates signed by the local authority key, writes them to firmware GATT
- **Mesh routing** — participates in H2H exchanges, runs the same routing-core behavior loops as firmware
- **Messaging** — sends pings and encrypted app messages over routed sessions via next-hop lookup

### Companion Controls

| Key | Action |
|-----|--------|
| `n` / `Tab` | Cycle views (Peers / Local / Network / Events) |
| `↑↓` | Navigate peer list |
| `e` | Enroll selected peer (from Peers view) |
| `r` | Reset network authority key (from Local view) |
| `m` | Compose message to selected mesh node (from Network view) |
| `p` | Ping selected mesh node (from Network view) |
| `q` / `Esc` | Quit |

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
      app.rs           # Routed infra/app frame families
      dedup.rs         # SeenMessages ring buffer
    routing/
      table.rs         # RoutingTable, forwarding_candidates, bloom, decay
      bloom.rs         # BloomFilter (256-bit, 3 hash functions)
    message.rs         # Transport-neutral per-hop routing decisions
    network.rs         # H2hInitiator/H2hResponder traits, NetworkError
    transport.rs       # TransportAddr (BLE MAC, CoreBluetooth device ID, etc.)
    facade.rs          # MeshFacade: stateful wrapper for routed packet build/receive/relay
    onboarding.rs      # Onboarding primitives: NetworkMarker, NodeCertificate,
                       #   DiscoveryInfo, NetworkAddr, certificate serialization
    node/
      roles.rs         # Capabilities bitfield

firmware/              # ESP32 bare-metal host
  partitions.csv       # Partition table (nvs, phy_init, factory, constellation)
  src/
    main.rs            # Embassy startup, BLE stack wiring, task orchestration
    transport/
      ble_network.rs   # trouble-host BLE: advertise, scan, L2CAP H2H + routed,
                       #   onboarding GATT service, enrollment commit, flash save
    node/
      storage.rs       # Flash persistence: PartitionedFlash, identity, provisioning,
                       #   sector-aligned reads, erase-before-write

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

companion/             # macOS BLE peer
  src/
    main.rs            # Entry point, tokio current_thread runtime
    runtime.rs         # CompanionRuntime with command channel, shared state
    ble/
      runtime.rs       # BLE scan/advertise/connect loop, enrollment, mesh sessions
      network.rs       # MacInitiator/MacResponder (blew L2CAP H2H + routed)
      constants.rs     # GATT service/characteristic UUIDs (shared with firmware)
    node/
      storage.rs       # Local identity + authority key persistence (~/.constellation/)
    onboarding/
      mod.rs           # Onboarding flow helpers
    diagnostics/
      state.rs         # SharedState, DiscoveredPeer, RoutingPeerView
    tui/
      mod.rs           # TUI entry, crossterm + ratatui loop
      app.rs           # App state, key handling
      ui.rs            # Peer/network/local/events rendering
```

### Routing Model

- **Direct peers**: discovered via scan, updated via `update_peer_compact()` with `TRUST_DIRECT`
- **Indirect peers**: learned from H2H exchange, stored with `learned_from` pointing to the direct partner, `TRUST_INDIRECT`
- **Low-power delayed delivery**: low-energy endpoints wake a preferred router first, then fall back through a deterministic backup-router subset derived from the LPN identity; routers replicate retained messages only into that backup subset
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

### Onboarding

New nodes are enrolled into the mesh by a companion device:

1. Node generates an ed25519 keypair on first boot, persists to flash
2. Node advertises `ONBOARDING_READY_NETWORK_ADDR` in BLE manufacturer data
3. Companion discovers the node, inspects its GATT characteristics
4. Companion issues a `NodeCertificate` signed by the local authority key
5. Companion writes authority pubkey, cert capabilities, cert signature to firmware GATT
6. Companion writes the commit characteristic
7. Firmware validates the certificate, persists enrollment, ACKs, then software resets
8. After reboot, the node advertises its real `NetworkAddr` in manufacturer data

### Flash Persistence

Firmware uses a dedicated 4KB partition labeled `constellation` at offset `0x210000`:

- **PartitionedFlash** wraps `FlashStorage` to translate partition-relative offsets to absolute
- All reads use sector-aligned 4096-byte buffers (ESP32 requires 4-byte alignment in offset AND length)
- Erase-before-write is enforced (NOR flash can only turn 1-bits into 0-bits)
- Identity and provisioning are saved/loaded from this partition

## License

TBD
