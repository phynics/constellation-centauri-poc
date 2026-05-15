# Hardware Testing Guide

## Quick Start

```bash
# Build firmware (ESP32-C6 target)
cd firmware && cargo build --release

# Flash to first ESP32-C6 board (Node A)
cargo esp32c6

# In a new terminal, flash to second board (Node B)
cargo esp32c6
```

## Prerequisites

### Hardware
- 2x ESP32-C6 development boards (e.g., ESP32-C6-DevKitC-1)
- 2x USB-C cables
- Computer with 2 USB ports (or a USB hub)
- macOS device for companion (optional, for onboarding)

### Software
- Rust toolchain with `riscv32imac-unknown-none-elf` target
- `espflash` or `espup` for flashing
- Serial monitor (screen, minicom, or the `--monitor` flag)

### Environment Setup
- **Nix users**: `nix develop` sets up the full environment
- **Non-Nix**: Install `espup`, run `espup install`, then `source export-esp.sh`

## Boot Sequence

On first boot, each node generates an ed25519 keypair and persists it to the
dedicated `constellation` flash partition:

```
Constellation Mesh Node - H2H (Heart2Heart)
=============================================
Build: <16-char hex fingerprint>
Node identity: <short_addr as hex>
Public key:    <pubkey as hex>
BLE address:   <6-byte MAC as hex>
[periph] Startup jitter: <N>ms
```

On subsequent boots, the identity is loaded from flash (same `ShortAddr`).

The **build fingerprint** is a hash of key source files computed at compile time. Both boards should show the same fingerprint to confirm identical firmware.

## Expected Behavior

### Discovery

### Discovery

Nodes discover each other via BLE advertising + scanning. The advertising
layout distributes data across primary and scan response:

- **Primary adv data**: Flags + onboarding service UUID (128-bit)
- **Scan response**: Manufacturer data (company ID `0x1234` + 18-byte payload:
  `short_addr` + `capabilities` + `network_addr`)

The companion scans without an OS-level service filter and matches
Constellation nodes by either service UUID or company ID in manufacturer
data. Each scan cycle logs diagnostics to the Events view.

Unenrolled nodes advertise `ONBOARDING_READY_NETWORK_ADDR = [0xFF; 8]` as their
network_addr. Enrolled nodes advertise their real network fingerprint.

### H2H Exchange

After discovery, the initiator (lexicographically smaller `ShortAddr`) opens an L2CAP connection:

```
[central] H2H cycle: 1 peers to connect
[central] H2H → <short_addr> (slot <N>s)
[central] Connected to <short_addr>
[central] H2H tx sent
[central] H2H rx from <short_addr>
[central] Routing table: 1 peers
```

The responder side:

```
[periph] Connection from <BLE MAC>
[periph] H2H rx <N> bytes
[periph] H2H step=1 partner=<short_addr>
[periph] H2H step=2 built payload, <N> peers
[periph] H2H step=3 serialized <N> bytes
[periph] H2H step=4 tx ok
[periph] Routing table: 1 peers
```

### Onboarding via Companion

The companion app (macOS) can enroll unprovisioned firmware nodes:

1. Start the companion: `cargo run -p companion`
2. Wait for the firmware node to appear in the Peers view (marked as onboarding-ready)
3. Press `e` to enroll the selected node
4. Watch the Events view (press `n`/Tab) for step-by-step progress
5. The firmware console should show:
   ```
   BLE central connected
   GATT write: authority_pubkey (32 bytes)
   GATT write: cert_capabilities (2 bytes)
   GATT write: cert_signature (64 bytes)
   GATT write: commit_enrollment
   Certificate verified, committed to network ab12cd34..
   Enrollment committed to flash
   Rebooting in 100ms...
   ```
6. After reboot, the node advertises its real network_addr instead of the onboarding-ready sentinel

### Delayed Delivery for Low-Power Endpoints

The BLE H2H session now remains open after the initial sync when low-power
delivery is needed.

- low-power endpoints wake a preferred router first
- if the preferred router is unavailable, they can fall back to other reachable
  routers
- retained-message replicas are propagated only into a deterministic backup set
  derived from the low-power destination identity

In simulator traces this shows up as:

- `Deferred`
- `LpnWakeSync`
- `PendingAnnounced`
- `DeliveredFromStore`
- `DeliveryConfirmed`
- `ExpiredFromStore`

### Error Cases

H2H failures now include specific reasons:

| Error | Meaning |
|-------|---------|
| `PeerInactive` | Target node is not active |
| `InitiateDisabled` | Source node's initiate behavior is off |
| `RespondDisabled` | Target node's respond behavior is off |
| `LinkDisabled` | Link between source and target is off |
| `DropRejected` | Link drop probability rejected this attempt |

## Simulator Validation

Before testing on hardware, validate routing behavior in the simulator:

```bash
cargo run -p sim
```

The simulator exercises the same `routing-core` behavior loops as the firmware. Use it to:
- Verify H2H discovery and routing table convergence
- Test message propagation (directed and broadcast)
- Observe indirect routing through bridge nodes
- Toggle links and inject drop probability
- Send manual messages and inspect hop-by-hop traces

### Simulator Scenarios

| Scenario | Description |
|----------|-------------|
| `Default` | 10 nodes, all routing-capable |
| `Minimal` | 3 nodes, basic connectivity |
| `PartitionedBridge` | Two partitions connected by bridge corridor |
| `FieldDeployment` | Mixed capabilities (routers, bridges, LE, apps) |

## Troubleshooting

### Build Errors

**Target not found:**
```bash
rustup target add riscv32imac-unknown-none-elf
```

**Dependency version mismatch:**
```bash
cargo update && cargo clean && cargo build --release
```

**Building firmware from workspace root:**
Cargo does not pick up `firmware/.cargo/config.toml` from the workspace root. Always build from the `firmware/` directory:
```bash
cd firmware && cargo check --no-default-features --features=esp32c6
```

### Flash Errors

**Permission denied on /dev/ttyUSB*:**
```bash
sudo usermod -a -G dialout $USER
# Log out and back in
```

**Failed to connect:**
- Hold BOOT button while connecting
- Press RESET button after connecting
- Try different USB cable/port

**Partition table not written:**
When flashing with `espflash`, the partition table in `partitions.csv` is
automatically written. If the `constellation` partition seems corrupted,
reflash with `--partition-table partitions.csv` explicitly.

### Runtime Issues

**No output on serial:**
- Check baud rate is 115200
- Press RESET button on board
- Verify correct USB port

**Panic on boot:**
- Check the panic message in serial output
- Common causes: heap allocation failure, flash storage init failure

**H2H ConnectionFailed:**
- Check both boards are running the same firmware (build fingerprint)
- Ensure both are within BLE range
- Verify neither node has disabled H2H behaviors

**Companion can't discover firmware node:**
- Switch to Events view (press `n`/Tab) to see scan diagnostics:
  - `"scan done: N discovery events, M known devices"` — if N=0, CoreBluetooth isn't finding any BLE devices; if N>0 but M=0, no device matched the Constellation filter
  - `"discovered {id} (svc=N ours=X mfr=Y constellation=Z)"` — for each raw device the central reports
- Run with `RUST_LOG=info cargo run -p companion` to see raw device count on stderr
- Verify the firmware serial console shows `"Ready — advertising for discovery + H2H exchange"`
- The firmware puts the onboarding service UUID in the primary advertising data and the manufacturer data in the scan response — both should be visible to CoreBluetooth
- If no devices appear at all, try resetting the macOS Bluetooth daemon: turn Bluetooth off and back on in System Settings
- The companion matches devices by either service UUID or Constellation company ID (`0x1234`) in manufacturer data

**Onboarding fails on companion:**
- Switch to Events view (press `n`/Tab) to see step-by-step progress
- Check firmware serial console for GATT write diagnostics
- Verify the firmware is advertising `ONBOARDING_READY_NETWORK_ADDR` in manufacturer data
- After enrollment, firmware reboots — the companion should treat the disconnect as success

**Flash read failures (ReadFailed):**
- ESP32 requires 4-byte alignment in both offset AND length for flash reads
- The firmware now uses sector-aligned 4096-byte reads to satisfy this requirement
- If you see `ReadFailed` in logs, check the flash access alignment

## Current Implementation Status

✅ **Working:**
- Identity generation with hardware TRNG + flash persistence (dedicated partition)
- BLE advertising with discovery payload (18 bytes: short_addr + capabilities + network_addr)
- BLE scanning for peer discovery and network identification
- L2CAP H2H exchange (initiator + responder)
- Extended H2H sessions for delayed delivery to low-power endpoints
- Routing table updates from discovery + H2H
- Build fingerprint for firmware equivalence checks
- Simulator with full routing-core behavior
- Onboarding GATT service with staged enrollment and commit
- Companion enrollment of firmware nodes

⏳ **In Progress:**
- End-to-end companion↔firmware onboarding validation on hardware
- Indirect routing validation on hardware (works in sim)
- Encrypted message exchange

❌ **Not Yet Implemented:**
- WiFi/LoRa transport
- H2H session authentication (signed H2H frames)
- Packet counter / replay protection in code
