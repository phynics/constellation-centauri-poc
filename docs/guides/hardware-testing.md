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

### Software
- Rust toolchain with `riscv32imac-unknown-none-elf` target
- `espflash` or `espup` for flashing
- Serial monitor (screen, minicom, or the `--monitor` flag)

### Environment Setup
- **Nix users**: `nix develop` sets up the full environment
- **Non-Nix**: Install `espup`, run `espup install`, then `source export-esp.sh`

## Boot Sequence

On first boot, each node generates an ed25519 keypair and persists it to flash:

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

Nodes discover each other via BLE advertising + scanning:

```
[central] New peer <short_addr> (1 total)
```

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

## Current Implementation Status

✅ **Working:**
- Identity generation with hardware TRNG + flash persistence
- BLE advertising with discovery payload
- BLE scanning for peer discovery
- L2CAP H2H exchange (initiator + responder)
- Routing table updates from discovery + H2H
- Build fingerprint for firmware equivalence checks
- Simulator with full routing-core behavior

⏳ **In Progress:**
- Indirect routing validation on hardware (works in sim)
- Encrypted message exchange

❌ **Not Yet Implemented:**
- Store-and-forward for low-energy nodes
- WiFi/LoRa transport
- Network key onboarding
