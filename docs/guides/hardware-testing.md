# Hardware Testing Guide - Phase 6

## Quick Start - TL;DR

```bash
# 1. Build
cargo build --release

# 2. Flash to first ESP32-C6 board (Node A)
espflash flash target/riscv32imac-unknown-none-elf/release/constellation --monitor

# 3. In a new terminal, flash to second board (Node B)
espflash flash target/riscv32imac-unknown-none-elf/release/constellation --monitor

# 4. Watch the serial output from both boards
```

## Overview

This guide covers testing the Constellation Mesh PoC on physical ESP32-C6 hardware. You'll need **two ESP32-C6 development boards** to demonstrate peer discovery and message exchange.

## Prerequisites

### Hardware
- 2x ESP32-C6 development boards (e.g., ESP32-C6-DevKitC-1)
- 2x USB-C cables
- Computer with 2 USB ports (or use a USB hub)

### Software
- Rust toolchain with riscv32imac target
- espflash or espup for flashing
- Serial monitor (screen, minicom, or espmonitor)

## Build & Flash Instructions

### 1. Build the Firmware

```bash
# From the project root
cargo build --release
```

Expected output:
```
Compiling constellation v0.1.0
Finished `release` profile target(s)
```

The binary will be at: `target/riscv32imac-unknown-none-elf/release/constellation`

### 2. Flash to Hardware

**Option A: Using espflash**

```bash
# Flash Node A (first board)
espflash flash target/riscv32imac-unknown-none-elf/release/constellation --monitor

# In a separate terminal, flash Node B (second board)
espflash flash target/riscv32imac-unknown-none-elf/release/constellation --monitor
```

**Option B: Using cargo-espflash**

```bash
# Flash Node A
cargo espflash flash --release --monitor

# Flash Node B in separate terminal
cargo espflash flash --release --monitor
```

### 3. Monitor Serial Output

If not using `--monitor` flag:

```bash
# Node A
screen /dev/ttyUSB0 115200

# Node B (separate terminal)
screen /dev/ttyUSB1 115200
```

On macOS:
```bash
screen /dev/tty.usbserial-* 115200
```

## Expected Behavior

### Boot Sequence (Each Node)

```
Constellation Mesh Node - Phase 5 PoC
======================================
No identity found. Generating new identity...
Identity saved to flash
Node identity: [a1, b2, c3, d4, e5, f6, 78, 90]
Public key: [32 bytes of hex...]
Shared state initialized
BLE tasks spawned
Main logic task spawned
Node is running. Waiting for peer discovery...
Status: 0 peers in routing table
```

**On subsequent boots** (identity persists):
```
Loading identity from flash...
Identity loaded successfully
Node identity: [a1, b2, c3, d4, e5, f6, 78, 90]  # Same as before
```

### Current Implementation Status

✅ **Working:**
- Identity generation with hardware TRNG
- Flash persistence (identity survives reboots)
- Embassy executor and task spawning
- Routing table and shared state
- Periodic status logging

⏳ **Partially Implemented (Skeletons):**
- BLE advertising (task runs but needs trouble-host integration)
- BLE scanning (task runs but needs trouble-host integration)
- GATT server (task runs but needs trouble-host integration)

❌ **Not Yet Functional:**
- Actual BLE radio communication (requires trouble-host API calls)
- Peer discovery via BLE
- Encrypted message exchange

## Troubleshooting

### Build Errors

**Error: `esp-hal` version mismatch**
```bash
cargo update
cargo clean
cargo build --release
```

**Error: Target not found**
```bash
rustup target add riscv32imac-unknown-none-elf
```

### Flash Errors

**Error: Permission denied on /dev/ttyUSB***
```bash
# Linux
sudo usermod -a -G dialout $USER
# Log out and back in

# Or use sudo
sudo espflash flash ...
```

**Error: Failed to connect**
- Hold BOOT button while connecting
- Press RESET button after connecting
- Try different USB cable/port

### Runtime Issues

**No output on serial monitor**
- Check baud rate is 115200
- Try pressing RESET button on board
- Verify correct USB port

**Panic on boot**
- Check the panic message in serial output
- Common causes:
  - Heap allocation failure (reduce HEAP_SIZE in main.rs)
  - Flash storage initialization failure
  - TRNG initialization failure

**Identity generation fails**
- Error: "Failed to initialize TRNG"
- Solution: ESP32-C6 should have hardware RNG - may be defective board

## Next Steps: BLE Integration

The BLE tasks currently log placeholder messages. To complete Phase 6, you need to:

### 1. Integrate trouble-host BLE API

Replace TODO comments in `src/transport/ble.rs`:

**Advertising Task:**
```rust
// Current (line ~120):
// TODO: Set advertising data using trouble-host API

// Need to implement:
// 1. Initialize BLE controller
// 2. Configure advertising parameters
// 3. Set advertising data with AdvBeacon
// 4. Start advertising
```

**Scanning Task:**
```rust
// Current (line ~150):
// TODO: Scan for advertising packets

// Need to implement:
// 1. Start BLE scanner
// 2. Receive advertising reports
// 3. Parse AdvBeacon from advertising data
// 4. Connect to peer (optional)
// 5. Read full heartbeat via GATT
// 6. Update routing table
```

**GATT Task:**
```rust
// Current (line ~185):
// TODO: Handle GATT events

// Need to implement:
// 1. Define GATT service with characteristics
// 2. Handle read requests (heartbeat characteristic)
// 3. Handle write requests (packet characteristic)
// 4. Send notifications for outgoing packets
```

### 2. Test BLE Communication

Once trouble-host is integrated:

1. **Flash both boards** with updated firmware
2. **Watch serial output** for discovery messages
3. **Expected log output:**

   **Node A:**
   ```
   BLE advertising beacon for [a1, b2, ...]
   Discovered peer [f0, e1, ...] at BLE addr [...]
   Routing table: 1 peer
   Demo: Would send encrypted message to [f0, e1, ...]
   ```

   **Node B:**
   ```
   BLE advertising beacon for [f0, e1, ...]
   Discovered peer [a1, b2, ...] at BLE addr [...]
   Routing table: 1 peer
   Received: "hello from constellation" from [a1, b2, ...]
   ```

### 3. Verify Success Criteria

From [poc-plan.md](../archive/poc-plan.md):

- [x] Node boots and generates/loads identity
- [x] Identity persists across reboots
- [ ] Nodes discover each other via BLE heartbeats (needs trouble-host)
- [ ] Routing table updates with peer information (needs BLE)
- [ ] Encrypted message sent from A to B (needs BLE)
- [ ] Message decrypted and verified on B (needs BLE)
- [ ] Bidirectional communication works (needs BLE)

## Development Workflow

### Iterative Testing

1. **Make changes** to BLE integration
2. **Build**: `cargo build --release`
3. **Flash**: `espflash flash --monitor`
4. **Observe** serial output
5. **Debug** and repeat

### Useful Commands

```bash
# Clean build
cargo clean && cargo build --release

# Check without building
cargo check

# View detailed panic traces
espflash monitor --speed 115200

# Erase flash completely (reset identity)
espflash erase-flash
```

### Adding Debug Logging

In any file:
```rust
use esp_println::println;

println!("Debug: value = {:?}", some_value);
```

Logs appear on serial monitor immediately.

## BLE Integration Resources

Since trouble-host API details aren't fully documented here, you may need to:

1. **Check trouble-host examples:**
   ```bash
   git clone https://github.com/embassy-rs/trouble.git
   cd trouble/examples
   # Look for esp32 or peripheral examples
   ```

2. **Read trouble-host source:**
   - `trouble-host/src/peripheral.rs` - Advertising/scanning
   - `trouble-host/src/gatt.rs` - GATT server setup
   - `trouble-host-macros` - Service/characteristic macros

3. **ESP32 BLE resources:**
   - [esp-rs BLE examples](https://github.com/esp-rs/esp-hal/tree/main/examples)
   - [trouble BLE stack docs](https://github.com/embassy-rs/trouble)

## Known Limitations (PoC)

1. **Single transport**: BLE only, no WiFi/LoRa
2. **Direct peers only**: No multi-hop routing
3. **No store-and-forward**: Low-energy node protocol not implemented
4. **Hardcoded capabilities**: Every node is ROUTE | APPLICATION
5. **Fixed heartbeat interval**: 60 seconds, not configurable
6. **No authentication**: Network key not implemented (trusts all signatures)

These are intentional for the PoC and will be addressed post-validation.

## Success Indicators

You know Phase 6 is complete when:

✅ Both nodes boot successfully
✅ Identity persists across reboots (same ShortAddr)
✅ BLE advertising starts without errors
✅ Nodes discover each other (peer appears in routing table)
✅ Encrypted message is sent and received
✅ Message decrypts correctly on receiving node
✅ Serial logs show successful end-to-end flow

## Getting Help

If you encounter issues:

1. **Check serial output** for panic messages or errors
2. **Verify hardware** with a simple ESP32-C6 blink example first
3. **Test incrementally** - start with just advertising, then add scanning, etc.
4. **Share serial logs** if asking for help

---

**Current Status**: Flash storage integrated ✅, BLE skeleton ready ⏳, awaiting trouble-host integration.

When you're ready to test, flash both boards and share the serial output. We can then debug and complete the BLE integration based on actual hardware behavior.
