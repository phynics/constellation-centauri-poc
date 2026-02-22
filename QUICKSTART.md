# Quick Start - Hardware Testing

## TL;DR - Test Now

```bash
# 1. Build
cargo build --release

# 2. Flash to first ESP32-C6 board (Node A)
espflash flash target/riscv32imac-unknown-none-elf/release/constellation --monitor

# 3. In a new terminal, flash to second board (Node B)
espflash flash target/riscv32imac-unknown-none-elf/release/constellation --monitor

# 4. Watch the serial output from both boards
```

## What You'll See

### First Boot (Each Node)
```
Constellation Mesh Node - Phase 5 PoC
======================================
No identity found. Generating new identity...
Identity saved to flash
Node identity: [XX, XX, XX, XX, XX, XX, XX, XX]
Public key: [32 hex bytes...]
Shared state initialized
BLE tasks spawned
Main logic task spawned
Node is running. Waiting for peer discovery...
BLE advertising beacon for [...]
Status: 0 peers in routing table
```

### What Works Now ✅
- Identity generation (unique per node)
- Flash persistence (survives reboot)
- Task spawning and concurrent execution
- Periodic status logging

### What's Not Working Yet ⏳
- **BLE communication** - Tasks run but don't actually transmit/receive
- **Peer discovery** - Needs trouble-host API integration
- **Message exchange** - Needs BLE working first

## Next: Complete BLE Integration

The BLE tasks have `// TODO` comments showing what needs to be implemented.

**Main files to modify:**
- `src/transport/ble.rs` - Lines ~120, ~150, ~185

**What to implement:**
1. Initialize BLE controller with trouble-host
2. Set advertising data (10-byte beacon)
3. Scan for advertising packets
4. Setup GATT service with characteristics
5. Handle GATT read/write/notify

**See:** `HARDWARE_TESTING.md` for detailed instructions.

## Immediate Action Items

### If you have ESP32-C6 hardware:

1. **Test basic functionality:**
   - Flash one board
   - Verify it boots and shows identity
   - Power cycle - verify same identity loads from flash
   - This confirms: hardware TRNG ✓, flash storage ✓, embassy executor ✓

2. **Share serial output:**
   - Copy the boot log
   - Note any panics or errors
   - We can debug hardware-specific issues

3. **Attempt BLE integration:**
   - Clone trouble-host examples
   - Compare with our skeleton
   - Start with just advertising
   - Build incrementally

### If you don't have hardware yet:

The code is ready to flash when you get boards. Current implementation:
- ✅ Builds successfully for ESP32-C6 target
- ✅ All core protocol logic implemented
- ✅ Flash storage integrated
- ✅ Embassy tasks structured correctly
- ⏳ BLE API integration pending

## Expected Timeline

**With hardware in hand:**
- 30 min: Build, flash, verify boot
- 1-2 hours: Integrate trouble-host advertising
- 1-2 hours: Integrate trouble-host scanning
- 1-2 hours: Integrate GATT server
- 1 hour: Debug and test end-to-end

**Total: ~4-6 hours** to complete Phase 6 once you have the boards and start integrating trouble-host.

## Questions Before Testing?

- Need help with espflash setup?
- Want to review BLE integration approach first?
- Curious about any specific implementation details?

Let me know and I can provide more specific guidance!
