# BLE Integration Guide

## Current Status

✅ **Working:**
- Node boots successfully
- Embassy executor running
- BLE task structure in place
- Identity generation and flash storage (with warnings)

❌ **Not Working:**
- BLE advertising (skeleton only)
- BLE scanning (skeleton only)
- GATT server (skeleton only)
- Peer discovery
- Message exchange

## Testing BLE Once Integrated

### BLE Scanner Apps

**iOS:**
- [nRF Connect](https://apps.apple.com/app/nrf-connect/id1054362403) - Best for development
- [LightBlue](https://apps.apple.com/app/lightblue/id557428110) - Simple interface

**Android:**
- [nRF Connect for Mobile](https://play.google.com/store/apps/details?id=no.nordicsemi.android.mcp)
- [BLE Scanner](https://play.google.com/store/apps/details?id=com.macdom.ble.blescanner)

**macOS/Linux:**
- `bluetoothctl` command line tool
- [nRF Connect Desktop](https://www.nordicsemi.com/Products/Development-tools/nRF-Connect-for-Desktop)

### What You'll See in Scanner

**Before Connection:**
```
Device: (no name)
Address: XX:XX:XX:XX:XX:XX
RSSI: -XX dBm
Advertising Data:
  - Service UUID: 0x1234
  - Manufacturer Data: [0x34, 0x12, 0xE0, 0xB6, 0xEF, 0xBE, 0x55, 0xA8, 0xA7, 0xE6]
                        ^------^  ^-----------------------------------------------^
                        Service   Node ShortAddr
```

**After Connection:**
```
Services:
└─ 12345678-9abc-def0-1234-56789abcdef1 (Constellation Mesh)
   ├─ ...def2 (Heartbeat) [Read]
   │  └─ Value: 71 bytes (HeartbeatPayload)
   └─ ...def3 (Packets) [Write, Notify]
      └─ For mesh packet exchange
```

## Implementation Steps

### Step 1: Study trouble-host API

```bash
# Clone trouble-host examples
git clone https://github.com/embassy-rs/trouble.git /tmp/trouble
cd /tmp/trouble/examples

# Look for ESP32 examples
ls -la | grep -i esp
ls -la | grep -i peripheral
```

Key files to study:
- How to create a BLE peripheral
- How to set advertising data
- How to define GATT services with macros
- How to handle characteristic read/write

### Step 2: Initialize BLE Controller

In `src/main.rs`, before spawning BLE tasks:

```rust
// Initialize BLE controller (pseudocode - adjust to actual trouble-host API)
let ble = init_ble_controller(peripherals.RADIO, ...)?;
let advertiser = ble.advertiser();
let scanner = ble.scanner();
let gatt_server = ble.gatt_server();

// Pass to tasks
spawner.spawn(advertise_task(short_addr, advertiser)).ok();
spawner.spawn(scan_task(routing_table, scanner)).ok();
spawner.spawn(gatt_task(heartbeat, incoming, outgoing, gatt_server)).ok();
```

### Step 3: Implement Advertising

In `src/transport/ble.rs`, `ble_advertise_task`:

```rust
pub async fn ble_advertise_task(
    short_addr: ShortAddr,
    mut advertiser: BleAdvertiser, // trouble-host type
) {
    let beacon = AdvBeacon::new(short_addr);
    let mut adv_buf = [0u8; MAX_ADV_PAYLOAD];
    let adv_len = beacon.serialize(&mut adv_buf);

    loop {
        // Set advertising data
        advertiser.set_data(&adv_buf[..adv_len]).await.ok();

        // Start advertising
        advertiser.start().await.ok();

        log::info!("BLE advertising beacon for {short_addr:x?}");

        // Wait for next heartbeat interval
        // (Will work once timer driver is configured)
        embassy_futures::yield_now().await;
    }
}
```

### Step 4: Implement Scanning

```rust
pub async fn ble_scan_task(
    routing_table: &'static Mutex<NoopRawMutex, RoutingTable>,
    mut scanner: BleScanner, // trouble-host type
) {
    // Start scanning
    scanner.start().await.ok();

    loop {
        // Wait for advertising report
        if let Ok(report) = scanner.next_report().await {
            // Parse beacon from advertising data
            if let Some(beacon) = AdvBeacon::deserialize(&report.data) {
                log::info!("Discovered peer {:x?} at {:x?}",
                          beacon.short_addr, report.address);

                // TODO: Connect to peer and read full heartbeat via GATT
                // TODO: Update routing table
            }
        }

        embassy_futures::yield_now().await;
    }
}
```

### Step 5: Define GATT Service

Using `trouble-host-macros`:

```rust
use trouble_host_macros::gatt_service;

#[gatt_service(uuid = "12345678-9abc-def0-1234-56789abcdef1")]
struct ConstellationService {
    #[characteristic(uuid = "...def2", read)]
    heartbeat: HeartbeatPayload,

    #[characteristic(uuid = "...def3", write, notify)]
    packets: PacketCharacteristic,
}
```

### Step 6: Implement GATT Task

```rust
pub async fn ble_gatt_task(
    heartbeat: &'static Mutex<NoopRawMutex, HeartbeatPayload>,
    incoming_packets: &'static Channel<NoopRawMutex, PacketBuf, 4>,
    outgoing_packets: &'static Channel<NoopRawMutex, PacketBuf, 4>,
    mut gatt: GattServer, // trouble-host type
) {
    loop {
        match gatt.next_event().await {
            GattEvent::Read { handle, responder } => {
                if handle == HEARTBEAT_CHAR {
                    let hb = heartbeat.lock().await;
                    let mut buf = [0u8; 128];
                    let len = hb.serialize(&mut buf).unwrap();
                    responder.respond(&buf[..len]).await.ok();
                }
            }
            GattEvent::Write { handle, data } => {
                if handle == PACKET_CHAR {
                    let mut packet = PacketBuf::new();
                    packet.extend_from_slice(data).ok();
                    incoming_packets.send(packet).await;
                }
            }
            _ => {}
        }

        // Check for outgoing packets to notify
        if let Ok(packet) = outgoing_packets.try_receive() {
            gatt.notify(PACKET_CHAR, &packet).await.ok();
        }

        embassy_futures::yield_now().await;
    }
}
```

## Testing Procedure

### 1. Flash Firmware

```bash
cargo build --release
espflash flash --monitor target/riscv32imac-unknown-none-elf/release/constellation
```

### 2. Open BLE Scanner App

- Launch nRF Connect (or similar)
- Start scanning
- Look for device with no name showing "0x1234" service

### 3. Verify Advertising

You should see:
- Device appears in scan list
- Service UUID: 0x1234
- Manufacturer data: 10 bytes starting with 0x34 0x12

### 4. Connect to Device

- Tap on the device
- Scanner will connect and discover services
- You should see Constellation Mesh service

### 5. Read Heartbeat

- Tap on Heartbeat characteristic
- Read value
- Should get 71 bytes:
  - 32 bytes: Public key
  - 2 bytes: Capabilities
  - 4 bytes: Uptime
  - 32 bytes: Bloom filter
  - 1 byte: Generation

### 6. Test Packet Exchange

- Write test data to Packet characteristic
- Check serial output for incoming packet log
- Verify node processes the packet

### 7. Test Two-Node Discovery

**With two ESP32-C6 boards:**

1. Flash both with same firmware
2. Power on both nodes
3. Watch serial output for peer discovery
4. Verify routing table updates on both
5. Check BLE scanner shows both devices

**Expected logs:**

Node A:
```
Discovered peer [XX, XX, ...] at BLE addr [...]
Routing table: 1 peer
```

Node B:
```
Discovered peer [YY, YY, ...] at BLE addr [...]
Routing table: 1 peer
```

## Troubleshooting

### No Device in Scanner

**Check:**
- BLE advertising actually started (add debug logs)
- Advertising data is valid (check buffer size)
- Phone Bluetooth is on and has permissions

**Debug:**
```rust
log::info!("Starting advertising with {} bytes", adv_len);
log::info!("Beacon data: {:x?}", &adv_buf[..adv_len]);
```

### Can Connect But No Services

**Check:**
- GATT server initialized properly
- Service UUIDs are correct
- Characteristics registered

### Connection Drops Immediately

**Check:**
- Connection parameters (interval, timeout)
- MTU size
- Memory allocation for connection state

### Can't Read Characteristics

**Check:**
- Read permissions set correctly
- Responder sends valid data
- Data length within MTU limit

## Next Steps After BLE Works

1. **Enable Timer Driver**
   - Configure esp-rtos timer properly
   - Re-enable periodic logging
   - Add proper heartbeat intervals

2. **Fix Flash Storage**
   - Configure flash partition
   - Ensure identity persists across reboots

3. **Complete Message Exchange**
   - Implement full packet send/receive
   - Add encryption/decryption
   - Test end-to-end message flow

4. **Multi-Hop Testing**
   - Deploy 3+ nodes
   - Verify routing through intermediaries
   - Test bloom filter propagation

## Resources

- [trouble-host GitHub](https://github.com/embassy-rs/trouble)
- [Embassy Book](https://embassy.dev/book/)
- [ESP32-C6 BLE Docs](https://docs.espressif.com/projects/esp-idf/en/latest/esp32c6/api-reference/bluetooth/index.html)
- [Bluetooth Core Spec](https://www.bluetooth.com/specifications/specs/core-specification/)

## Need Help?

If you get stuck on BLE integration:
1. Share the trouble-host API you find in examples
2. Show any compilation errors
3. Copy relevant logs from serial output
4. I can help adapt the integration to the actual API
