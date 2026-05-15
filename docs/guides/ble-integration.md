# BLE Integration Guide

## Current Status

✅ **Working:**
- Node boots with Embassy executor
- BLE advertising with discovery payload (short_addr + capabilities + network_addr, 18 bytes)
- BLE scanning for peer discovery and network identification
- L2CAP Connection-Oriented Channel H2H exchange (initiator + responder)
- Extended H2H sessions for low-power delayed delivery and router-to-router retained-message replication
- Routing table updates from discovery and H2H
- Identity generation and flash persistence (dedicated `constellation` partition)
- Onboarding GATT service with staged enrollment and commit
- Companion enrollment of firmware nodes (certificate issuance + commit)
- Build fingerprint for firmware equivalence checking
- Companion mesh participation (routing, pings, encrypted messages)

⏳ **In Progress:**
- End-to-end companion↔firmware onboarding validation on hardware
- Multi-hop message routing validation on hardware
- Encrypted message exchange (ECDH + ChaCha20-Poly1305)

❌ **Not Yet Implemented:**
- WiFi/LoRa transport
- H2H session authentication (signed H2H frames)
- Packet counter / replay protection in code

## BLE Architecture

The firmware uses a two-role BLE architecture:

```
┌─────────────────────────────────────────────────────────┐
│ Node Firmware                                            │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ peripheral   │  │ central      │  │ ble_runner    │  │
│  │ _h2h_task    │  │ _h2h_task    │  │ _task         │  │
│  └──────┬───────┘  └──────┬───────┘  └───────┬───────┘  │
│         │                 │                  │          │
│  Connectable adv   Discovery scan     HCI event pump   │
│  + L2CAP accept    + L2CAP initiate                    │
│  + Onboarding GATT                                      │
│         │                 │                  │          │
│  ┌──────┴─────────────────┴──────────────────┴───────┐  │
│  │              trouble-host BLE stack                │  │
│  └───────────────────────┬───────────────────────────┘  │
│                          │                              │
│  ┌───────────────────────┴───────────────────────────┐  │
│  │            esp-wifi BLE controller                 │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

All tasks run cooperatively via Embassy `join4` on a single-threaded executor.

## Discovery Advertisements

### Primary Advertising Data (25 bytes)

```
AD Structure 1: Flags (3 bytes)
  LE General Discoverable, BR/EDR Not Supported

AD Structure 2: Manufacturer Specific Data (22 bytes)
  Length: 22, Type: 0xFF
  Company ID: 0x1234 (2 bytes, little-endian)
  Payload: [short_addr:8][capabilities:2][network_addr:8]
```

### Scan Response Data (20 bytes)

```
AD Structure: Complete 128-bit Service UUIDs
  UUID: 43d7aa10-5f4b-4c84-a100-000000000001 (onboarding service)
```

### NetworkAddr

`network_addr` is an 8-byte fingerprint of the network authority public key,
derived via `SHA-256(pubkey)[0..8]`. This enables companions to identify
network membership from advertisement data alone.

- **Enrolled nodes**: advertise `network_addr_of(authority_pubkey)`
- **Unenrolled nodes**: advertise `ONBOARDING_READY_NETWORK_ADDR = [0xFF; 8]`

## Onboarding GATT Service

The firmware exposes a GATT service for onboarding:

| UUID suffix | Access | Value | Description |
|---|---|---|---|
| `...0001` | service | — | Onboarding service |
| `...0002` | read | 16 bytes | Protocol signature |
| `...0003` | read | 33 bytes | Network marker (onboarding-ready string or 32-byte pubkey + padding) |
| `...0004` | read | 32 bytes | Node ed25519 public key |
| `...0005` | read | 2 bytes | Node capabilities |
| `...0006` | read | 8 bytes | Short address |
| `...0007` | read | 2 bytes | L2CAP PSM |
| `...0008` | read, write | 32 bytes | Authority public key (staged) |
| `...0009` | read, write | 2 bytes | Certified capabilities (staged) |
| `...000a` | read, write | 64 bytes | Network signature (staged) |
| `...000b` | write | 1 byte | Commit enrollment |
| `...000c` | read | 98 bytes | Certificate data (commit+authority+signature) |

### Enrollment Flow

1. Companion connects to the unprovisioned node
2. Companion discovers the onboarding service
3. Companion reads `node_pubkey` (32 bytes) and `capabilities` (2 bytes)
4. Companion issues a `NodeCertificate` signed by the local authority key
5. Companion writes `authority_pubkey`, `cert_capabilities`, `cert_signature`
6. Companion writes `commit_enrollment` (any non-zero byte)
7. Firmware validates the certificate:
   - All staged fields are present
   - Certificate verifies for the local node pubkey
   - Signature is valid under the authority key
8. Firmware persists enrollment to the `constellation` flash partition
9. Firmware ACKs the commit write
10. Firmware performs a software reset (100ms delay)
11. After reboot, firmware advertises `network_addr_of(authority_pubkey)` instead of `ONBOARDING_READY_NETWORK_ADDR`

### GATT Characteristic Value Notes

- **Network marker**: when unenrolled, contains the ASCII string `constellation:onboarding-ready:v1` (33 bytes, zero-padded). When enrolled, contains the 32-byte network authority pubkey followed by a zero byte.
- **All multi-byte values** are little-endian.
- **trouble-host GATT characteristics require fixed-size arrays**. Variable-length values use zero-padding; companion must trim trailing nuls.

## H2H Exchange

The H2H (Heart2Heart) exchange is the core peer-state synchronization mechanism:

1. **Initiator selection**: lexicographically smaller `ShortAddr` initiates
2. **Slot scheduling**: deterministic slot offset from `SHA-256(lo || hi)`
3. **Exchange**: initiator opens L2CAP CoC, sends payload, receives response
4. **Routing update**: both peers update their routing tables with direct and indirect peer info

### Extended Low-Power Delivery Sessions

H2H now stays open after the initial sync exchange when the peers need to handle
low-power delayed delivery.

- **LPN wake path**: the low-power endpoint wakes a preferred router first, then
  can fall back to other reachable routers if the preferred one is unavailable.
- **Backup placement**: the preferred router is still chosen from local
  freshness/quality, but retained-message replicas are only propagated to a
  deterministic backup subset derived from the LPN identity.
- **Router redundancy**: routers exchange retained-message replicas and
  tombstones over typed follow-up H2H frames instead of a parallel protocol.

The simulator trace model now records this explicitly with:

- `Deferred`
- `LpnWakeSync`
- `PendingAnnounced`
- `DeliveredFromStore`
- `DeliveryConfirmed`
- `ExpiredFromStore`

### H2H Payload

```
Offset  Size      Field            Notes
──────  ────      ─────            ─────
0       1         flags            Bit field (has_pubkey, etc.)
1       1         version          Protocol version (0x02)
2       0|32      full_pubkey      Conditional on flags.0
?       2         capabilities     Sender's capability bitfield
?       4         uptime_secs      Sender's uptime
?       1         peer_count       Number of peer entries (0–8)
?       N × 11    peers[]          Peer info entries
```

### Peer Selection

Peers included in the H2H payload are selected via recency-weighted reservoir sampling:
- Weight: `10000 / ((1 + age_secs) × (1 + hop_count))`
- Direct peers get minimum weight 2500
- Exclusions: partner's own entry, and indirect peers learned from the partner

## Flash Persistence

The firmware uses a dedicated 4KB partition (`constellation` at offset `0x210000`)
for identity and provisioning state:

- **PartitionedFlash** wraps `FlashStorage` to translate partition-relative offsets
- All reads use sector-aligned 4096-byte buffers (ESP32 requires 4-byte alignment in both offset and length)
- Erase-before-write is enforced (NOR flash can only turn 1-bits into 0-bits)
- Storage format: 236 bytes of structured data within the 4096-byte sector

## Error Diagnostics

The sim now returns specific H2H failure reasons instead of the generic `ConnectionFailed`:

| Error | Meaning |
|-------|---------|
| `PeerInactive` | Target node is not currently active |
| `InitiateDisabled` | Source node's H2H initiate behavior is disabled |
| `RespondDisabled` | Target node's H2H respond behavior is disabled |
| `LinkDisabled` | The link between source and target is disabled |
| `DropRejected` | The link drop probability rejected this attempt |
| `ConnectionFailed` | Generic connection failure (fallback) |

## Testing BLE on Hardware

### Flash Two Boards

```bash
# Flash Node A (first board)
cd firmware && cargo esp32c6

# In a separate terminal, flash Node B
cd firmware && cargo esp32c6
```

### Expected Logs

**Node A:**
```
[central] H2H cycle: 1 peers to connect
[central] Connected to <short_addr>
[central] H2H rx from <short_addr>
[central] Routing table: 1 peers
```

**Node B:**
```
[periph] Connection from <BLE MAC>
[periph] H2H step=1 partner=<short_addr>
[periph] H2H step=4 tx ok
[periph] Routing table: 1 peers
```

### Build Fingerprint

Both boards print a build fingerprint at startup. If they are running identical firmware, the fingerprints should match. This is important for debugging H2H exchange failures.

## Simulator Testing

Before testing on hardware, verify routing behavior in the simulator:

```bash
cargo run -p sim
```

The simulator runs the same shared `routing-core` behavior loops and provides:
- Hop-by-hop message trace debugging
- Scenario presets including partitioned topologies
- Live link/capability editing
- Broadcast fan-out observation

## Resources

- [trouble-host GitHub](https://github.com/embassy-rs/trouble)
- [Embassy Book](https://embassy.dev/book/)
- [ESP32-C6 BLE Docs](https://docs.espressif.com/projects/esp-idf/en/latest/esp32c6/api-reference/bluetooth/index.html)
