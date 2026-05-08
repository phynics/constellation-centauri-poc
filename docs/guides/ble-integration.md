# BLE Integration Guide

## Current Status

✅ **Working:**
- Node boots with Embassy executor
- BLE advertising with discovery payload (short_addr + capabilities)
- BLE scanning for peer discovery
- L2CAP Connection-Oriented Channel H2H exchange (initiator + responder)
- Extended H2H sessions for low-power delayed delivery and router-to-router retained-message replication
- Routing table updates from discovery and H2H
- Identity generation and flash persistence
- Build fingerprint for firmware equivalence checking

⏳ **In Progress:**
- Multi-hop message routing validation on hardware
- Encrypted message exchange (ECDH + ChaCha20-Poly1305)

❌ **Not Yet Implemented:**
- WiFi/LoRa transport
- Network key onboarding

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
cargo esp32c6

# In a separate terminal, flash Node B
cargo esp32c6
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
