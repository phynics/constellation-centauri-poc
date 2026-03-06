# Constellation BLE Protocol Specification

This document specifies the BLE-layer protocol: advertisement formats, the H2H (Heart2Heart) exchange, debug messaging, and protocol versioning.

For the higher-level mesh protocol (routing, cryptography, store-and-forward), see [SPEC.md](SPEC.md).

---

## 1. BLE Architecture

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

---

## 2. Discovery Advertisements

Lightweight BLE advertisements for peer discovery. **No connection required.**

### 2.1 Advertisement Structure

```
AD Structure 1: Flags (LE General Discoverable, BR/EDR Not Supported)
AD Structure 2: Manufacturer Specific Data
  Company ID:  0x1234 (2 bytes, little-endian)
  Payload:     Discovery payload (10 bytes)
```

### 2.2 Discovery Payload (10 bytes)

```
Offset  Size  Field
──────  ────  ──────────────
0       8     short_addr      ShortAddr of the advertising node
8       2     capabilities    Capability bitfield (LE u16)
```

Fits within the 31-byte BLE advertising data limit.

### 2.3 BLE Address Derivation

Each node derives its random static BLE address from its `ShortAddr`:

```
mac[0..6] = short_addr[0..6]
mac[5]   |= 0xC0            // marks as random static per BLE spec
```

This means the first 5 bytes of the BLE MAC match the `ShortAddr`, enabling quick correlation.

---

## 3. H2H (Heart2Heart) Exchange

Full peer-state exchange over BLE L2CAP Connection-Oriented Channels (CoC).

### 3.1 Transport Parameters

| Parameter | Value |
|-----------|-------|
| L2CAP PSM | `0x0081` (dynamic range, odd) |
| MTU | 128 bytes |
| Connection timeout | 5 seconds |
| Cycle period | 60 seconds |

### 3.2 Pair Scheduling

For any pair of nodes (A, B):

1. **Canonical order**: `(lo, hi) = sort_lexicographic(A.short_addr, B.short_addr)`
2. **Pair hash**: `SHA-256(lo || hi)` → 32 bytes
3. **Initiator**: the node with the lexicographically smaller `ShortAddr`
4. **Slot offset**: `u16_le(pair_hash[0..2]) % 60` → second within the 60s cycle

Both nodes compute the same values deterministically.

### 3.3 Exchange Protocol

```
Initiator (central)              Responder (peripheral)
─────────────────────            ─────────────────────
                                 Advertise (connectable)
Connect via BLE ──────────────►  Accept connection
Create L2CAP CoC ─────────────►  Accept L2CAP CoC
Send H2hPayload ──────────────►
                                 Receive + deserialize
                                 Build response
                  ◄────────────── Send H2hPayload
Receive + deserialize
Update routing table             Update routing table
                                 (flush delay 200ms)
Disconnect                       Disconnect
```

### 3.4 H2H Payload Wire Format

```
Offset  Size      Field            Notes
──────  ────      ─────            ─────
0       1         flags            Bit field (see §3.5)
1       1         version          Protocol version (see §3.6)
2       0 | 32    full_pubkey      Conditional on flags.0
?       2         capabilities     Sender's capability bitfield (LE u16)
?       4         uptime_secs      Sender's uptime in seconds (LE u32)
?       1         peer_count       Number of peer entries (0–8)
?       N × 11    peers[]          Peer info entries
```

**Total size**: 10–98 bytes (without pubkey), 42–130 bytes (with pubkey).

Practical max with `H2H_MAX_PEER_ENTRIES = 8`: 98 bytes (no pubkey) or 130 bytes (with pubkey).

### 3.5 Flags Byte

```
Bit  Name          Description
───  ────          ───────────
0    has_pubkey    1 = 32-byte pubkey follows flags; 0 = omitted
1    (reserved)
2    (reserved)
3    (reserved)
4    (reserved)
5    (reserved)
6    (reserved)
7    (reserved)
```

**Pubkey omission logic**: the sender checks the routing table — if the partner's entry already has a non-zero pubkey, the sender omits its own pubkey (saves 32 bytes). First exchanges always include the pubkey.

### 3.6 Version Byte

The `version` byte immediately follows `flags`. It identifies the H2H protocol version used by the sender. The current version is `0x02`.

A receiver **MUST** check the version byte. If it does not support the received version, it **SHOULD** log a debug message and skip processing (but not disconnect — the peer may still understand the response).

### 3.7 Peer Info Entry (35 bytes)

```
Offset  Size  Field
──────  ────  ─────
0       32    pubkey          Peer's full Ed25519 Public Key
32      2     capabilities    Peer's capability bitfield (LE u16)
34      1     hop_count       Hops from sender to this peer (0 = direct)
```

### 3.8 Peer Selection

Peers included in the list are selected via **recency-weighted reservoir sampling**:

- **Weight**: `10000 / ((1 + age_secs) × (1 + hop_count))`
- **Direct peer floor**: direct peers (hop=0) get minimum weight `2500`
- **Exclusions**: the partner's own entry, and indirect peers whose `learned_from` matches the partner (redundant information)
- **RNG**: xorshift32 seeded from `our_short_addr[0..4] XOR now_ticks`

---

## 4. Debug Messages

Debug messages provide diagnostic visibility into the BLE protocol layer. All are prefixed with a tag indicating the subsystem.

### 4.1 Log Tags

| Tag | Subsystem |
|-----|-----------|
| `[periph]` | Peripheral H2H task (responder) |
| `[central]` | Central H2H task (initiator + discovery) |
| `[ble_runner]` | BLE HCI event loop |
| `[heartbeat]` | Uptime + routing table health |

### 4.2 Startup Messages

```
Constellation Mesh Node - H2H (Heart2Heart)
=============================================
Build: <16-char hex fingerprint>
Node identity: <short_addr as hex>
Public key:    <pubkey as hex>
BLE address:   <6-byte MAC as hex>
[periph] Startup jitter: <N>ms
```

The **build fingerprint** is a hash of key source files, computed at compile time. Both devices in a pair must show the same fingerprint to confirm identical firmware.

### 4.3 Discovery Messages

```
[central] New peer <short_addr> (<N> total)
```

Only printed when a **genuinely new** peer is added to the routing table (not on re-discovery of a known peer).

### 4.4 H2H Exchange Messages (Initiator / Central)

```
[central] H2H cycle: <N> peers to connect
[central] H2H → <short_addr> (slot <N>s)
[central] Connected to <short_addr>
[central] H2H tx sent
[central] H2H rx from <short_addr>
[central] Routing table: <N> peers
```

**Error cases**:
```
[central] L2CAP send error: <error>
[central] L2CAP rx error: <error>
[central] L2CAP create error: <error>
[central] Connect to <short_addr> failed: <error>
[central] Scan error: <error>
```

### 4.5 H2H Exchange Messages (Responder / Peripheral)

```
[periph] Connection from <BLE MAC>
[periph] H2H rx <N> bytes
[periph] H2H step=1 partner=<short_addr prefix>
[periph] H2H step=2 built payload, <N> peers
[periph] H2H step=3 serialized <N> bytes
[periph] H2H step=4 tx ok
[periph] Routing table: <N> peers
```

**Error cases**:
```
[periph] H2H step=4 tx ERR: <error>
[periph] H2H serialize error: <error>
[periph] H2H deserialize FAILED (<N> bytes)
[periph] L2CAP rx error: <error>
[periph] L2CAP accept error: <error>
[periph] Accept error: <error>
[periph] Advertise error: <error>
[periph] AD encode error: <error>
```

### 4.6 Periodic Health

```
[heartbeat] Uptime: <N>s, peers: <N>
```

Printed every 5 seconds.

---

## 5. Protocol Versioning

### 5.1 Version Location

The protocol version appears in two places:

| Context | Field | Current Value |
|---------|-------|---------------|
| Mesh packet header | `version` (upper 4 bits of byte 0) | `0x01` |
| H2H payload | `version` (byte 1) | `0x01` |

### 5.2 Compatibility Rules

- **Same major version (0x0X)**: nodes MUST be able to parse the payload, ignoring unknown flags. Unknown flag bits are reserved and MUST be zero on send.
- **Different major version**: nodes SHOULD log a version mismatch and skip processing.
- **Version negotiation**: not implemented. Both peers send their version; the receiver decides whether it can parse the payload.

### 5.3 Breaking Changes

Changes that bump the version byte:

- Adding required fields before `peer_count`
- Changing the semantic meaning of existing fields
- Changing `PeerInfo` entry size

Changes that do **not** bump the version:

- Adding new flag bits (receivers ignore unknown flags)
- Changing peer selection algorithm (wire format unchanged)

---

## 6. IPv6-Compatible Addressing

### 6.1 Address Derivation

Constellation's `ShortAddr` (8 bytes / 64 bits) maps directly to an IPv6 interface identifier. Combined with a network-derived prefix, every node has a deterministic IPv6 address:

```
fd XX:XXXX:XXXX:XXXX : SSSS:SSSS:SSSS:SSSS
└── network prefix ──────┘ └── ShortAddr (8B) ──┘
         /64                   interface ID
```

### 6.2 Network Prefix

The `/64` prefix is derived from the **network authority's public key**:

```
prefix[0]    = 0xFD                          // ULA (RFC 4193)
prefix[1..8] = SHA-256(NetworkAuthorityPubKey)[0..7]  // 7 bytes
```

This gives each constellation network a unique `/64` within the `fd00::/8` ULA range. The probability of collision is negligible (2⁻⁵⁶).

### 6.3 Full IPv6 Address

```
addr[0..8]  = network prefix  (fd + 7 bytes from network key hash)
addr[8..16] = ShortAddr        (8 bytes from SHA-256(NodePubKey))
```

**Example**:
```
Network key hash: a3 b7 c2 e8 1b 4d 90
Node ShortAddr:   ee f1 9d bb 92 48 3d 89

IPv6 address:     fda3:b7c2:e81b:4d90:eef1:9dbb:9248:3d89
```

### 6.4 Transport Implications

| Transport | Address Usage |
|-----------|---------------|
| **BLE** | ShortAddr in advertisements and L2CAP; IPv6 not used on the wire |
| **WiFi** | Full IPv6 address assigned to the interface; direct UDP/TCP |
| **LoRa** | ShortAddr only (bandwidth-constrained) |

When WiFi transport is added, nodes bind their derived IPv6 address to the WiFi interface, enabling seamless mesh-layer to IP-layer bridging without address translation.

### 6.5 Backward Compatibility

The `ShortAddr` type remains `[u8; 8]` throughout the codebase. IPv6 addresses are constructed only at the transport boundary. No changes to routing tables, peer entries, or packet headers are required.

---

## 7. Constants

```
PROTOCOL_VERSION          = 0x01
H2H_CYCLE_SECS            = 60
H2H_MAX_PEER_ENTRIES       = 8
H2H_CONNECTION_TIMEOUT_SECS = 5
H2H_PSM                   = 0x0081
H2H_MTU                   = 128
CONSTELLATION_COMPANY_ID   = 0x1234
DISCOVERY_PAYLOAD_SIZE     = 10
PEER_INFO_SIZE             = 11
TICK_HZ                    = 1_000_000 (Embassy ESP32 default)
WEIGHT_SCALE               = 10_000
DIRECT_WEIGHT_FLOOR        = 2_500
MAX_PEERS                  = 32
```
