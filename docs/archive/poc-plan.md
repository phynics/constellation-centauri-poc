# Proof of Concept Implementation Plan

> Archive note: this document reflects the pre-workspace repository layout that
> used a top-level `src/` tree. Active code now lives in `routing-core/`,
> `firmware/`, and `sim/`, so path references below are historical.

## Goal

Demonstrate two ESP32-C6 nodes discovering each other via BLE heartbeats and exchanging an encrypted, authenticated message. This validates the core protocol stack end-to-end: identity, packet format, bloom filter routing, BLE transport, and ECDH encryption.

## PoC Scope

### In Scope
- ed25519 identity generation and flash persistence
- Packet header serialization/deserialization (wire format)
- Bloom filter (256-bit, insert/contains/merge)
- Heartbeat broadcast via BLE advertising
- Heartbeat receive via BLE scanning
- Peer registry (direct neighbors only)
- Single-hop encrypted message send/receive via BLE GATT
- Message deduplication ring buffer
- Serial log output for observability

### Out of Scope (deferred to post-PoC)
- Multi-hop forwarding (needs 3+ physical nodes)
- Store-and-forward / LE node protocol
- Onboarding via companion app (PoC uses hardcoded network key)
- Display rendering
- WiFi / LoRa transports
- Heartbeat suppression
- Announcement packets
- Certificate verification (PoC trusts all ed25519 signatures directly)

## Success Criteria

1. **Node A** boots, generates identity (or loads from flash), starts BLE advertising heartbeats
2. **Node B** boots, does the same, scans and discovers Node A's heartbeat
3. Both nodes update their routing table and bloom filter with each other's ShortAddr
4. Node A encrypts a test message for Node B's public key and sends it via BLE GATT
5. Node B receives, decrypts, verifies signature, and logs the plaintext over serial
6. Reverse direction also works (B -> A)

---

## Phase 0: Project Setup

### 0.1 Rename Package
- Rename crate from `ble-connect` to `constellation` in `Cargo.toml`

### 0.2 Add Dependencies
Add to `Cargo.toml`:
```toml
x25519-dalek = { version = "2", default-features = false, features = ["static_secrets"] }
chacha20poly1305 = { version = "0.10", default-features = false }
hkdf = { version = "0.12", default-features = false }
sha2 = { version = "0.10", default-features = false }
```

Remove unused deps (PoC doesn't need display):
```
mousefood   -- remove
mipidsi     -- remove
```

### 0.3 Create Module Skeleton
Create the directory structure with empty `mod.rs` files:
```
src/
  main.rs
  crypto/
    mod.rs
    identity.rs
    encryption.rs
  protocol/
    mod.rs
    packet.rs
    heartbeat.rs
    dedup.rs
  routing/
    mod.rs
    bloom.rs
    table.rs
  transport/
    mod.rs
    ble.rs
  node/
    mod.rs
    roles.rs
    storage.rs
  config.rs
```

### 0.4 Verify Clean Build
Run `cargo build` to confirm the skeleton compiles with all new deps on `riscv32imac-unknown-none-elf`.

---

## Phase 1: Core Types & Crypto

Build the foundational types that everything else depends on. No hardware interaction yet — pure logic, testable in isolation.

### 1.1 `src/config.rs` — Constants
Implement the configuration constants from [protocol.md](../spec/protocol.md) Section 13:
- `PROTOCOL_VERSION`, `HEARTBEAT_INTERVAL`, `DEFAULT_TTL`
- `BLOOM_FILTER_BYTES`, `BLOOM_HASH_COUNT`, `SEEN_MESSAGES_CAPACITY`
- `MAX_PEERS`, `HEAP_SIZE`

### 1.2 `src/node/roles.rs` — Capabilities
- Define `Capabilities` as a `u16` with manual bitflag methods (avoid `bitflags` macro dep; just use const + bitwise ops)
- Constants: `ROUTE`, `STORE`, `BRIDGE`, `APPLICATION`, `LOW_ENERGY`, `MOBILE`
- Helper: `Capabilities::is_knot()`, `is_low_energy()`

### 1.3 `src/crypto/identity.rs` — Node Identity
Types:
```rust
pub type PubKey = [u8; 32];
pub type ShortAddr = [u8; 8];
pub type Signature = [u8; 64];

pub struct NodeIdentity {
    signing_key: ed25519_dalek::SigningKey,
    verifying_key: ed25519_dalek::VerifyingKey,
    short_addr: ShortAddr,
}
```

Functions:
- `NodeIdentity::generate(rng: &mut impl RngCore)` — create new keypair
- `NodeIdentity::from_bytes(secret: &[u8; 32])` — restore from flash
- `NodeIdentity::short_addr(&self) -> ShortAddr` — SHA-256 of pubkey, first 8 bytes
- `NodeIdentity::sign(&self, data: &[u8]) -> Signature`
- `NodeIdentity::pubkey(&self) -> PubKey`
- `pub fn verify(pubkey: &PubKey, data: &[u8], sig: &Signature) -> bool`
- `pub fn short_addr_of(pubkey: &PubKey) -> ShortAddr`

### 1.4 `src/crypto/encryption.rs` — ECDH + ChaCha20-Poly1305
Functions:
- `pub fn encrypt(sender: &NodeIdentity, recipient_pubkey: &PubKey, plaintext: &[u8], nonce: &[u8; 12], output: &mut [u8]) -> Result<usize, CryptoError>`
  - Performs ed25519->x25519 conversion, ECDH, HKDF, encrypt
  - Writes `[nonce (12) | ciphertext | tag (16)]` to output buffer
  - Returns total bytes written
- `pub fn decrypt(recipient: &NodeIdentity, sender_pubkey: &PubKey, encrypted: &[u8], output: &mut [u8]) -> Result<usize, CryptoError>`
  - Extracts nonce, derives shared key, decrypts+verifies tag
  - Returns plaintext length
- Internal: `fn derive_shared_key(our_secret: &[u8; 32], their_pubkey: &PubKey) -> [u8; 32]`
  - ed25519 secret -> SHA-512 lower 32 -> x25519 StaticSecret
  - ed25519 pubkey -> Edwards decompress -> Montgomery -> x25519 PublicKey
  - ECDH -> HKDF-SHA256 -> 32-byte symmetric key

### 1.5 `src/protocol/packet.rs` — Wire Format
Types:
```rust
pub struct PacketHeader {
    pub version: u8,         // upper nibble: version, lower nibble: type
    pub flags: u8,
    pub ttl: u8,
    pub hop_count: u8,
    pub src: ShortAddr,
    pub dst: ShortAddr,
    pub message_id: [u8; 8],
    pub signature: Signature,
}
```

Functions:
- `PacketHeader::serialize(&self, buf: &mut [u8]) -> usize` — write header bytes
- `PacketHeader::deserialize(buf: &[u8]) -> Result<(PacketHeader, &[u8]), PacketError>` — parse header, return remaining payload slice
- `PacketHeader::sign(&mut self, identity: &NodeIdentity, payload: &[u8])` — compute signature over signable fields + payload
- `PacketHeader::verify(&self, sender_pubkey: &PubKey, payload: &[u8]) -> bool`
- `pub fn build_packet(identity: &NodeIdentity, packet_type: u8, flags: u8, dst: ShortAddr, payload: &[u8], buf: &mut [u8]) -> usize` — convenience: builds full packet in buf

Constants:
- `HEADER_SIZE: usize = 84` (4 + 8 + 8 + 8 + 64, aligned)
- `BROADCAST_ADDR: ShortAddr = [0xFF; 8]`

### 1.6 `src/protocol/heartbeat.rs` — Heartbeat Payload
Types:
```rust
pub struct HeartbeatPayload {
    pub full_pubkey: PubKey,
    pub capabilities: u16,
    pub uptime_secs: u32,
    pub bloom_filter: [u8; 32],
    pub bloom_generation: u8,
}
```

Functions:
- `HeartbeatPayload::serialize(&self, buf: &mut [u8]) -> usize`
- `HeartbeatPayload::deserialize(buf: &[u8]) -> Result<HeartbeatPayload, PacketError>`

### 1.7 `src/protocol/dedup.rs` — Seen Messages
```rust
pub struct SeenMessages {
    ring: heapless::Deque<[u8; 8], 128>,
}
```

- `SeenMessages::new() -> Self`
- `SeenMessages::check_and_insert(&mut self, id: &[u8; 8]) -> bool` — returns `true` if already seen

---

## Phase 2: Routing Core

### 2.1 `src/routing/bloom.rs` — Bloom Filter
```rust
pub struct BloomFilter {
    pub bits: [u8; 32],
    pub generation: u8,
}
```

Functions:
- `BloomFilter::new() -> Self`
- `BloomFilter::insert(&mut self, addr: &ShortAddr)`
- `BloomFilter::contains(&self, addr: &ShortAddr) -> bool`
- `BloomFilter::merge(&mut self, other: &BloomFilter)` — bitwise OR
- `BloomFilter::clear(&mut self)`
- `fn hash_indices(addr: &ShortAddr) -> [u8; 3]` — 3 positions from addr bytes
  - Use simple byte mixing: `addr[0..3]`, `addr[2..5]`, `addr[5..8]` each mod 256

### 2.2 `src/routing/table.rs` — Routing Table
Types:
```rust
pub struct PeerEntry {
    pub pubkey: PubKey,
    pub short_addr: ShortAddr,
    pub capabilities: u16,
    pub bloom: BloomFilter,
    pub transport_addr: TransportAddr,
    pub last_seen_ticks: u64,
    pub hop_count: u8,
    pub trust: u8,
}

pub struct RoutingTable {
    self_identity: ShortAddr,
    peers: heapless::Vec<PeerEntry, 32>,
    local_bloom: BloomFilter,
    bloom_generation: u8,
    seen: SeenMessages,
}
```

Functions:
- `RoutingTable::new(self_addr: ShortAddr) -> Self`
- `RoutingTable::update_peer(&mut self, heartbeat: &HeartbeatPayload, transport_addr: TransportAddr, now: u64)` — insert or update peer entry from heartbeat
- `RoutingTable::find_peer(&self, dst: &ShortAddr) -> Option<&PeerEntry>` — direct lookup
- `RoutingTable::find_routes(&self, dst: &ShortAddr) -> heapless::Vec<&PeerEntry, 8>` — neighbors whose bloom contains dst
- `RoutingTable::recompute_bloom(&mut self)` — rebuild local bloom from all known peers
- `RoutingTable::local_bloom(&self) -> &BloomFilter`
- `RoutingTable::decay(&mut self, now: u64, max_age: u64)` — remove stale entries

---

## Phase 3: BLE Transport

The most hardware-dependent phase. Wraps `trouble-host` + `esp-wifi` BLE.

### 3.1 `src/transport/mod.rs` — Transport Types
```rust
pub struct TransportAddr {
    pub addr_type: u8,  // 0 = BLE
    pub addr: [u8; 6],  // BLE MAC
}
```

No full `Transport` trait yet — PoC uses BLE directly. The trait abstraction comes post-PoC when adding WiFi.

### 3.2 `src/transport/ble.rs` — BLE Transport

This is the critical integration file. It needs to:

**Advertising (heartbeat broadcast):**
- Configure BLE advertising with custom manufacturer-specific data
- Pack heartbeat payload into advertising data (max ~31 bytes in legacy advertising, so we may need scan response data too, or use extended advertising if available)
- **Fallback**: If advertising payload is too small for full heartbeat, use a GATT characteristic and advertise only a minimal beacon (pubkey hash + service UUID). Peers connect briefly to read the full heartbeat.
- Advertise periodically (every 60s, but BLE advertising interval itself can be faster for discoverability)

**Scanning (heartbeat receive):**
- Run BLE scanner continuously
- Parse incoming advertising data for constellation service UUID
- Extract heartbeat payload
- Feed into routing table

**GATT Service (data exchange):**
- Define a custom GATT service with UUID for constellation mesh
- One writable characteristic for incoming mesh packets
- One notifiable characteristic for outgoing mesh packets
- On write: deserialize packet, feed to router
- On notify: serialize packet, push to connected peer

**Connection management:**
- When routing decides to send a data packet to a peer:
  1. Check if already connected
  2. If not, initiate connection using BLE address from `PeerEntry.transport_addr`
  3. Write packet to the peer's writable characteristic
  4. Optionally disconnect (or keep alive for a window)

### 3.3 Embassy Tasks

```rust
#[embassy_executor::task]
async fn ble_advertise_task(/* identity, routing_table */) {
    loop {
        let heartbeat = build_heartbeat(identity, routing_table);
        set_advertising_data(heartbeat);
        Timer::after(HEARTBEAT_INTERVAL).await;
    }
}

#[embassy_executor::task]
async fn ble_scan_task(/* routing_table */) {
    loop {
        let (adv_data, addr) = scan_next().await;
        if let Ok(heartbeat) = parse_heartbeat(adv_data) {
            routing_table.update_peer(heartbeat, addr);
        }
    }
}

#[embassy_executor::task]
async fn ble_gatt_task(/* gatt_server, router_channel */) {
    // Handle incoming GATT writes -> router_channel
    // Handle outgoing packets from router_channel -> GATT notify
}
```

### 3.4 Shared State

Tasks share state via `static` cells with Embassy primitives:
```rust
static ROUTING_TABLE: StaticCell<Mutex<NoopRawMutex, RoutingTable>> = StaticCell::new();
static OUTGOING: StaticCell<Channel<NoopRawMutex, PacketBuf, 4>> = StaticCell::new();
static INCOMING: StaticCell<Channel<NoopRawMutex, PacketBuf, 4>> = StaticCell::new();
```

---

## Phase 4: Node Storage

### 4.1 `src/node/storage.rs` — Flash Persistence

Functions:
- `pub fn is_provisioned(storage: &mut impl ReadStorage) -> bool` — check magic bytes at `MAGIC_OFFSET`
- `pub fn load_identity(storage: &mut impl ReadStorage) -> Option<NodeIdentity>` — read private key from flash, reconstruct identity
- `pub fn save_identity(storage: &mut impl ReadNorFlash, identity: &NodeIdentity)` — write private key + public key + magic
- Use `esp-storage`'s `FlashStorage` as the concrete impl

**First boot flow:**
1. Check magic bytes
2. If absent: generate keypair with `Trng` RNG, save to flash
3. If present: load keypair from flash
4. Log ShortAddr over serial

---

## Phase 5: Integration — Main Loop

### 5.1 `src/main.rs` — Wire Everything Together

```rust
#[esp_hal_embassy::main]
async fn main(spawner: Spawner) {
    // 1. Init peripherals, clock, heap, RNG, timers
    // 2. Init WiFi/BLE controller (esp_wifi::init)
    // 3. Load or generate identity from flash
    // 4. Log: "Node {short_addr:x} ready"
    // 5. Create shared state (routing table, channels)
    // 6. Create BLE controller + GATT server
    // 7. Spawn tasks:
    //    - ble_advertise_task
    //    - ble_scan_task
    //    - ble_gatt_task
    // 8. Main loop: periodically log routing table state
    //    - Also: demo sending an encrypted message if a peer is discovered
}
```

### 5.2 Demo Flow (hardcoded in main for PoC)

After peer discovery (routing table has >= 1 entry):
1. Build a plaintext test message: `b"hello from {short_addr}"`
2. Encrypt with peer's public key
3. Build a `DataEncrypted` packet
4. Send via GATT to peer
5. Log: `"Sent encrypted message to {peer_short_addr}"`

On receive:
1. Verify signature
2. Check dedup
3. Decrypt with own identity
4. Log: `"Received: {plaintext} from {sender_short_addr}"`

---

## Phase 6: Testing & Validation

### 6.1 Serial Log Validation
Both nodes connected via USB serial. Expected log output:

**Node A:**
```
[INFO] Node a1b2c3d4e5f67890 ready (generated new identity)
[INFO] BLE advertising started
[INFO] Discovered peer f0e1d2c3b4a59687 (direct heartbeat)
[INFO] Routing table: 1 peer, bloom has 2 entries
[INFO] Sending encrypted message to f0e1d2c3b4a59687
[INFO] Received: "hello from f0e1d2c3b4a59687" from f0e1d2c3b4a59687
```

**Node B:**
```
[INFO] Node f0e1d2c3b4a59687 ready (loaded identity from flash)
[INFO] BLE advertising started
[INFO] Discovered peer a1b2c3d4e5f67890 (direct heartbeat)
[INFO] Routing table: 1 peer, bloom has 2 entries
[INFO] Received: "hello from a1b2c3d4e5f67890" from a1b2c3d4e5f67890
[INFO] Sending encrypted message to a1b2c3d4e5f67890
```

### 6.2 What to Verify
- [ ] Identity persists across reboots (same ShortAddr after power cycle)
- [ ] Heartbeats are discovered within ~60s of both nodes being powered
- [ ] Bloom filter correctly reflects known peers
- [ ] Encrypted message decrypts successfully on the other side
- [ ] Signature verification passes
- [ ] Dedup prevents processing same message twice
- [ ] Routing table decays entries if a node is powered off

---

## Implementation Order Summary

| Phase | What | Depends On | Estimated Effort |
|-------|------|-----------|-----------------|
| **0** | Project setup, deps, module skeleton | — | Small |
| **1** | Core types: identity, encryption, packet, heartbeat, dedup | Phase 0 | Medium |
| **2** | Routing: bloom filter, routing table | Phase 1 | Medium |
| **3** | BLE transport: advertising, scanning, GATT | Phase 1, 2 | Large (hardware) |
| **4** | Flash storage: identity persistence | Phase 1 | Small |
| **5** | Main loop integration | Phase 1-4 | Medium |
| **6** | Testing on 2 physical nodes | Phase 5 | Validation |

Phases 1 and 2 are pure logic with no hardware deps — they can be developed and unit-tested conceptually even without ESP32 hardware. Phase 3 is the riskiest and most complex due to BLE API surface area. Phase 4 is straightforward. Phase 5 is integration glue.

---

## BLE Advertising Payload Concern

BLE legacy advertising data is limited to 31 bytes. The full heartbeat payload is ~71 bytes. Options:

1. **Extended advertising** (BLE 5.0): ESP32-C6 supports extended advertising with up to 251 bytes. Use if `trouble-host` exposes the API.
2. **Scan response**: Use both advertising data (31 bytes) and scan response data (31 bytes) = 62 bytes. Still not enough for full heartbeat.
3. **Minimal advertising + GATT read**: Advertise only `[service_uuid (2) | short_addr (8)]` = 10 bytes. Peers that want the full heartbeat connect and read a GATT characteristic. This is the safest fallback.
4. **Hybrid**: Put `short_addr + capabilities + bloom_generation` in advertising (compact beacon), full heartbeat in GATT characteristic.

**PoC strategy**: Start with option 3 (minimal advertising + GATT read). If extended advertising works, migrate to option 1 for efficiency.

---

## Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| `trouble-host` API doesn't support simultaneous advertise + scan + GATT | Blocks BLE transport | Check API; may need to time-multiplex (advertise window / scan window / connection window) |
| `x25519-dalek` doesn't compile on `riscv32imac` | Blocks encryption | Already uses `curve25519-dalek` u32 backend; should work. Fallback: use `curve25519-dalek` directly |
| BLE advertising payload too small | Blocks heartbeat broadcast | Use GATT-based heartbeat exchange (option 3 above) |
| `esp-storage` flash sector conflicts with firmware | Corrupts identity | Use a dedicated partition; verify linker script reserves space |
| Embassy task arena too small for all tasks | Runtime panic | Increase `task-arena-size-32768` if needed |
