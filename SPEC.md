# Constellation Mesh Protocol Specification

## 1. Overview

Constellation is a decentralized mesh communication protocol for ESP32 microcontrollers. Nodes communicate via asymmetric-key authenticated and encrypted messages, with network routing derived from heartbeat-based topology discovery. The protocol is transport-agnostic, starting with BLE and extensible to WiFi (IPv6) and LoRa.

### Design Principles

- **No central coordinator** (at scales of tens of nodes)
- **Heterogeneous hardware**: any ESP32 variant can participate
- **Role-based participation**: nodes opt into network functions via capability flags
- **Transport-pluggable**: same protocol frames over BLE, WiFi, LoRa
- **Asymmetric crypto identity**: every node is its public key

---

## 2. Node Roles & Capabilities

Roles are not fixed categories but bitfields of capabilities a node participates in.

### Capability Bitfield

```rust
bitflags! {
    pub struct Capabilities: u16 {
        const ROUTE       = 0b0000_0001;  // forwards messages for others
        const STORE       = 0b0000_0010;  // store-and-forward for LE nodes (DHT carrier)
        const BRIDGE      = 0b0000_0100;  // bridges to IP / other networks
        const APPLICATION = 0b0000_1000;  // runs application services
        const LOW_ENERGY  = 0b0001_0000;  // battery-powered, does not route
        const MOBILE      = 0b0010_0000;  // mobile device (phone companion app)
    }
}
```

### Role Archetypes

| Archetype | Typical Capabilities | Description |
|-----------|---------------------|-------------|
| **Node** (low-energy) | `LOW_ENERGY` | Battery device. Does not route. Wakes periodically, sends heartbeat, receives stored messages. |
| **Knot** (routing node) | `ROUTE \| STORE` | Powered device. Routes messages, maintains mesh topology, acts as DHT carrier for nearby LE nodes. |
| **Application node** | `ROUTE \| STORE \| BRIDGE \| APPLICATION` | Server-class. Bridges to IP networks, hosts application services, higher bandwidth. |
| **Mobile node** | `MOBILE` | Phone companion app. Participates in onboarding, relays via BLE to nearby knots. |

Knots are the **spatial leaders** of their neighborhood: they maintain the routing table, carry messages for LE nodes, and make forwarding decisions.

---

## 3. Identity & Cryptography

### 3.1 Key Hierarchy

```
Network Authority (offline)
  |
  |-- ed25519 keypair (NetworkKey)
  |     Signs node certificates during onboarding
  |
Node Identity
  |
  |-- ed25519 keypair (NodeKey)
  |     Generated on first boot, persisted to flash
  |     Public key = node address
  |
  |-- x25519 keypair (derived from ed25519)
  |     Used for ECDH key agreement
  |
  |-- NodeCertificate
        = { node_pubkey, capabilities, signature_by_network_key }
```

### 3.2 Node Address

A node's address IS its ed25519 public key (32 bytes). For compact representation in packets, a **truncated hash** (8 bytes of SHA-256) is used as `ShortAddr`. Bloom filters and routing tables use `ShortAddr`.

```rust
pub type PubKey = [u8; 32];       // ed25519 public key
pub type ShortAddr = [u8; 8];     // first 8 bytes of SHA-256(PubKey)
pub type Signature = [u8; 64];    // ed25519 signature
```

### 3.3 Encryption Flow

Per-message encryption using ECDH + ChaCha20-Poly1305:

```
1. Sender converts its ed25519 SigningKey -> x25519 StaticSecret
2. Sender converts recipient ed25519 VerifyingKey -> x25519 PublicKey
3. ECDH: shared_secret = x25519(sender_secret, recipient_public)
4. KDF:  symmetric_key = HKDF-SHA256(shared_secret, salt=sender_pubkey || recipient_pubkey)
5. Encrypt: ChaCha20-Poly1305(symmetric_key, nonce, plaintext) -> ciphertext + tag
6. Packet carries: sender_pubkey, nonce, ciphertext, tag
```

**Nonce strategy (v1)**: Random 12-byte nonce per message. Replay protection is out of scope for v1, but the nonce field reserves space for future sequence-number-based schemes.

### 3.4 Crate Dependencies

```toml
ed25519-dalek = { version = "2.1", default-features = false, features = ["rand_core"] }
x25519-dalek = { version = "2", default-features = false }
chacha20poly1305 = { version = "0.10", default-features = false, features = ["heapless"] }
hkdf = { version = "0.12", default-features = false }
sha2 = { version = "0.10", default-features = false }
```

All crates are `no_std` compatible and use `curve25519-dalek` (already a transitive dependency of `ed25519-dalek`).

### 3.5 Onboarding

1. Mobile phone (companion app) generates or holds the **NetworkKey** private key
2. New node generates an ed25519 keypair on first boot, persists to flash via `esp-storage`
3. Node advertises its public key over BLE to the companion app
4. Companion app signs `NodeCertificate { pubkey, capabilities }` with the NetworkKey
5. Signed certificate is written back to the node and persisted
6. Node is now a trusted member of the mesh

```rust
#[derive(Clone)]
pub struct NodeCertificate {
    pub pubkey: PubKey,
    pub capabilities: Capabilities,
    pub network_signature: Signature,  // signed by NetworkKey
}
```

---

## 4. Packet Format

All packets share a common header. Maximum frame size targets ~200 bytes for BLE compatibility.

### 4.1 Packet Header (fixed, 82 bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Ver  | Type  |    Flags      |   TTL   |   Hop Count         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    Source ShortAddr (8 bytes)                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                 Destination ShortAddr (8 bytes)                |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     Message ID (8 bytes)                      |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                  Signature (64 bytes, ed25519)                |
|                          ...                                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Payload (variable)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Note**: Signature covers `[ver, type, flags, ttl, src, dst, message_id, payload]` but NOT hop_count (since relays increment it).

```rust
#[repr(u8)]
pub enum PacketType {
    Heartbeat    = 0x01,
    Data         = 0x02,
    DataEncrypted = 0x03,
    Announce     = 0x04,  // node joining / capability change
    Ack          = 0x05,
    // Future: RouteRequest = 0x10, Tunnel = 0x20
}

bitflags! {
    pub struct PacketFlags: u8 {
        const ACK_REQUESTED = 0b0000_0001;
        const FRAGMENTED    = 0b0000_0010;
        const BROADCAST     = 0b0000_0100;
    }
}
```

```rust
pub struct PacketHeader {
    pub version: u4,          // protocol version (0x01)
    pub packet_type: u4,      // PacketType
    pub flags: PacketFlags,
    pub ttl: u8,              // max remaining hops
    pub hop_count: u8,        // hops so far (not signed)
    pub src: ShortAddr,       // sender short address
    pub dst: ShortAddr,       // destination (0xFF..FF = broadcast)
    pub message_id: [u8; 8],  // random, for dedup
    pub signature: Signature, // ed25519 over header+payload (excl hop_count)
}
```

### 4.2 Payload Budget

With BLE default MTU of ~244 bytes (after L2CAP overhead), and an 82-byte header:
- **~162 bytes** available for payload
- For encrypted data: 12-byte nonce + 16-byte Poly1305 tag = 28 bytes overhead -> **~134 bytes cleartext**

### 4.3 Heartbeat Payload

```rust
pub struct HeartbeatPayload {
    pub full_pubkey: PubKey,       // 32 bytes - full key for discovery
    pub capabilities: Capabilities, // 2 bytes
    pub uptime_secs: u32,          // 4 bytes
    pub bloom_filter: [u8; 32],    // 256-bit bloom filter of known nodes
    pub bloom_generation: u8,      // monotonic counter, for staleness
}
// Total: ~71 bytes -> fits in payload budget
```

**Bloom filter sizing**: 256 bits (32 bytes) with 3 hash functions supports ~20-30 nodes at <5% false positive rate. Sufficient for v1 scale of tens of nodes.

### 4.4 Announcement Payload

Sent on join, capability change, or periodically alongside heartbeats:

```rust
pub struct AnnouncePayload {
    pub certificate: NodeCertificate,  // pubkey + caps + network sig
    pub transport_hints: TransportHints, // how to reach this node
}

pub struct TransportHints {
    pub ble_addr: Option<[u8; 6]>,     // BLE MAC if available
    pub ipv6_addr: Option<[u8; 16]>,   // IPv6 if WiFi-capable
}
```

### 4.5 Message Deduplication

Every node maintains a **seen messages** ring buffer:

```rust
pub struct SeenMessages {
    ring: heapless::Deque<[u8; 8], 128>,  // message_id ring buffer
}

impl SeenMessages {
    /// Returns true if this message was already seen. Adds it if not.
    pub fn check_and_insert(&mut self, message_id: &[u8; 8]) -> bool;
}
```

This prevents routing loops when messages are flooded to multiple neighbors.

---

## 5. Transport Layer

### 5.1 Transport Trait

```rust
/// A peer identifier, opaque to the mesh layer.
/// Maps to BLE connection handle, IPv6 socket addr, LoRa node ID, etc.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TransportPeerId {
    pub transport_type: TransportType,
    pub addr: heapless::Vec<u8, 16>,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportType {
    Ble = 0,
    Wifi = 1,
    Lora = 2,
}

/// Core transport abstraction. Implemented per radio.
pub trait Transport {
    type Error;

    /// Broadcast a frame to all nearby peers (e.g., BLE advertising, multicast).
    async fn broadcast(&mut self, frame: &[u8]) -> Result<(), Self::Error>;

    /// Send a frame to a specific peer.
    async fn send(&mut self, peer: &TransportPeerId, frame: &[u8]) -> Result<(), Self::Error>;

    /// Receive the next incoming frame. Returns the sender peer and bytes read.
    async fn recv(&mut self, buf: &mut [u8]) -> Result<(TransportPeerId, usize), Self::Error>;

    /// Return the maximum transmission unit for this transport.
    fn mtu(&self) -> usize;

    /// The transport type identifier.
    fn transport_type(&self) -> TransportType;
}
```

### 5.2 Peer Resolution

The mesh layer needs to resolve `ShortAddr` -> `TransportPeerId`. This is built from announcements and heartbeats:

```rust
pub struct PeerRegistry {
    /// Known peers and their transport addresses.
    entries: heapless::FnvIndexMap<ShortAddr, PeerInfo, 64>,
}

pub struct PeerInfo {
    pub full_pubkey: PubKey,
    pub certificate: Option<NodeCertificate>,
    pub transports: heapless::Vec<TransportPeerId, 4>,  // multi-transport
    pub capabilities: Capabilities,
    pub last_seen: Instant,
    pub hop_count: u8,         // 0 = direct neighbor
    pub trust_level: TrustLevel,
}

#[repr(u8)]
pub enum TrustLevel {
    DirectHeartbeat = 3,    // we heard their heartbeat directly
    NeighborBloom = 1,      // a neighbor's bloom filter claims to know them
    Expired = 0,            // haven't heard from them in a while
}
```

### 5.3 BLE Transport Implementation

The BLE transport wraps `trouble-host` (GATT peripheral/central):

```rust
pub struct BleTransport {
    controller: ExternalController<BleConnector, PACKET_POOL_SIZE>,
    // GATT service for mesh protocol
    // Custom characteristic for mesh frames
}
```

**BLE strategy**:
- Heartbeats sent via **BLE advertising** (broadcast, no connection needed)
- Data packets sent via **GATT write** (connection-oriented, reliable)
- Scanner continuously listens for advertising heartbeats
- MTU: ~244 bytes (negotiated, `DEFAULT_PACKET_POOL_MTU = 251` minus L2CAP header)

### 5.4 WiFi Transport (Future)

- Uses IPv6 multicast for broadcast/heartbeat
- UDP unicast for directed messages
- Preferred for bandwidth-intensive data and tunnel mode
- Control messages (heartbeats) still prefer BLE for power efficiency

### 5.5 Multi-Transport Routing

When a knot has multiple transports available:

```rust
impl Router {
    fn select_transport(&self, peer: &PeerInfo, packet_type: PacketType) -> &TransportPeerId {
        match packet_type {
            // Control traffic prefers low-power transport
            PacketType::Heartbeat | PacketType::Announce =>
                peer.prefer_transport(TransportType::Ble),
            // Data prefers high-bandwidth transport
            PacketType::Data | PacketType::DataEncrypted =>
                peer.prefer_transport(TransportType::Wifi)
                    .or_else(|| peer.prefer_transport(TransportType::Ble)),
            _ => peer.best_transport(),
        }
    }
}
```

---

## 6. Routing

### 6.1 Topology Discovery

Each node maintains a **routing table** built from:

1. **Direct heartbeats**: Nodes heard directly -> `TrustLevel::DirectHeartbeat`
2. **Bloom filters from neighbors**: Merged with lower trust -> `TrustLevel::NeighborBloom`
3. **Retransmitted heartbeats**: Heartbeats forwarded by knots -> builds authoritative multi-hop view

```rust
pub struct RoutingTable {
    /// Our own node identity
    self_addr: ShortAddr,
    /// Peer registry with transport mappings
    peers: PeerRegistry,
    /// Our bloom filter (recomputed periodically)
    local_bloom: BloomFilter,
    /// Recently seen message IDs for dedup
    seen: SeenMessages,
    /// Decay timer: entries not refreshed within TTL are demoted/removed
    decay_interval: Duration,  // e.g., 3 * heartbeat_interval = 180s
}
```

### 6.2 Bloom Filter

```rust
pub struct BloomFilter {
    bits: [u8; 32],  // 256 bits
    generation: u8,
}

impl BloomFilter {
    pub fn insert(&mut self, addr: &ShortAddr);
    pub fn contains(&self, addr: &ShortAddr) -> bool;
    pub fn merge(&mut self, other: &BloomFilter); // OR operation
    pub fn clear(&mut self);

    // Uses 3 independent hash positions derived from addr bytes
    fn hash_indices(addr: &ShortAddr) -> [usize; 3];
}
```

The bloom filter in each heartbeat advertises "nodes I can route to." Receivers merge incoming bloom filters into their routing knowledge with appropriate trust decay.

### 6.3 Forwarding Algorithm

```
fn forward(packet: Packet):
    if packet.dst == self.addr:
        deliver_locally(packet)
        return

    if seen.check_and_insert(packet.message_id):
        return  // already forwarded, drop (loop prevention)

    if packet.ttl == 0:
        return  // TTL expired

    packet.ttl -= 1
    packet.hop_count += 1

    // Find neighbors whose bloom filters contain the destination
    candidates = neighbors.filter(|n| n.bloom.contains(packet.dst))

    if candidates.is_empty():
        // No bloom match: flood to all known routing neighbors
        candidates = neighbors.filter(|n| n.capabilities.contains(ROUTE))

    // Send to ALL matching candidates (multi-path)
    for neighbor in candidates:
        transport = select_transport(neighbor, packet.type)
        transport.send(neighbor.transport_id, packet.serialize())
```

**Key behaviors**:
- **Multiple bloom hits**: send to ALL matching neighbors (increases delivery probability)
- **No bloom hits**: flood to all routing-capable neighbors
- **Loop prevention**: `SeenMessages` ring buffer ensures a message is forwarded at most once
- **TTL**: prevents infinite propagation; default TTL = 10

### 6.4 Bloom Filter False Positives

A bloom filter false positive means a neighbor claims to know a route but doesn't. The packet is forwarded there anyway but will eventually be dropped when TTL expires. The multi-path forwarding strategy means the packet likely reaches the destination via another neighbor. No explicit backtracking is needed in v1.

### 6.5 Entry Decay

```rust
impl RoutingTable {
    /// Called periodically (e.g., every heartbeat interval)
    pub fn decay(&mut self, now: Instant) {
        for (addr, peer) in self.peers.iter_mut() {
            let age = now - peer.last_seen;
            if age > self.decay_interval * 3 {
                // Remove entirely
                self.peers.remove(addr);
            } else if age > self.decay_interval {
                // Demote trust
                peer.trust_level = TrustLevel::Expired;
            }
        }
        // Recompute local bloom filter
        self.recompute_bloom();
    }
}
```

---

## 7. Low-Energy Node Protocol

### 7.1 Store-and-Forward via DHT Carriers

Low-energy (LE) nodes do not maintain connections or route messages. Instead:

1. LE node sends a heartbeat with `LOW_ENERGY` capability flag
2. Nearby knots with `STORE` capability become **DHT carriers** for that LE node
3. When a message arrives destined for an LE node, the routing layer delivers it to the DHT carrier knots
4. Carrier knots buffer the message in a per-destination queue
5. When the LE node wakes and sends its next heartbeat, carriers deliver buffered messages

```rust
pub struct StoreForwardBuffer {
    /// Messages buffered per destination LE node
    queues: heapless::FnvIndexMap<ShortAddr, MessageQueue, 16>,
    /// Max messages per LE node
    max_per_node: usize,  // e.g., 8
    /// Max age before dropping
    max_age: Duration,    // e.g., 10 minutes
}

pub struct MessageQueue {
    messages: heapless::Deque<BufferedMessage, 8>,
}

pub struct BufferedMessage {
    packet: heapless::Vec<u8, 256>,
    received_at: Instant,
}
```

### 7.2 DHT Carrier Selection

Which knots carry for which LE nodes:
- All knots that **directly hear** the LE node's heartbeat become carriers
- This naturally creates geographic redundancy
- Consistent hashing for tie-breaking when buffer space is limited (future optimization)

### 7.3 LE Wake Cycle

```
LE node:
  1. Sleep for N seconds (configurable, default 60s matches heartbeat)
  2. Wake, send heartbeat
  3. Listen for a delivery window (e.g., 2 seconds)
  4. Carrier knots that hear the heartbeat immediately transmit buffered messages
  5. LE node processes received messages
  6. Return to sleep
```

Future optimization: coordinate wake times between LE node and carrier to minimize both parties' active time.

---

## 8. Active Node Heartbeat Suppression

Nodes that are actively sending or receiving data packets can **delay heartbeat transmission** up to a configurable maximum (e.g., 3x normal interval = 180s). This reduces bandwidth overhead during active communication.

The routing table is still partially updated by observing the active data packets (source addresses prove liveness), even without explicit heartbeats. However, the full bloom filter is only carried in heartbeats, so suppression is bounded to avoid stale routing.

```rust
pub struct HeartbeatScheduler {
    interval: Duration,          // 60s
    max_suppression: Duration,   // 180s
    last_sent: Instant,
    last_activity: Instant,      // last data packet sent/received

    pub fn should_send(&self, now: Instant) -> bool {
        let since_last = now - self.last_sent;
        let since_activity = now - self.last_activity;

        // Always send if max suppression exceeded
        if since_last >= self.max_suppression {
            return true;
        }
        // Send at normal interval if no recent activity
        if since_activity >= self.interval && since_last >= self.interval {
            return true;
        }
        false
    }
}
```

---

## 9. Storage Layer

Node identity and certificates are persisted to flash:

```rust
/// Flash storage layout (fixed offsets in a reserved flash sector)
pub struct FlashLayout;

impl FlashLayout {
    const NODE_PRIVKEY_OFFSET: u32 = 0x0000;  // 32 bytes
    const NODE_PUBKEY_OFFSET: u32  = 0x0020;  // 32 bytes
    const CERTIFICATE_OFFSET: u32  = 0x0040;  // ~98 bytes
    const NETWORK_PUBKEY_OFFSET: u32 = 0x00A8; // 32 bytes
    const MAGIC_OFFSET: u32 = 0x00C8;          // 4 bytes, 0xC0DE_CAFE
}

pub trait NodeStorage {
    fn is_provisioned(&self) -> bool;
    fn read_identity(&self) -> Option<NodeIdentity>;
    fn write_identity(&mut self, identity: &NodeIdentity) -> Result<(), StorageError>;
    fn read_certificate(&self) -> Option<NodeCertificate>;
    fn write_certificate(&mut self, cert: &NodeCertificate) -> Result<(), StorageError>;
}
```

Uses `esp-storage` + `embedded-storage` traits for flash read/write.

---

## 10. Module Structure

```
src/
  main.rs                   -- entry point, peripheral init, task spawning
  lib.rs                    -- (optional) shared types for testing on host

  crypto/
    mod.rs
    identity.rs             -- NodeIdentity, key generation, ed25519 ops
    encryption.rs           -- ECDH, ChaCha20-Poly1305 encrypt/decrypt
    certificate.rs          -- NodeCertificate, verification

  protocol/
    mod.rs
    packet.rs               -- PacketHeader, PacketType, serialization
    heartbeat.rs            -- HeartbeatPayload, HeartbeatScheduler
    announce.rs             -- AnnouncePayload
    dedup.rs                -- SeenMessages ring buffer

  routing/
    mod.rs
    table.rs                -- RoutingTable, entry decay
    bloom.rs                -- BloomFilter (256-bit, 3 hash functions)
    forward.rs              -- forwarding logic, multi-path

  transport/
    mod.rs                  -- Transport trait, TransportPeerId, TransportType
    ble.rs                  -- BleTransport (trouble-host + esp-wifi)
    wifi.rs                 -- WifiTransport (future, IPv6)
    lora.rs                 -- LoraTransport (future)
    registry.rs             -- PeerRegistry, PeerInfo, transport selection

  node/
    mod.rs
    roles.rs                -- Capabilities bitfield
    storage.rs              -- Flash persistence, NodeStorage trait
    store_forward.rs        -- StoreForwardBuffer for LE nodes

  display/
    mod.rs                  -- ILI9486 display driver, status rendering (optional)
```

---

## 11. Embassy Task Architecture

The firmware runs as cooperative async tasks on the Embassy executor:

```rust
#[embassy_executor::task]
async fn heartbeat_task(/* routing table, transport */) {
    // Periodic heartbeat send + schedule management
}

#[embassy_executor::task]
async fn ble_rx_task(/* ble transport, routing table */) {
    // Continuously receive BLE frames, dispatch to router
}

#[embassy_executor::task]
async fn router_task(/* routing table, transports, store_forward */) {
    // Central routing loop: receives from channel, forwards or delivers
    // Also handles entry decay on timer
}

#[embassy_executor::task]
async fn store_forward_task(/* buffer, transports */) {
    // Watches for LE node heartbeats, delivers buffered messages
}

// Future:
// async fn wifi_rx_task(...)
// async fn display_task(...)
```

Tasks communicate via `embassy_sync::Channel` and shared state protected by `embassy_sync::Mutex`.

---

## 12. Network Flow Examples

### 12.1 Normal Message: Knot A -> Knot C (2 hops via Knot B)

```
Knot A                    Knot B                    Knot C
  |                         |                         |
  |  [Heartbeat, bloom={A}] |                         |
  |------------------------>|  [Heartbeat, bloom={B,A}]|
  |                         |------------------------>|
  |                         |  [Heartbeat, bloom={C}] |
  |                         |<------------------------|
  |  [Heartbeat, bloom={B,C}]                         |
  |<------------------------|                         |
  |                         |                         |
  | A wants to send to C    |                         |
  | A checks bloom: B knows C                         |
  |                         |                         |
  | [Data, src=A, dst=C]    |                         |
  |------------------------>|                         |
  |                    B checks bloom: I know C directly
  |                         | [Data, src=A, dst=C]    |
  |                         |------------------------>|
  |                         |                    C receives, decrypts
```

### 12.2 LE Node Message Delivery

```
LE Node                   Carrier Knot              Sender Knot
  |                         |                         |
  | [Heartbeat, LE flag]    |                         |
  |------------------------>|                         |
  |                    Knot registers as DHT carrier   |
  |                         |                         |
  | (LE node sleeps)        |                         |
  |                         |  [Data, dst=LE_addr]    |
  |                         |<------------------------|
  |                    Knot buffers message            |
  |                         |                         |
  | (LE node wakes)         |                         |
  | [Heartbeat, LE flag]    |                         |
  |------------------------>|                         |
  |                    Knot detects LE heartbeat       |
  | [Buffered Data]         |                         |
  |<------------------------|                         |
  | (processes, sleeps)     |                         |
```

### 12.3 No-Route Flood

```
Knot A                    Knot B          Knot C          Knot D
  |                         |               |               |
  | A wants to send to X    |               |               |
  | No bloom filter match for X anywhere    |               |
  |                         |               |               |
  | [Data, dst=X, ttl=10]  |               |               |
  |------------------------>|               |               |
  | [Data, dst=X, ttl=10]  |               |               |
  |---------------------------------------->|               |
  | [Data, dst=X, ttl=10]  |               |               |
  |-------------------------------------------------------->|
  |                    Each knot checks its bloom, forwards or drops
  |                    SeenMessages prevents re-forwarding loops
```

### 12.4 Onboarding Flow

```
New Node                  Companion App (Phone)
  |                         |
  | (First boot, generates ed25519 keypair)
  | (Persists to flash)     |
  |                         |
  | [BLE Advertise: pubkey] |
  |------------------------>|
  |                    App verifies hardware, user confirms
  |                    App signs NodeCertificate with NetworkKey
  |                         |
  | [BLE GATT Write: cert]  |
  |<------------------------|
  | (Persists certificate)  |
  |                         |
  | [First Heartbeat + Announce]
  |------------------------>| (relayed to mesh)
  | (Node is now a mesh member)
```

---

## 13. Configuration Constants

```rust
pub mod config {
    use core::time::Duration;

    pub const PROTOCOL_VERSION: u8 = 0x01;
    pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);
    pub const HEARTBEAT_MAX_SUPPRESSION: Duration = Duration::from_secs(180);
    pub const DEFAULT_TTL: u8 = 10;
    pub const BLOOM_FILTER_BYTES: usize = 32;   // 256 bits
    pub const BLOOM_HASH_COUNT: usize = 3;
    pub const SEEN_MESSAGES_CAPACITY: usize = 128;
    pub const ROUTING_DECAY_FACTOR: u8 = 3;     // entries expire at 3x heartbeat interval
    pub const LE_DELIVERY_WINDOW: Duration = Duration::from_secs(2);
    pub const STORE_FORWARD_MAX_PER_NODE: usize = 8;
    pub const STORE_FORWARD_MAX_AGE: Duration = Duration::from_secs(600);
    pub const MAX_PEERS: usize = 64;
    pub const HEAP_SIZE: usize = 72 * 1024;
}
```

---

## 14. Future Work (Out of Scope for v1)

- **Tunnel mode**: Latency/bandwidth-optimized established routes with multi-path control signals for quick fallback
- **Replay protection**: Sequence numbers or timestamp-based nonce scheme
- **Coordinator**: For networks beyond tens of nodes, a coordinator role for route computation
- **LE wake coordination**: Synchronized wake schedules between LE nodes and their carriers
- **Fragmentation**: For tunnel mode, larger payloads over WiFi or BLE extended advertisements
- **LoRa transport**: Long-range, low-bandwidth transport implementation
- **Route metrics**: Signal strength weighting, latency-aware routing
