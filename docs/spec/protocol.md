# Constellation Mesh Protocol Specification

## 1. Overview

Constellation is a decentralized mesh communication protocol for ESP32 microcontrollers. Nodes communicate via asymmetric-key authenticated and encrypted messages, with network routing currently derived from transport-level neighbor discovery plus direct H2H (Heart2Heart) peer exchanges. The protocol is transport-agnostic, starting with BLE and intended to remain implementable over WiFi (IPv6), LoRa, and other future interfaces.

### 1.1 Conformance Language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this
document are to be interpreted as described in RFC 2119 / RFC 8174 when, and
only when, they appear in all capitals.

Unless otherwise noted, Sections 1–14 define the authoritative mesh protocol
behavior. The transport-specific BLE section later in this document defines one
concrete binding for those semantics.

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
| **Mobile node** | `MOBILE` | Phone companion app. Participates in onboarding and may relay through nearby mesh peers over whatever local transport is available. |

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
6. Packet carries: `src = ShortAddr(sender_pubkey)`, `packet_counter`, and an encrypted payload containing nonce + ciphertext + tag
```

**Nonce strategy (payload encryption)**: Random 12-byte nonce per encrypted
payload.

Payload-encryption nonces are **NOT** the protocol's replay defense. Replay
resistance **MUST** come from explicit freshness state in the signed packet
header and receiver-side acceptance rules.

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
2. New node generates an ed25519 keypair on first boot, persists to dedicated flash partition
3. Node advertises itself via BLE manufacturer data with `network_addr = ONBOARDING_READY_NETWORK_ADDR`
4. Companion discovers the node via BLE scan, parses manufacturer data, identifies as onboarding-ready
5. Companion optionally inspects the node's GATT service for full pubkey, capabilities, network marker
6. Companion signs `NodeCertificate { pubkey, capabilities }` with the NetworkKey
7. Companion writes authority pubkey, cert capabilities, cert signature to the node's GATT characteristics
8. Companion writes the commit characteristic
9. Node validates the certificate against the authority pubkey, persists enrollment to flash, ACKs, then software resets
10. After reboot, the node advertises its real `NetworkAddr` in manufacturer data
11. Node is now an authenticated member of the mesh

The onboarding procedure is transport-neutral. Concrete deployments MAY realize
it over BLE, USB, WiFi, or another local provisioning channel.

```rust
#[derive(Clone)]
pub struct NodeCertificate {
    pub pubkey: PubKey,
    pub capabilities: Capabilities,
    pub network_signature: Signature,  // signed by NetworkKey
}
```

Each enrolled node possesses the network public key. Certificate validation is
therefore a local operation: a node **MUST** verify peer certificates against
its stored network public key before granting routing or storage authority.

The GATT onboarding service exposes:

| Characteristic | Access | Description |
|---|---|---|
| protocol_signature | read | Identifies Constellation devices |
| network_marker | read | Onboarding-ready marker or 32-byte network pubkey |
| node_pubkey | read | 32-byte ed25519 public key |
| capabilities | read | 2-byte capability bitfield |
| short_addr | read | 8-byte short address |
| l2cap_psm | read | 2-byte L2CAP PSM for H2H/routed sessions |
| authority_pubkey | read, write | Authority's 32-byte ed25519 public key |
| cert_capabilities | read, write | Certified capabilities (2 bytes) |
| cert_signature | read, write | Network signature (64 bytes) |
| commit_enrollment | write | Trigger enrollment commit (1 byte) |
| cert_data | read | Full certificate wire format (98 bytes) |

### 3.6 Threat Model

This protocol is designed for a hostile and unreliable environment. A
conforming implementation **MUST** assume all of the following are possible
unless they are explicitly prevented by the protocol:

- packet loss, duplication, reordering, and asymmetric links
- stale discovery information and stale routing state
- low-power nodes waking briefly and unpredictably
- passive traffic observation
- replay of previously valid routed packets
- replay of previously valid control/session frames
- forged discovery beacons and forged capability claims
- unauthenticated attempts to consume buffer space, session slots, or wake time
- selective dropping of acknowledgements or completion frames

The protocol **MUST** resist at least:

- replay of routed packets
- unauthenticated routing-state mutation
- unauthenticated retained-state mutation or deletion
- capability/role spoofing before trust establishment
- unbounded forwarding amplification from ambiguous routing hints

The protocol does **NOT** assume that transport-layer primitives alone provide
authentication, integrity, freshness, or anti-replay.

### 3.7 Peer Admission and Trust Model

The protocol distinguishes four states for a peer:

1. **Observed peer**
   - discovered through a transport binding
   - transport reachability is known
   - identity, capabilities, and routing role are **NOT** yet trusted
2. **Authenticated peer**
   - long-term identity has been cryptographically verified
   - the peer's certificate has been validated against the network authority
3. **Routing-authorized peer**
   - authenticated peer whose certified capabilities authorize `ROUTE`
   - may be used as a forwarding candidate
4. **Store-authorized peer**
   - authenticated peer whose certified capabilities authorize `STORE`
   - may receive retained replicas or participate in retained-state control

The protocol **MUST NOT** treat unauthenticated capability claims as sufficient
for routing, storage, or retained-delivery authority.

Authenticated membership means "member of the network", not "incapable of
fault or compromise". The protocol **MUST** still tolerate malicious or broken
nodes that do possess valid network membership.

Neighbor discovery **MAY** create observed peers. Promotion beyond observed
peer status **MUST** require authenticated identity and certificate validation.

---

## 4. Packet Format

All packets share a common header. The wire format **MUST** remain compact enough
to fit constrained transports; BLE compatibility is the current sizing pressure,
not the protocol's only target.

### 4.1 Packet Header (fixed, 92 bytes)

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
|                    Packet Counter (8 bytes)                   |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                  Signature (64 bytes, ed25519)                |
|                          ...                                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Payload (variable)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Note**: Signature covers `[ver, type, flags, src, dst, packet_counter, payload]` but NOT `ttl` or `hop_count` (since relays decrement/increment them while forwarding).

```rust
#[repr(u8)]
pub enum PacketType {
    Heartbeat    = 0x01,
    Data         = 0x02,
    DataEncrypted = 0x03,
    Announce     = 0x04,  // node joining / capability change
    Ack          = 0x05,  // reserved / unused in v1
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
    pub packet_counter: u64,  // per-sender monotonic freshness counter
    pub signature: Signature, // ed25519 over header+payload (excl ttl/hop_count)
}
```

Older implementation/code paths may still call this field `message_id`. In this
spec, the canonical meaning is **`packet_counter`**: a per-sender monotonic
freshness value. It **MUST NOT** be treated as an arbitrary random identifier.

### 4.2 Payload Budget

With a constrained-transport MTU of ~244 bytes (after transport overhead), and a 92-byte header:
- **~152 bytes** available for payload
- For encrypted data: 12-byte nonce + 16-byte Poly1305 tag = 28 bytes overhead -> **~124 bytes cleartext**

### 4.3 Encrypted Payload Format

`PacketType::DataEncrypted` uses the normal packet header plus the following
payload body:

```rust
pub struct EncryptedPayload {
    pub nonce: [u8; 12],
    pub ciphertext_and_tag: heapless::Vec<u8, N>,
}
```

The sender's full public key is **NOT** carried in every encrypted packet.
Receivers **MUST** resolve `src` through the authenticated peer registry to
obtain the sender public key required for signature verification and payload
decryption context. A node **MUST NOT** accept `DataEncrypted` from an
unresolved or unauthenticated sender.

### 4.4 Heartbeat Payload

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

### 4.5 Announcement Payload

Sent on join, capability change, or periodically alongside heartbeats:

```rust
pub struct AnnouncePayload {
    pub certificate: NodeCertificate,  // pubkey + caps + network sig
    pub transport_hints: TransportHints, // how to reach this node
}

pub struct TransportHints {
    pub local_link_addr: Option<[u8; 16]>, // binding-defined local transport endpoint
    pub network_addr: Option<[u8; 16]>,    // binding-defined routed/network endpoint
}
```

### 4.6 Replay Protection and Duplicate Handling

Every node maintains receiver-side freshness state per authenticated sender.

A conforming implementation **MUST** enforce all of the following:

1. each routed packet **MUST** carry a sender-scoped freshness value in
   `packet_counter`
2. that freshness value **MUST** be included in the signed material
3. receivers **MUST** reject packets whose freshness value is outside the
   configured acceptance window for that sender
4. replay acceptance after simple process restart **MUST NOT** be silently
   permitted if the implementation claims durable security semantics

Pattern A is the normative model for this protocol version: the freshness value
is a **per-sender monotonic counter**.

#### 4.6.1 Acceptance Window

Receivers **MUST** track replay state per authenticated sender.

The normative receiver algorithm is:

- maintain `highest_counter` per sender
- maintain a replay bitmap covering the previous `REPLAY_WINDOW_SIZE` counters
- accept a packet if:
  - `packet_counter > highest_counter`, or
  - `packet_counter` falls within the replay window and has not yet been seen
- reject a packet if:
  - `packet_counter` is older than `highest_counter - REPLAY_WINDOW_SIZE`, or
  - the replay bitmap shows that counter was already accepted

`REPLAY_WINDOW_SIZE` is 64 in this protocol version.

This allows limited reordering without allowing indefinite replay.

#### 4.6.2 Sender Persistence

`packet_counter` is per-sender and **MUST** increase monotonically across all
authenticated routed packets emitted by that node.

Senders **MUST** persist enough state to avoid counter rollback across reboot.
If a node loses counter state and cannot prove a strictly greater next counter,
it **MUST NOT** emit further authenticated routed packets under the same long-
term identity until it has either:

- recovered its persisted counter state, or
- generated a new node identity and been re-enrolled

Silent counter rollback is non-conforming.

An implementation MAY additionally keep a fixed-capacity duplicate cache for
fast recent-message rejection:

```rust
pub struct SeenMessages {
    ring: heapless::Deque<(ShortAddr, u64), 128>,  // recent (src, packet_counter) tuples
}

impl SeenMessages {
    /// Returns true if this message from this sender was already seen. Adds it if not.
    pub fn check_and_insert(&mut self, src: ShortAddr, packet_counter: u64) -> bool;
}
```

This cache is an optimization for loop suppression and short-window duplicate
handling. It is **NOT** sufficient anti-replay protection by itself.

An implementation MAY mix an advertised state digest or epoch value into key
derivation, receipt summaries, or other higher-level context. It **MUST NOT**
replace the per-sender counter as the protocol's primary replay defense.

### 4.7 Delivery Semantics

For routed traffic to intermittently reachable low-power nodes, the network
guarantee is **at-least-once delivery**.

That means:

- the network **MAY** redeliver an already-consumed retained item if completion
  proof was lost
- low-power receivers **SHOULD** treat retained items as idempotent using the
  signed `packet_counter` or a higher-level application idempotence key
- the protocol **MUST NOT** claim exactly-once delivery at the mesh layer

---

## 5. Transport Layer

### 5.1 Transport Trait

This section defines the protocol's transport abstraction. Conforming
implementations **MUST** preserve the semantics of discovery, direct peer sync,
and frame exchange defined here regardless of the underlying link technology.

```rust
/// A peer identifier, opaque to the mesh layer.
/// Maps to a binding-defined endpoint such as a local link handle,
/// network-layer socket address, or radio-specific node identifier.
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

    /// Broadcast or otherwise publish a frame to nearby peers using the
    /// binding's discovery/broadcast primitive.
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

The protocol-level requirement is that a node can map a mesh identity to one or
more usable transport endpoints. The exact representation of those endpoints is
binding-specific.

Only authenticated peers may be elevated to forwarding or storage authority.
Observed peers may contribute transport reachability hints, but they **MUST
NOT** be treated as routing-authorized or store-authorized participants until
authenticated.

Protocol version 1 performs authoritative peer promotion during authenticated
H2H exchange. Discovery and announcement traffic may carry certificate material,
certificate digests, or transport hints, but discovery alone does not grant
routing or storage authority.

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
    pub trust: u8,             // TRUST_DIRECT, TRUST_INDIRECT, TRUST_BLOOM, TRUST_EXPIRED
    pub learned_from: ShortAddr, // for indirect peers: the direct partner that taught us
}

/// Trust levels for routing table entries.
pub const TRUST_DIRECT: u8 = 3;   // direct H2H exchange
pub const TRUST_INDIRECT: u8 = 2;  // learned from a partner's H2H peer list
pub const TRUST_BLOOM: u8 = 1;    // bloom filter match only
pub const TRUST_EXPIRED: u8 = 0;  // stale, not refreshed within decay interval
```

### 5.3 BLE Binding Example

The current BLE binding wraps `trouble-host` (GATT peripheral/central):

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

### 5.4 Alternate Binding Sketches

- A WiFi binding may use IPv6 multicast for neighborhood discovery and UDP
  unicast for directed traffic.
- A low-bandwidth radio binding may use a smaller MTU and a different session
  establishment mechanism while still preserving the same mesh semantics.
- Transport preference is a policy choice, not part of the core protocol.

### 5.5 Multi-Transport Routing

Transport selection is a policy choice above the core routed-packet semantics.
The protocol **SHOULD** preserve packet meaning across transports even when a
binding changes how discovery, session setup, or addressing is realized.

When a knot has multiple transports available, a host may apply a local
transport-selection policy such as:

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

### 5.6 H2H Session Security Requirements

H2H is the protocol's direct peer-synchronization and retained-delivery control
plane. It **MUST NOT** rely on transport bindings for its security properties.

A conforming H2H implementation **MUST** provide:

1. mutual peer authentication bound to long-term node identity
2. control-frame authenticity and integrity bound to authenticated node identity
3. freshness protection for every control frame
4. explicit peer authorization before accepting any frame that mutates routing,
   retention, or delivery state

This protocol version does **NOT** require derived session keys. H2H control
frames MAY be authenticated directly with node identity signatures and
freshness counters. A future version MAY derive symmetric session keys for
efficiency, but session-key establishment is not required for conformance today.

The following frame classes are state-mutating and therefore **MUST** be
authenticated and freshness-protected:

- sync request / sync response
- delivery acknowledgements
- retention acknowledgements
- retention tombstones
- session termination

Unauthenticated H2H control frames are non-conforming.

#### 5.6.1 H2H Frame Authentication Format

This protocol version authenticates H2H control traffic directly with node
identity signatures rather than mandatory derived session keys.

Every H2H control frame **MUST** carry an authenticated envelope containing at
least:

```rust
pub struct H2hAuthHeader {
    pub session_id: u64,         // chosen by initiator, unique per H2H exchange
    pub sender: ShortAddr,       // sender identity
    pub frame_counter: u32,      // per-sender monotonic within this session
    pub frame_type: u8,          // SyncRequest, DeliveryAck, etc.
}
```

The signature or equivalent authenticator **MUST** cover:

- `session_id`
- `sender`
- `frame_counter`
- `frame_type`
- the full frame body

Receivers **MUST** reject H2H frames when:

- the sender identity is not an authenticated member
- the sender is not authorized for the requested routing/storage mutation
- `frame_counter` falls outside the current session replay window or has
  already been seen within that window
- `session_id` does not match the active H2H exchange

Per sender within a session, receivers **MUST** maintain:

- `highest_frame_counter`
- a replay bitmap covering the previous `H2H_SESSION_REPLAY_WINDOW` counters

`H2H_SESSION_REPLAY_WINDOW` is 16 in this protocol version.

#### 5.6.2 Session Establishment Rules

For protocol version 1:

- the initiator **MUST** choose a fresh `session_id`
- `SyncRequest` **MUST** carry enough identity material to authenticate the
  initiator before the responder accepts any routing, storage, or retained-state
  mutation from that exchange
- `SyncResponse` **MUST** carry enough identity material to authenticate the
  responder before the initiator accepts any routing, storage, or retained-state
  mutation from that exchange
- the minimum sufficient identity material is:
  - the sender's `full_pubkey`, and
  - the sender's `NodeCertificate` or an exact certificate object previously
    validated and still bound to that `full_pubkey`
- a peer **MUST NOT** omit certificate material on first authenticated contact
  with a given partner
- pubkey or certificate omission is allowed only when the sender has reason to
  believe the partner already holds the same validated binding
- both sides **MUST** validate peer certificate material against the stored
  network public key before accepting state-mutating follow-up frames or
  promoting the peer beyond observed status

Session keys MAY be introduced later as an optimization, but they are not part
of conformance for this protocol version.

---

All H2H wire payloads in this protocol version are carried inside an
authenticated envelope:

```rust
pub struct SignedH2hFrame {
    pub auth: H2hAuthHeader,
    pub body: H2hFrameBody,
    pub signature: Signature,
}
```

`SyncRequest`, `SyncResponse`, and all follow-up H2H frames use this outer
envelope. Any binding-specific H2H wire format that omits the authenticated
envelope is non-conforming.

## 6. Routing

### 6.1 Topology Discovery

Each node maintains a **routing table** from two concrete inputs:

1. **Neighbor discovery events** → observed peer entries with transport address and provisional capability claims
2. **Authenticated H2H peer exchanges** → direct peer refresh plus indirect peer learning via the partner's authenticated peer list

That means the runtime discovery algorithm is:

1. A node **MUST** perform transport-level neighbor discovery for the configured discovery window.
2. For each discovery event, the node **MUST** record a transport-reachable observed peer or update an existing observed/authenticated peer with fresher transport information.
3. Discovery alone **MUST NOT** grant routing or storage trust.
4. After discovery, the node **MUST** build the H2H candidate set from observed or authenticated peers with usable transport information.
5. Nodes **MUST** perform deterministic pairwise H2H exchanges according to the initiator/slot rules in the H2H section.
6. For each successful H2H exchange, the node **MUST**:
   - authenticate the partner identity before promoting it to a routing-authorized or store-authorized peer
   - refresh the partner itself as a direct authenticated peer
   - import only authenticated peer-list entries as indirect routes with `learned_from = partner_short_addr`
   - recompute the local bloom filter from current peer knowledge
7. Nodes **MUST** periodically decay stale peers; entries older than the decay threshold **MUST** be demoted, and entries older than the removal threshold **MUST** be removed.

Heartbeat packet and bloom payload types still exist in the shared protocol layer, but the active runtime flow today is transport-level discovery plus H2H. In the BLE binding, that discovery mechanism is advertisement scanning.

```rust
pub struct RoutingTable {
    /// Our own node identity
    self_addr: ShortAddr,
    /// Peer registry with transport mappings
    peers: PeerRegistry,
    /// Our bloom filter (recomputed periodically)
    local_bloom: BloomFilter,
    /// Fast recent duplicate cache for loop suppression
    seen: SeenMessages,
    /// Decay timer: entries not refreshed within TTL are demoted/removed
    decay_interval: Duration,  // e.g., 3 * heartbeat_interval = 180s
}
```

Authentication/authorization state and routing-confidence state are separate
dimensions:

- membership/auth state: observed, authenticated, routing-authorized,
  store-authorized
- route-confidence state: direct, indirect, bloom-derived, expired

An implementation **MUST NOT** collapse these into a single conceptual trust
level when making forwarding or storage-authority decisions.

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
    if !verify_sender_membership_and_signature(packet):
        return

    if !replay_window_accepts(packet.src, packet.packet_counter):
        return

    if packet.dst == self.addr:
        deliver_locally(packet)
        return

    if seen.check_and_insert(packet.src, packet.packet_counter):
        return  // already forwarded for this sender, drop (loop prevention)

    if packet.ttl == 0:
        return  // TTL expired

    packet.ttl -= 1
    packet.hop_count += 1

    candidates = forwarding_candidates(packet.dst)

    if candidates.is_empty():
        // No route: drop
        return

    // Send according to forwarding class:
    // - direct / indirect next-hop: one chosen next-hop
    // - bloom-derived: ordered top-N bounded by BLOOM_FANOUT_MAX
    for neighbor in candidates:
        transport = select_transport(neighbor, packet.type)
        transport.send(neighbor.transport_id, packet.serialize())
```

**`forwarding_candidates(dst)` resolution order**:

1. **Direct authenticated destination**: if `dst` is a known authenticated peer with usable transport → forward directly
2. **Indirect authenticated next-hop**: if `dst` is an indirect peer, resolve `learned_from` to a usable authenticated direct neighbor → forward via that neighbor
3. **Bounded bloom-route candidates**: neighbors whose authenticated bloom state claims they know `dst` → forward via bounded bloom-hint fan-out
4. **Router-uplink fallback**: if the local node is not itself acting as a routing topology holder and no direct/indirect/bloom candidates exist, forward to the single best authenticated routing-authorized direct neighbor
5. **No candidates**: packet is dropped

**Key behaviors**:
- **Indirect routing**: destinations learned from H2H **MUST** carry `learned_from`, which is the next-hop hint for indirect peers.
- **Multiple bloom hits**: implementations **MUST NOT** forward to an unbounded candidate set. `BLOOM_FANOUT_MAX` is 2 in this protocol version.
- **Candidate ordering**: bloom candidates **MUST** be sorted by:
  1. stronger trust class first
  2. fresher `last_seen` first
  3. lower `hop_count` first
  4. lexicographically smaller `ShortAddr` first
  Only the first `BLOOM_FANOUT_MAX` candidates may be used.
- **Router-uplink fallback**: this fallback **MUST** select at most one direct authenticated routing-authorized neighbor. It exists to let non-router/edge nodes hand uncertainty upward to a topology holder.
- **No recursive router escalation**: a router that receives a packet through router-uplink fallback and still has no direct, indirect, bloom, or delayed-delivery reason to keep it **MUST** terminate it as `NoRoute` rather than blindly forwarding it to another router.
- **No bloom hits**: if resolution yields no candidates, the node **MUST NOT** perform an unconditional flood in the current protocol.
- **Loop prevention**: `SeenMessages` ring buffer **MUST** key duplicate suppression by at least `(src, packet_counter)` so different senders do not collide.
- **TTL**: nodes **MUST** decrement TTL on forward and **MUST NOT** forward packets whose TTL has reached zero.

### 6.4 Routing Confidence

The protocol separates **reachability hints** from **forwarding authority**.

- observed peer state is sufficient to attempt authenticated session setup
- authenticated direct peer state is sufficient for direct forwarding
- authenticated indirect peer state is sufficient only when `learned_from`
  resolves to an authenticated direct next hop
- bloom-derived routing is advisory and lower confidence than direct or indirect
  authenticated state

### 6.5 Bloom Filter False Positives

A bloom filter false positive means a neighbor claims to know a route but doesn't. The packet is forwarded there anyway but will eventually be dropped when TTL expires. The multi-path forwarding strategy means the packet likely reaches the destination via another neighbor. No explicit backtracking is needed in v1.

### 6.6 Entry Decay

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

### 7.1 Store-and-Forward via H2H Wake Sessions

Low-energy (LE) nodes do not route and do not stay continuously reachable. In the current executable design, delayed delivery is modeled as an **extended H2H session** layered on top of the normal peer-sync exchange.

Current algorithm:

1. The LE node **MUST** discover nearby routers through the active transport's normal neighbor-discovery mechanism.
2. The LE node **MUST** rank candidate routers:
   - **primary router** = best local router by trust / freshness / address tie-break
   - **fallback routers** = remaining reachable routers, ordered deterministically from the LE node identity
3. A sender **MUST** route toward the LE destination using the normal forwarding algorithm first.
4. If a store-authorized router holds the packet and has no immediate forwarding candidate to the sleeping LE endpoint, it **MUST** retain the packet locally.
5. Owner routers **MAY** replicate retained messages, but if they do, they **MUST** restrict placement to the deterministic backup subset.
6. On wake, the LE node **MUST** initiate one H2H session to the best-ranked reachable router first.
7. After the normal sync request/response completes, the router **MUST** send a `DeliverySummary` frame before any retained data frames.
8. The router **MUST** send one `DeliveryData` frame per retained message it chooses to deliver in that wake session.
9. The LE node **MAY** acknowledge delivered items with `DeliveryAck` when an explicit return path is available and cheap enough for the wake session.
10. If no explicit acknowledgement is sent, the LE node **SHOULD** later advertise an authenticated passive receipt summary keyed by original message source, such as the highest accepted retained `packet_counter` per source.
11. After explicit acknowledgement or sufficiently specific authenticated passive receipt evidence, the serving router **MUST** remove acknowledged retained entries and **SHOULD** emit authenticated tombstones so redundant replicas can be cleared.
12. The session **MUST** terminate with `SessionDone`.

Delivery semantics are **at-least-once**. If acknowledgement or passive receipt
evidence is lost, the same retained item MAY be delivered again on a later wake. Low-power receivers
therefore **SHOULD** apply idempotence at message-consumption time.

Important: the **primary wake router** and the **backup replica placement** use intentionally different rankings. The primary choice is local-quality driven; backup placement is deterministic from the LE identity so different routers can independently derive the same redundancy set.

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

### 7.2 Router Selection for Retained Delivery

The current selection rules are:

- Any store-authorized router that ends up holding the undeliverable packet **MAY** become the **owner router** for that retained entry.
- Backup replica placement **MUST** be limited to the deterministic subset returned by `is_backup_router_for_lpn(...)`.
- The preferred wake router for the LE node **MUST** be chosen from live local peer quality, not from the deterministic backup ranking.
- A successful LE wake session **MUST** stop after the **first** successful router exchange in that wake window; later candidates are fallback choices, not additional sync partners.

Retained-state mutation authority is strict:

- only store-authorized peers may hold replicas
- only authenticated session participants may exchange retained-delivery control frames
- deletion frames such as tombstones **MUST** be authenticated and freshness-protected
- retained-state deletion **MUST** be scoped to a specific retained item and owner identity

### 7.3 Passive Receipt Summary

Explicit acknowledgement is preferred when it is cheap enough for the wake
session, but the protocol also supports conservative passive completion
evidence.

An LE node **SHOULD** advertise an authenticated passive receipt summary after a
successful retained-delivery wake session when explicit acknowledgements were
omitted or may have been lost.

The passive receipt summary format for protocol version 1 is:

```rust
pub struct ReceiptSummary {
    pub lpn: ShortAddr,
    pub summary_counter: u32,   // monotonic per LPN receipt summary
    pub entries: heapless::Vec<ReceiptSummaryEntry, RECEIPT_SUMMARY_MAX_ENTRIES>,
    pub signature: Signature,
}

pub struct ReceiptSummaryEntry {
    pub source: ShortAddr,
    pub highest_contiguous_counter: u64,
}
```

Rules:

- `summary_counter` **MUST** increase monotonically per LPN so summaries cannot
  be replayed indefinitely
- each entry acknowledges only a **contiguous prefix** of retained packets from
  one original source to this LPN
- routers **MUST** clear retained items conservatively: an item may be removed
  only if its `(source, packet_counter)` is covered by a validated receipt
  summary entry for that destination LPN
- receipt summaries **MUST NOT** authorize deletion of items from unrelated
  sources or for unrelated destination LPNs
- only the owner router for a retained item may originate authoritative
  tombstones for that item after validating receipt evidence

This summary mechanism is deliberately conservative. It is intended to provide
"good enough" completion evidence without requiring explicit ack traffic for
every wake session.

### 7.4 LE Wake Cycle

```
LE node:
  1. Wake and scan for reachable routers
  2. Attempt H2H with the best-ranked router
  3. If that fails, try later fallback routers in rank order
  4. On first successful H2H, receive delayed-delivery frames
  5. Optionally send explicit `DeliveryAck`, or later advertise passive receipt summary state
  6. End the session and go back to sleep
```

In the current simulator model, retained delivery, replica transfer, and tombstone cleanup are all expressed as typed H2H follow-up frames rather than a second protocol.

### 7.5 Overload and Queue Exhaustion

Retained delivery is capacity-bounded. The protocol **MUST** define overflow
behavior explicitly.

At minimum, a conforming implementation **MUST** define:

- whether oldest or newest retained items are dropped first
- whether replicas and owner copies share the same quota
- whether some traffic classes outrank others for retention
- whether overflow is silent best effort or surfaced as a delivery failure state

Protocol version 1 defines the following policy:

1. expired retained items **MUST** be dropped before admitting new retained
   items
2. owner copies outrank replicas
3. if a new replica arrives and the holder is at quota, the replica **MUST** be
   rejected rather than evicting an owner copy
4. if a new owner copy arrives and the holder is at quota, the implementation
   **MUST** first evict the oldest replica held by that node if one exists
5. if the holder contains only owner copies and remains at quota, the new owner
   copy **MUST** be rejected rather than evicting an already-accepted owner copy
6. accepted owner copies for a given destination **SHOULD** preserve FIFO
   delivery order

Overflow is still best-effort in protocol version 1, but it **MUST** be
observable locally through logs, metrics, or traces. Silent overflow without
defined policy is non-conforming.

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

Node identity and certificates are persisted to a dedicated flash partition:

```
ESP-IDF Partition Table:
  Name          Type    SubType    Offset     Size
  nvs           data    nvs        0x9000     0x4000
  phy_init      data    phy        0xf000     0x1000
  factory       app     factory    0x10000    0x200000
  constellation data    undefined  0x210000   0x1000     (4 KB)
```

The `constellation` partition holds identity and provisioning state:

```
Flash Layout (within constellation partition, 236 bytes used out of 4096):

Offset  Field                         Size
0x0000  magic (0xC0DECAFE)            4 bytes
0x0004  version (STORAGE_VERSION_V3)  1 byte
0x0005  flags                         1 byte
0x0006  secret_key (ed25519)          32 bytes
0x0026  committed_membership          106 bytes
0x008E  staged_membership             98 bytes
0x00F0  reserved                       70 bytes
```

`PartitionedFlash` wraps `FlashStorage` to translate partition-relative
offsets (starting at 0) to absolute flash addresses. All reads use
sector-aligned 4096-byte buffers to satisfy ESP32 alignment requirements
(4-byte aligned in both offset and length). Erase-before-write is enforced
since NOR flash can only turn 1-bits into 0-bits.

```rust
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

# Appendix A. BLE Binding (Current Reference Binding)

This appendix specifies the current BLE binding: advertisement formats and the H2H
(Heart2Heart) exchange over BLE primitives.

The core mesh protocol is defined in the sections above. This appendix is a
transport-specific realization of those semantics, not the definition of the
mesh protocol itself.

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
  Payload:     Discovery payload (18 bytes)
```

### 2.2 Discovery Payload (18 bytes)

```
Offset  Size  Field
──────  ────  ──────────────
0       8     short_addr      ShortAddr of the advertising node
8       2     capabilities    Capability bitfield (LE u16)
10      8     network_addr    NetworkAddr of the advertising node's authority
```

`network_addr` is a compact 8-byte fingerprint of the network authority
public key, derived via `SHA-256(pubkey)[0..8]`. Unenrolled nodes
advertise `ONBOARDING_READY_NETWORK_ADDR = [0xFF; 8]` instead.

This allows companions to identify network membership from advertisement
data alone, without a GATT connection. Enrolled nodes advertise their
real `NetworkAddr`; unenrolled nodes advertise the onboarding-ready sentinel.

Fits within the 31-byte BLE advertising data limit (3 bytes flags + 22
bytes manufacturer-specific AD structure = 25 bytes).

This BLE discovery payload provides observed-peer hints:

- `short_addr`
- provisional capabilities
- `network_addr` — identifies which network the node belongs to, or
  whether it is unenrolled (onboarding-ready)

It does **NOT** by itself grant routing or storage authority. In protocol
version 1, authoritative peer promotion occurs during authenticated H2H, not
from advertisement parsing alone. However, the `network_addr` field enables
fast filtering: companions can ignore advertisements from other networks and
prioritize onboarding-ready devices without GATT connections.

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
| MTU | 512 bytes |
| Connection timeout | 5 seconds |
| Cycle period | 60 seconds |

### 3.2 Pair Scheduling

For any pair of nodes (A, B):

1. **Canonical order**: `(lo, hi) = sort_lexicographic(A.short_addr, B.short_addr)`
2. **Pair hash**: `SHA-256(lo || hi)` → 32 bytes
3. **Initiator**: the node with the lexicographically smaller `ShortAddr`
4. **Slot offset**: `u16_le(pair_hash[0..2]) % 60` → second within the 60s cycle

Both nodes **MUST** compute the same values deterministically. Implementations **MUST NOT** use local heuristics to override initiator ownership for non-low-power peers.

### 3.3 Exchange Protocol

The current H2H session is a two-phase protocol:

#### Phase A — mandatory peer sync

1. The responder **MUST** advertise and accept a BLE connection.
2. The initiator **MUST** connect and open the L2CAP CoC.
3. The initiator **MUST** send `SignedH2hFrame { auth, body = SyncRequest(H2hPayload), signature }`.
4. The responder **MUST** parse the request and resolve the partner identity.
5. The responder **MUST** build its response payload before mutating the routing table.
6. The responder **MUST** update its routing table from the initiator payload.
7. The responder **MUST** send `SignedH2hFrame { auth, body = SyncResponse(H2hPayload), signature }`.
8. The initiator **MUST** update its routing table from the responder payload.

Both `SyncRequest` and `SyncResponse` are carried inside authenticated
`SignedH2hFrame` envelopes as defined in the core specification.

#### Phase B — optional follow-up frames on the same session

If the host/runtime needs extra work after sync, the same session **MAY** stay open for typed `H2hFrame`s:

- `DeliverySummary`
- `DeliveryData`
- `DeliveryAck`
- `RetentionReplica`
- `RetentionAck`
- `RetentionTombstone`
- `SessionDone`

Delayed delivery and router-to-router replica transfer **MUST NOT** introduce a second parallel session protocol when the same semantics can be expressed as follow-up `H2hFrame`s on the active H2H session.

All follow-up `H2hFrame` bodies in Phase B are likewise carried inside
`SignedH2hFrame` envelopes with the same `session_id` and per-sender
`frame_counter` progression.

### 3.4 H2H Payload Wire Format

The H2H payload described below is the **body** of `SyncRequest` /
`SyncResponse`. On the wire, the full frame is:

```
SignedH2hFrame {
  auth: H2hAuthHeader,
  body: SyncRequest(H2hPayload) | SyncResponse(H2hPayload) | follow-up H2hFrame,
  signature: Signature,
}
```

Any BLE exchange that omits this authenticated outer envelope is
non-conforming, even if the inner `H2hPayload` matches the layout below.

```
Offset  Size         Field            Notes
──────  ────         ─────            ─────
0       1            flags            Bit field (see §3.5)
1       1            version          Protocol version (see §3.6)
2       0 | 32       full_pubkey      Present when flags.0 = 1
?       0 | CERT_LEN certificate      Present when flags.1 = 1; serialized `NodeCertificate`
?       2            capabilities     Sender's capability bitfield (LE u16)
?       4            uptime_secs      Sender's uptime in seconds (LE u32)
?       1            peer_count       Number of peer entries (0–8)
?       N × 35       peers[]          Peer info entries
```

The fixed portion without optional identity material is **9 bytes**. With only
`full_pubkey` it is **41 bytes** before peer entries. With both `full_pubkey`
and `certificate`, it is `41 + CERT_LEN` bytes before peer entries.

A sender **MUST** include certificate material on first authenticated contact
with a partner. Later exchanges MAY omit fields already validated by that
partner, subject to the authenticated-bootstrap rules in §5.6.2.

### 3.5 Flags Byte

```
Bit  Name          Description
───  ────          ───────────
0    has_pubkey      1 = 32-byte pubkey follows flags; 0 = omitted
1    has_certificate  1 = serialized NodeCertificate follows optional pubkey; 0 = omitted
2    (reserved)
3    (reserved)
4    (reserved)
5    (reserved)
6    (reserved)
7    (reserved)
```

**Identity-material omission logic**: the sender **MAY** omit `full_pubkey` or `certificate` only when the partner is already known to hold the same validated identity binding. First authenticated exchanges **MUST** include both `full_pubkey` and `certificate`.

### 3.6 Version Byte

The `version` byte immediately follows `flags`. It identifies the H2H wire-format version used by the sender. In protocol version 1, the H2H wire-format version is also `0x01`.

A receiver **MUST** check the version byte. If it does not support the received version, it **MUST** reject the frame without applying any state mutation.

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
