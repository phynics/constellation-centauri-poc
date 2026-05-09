# Constellation protocol review

This review uses `docs/spec/protocol.md` as the source of truth and checks the
actual code paths against the stated protocol behavior.

## Verdict

This protocol is **not fit for purpose** as a secure, resilient mesh protocol in
messy communication environments.

It has the beginnings of a workable routing and delayed-delivery model, but the
current design is still a fragile prototype. It does not provide credible
security against replay, state-forgery, routing poisoning, or retained-delivery
deletion. It also does not provide reliable delivery semantics for low-power
nodes under realistic packet loss. The protocol document is now cleaner than
the implementation, but the protocol itself is still incomplete in ways that
matter operationally.

If deployed as described, the system would be easy to disrupt, easy to poison,
and unable to make strong delivery guarantees for intermittently reachable
devices.

---

## Findings

## 1. Routed replay protection is absent

**Severity:** Critical  
**Type:** Protocol design flaw

The spec explicitly leaves replay protection out of scope. The implementation
confirms that:

- routed packets carry a random 8-byte `message_id`
- duplicate suppression is only a fixed in-memory ring (`SeenMessages`)
- the ring capacity is 128 IDs
- state is not durable across restart/reset

Code basis:

- `routing-core/src/protocol/packet.rs`
- `routing-core/src/protocol/dedup.rs`

This is not a minor omission. It means the protocol has no real anti-replay
story.

Concrete consequences:

- a captured valid packet can be replayed after the dedup window rolls over
- a replayed packet will also be accepted after node restart or reset
- low-rate replay is enough; the attacker does not need to flood continuously

That breaks the claimed authenticated messaging model. A signed packet without a
freshness mechanism is replayable authenticated garbage.

**Required fix direction:**

- define per-sender freshness semantics
- bind freshness into the signed material
- decide whether freshness is sequence-based, window-based, epoch-based, or
  challenge-based
- define persistence expectations for replay state

---

## 2. H2H has no authentication, no integrity protection, and no anti-replay

**Severity:** Critical  
**Type:** Protocol design flaw

The H2H control plane is completely unauthenticated.

The following frame families are accepted based on wire shape alone:

- `SyncRequest`
- `SyncResponse`
- `DeliverySummary`
- `DeliveryData`
- `DeliveryAck`
- `RetentionReplica`
- `RetentionAck`
- `RetentionTombstone`
- `SessionDone`

Code basis:

- `routing-core/src/protocol/h2h.rs`
- `routing-core/src/network.rs`
- `sim/src/behavior.rs`

There is:

- no session authentication
- no frame MAC/signature
- no nonce/counter/window on H2H frames
- no cryptographic binding between a frame and the node identity it claims to
  represent

This is a hard failure, not an enhancement backlog item.

Concrete consequences:

- forged `DeliveryAck` can make a router discard undelivered retained messages
- forged `RetentionTombstone` can delete retained replicas on other routers
- forged `RetentionReplica` can inject false state into backup routers
- replayed H2H follow-up frames can re-open or corrupt retained-delivery state
- `SessionDone` is spoofable and can terminate an exchange early

The simulator proof test for forged tombstones captures one concrete instance of
this problem.

**Required fix direction:**

- define authenticated session establishment for H2H
- authenticate every follow-up frame
- include monotonically advancing freshness inside the authenticated frame
- bind H2H control messages to long-term node identity and peer identity

---

## 3. Discovery is unauthenticated and therefore poisonable

**Severity:** Critical  
**Type:** Protocol design flaw

Neighbor discovery currently accepts capability and address claims before any
certificate or signed proof is validated.

Code basis:

- `routing-core/src/behavior.rs::apply_discovery_events`
- `routing-core/src/routing/table.rs::update_peer_compact`
- transport binding behavior in sim and firmware

The discovery path accepts:

- `short_addr`
- `capabilities`
- `transport_addr`

and turns that into a direct peer entry.

Concrete consequences:

- an attacker can advertise fake routers and fake store nodes
- an attacker can bias low-power nodes toward bad wake targets
- an attacker can cause route blackholing or traffic steering
- capability poisoning can trick the system into replicating retained state to
  untrusted holders

`NodeCertificate` exists, but it is not part of the actual routing acceptance
path. Right now the certificate concept is decorative.

**Required fix direction:**

- define authenticated discovery or an authenticated promotion path from
  discovered peer -> trusted routing participant
- do not trust capability claims before authentication
- separate "heard a beacon" from "accepted as a routing/store participant"

---

## 4. Packet signatures exist but are not part of the runtime forwarding path

**Severity:** Critical  
**Type:** Spec/implementation gap

The packet layer can sign and verify packets. The routing/runtime path shown in
the simulator does not actually use those checks for forwarded application
messages.

Code basis:

- signing/verification helpers: `routing-core/src/protocol/packet.rs`
- simulator forwarding path: `sim/src/message_task.rs`

The simulator's routed traffic uses `SimDataMessage` directly. It does not
serialize a packet, verify a packet signature, or enforce the packet wire model.

This means the protocol's claimed authenticated packet semantics are not being
exercised by the main experiment harness.

Consequences:

- the most important verification surface is not testing the most important
  security property
- the spec can drift into wishful thinking because the harness is not forcing
  packet validation behavior

This does not automatically mean firmware also skips validation in all paths,
but the shared-core proof surface is weak where it matters most.

**Required fix direction:**

- make the shared/runtime harness operate on real packet objects or serialized
  packet bytes for security-relevant paths
- ensure signature verification failures are part of normal tests

---

## 5. Low-power delivery is not reliable under packet loss

**Severity:** High  
**Type:** Protocol design flaw

The delayed-delivery flow is missing a robust loss-tolerant state machine.

Code basis:

- `sim/src/behavior.rs`
- `sim/src/store_forward.rs`
- `routing-core/src/protocol/h2h.rs`

The current model is:

1. router sends `DeliverySummary`
2. router sends `DeliveryData`
3. low-power node sends `DeliveryAck`
4. router clears retained state

This is not enough.

Failure modes:

- if `DeliveryData` arrives but `DeliveryAck` is lost, the router keeps the
  message and redelivers it later
- if `DeliverySummary` is lost, the wake window may be wasted
- if `SessionDone` or a later ack is lost, completion semantics become ambiguous
- there is no end-to-end idempotent delivery contract for the low-power node

The simulator proof test for missing delivery ack demonstrates the duplicate
redelivery problem directly.

This protocol cannot honestly claim reliable low-power delivery in lossy
conditions.

**Required fix direction:**

- define idempotent delivery tokens distinct from mere transient H2H ack frames
- define retransmission and completion semantics
- define what both sides persist across wake cycles
- decide whether delivery is at-most-once, at-least-once, or effectively-once

---

## 6. Retained-delivery deletion semantics are unsafe

**Severity:** High  
**Type:** Protocol design flaw

`RetentionTombstone` is a destructive state mutation keyed by trace IDs. There
is no proof in the protocol that the sender is authorized to clear that state.

Code basis:

- `routing-core/src/protocol/h2h.rs`
- `sim/src/store_forward.rs::apply_tombstones`

Any accepted tombstone clears all retained copies matching the trace IDs across
holders.

Consequences:

- deletion can be spoofed
- deletion can be replayed
- deletion can race with legitimate delivery
- a backup router can wipe state it never delivered

This is a direct retained-delivery deauth primitive.

**Required fix direction:**

- authenticate tombstones
- bind them to delivery authority or explicit owner state
- include freshness and scope
- define whether owner-only, holder-only, or quorum-based deletion is required

---

## 7. H2H identity resolution has dangerous fallback behavior

**Severity:** High  
**Type:** Protocol design flaw / parser-state flaw

When a responder receives an H2H payload without `full_pubkey`, it resolves the
partner by looking up the transport address. If that lookup fails, the code can
fall back to `[0u8; 8]` as the partner short address.

Code basis:

- `routing-core/src/behavior.rs::run_responder_loop`
- `routing-core/src/routing/table.rs::update_peer_from_h2h`

That means a malformed or adversarial session can potentially create or refresh
state for a zero short address instead of failing closed.

This is wrong. Identity resolution failure is not a valid peer identity.

**Required fix direction:**

- fail the session on unresolved peer identity
- do not treat zero address as a usable peer identity
- make pubkey omission conditional on already-authenticated peer state, not just
  opportunistic state lookup

---

## 8. The protocol still trusts ambient topology too much in messy environments

**Severity:** High  
**Type:** Fit-for-purpose flaw

The routing model assumes that:

- discovery state is reasonably fresh
- H2H pair opportunities occur often enough
- `learned_from` remains meaningful long enough to forward usefully
- bloom hints are acceptable as routing amplification hints

This is weak in the target environment.

In messy RF conditions:

- links are asymmetric
- discovery refresh is partial and bursty
- low-power nodes disappear for long periods
- direct peers decay while indirect claims survive just long enough to be wrong

The current protocol has no explicit route confidence model beyond
direct/indirect/bloom/expired and last-seen timing. That is thin for a sparse,
lossy mesh with intermittent endpoints.

**Required fix direction:**

- better route confidence and freshness semantics
- explicit handling of asymmetric links
- delivery policy aware of stale indirect next hops
- tighter separation between optimistic hints and forwardable routes

---

## 9. Multi-path bloom forwarding is an amplification vector

**Severity:** High  
**Type:** Protocol design flaw

The forwarding rule says to send to all usable bloom-matching candidates.

Code basis:

- `routing-core/src/routing/table.rs::forwarding_candidates`
- `sim/src/message_task.rs`

That helps delivery probability, but it is also a built-in amplification rule.

Consequences:

- an attacker can cause excessive retransmission load with crafted traffic to
  sparse/unreachable destinations
- false positives translate directly into extra forwarding work
- there is no rate control, no fan-out cap, and no congestion response

This is not acceptable in a constrained, lossy, battery-sensitive network.

**Required fix direction:**

- cap fan-out
- add route confidence ranking
- add rate limiting / admission control
- define fallback behavior for unresolved destinations that does not blindly
  multiply traffic

---

## 10. Store-forward capacity is implementation-bounded with no protocol answer

**Severity:** Medium  
**Type:** Missing protocol requirement

Retained delivery is bounded by small local queues (`STORE_FORWARD_MAX_PER_NODE`
= 8, age limit 600s).

Code basis:

- `routing-core/src/config.rs`
- `sim/src/store_forward.rs`

The protocol does not define what should happen when:

- the queue is full
- multiple senders target the same sleeping endpoint
- a low-power node is absent longer than retention age
- owners and backups disagree about who should keep the last surviving copy

Right now this is just best effort local dropping.

For the target environment, that is not enough.

**Required fix direction:**

- define overflow policy
- define retention priority
- define sender-visible failure or non-delivery semantics
- define whether replicas consume separate quota or shared quota

---

## 11. The protocol has no anti-DoS story for session establishment

**Severity:** Medium  
**Type:** Missing protocol requirement

Deterministic pair scheduling makes the session plan predictable. That is good
for coordination, but there is no countermeasure for abusive repeated session
attempts, bogus peers, or expensive responder wakeups.

Consequences:

- responders can be forced to spend energy on junk sessions
- low-power-oriented deployments are especially exposed because brief wake
  windows matter
- the protocol does not define rejection backoff, authentication gating, or
  peer admission control

**Required fix direction:**

- bounded session admission
- per-peer rate limiting
- authentication before expensive state mutation
- responder-side cheap rejection path

---

## 12. Security claims are ahead of reality

**Severity:** Medium  
**Type:** Protocol/document honesty problem

The spec talks about asymmetric-key authenticated and encrypted messaging. The
actual system behavior today is much weaker:

- routing/discovery trust is unauthenticated
- H2H control plane is unauthenticated
- replay protection is absent
- the main simulator path does not exercise real signed packet forwarding

That gap matters because it changes design decisions. A protocol that still
needs basic freshness/authentication machinery should not be judged as though it
already has it.

---

## Missing pieces that must exist before this protocol is fit for purpose

These are not optional nice-to-haves.

1. **Replay protection for routed packets**
2. **Authenticated H2H sessions and authenticated H2H follow-up frames**
3. **Authenticated peer discovery or authenticated promotion to trusted peer**
4. **Robust low-power delivery semantics under loss**
5. **Safe retained-state deletion rules**
6. **Rate limiting / anti-amplification controls**
7. **Explicit overflow semantics for retained queues**
8. **A real trust model for capabilities and store/router roles**

Until those exist, the protocol is not ready for the environment it claims to
target.

---

## What is salvageable

The protocol is not worthless. These parts are directionally sound:

- transport-neutral routing core separation
- deterministic pair ownership for direct sync
- explicit low-power delayed-delivery model
- shared simulator/runtime harness for proving behavior
- indirect routing through `learned_from` rather than pretending bloom alone is
  enough

But that is the scaffold, not the finished protocol.

---

## Tests added to demonstrate concrete deficiencies

The simulator can already demonstrate three real problems. These tests are
checked in as **ignored** failure proofs so the default suite stays green.

1. `replayed_message_is_accepted_again_after_dedup_window_rollover`
   - proves replay becomes possible again once the dedup ring rolls over

2. `retained_delivery_queue_overflow_drops_messages_for_sleeping_low_power_nodes`
   - proves fixed retained-queue limits silently drop traffic for sleeping
     endpoints under burst load

3. `missing_delivery_ack_causes_duplicate_redelivery_on_next_wake`
   - proves a lost ack causes duplicate retained delivery on later wakes

These are not theoretical concerns. The harness can reproduce them now.
