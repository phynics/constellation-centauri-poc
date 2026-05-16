# AGENTS.md

## Constellation boundary rules

- `routing-core/` owns transport-agnostic protocol, routing, crypto, onboarding primitives, routed packet handling, and discovery payload serialization/parsing.
- `firmware/` owns ESP32, Embassy, trouble-host, flash, partition, and reboot behavior.
- `companion/` owns macOS/CoreBluetooth (`blew`), local persistence, and diagnostics UI.
- `sim/` is a host harness for `routing-core`, not a separate routing model.

## Discovery and routing lessons

- Treat advertisement/manufacturer discovery as **shared routing input**, not just UI metadata.
- If a host crate parses Constellation discovery payloads, it should feed those results into shared routing state via `routing_core::behavior::apply_discovery_events(...)` or equivalent shared-core updates.
- Do not let diagnostics/TUI state become a shadow peer database that diverges from `RoutingTable`.
- Protocol-level discovery constants such as `CONSTELLATION_COMPANY_ID`, `DiscoveryInfo`, and discovery payload parsing belong in `routing-core` and should be imported from there.

## Scope guardrails

- Keep BLE-binding specifics that are truly host-facing, like `Uuid`-typed GATT constants and stack wiring, in host crates unless there is a clear shared representation need.
- Prefer fixing boundary drift by reusing an existing shared-core path before inventing a second host-specific flow.

## Current agentic dev loop

- Start in `routing-core/` first; treat it as the primary design and documentation surface before touching host crates unless the issue is clearly host-specific.
- Improve `routing-core/` with extensive documentation as you work, including the design decisions that led to the current shape.
- Each `routing-core` source file should begin with a concise comment header covering: purpose, key invariants or boundaries when relevant, and a compact log of design decisions.
- File-local design decisions belong in that file's decision log.
- Cross-file or broader-scope design decisions belong in `AGENTS.md`.
- Whenever a feature, fix, or similar change introduces a real design decision, update the corresponding file decision log or `AGENTS.md` in the same change.
- Keep these headers current, but keep them short enough to stay readable during implementation.
