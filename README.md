# Constellation Mesh

A decentralized mesh communication protocol for ESP32 microcontrollers. 

Constellation nodes communicate via asymmetric-key authenticated and encrypted messages, with network routing derived from heartbeat-based topology discovery.

## Documentation Index

- **[Quick Start & Hardware Testing](docs/guides/hardware-testing.md)** - Get it running on your ESP32-C6.
- **[Protocol Specification](docs/spec/protocol.md)** - High-level mesh and low-level BLE protocol details.
- **[BLE Integration Guide](docs/guides/ble-integration.md)** - Development status and guide for the BLE transport layer.
- **[Archive](docs/archive/)** - Historical summaries and plans.

## Project Structure

- `firmware/` - ESP32-C6 firmware (Embassy-based).
- `routing-core/` - Core protocol logic (no-std, transport-agnostic).
- `sim/` - Network simulator for protocol testing.
- `docs/` - Project documentation.

## License

TBD
