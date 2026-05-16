//! Transport-opaque peer address representation.
//!
//! Purpose: carry host-provided peer transport identifiers through shared-core
//! routing code without teaching the protocol about specific platform APIs.
//!
//! Design decisions:
//! - Keep the address payload transport-opaque so hosts without raw BLE MAC
//!   access can still participate with stable local identifiers.
//! - Let host crates own concrete transport semantics while the core only needs
//!   equality, emptiness, and basic construction helpers.
//!
/// Currently only BLE is supported. WiFi and LoRa will be added post-PoC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TransportAddr {
    pub addr_type: u8, // 0 = BLE, 1 = WiFi (future), 2 = LoRa (future)
    pub len: u8,
    pub addr: [u8; 16],
}

impl TransportAddr {
    /// Create a BLE transport address.
    pub const fn ble(mac: [u8; 6]) -> Self {
        let mut addr = [0u8; 16];
        addr[0] = mac[0];
        addr[1] = mac[1];
        addr[2] = mac[2];
        addr[3] = mac[3];
        addr[4] = mac[4];
        addr[5] = mac[5];
        Self {
            addr_type: 0,
            len: 6,
            addr,
        }
    }

    pub const fn opaque(addr_type: u8, len: u8, addr: [u8; 16]) -> Self {
        Self {
            addr_type,
            len,
            addr,
        }
    }

    pub const fn empty() -> Self {
        Self {
            addr_type: 0,
            len: 0,
            addr: [0u8; 16],
        }
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_ble_mac(&self) -> Option<[u8; 6]> {
        if self.addr_type != 0 || self.len != 6 {
            return None;
        }
        Some([
            self.addr[0],
            self.addr[1],
            self.addr[2],
            self.addr[3],
            self.addr[4],
            self.addr[5],
        ])
    }
}
