//! Compact bloom-filter summaries for indirect reachability hints.

use crate::config::BLOOM_FILTER_BYTES;
use crate::crypto::identity::ShortAddr;

pub struct BloomFilter {
    pub bits: [u8; BLOOM_FILTER_BYTES],
    pub generation: u8,
}

impl BloomFilter {
    pub const fn new() -> Self {
        Self {
            bits: [0u8; BLOOM_FILTER_BYTES],
            generation: 0,
        }
    }

    pub fn insert(&mut self, addr: &ShortAddr) {
        let indices = Self::hash_indices(addr);
        for idx in indices {
            let byte = (idx / 8) as usize;
            let bit = idx % 8;
            self.bits[byte] |= 1 << bit;
        }
    }

    pub fn contains(&self, addr: &ShortAddr) -> bool {
        let indices = Self::hash_indices(addr);
        for idx in indices {
            let byte = (idx / 8) as usize;
            let bit = idx % 8;
            if self.bits[byte] & (1 << bit) == 0 {
                return false;
            }
        }
        true
    }

    pub fn merge(&mut self, other: &BloomFilter) {
        for i in 0..BLOOM_FILTER_BYTES {
            self.bits[i] |= other.bits[i];
        }
    }

    pub fn clear(&mut self) {
        self.bits = [0u8; BLOOM_FILTER_BYTES];
        self.generation = self.generation.wrapping_add(1);
    }

    /// Derive 3 bit positions (0..255) from the ShortAddr bytes.
    fn hash_indices(addr: &ShortAddr) -> [u8; 3] {
        // Mix different byte ranges to get independent positions
        let h0 = addr[0] ^ addr[1] ^ addr[2];
        let h1 = addr[2] ^ addr[3] ^ addr[4];
        let h2 = addr[5] ^ addr[6] ^ addr[7];
        [h0, h1, h2]
    }
}
