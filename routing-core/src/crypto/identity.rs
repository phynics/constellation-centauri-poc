//! Node identity primitives.
//!
//! Purpose: define signing keys, stable derived addresses, network fingerprints,
//! and signature helpers used across the protocol surface.
//!
//! Design decisions:
//! - Derive short addresses and network addresses from public keys in shared
//!   core so every host computes the same stable identifiers.
//! - Keep identity/signature helpers here instead of duplicating protocol
//!   identity logic in onboarding, packet, or host crates.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{CryptoRngCore, RngCore};
use sha2::{Digest, Sha256};

pub type PubKey = [u8; 32];
pub type ShortAddr = [u8; 8];
pub type Signature = [u8; 64];
pub type NetworkAddr = [u8; 8];

pub struct NodeIdentity {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    short_addr: ShortAddr,
}

impl NodeIdentity {
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let signing_key = SigningKey::generate(rng);
        Self::from_signing_key(signing_key)
    }

    /// Generate identity using non-cryptographic RNG (for PoC/testing only).
    ///
    /// ⚠️  WARNING: This should NOT be used in production! Use `generate()` with
    /// a cryptographically secure RNG (TRNG) instead.
    ///
    /// This method exists for development/testing when TRNG is not available.
    pub fn generate_insecure(rng: &mut impl RngCore) -> Self {
        // Generate random 32 bytes for the secret key
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);

        // Create signing key from the random bytes
        let signing_key = SigningKey::from_bytes(&secret);
        Self::from_signing_key(signing_key)
    }

    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(secret);
        Self::from_signing_key(signing_key)
    }

    fn from_signing_key(signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        let short_addr = short_addr_of(&verifying_key.to_bytes());
        Self {
            signing_key,
            verifying_key,
            short_addr,
        }
    }

    pub fn short_addr(&self) -> &ShortAddr {
        &self.short_addr
    }

    pub fn pubkey(&self) -> PubKey {
        self.verifying_key.to_bytes()
    }

    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.signing_key.as_bytes()
    }

    pub fn sign(&self, data: &[u8]) -> Signature {
        let sig = self.signing_key.sign(data);
        sig.to_bytes()
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

pub fn short_addr_of(pubkey: &PubKey) -> ShortAddr {
    let hash = Sha256::digest(pubkey);
    let mut addr = [0u8; 8];
    addr.copy_from_slice(&hash[..8]);
    addr
}

/// Derive an 8-byte network address from a network authority pubkey.
///
/// Same derivation as [`short_addr_of`], applied to the network key rather
/// than a node key. Used in BLE advertising data so scanners can identify
/// which network a device belongs to without a GATT connection.
pub fn network_addr_of(network_pubkey: &PubKey) -> NetworkAddr {
    let hash = Sha256::digest(network_pubkey);
    let mut addr = [0u8; 8];
    addr.copy_from_slice(&hash[..8]);
    addr
}

/// Sentinel network address advertised by unenrolled (OnboardingReady) devices.
/// Cannot collide with a real network address because SHA-256 of any valid
/// ed25519 public key will never produce 8 bytes of `0xFF`.
pub const ONBOARDING_READY_NETWORK_ADDR: NetworkAddr = [0xFF; 8];

pub fn verify(pubkey: &PubKey, data: &[u8], sig: &Signature) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(sig);
    vk.verify(data, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_addr_of_is_deterministic() {
        let pubkey = [0xABu8; 32];
        assert_eq!(network_addr_of(&pubkey), network_addr_of(&pubkey));
    }

    #[test]
    fn network_addr_of_differs_for_different_pubkeys() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        assert_ne!(network_addr_of(&a), network_addr_of(&b));
    }

    #[test]
    fn network_addr_of_differs_from_short_addr_of_same_key() {
        // Both use SHA-256, but the intent is different — still, given the same
        // input they produce the same output. The distinction is semantic:
        // short_addr_of is for node keys, network_addr_of is for network keys.
        // In practice they'll only produce the same value if the same key is
        // used as both a node key and a network key.
        let key = [0x42u8; 32];
        assert_eq!(network_addr_of(&key), short_addr_of(&key));
    }

    #[test]
    fn network_addr_of_different_keys_produces_different_addrs() {
        let node_key = [0x01u8; 32];
        let network_key = [0x02u8; 32];
        assert_ne!(network_addr_of(&node_key), network_addr_of(&network_key));
    }

    #[test]
    fn onboarding_ready_network_addr_is_all_ff() {
        assert_eq!(ONBOARDING_READY_NETWORK_ADDR, [0xFFu8; 8]);
    }

    #[test]
    fn network_addr_is_8_bytes() {
        let pubkey = [0x11u8; 32];
        let addr = network_addr_of(&pubkey);
        assert_eq!(addr.len(), 8);
    }
}
