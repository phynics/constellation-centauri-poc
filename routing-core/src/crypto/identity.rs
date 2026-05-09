//! Node identity primitives: signing keys, short addresses, and signatures.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{CryptoRngCore, RngCore};
use sha2::{Digest, Sha256};

pub type PubKey = [u8; 32];
pub type ShortAddr = [u8; 8];
pub type Signature = [u8; 64];

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

pub fn verify(pubkey: &PubKey, data: &[u8], sig: &Signature) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(sig);
    vk.verify(data, &signature).is_ok()
}
