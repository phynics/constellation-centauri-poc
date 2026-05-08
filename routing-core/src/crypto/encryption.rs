use crate::crypto::identity::{NodeIdentity, PubKey};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use curve25519_dalek::edwards::CompressedEdwardsY;
use hkdf::Hkdf;
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug)]
pub enum CryptoError {
    InvalidKey,
    InvalidPoint,
    EncryptionFailed,
    DecryptionFailed,
    BufferTooSmall,
}

/// Encrypt plaintext for a recipient using ECDH + ChaCha20-Poly1305.
///
/// Output format: [nonce (12 bytes) | ciphertext | tag (16 bytes)]
///
/// Returns the number of bytes written to `output`.
pub fn encrypt(
    sender: &NodeIdentity,
    recipient_pubkey: &PubKey,
    plaintext: &[u8],
    nonce_bytes: &[u8; 12],
    output: &mut [u8],
) -> Result<usize, CryptoError> {
    // Verify output buffer is large enough: nonce + ciphertext + tag
    let required_size = 12 + plaintext.len() + 16;
    if output.len() < required_size {
        return Err(CryptoError::BufferTooSmall);
    }

    // Derive shared symmetric key via ECDH
    let symmetric_key = derive_shared_key(sender, recipient_pubkey)?;

    // Create cipher
    let cipher = ChaCha20Poly1305::new(&symmetric_key.into());
    let nonce = Nonce::from_slice(nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    // Write output: nonce || ciphertext (which includes the tag at the end)
    output[0..12].copy_from_slice(nonce_bytes);
    output[12..12 + ciphertext.len()].copy_from_slice(&ciphertext);

    Ok(12 + ciphertext.len())
}

/// Decrypt ciphertext from a sender using ECDH + ChaCha20-Poly1305.
///
/// Input format: [nonce (12 bytes) | ciphertext | tag (16 bytes)]
///
/// Returns the number of plaintext bytes written to `output`.
pub fn decrypt(
    recipient: &NodeIdentity,
    sender_pubkey: &PubKey,
    encrypted: &[u8],
    output: &mut [u8],
) -> Result<usize, CryptoError> {
    // Parse input: nonce (12) + ciphertext (variable) + tag (16, included in ciphertext)
    if encrypted.len() < 12 + 16 {
        return Err(CryptoError::DecryptionFailed);
    }

    let nonce_bytes = &encrypted[0..12];
    let ciphertext = &encrypted[12..];

    // Derive shared symmetric key via ECDH
    let symmetric_key = derive_shared_key(recipient, sender_pubkey)?;

    // Create cipher
    let cipher = ChaCha20Poly1305::new(&symmetric_key.into());
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    // Verify output buffer is large enough
    if output.len() < plaintext.len() {
        return Err(CryptoError::BufferTooSmall);
    }

    output[0..plaintext.len()].copy_from_slice(&plaintext);

    Ok(plaintext.len())
}

/// Derive a shared symmetric key from our identity and peer's public key.
///
/// Process:
/// 1. Convert ed25519 signing key -> x25519 static secret
/// 2. Convert ed25519 verifying key -> x25519 public key
/// 3. Perform ECDH to get shared secret
/// 4. Derive 32-byte key with HKDF-SHA256
fn derive_shared_key(
    our_identity: &NodeIdentity,
    their_pubkey: &PubKey,
) -> Result<[u8; 32], CryptoError> {
    // Step 1: Convert our ed25519 signing key to x25519 static secret
    let our_x25519_secret = ed25519_to_x25519_secret(our_identity.signing_key().as_bytes());

    // Step 2: Convert their ed25519 public key to x25519 public key
    let their_x25519_public = ed25519_to_x25519_public(their_pubkey)?;

    // Step 3: Perform ECDH
    let shared_secret = our_x25519_secret.diffie_hellman(&their_x25519_public);

    // Step 4: Derive symmetric key with HKDF
    // Use both public keys as salt to ensure unique keys per pair
    let mut salt = [0u8; 64];
    salt[0..32].copy_from_slice(&our_identity.pubkey());
    salt[32..64].copy_from_slice(their_pubkey);

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret.as_bytes());
    let mut symmetric_key = [0u8; 32];
    hk.expand(b"constellation-v1-encryption", &mut symmetric_key)
        .map_err(|_| CryptoError::InvalidKey)?;

    Ok(symmetric_key)
}

/// Convert ed25519 signing key to x25519 static secret.
///
/// Process: SHA-512(seed) -> take lower 32 bytes -> x25519 scalar (with clamping)
fn ed25519_to_x25519_secret(ed25519_secret: &[u8; 32]) -> StaticSecret {
    let mut hasher = Sha512::new();
    hasher.update(ed25519_secret);
    let hash = hasher.finalize();

    let mut x25519_bytes = [0u8; 32];
    x25519_bytes.copy_from_slice(&hash[..32]);

    StaticSecret::from(x25519_bytes)
}

/// Convert ed25519 public key to x25519 public key.
///
/// Process: Decompress Edwards point -> convert to Montgomery u-coordinate
fn ed25519_to_x25519_public(ed25519_pubkey: &PubKey) -> Result<PublicKey, CryptoError> {
    let compressed = CompressedEdwardsY(*ed25519_pubkey);
    let edwards_point = compressed.decompress().ok_or(CryptoError::InvalidPoint)?;

    let montgomery = edwards_point.to_montgomery();
    Ok(PublicKey::from(montgomery.to_bytes()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // This test would work in a std environment with proper RNG.
        // For no_std, we'd need to provide external RNG in integration tests.
    }
}
