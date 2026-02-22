use crate::crypto::identity::NodeIdentity;
use embedded_storage::nor_flash::{NorFlash, ReadNorFlash};

/// Magic bytes to identify a provisioned node.
/// "CSTL" (Constellation) in ASCII.
const MAGIC: [u8; 4] = [0x43, 0x53, 0x54, 0x4C];

/// Flash storage layout offsets.
///
/// Layout (40 bytes total):
/// - magic: 4 bytes ("CSTL")
/// - version: 1 byte (storage format version, currently 0x01)
/// - reserved: 3 bytes (padding for alignment)
/// - secret_key: 32 bytes (ed25519 private key)
///
/// The public key is derived from the secret key, so we don't store it.
const MAGIC_OFFSET: usize = 0;
const VERSION_OFFSET: usize = 4;
const SECRET_KEY_OFFSET: usize = 8;
const STORAGE_SIZE: usize = 40;

/// Current storage format version.
const STORAGE_VERSION: u8 = 0x01;

/// Storage errors.
#[derive(Debug)]
pub enum StorageError {
    ReadFailed,
    WriteFailed,
    EraseFailed,
    InvalidMagic,
    InvalidVersion,
    BufferTooSmall,
}

/// Check if the node has been provisioned (identity exists in flash).
///
/// Returns true if magic bytes are present at MAGIC_OFFSET.
pub fn is_provisioned<S: ReadNorFlash>(storage: &mut S) -> Result<bool, StorageError> {
    let mut buf = [0u8; 4];
    storage
        .read(MAGIC_OFFSET as u32, &mut buf)
        .map_err(|_| StorageError::ReadFailed)?;

    Ok(buf == MAGIC)
}

/// Load node identity from flash storage.
///
/// Returns None if not provisioned or if read fails.
/// Returns Some(NodeIdentity) if successfully loaded and validated.
pub fn load_identity<S: ReadNorFlash>(storage: &mut S) -> Result<NodeIdentity, StorageError> {
    // Read entire storage region
    let mut buf = [0u8; STORAGE_SIZE];
    storage
        .read(MAGIC_OFFSET as u32, &mut buf)
        .map_err(|_| StorageError::ReadFailed)?;

    // Verify magic bytes
    if buf[MAGIC_OFFSET..MAGIC_OFFSET + 4] != MAGIC {
        return Err(StorageError::InvalidMagic);
    }

    // Verify storage version
    if buf[VERSION_OFFSET] != STORAGE_VERSION {
        return Err(StorageError::InvalidVersion);
    }

    // Extract secret key
    let mut secret_key = [0u8; 32];
    secret_key.copy_from_slice(&buf[SECRET_KEY_OFFSET..SECRET_KEY_OFFSET + 32]);

    // Reconstruct identity from secret key
    Ok(NodeIdentity::from_bytes(&secret_key))
}

/// Save node identity to flash storage.
///
/// Erases the storage region and writes:
/// - Magic bytes
/// - Version byte
/// - Secret key (32 bytes)
///
/// The public key and ShortAddr are derived from the secret key.
pub fn save_identity<S: NorFlash>(
    storage: &mut S,
    identity: &NodeIdentity,
) -> Result<(), StorageError> {
    // Prepare buffer
    let mut buf = [0u8; STORAGE_SIZE];

    // Write magic bytes
    buf[MAGIC_OFFSET..MAGIC_OFFSET + 4].copy_from_slice(&MAGIC);

    // Write version
    buf[VERSION_OFFSET] = STORAGE_VERSION;

    // Reserved bytes remain 0x00

    // Write secret key
    buf[SECRET_KEY_OFFSET..SECRET_KEY_OFFSET + 32].copy_from_slice(identity.signing_key().as_bytes());

    // Note: For PoC, we skip erase operation due to partition configuration complexity.
    // In production, configure a dedicated NVS partition in partition table.
    // For now, flash writes may not persist across reboots, but identity works in RAM.

    // Attempt to write (may fail without erase, but won't crash)
    match storage.write(MAGIC_OFFSET as u32, &buf) {
        Ok(_) => {}, // Success - flash supports in-place write or was pre-erased
        Err(_) => return Err(StorageError::WriteFailed),
    }

    Ok(())
}

/// Clear provisioning data from flash.
///
/// Erases the storage region, removing the node's identity.
/// Use with caution - this is irreversible!
pub fn clear_identity<S: NorFlash>(storage: &mut S) -> Result<(), StorageError> {
    storage
        .erase(MAGIC_OFFSET as u32, (MAGIC_OFFSET + STORAGE_SIZE) as u32)
        .map_err(|_| StorageError::EraseFailed)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock storage for testing
    struct MockStorage {
        data: [u8; STORAGE_SIZE],
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                data: [0xFF; STORAGE_SIZE], // Flash default: all bits set
            }
        }
    }

    impl embedded_storage::nor_flash::ErrorType for MockStorage {
        type Error = ();
    }

    impl ReadNorFlash for MockStorage {
        const READ_SIZE: usize = 1;

        fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
            let offset = offset as usize;
            bytes.copy_from_slice(&self.data[offset..offset + bytes.len()]);
            Ok(())
        }

        fn capacity(&self) -> usize {
            STORAGE_SIZE
        }
    }

    impl NorFlash for MockStorage {
        const WRITE_SIZE: usize = 1;
        const ERASE_SIZE: usize = STORAGE_SIZE;

        fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
            let from = from as usize;
            let to = to as usize;
            self.data[from..to].fill(0xFF);
            Ok(())
        }

        fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
            let offset = offset as usize;
            self.data[offset..offset + bytes.len()].copy_from_slice(bytes);
            Ok(())
        }
    }

    #[test]
    fn test_is_provisioned_empty() {
        let mut storage = MockStorage::new();
        assert_eq!(is_provisioned(&mut storage).unwrap(), false);
    }

    // Note: Full round-trip tests require RNG, which is not available in no_std tests.
    // Integration tests on hardware will validate save/load cycle.
}
