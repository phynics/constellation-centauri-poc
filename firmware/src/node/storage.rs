//! Flash-backed persistence for firmware node identities.

use embedded_storage::nor_flash::{NorFlash, ReadNorFlash};
use routing_core::crypto::identity::{NodeIdentity, PubKey, Signature};
use routing_core::onboarding::NodeCertificate;

/// Magic bytes to identify a provisioned node.
/// "CSTL" (Constellation) in ASCII.
const MAGIC: [u8; 4] = [0x43, 0x53, 0x54, 0x4C];

/// Flash storage layout offsets.
///
/// Layout:
/// - magic: 4 bytes ("CSTL")
/// - version: 1 byte (storage format version)
/// - flags: 1 byte
/// - reserved: 2 bytes (padding for alignment)
/// - secret_key: 32 bytes (ed25519 private key)
/// - committed_membership: 98 bytes
/// - staged_membership: 98 bytes
///
/// The public key is derived from the secret key, so we don't store it.
const MAGIC_OFFSET: usize = 0;
const VERSION_OFFSET: usize = 4;
const FLAGS_OFFSET: usize = 5;
const SECRET_KEY_OFFSET: usize = 8;

const MEMBERSHIP_PUBKEY_SIZE: usize = 32;
const MEMBERSHIP_CAPABILITIES_SIZE: usize = 2;
const MEMBERSHIP_SIGNATURE_SIZE: usize = 64;
const MEMBERSHIP_SIZE: usize =
    MEMBERSHIP_PUBKEY_SIZE + MEMBERSHIP_CAPABILITIES_SIZE + MEMBERSHIP_SIGNATURE_SIZE;

const COMMITTED_MEMBERSHIP_OFFSET: usize = 40;
const STAGED_MEMBERSHIP_OFFSET: usize = COMMITTED_MEMBERSHIP_OFFSET + MEMBERSHIP_SIZE;
const STORAGE_SIZE: usize = STAGED_MEMBERSHIP_OFFSET + MEMBERSHIP_SIZE;

/// Current storage format version.
const STORAGE_VERSION_V1: u8 = 0x01;
const STORAGE_VERSION: u8 = 0x02;
const STORAGE_VERSION_V3: u8 = 0x03;

const FLAG_COMMITTED_PRESENT: u8 = 1 << 0;
const FLAG_STAGED_AUTHORITY_PRESENT: u8 = 1 << 1;
const FLAG_STAGED_CAPABILITIES_PRESENT: u8 = 1 << 2;
const FLAG_STAGED_SIGNATURE_PRESENT: u8 = 1 << 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredMembership {
    pub network_pubkey: PubKey,
    pub cert_capabilities: u16,
    pub cert_signature: Signature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct StagedEnrollment {
    pub authority_pubkey: Option<PubKey>,
    pub cert_capabilities: Option<u16>,
    pub cert_signature: Option<Signature>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ProvisioningState {
    pub committed: Option<StoredMembership>,
    pub staged: StagedEnrollment,
}

impl StoredMembership {
    pub fn certificate_for(&self, identity: &NodeIdentity) -> NodeCertificate {
        NodeCertificate {
            pubkey: identity.pubkey(),
            capabilities: self.cert_capabilities,
            network_signature: self.cert_signature,
        }
    }

    pub fn verifies_for(&self, identity: &NodeIdentity) -> bool {
        self.certificate_for(identity)
            .verify_against_network(&self.network_pubkey)
    }
}

impl StagedEnrollment {
    pub fn is_complete(&self) -> bool {
        self.authority_pubkey.is_some()
            && self.cert_capabilities.is_some()
            && self.cert_signature.is_some()
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }

    pub fn into_membership(self) -> Option<StoredMembership> {
        Some(StoredMembership {
            network_pubkey: self.authority_pubkey?,
            cert_capabilities: self.cert_capabilities?,
            cert_signature: self.cert_signature?,
        })
    }
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollmentError {
    AlreadyEnrolled,
    IncompleteStagedEnrollment,
    InvalidCertificate,
}

pub fn effective_capabilities(
    identity: &NodeIdentity,
    provisioning: &mut ProvisioningState,
    default_capabilities: u16,
) -> u16 {
    if let Some(committed) = provisioning.committed {
        if committed.verifies_for(identity) {
            committed.cert_capabilities
        } else {
            provisioning.committed = None;
            default_capabilities
        }
    } else {
        default_capabilities
    }
}

pub fn commit_staged_enrollment(
    identity: &NodeIdentity,
    provisioning: &mut ProvisioningState,
) -> Result<StoredMembership, EnrollmentError> {
    if provisioning.committed.is_some() {
        return Err(EnrollmentError::AlreadyEnrolled);
    }

    let committed = provisioning
        .staged
        .into_membership()
        .ok_or(EnrollmentError::IncompleteStagedEnrollment)?;

    if !committed.verifies_for(identity) {
        return Err(EnrollmentError::InvalidCertificate);
    }

    provisioning.committed = Some(committed);
    provisioning.staged.clear();
    Ok(committed)
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
    if buf[VERSION_OFFSET] != STORAGE_VERSION
        && buf[VERSION_OFFSET] != STORAGE_VERSION_V1
        && buf[VERSION_OFFSET] != STORAGE_VERSION_V3
    {
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
pub fn save_identity<S: NorFlash + ReadNorFlash>(
    storage: &mut S,
    identity: &NodeIdentity,
) -> Result<(), StorageError> {
    let provisioning = load_provisioning(storage).unwrap_or_default();
    save_provisioning(storage, identity, &provisioning)
}

pub fn load_onboarding<S: ReadNorFlash>(storage: &mut S) -> Result<Option<StoredMembership>, StorageError> {
    Ok(load_provisioning(storage)?.committed)
}

pub fn load_provisioning<S: ReadNorFlash>(storage: &mut S) -> Result<ProvisioningState, StorageError> {
    let mut magic = [0u8; 4];
    storage
        .read(MAGIC_OFFSET as u32, &mut magic)
        .map_err(|_| StorageError::ReadFailed)?;
    if magic != MAGIC {
        return Err(StorageError::InvalidMagic);
    }

    let mut version = [0u8; 1];
    storage
        .read(VERSION_OFFSET as u32, &mut version)
        .map_err(|_| StorageError::ReadFailed)?;

    if version[0] == STORAGE_VERSION_V1 {
        return Ok(ProvisioningState::default());
    }
    if version[0] == STORAGE_VERSION {
        let mut buf = [0u8; STORAGE_SIZE];
        storage
            .read(MAGIC_OFFSET as u32, &mut buf)
            .map_err(|_| StorageError::ReadFailed)?;

        let membership = read_membership(&buf, COMMITTED_MEMBERSHIP_OFFSET)?;
        return Ok(ProvisioningState {
            committed: membership,
            staged: StagedEnrollment::default(),
        });
    }
    if version[0] != STORAGE_VERSION_V3 {
        return Err(StorageError::InvalidVersion);
    }

    let mut buf = [0u8; STORAGE_SIZE];
    storage
        .read(MAGIC_OFFSET as u32, &mut buf)
        .map_err(|_| StorageError::ReadFailed)?;

    let flags = buf[FLAGS_OFFSET];
    let committed = if flags & FLAG_COMMITTED_PRESENT != 0 {
        read_membership(&buf, COMMITTED_MEMBERSHIP_OFFSET)?
    } else {
        None
    };

    let staged = StagedEnrollment {
        authority_pubkey: if flags & FLAG_STAGED_AUTHORITY_PRESENT != 0 {
            Some(read_pubkey(&buf, STAGED_MEMBERSHIP_OFFSET)?)
        } else {
            None
        },
        cert_capabilities: if flags & FLAG_STAGED_CAPABILITIES_PRESENT != 0 {
            Some(read_capabilities(&buf, STAGED_MEMBERSHIP_OFFSET)?)
        } else {
            None
        },
        cert_signature: if flags & FLAG_STAGED_SIGNATURE_PRESENT != 0 {
            Some(read_signature(&buf, STAGED_MEMBERSHIP_OFFSET)?)
        } else {
            None
        },
    };

    Ok(ProvisioningState { committed, staged })
}

pub fn save_onboarding<S: NorFlash + ReadNorFlash>(
    storage: &mut S,
    identity: &NodeIdentity,
    onboarding: &StoredMembership,
) -> Result<(), StorageError> {
    let mut provisioning = load_provisioning(storage).unwrap_or_default();
    provisioning.committed = Some(*onboarding);
    provisioning.staged.clear();
    save_provisioning(storage, identity, &provisioning)
}

pub fn save_provisioning<S: NorFlash>(
    storage: &mut S,
    identity: &NodeIdentity,
    provisioning: &ProvisioningState,
) -> Result<(), StorageError> {
    let mut buf = [0xFFu8; STORAGE_SIZE];
    buf[MAGIC_OFFSET..MAGIC_OFFSET + 4].copy_from_slice(&MAGIC);
    buf[VERSION_OFFSET] = STORAGE_VERSION_V3;
    buf[SECRET_KEY_OFFSET..SECRET_KEY_OFFSET + 32].copy_from_slice(identity.signing_key().as_bytes());

    let mut flags = 0u8;
    if let Some(committed) = provisioning.committed {
        write_membership(&mut buf, COMMITTED_MEMBERSHIP_OFFSET, &committed);
        flags |= FLAG_COMMITTED_PRESENT;
    }
    if let Some(authority_pubkey) = provisioning.staged.authority_pubkey {
        write_pubkey(&mut buf, STAGED_MEMBERSHIP_OFFSET, &authority_pubkey);
        flags |= FLAG_STAGED_AUTHORITY_PRESENT;
    }
    if let Some(capabilities) = provisioning.staged.cert_capabilities {
        write_capabilities(&mut buf, STAGED_MEMBERSHIP_OFFSET, capabilities);
        flags |= FLAG_STAGED_CAPABILITIES_PRESENT;
    }
    if let Some(signature) = provisioning.staged.cert_signature {
        write_signature(&mut buf, STAGED_MEMBERSHIP_OFFSET, &signature);
        flags |= FLAG_STAGED_SIGNATURE_PRESENT;
    }
    buf[FLAGS_OFFSET] = flags;

    storage
        .write(MAGIC_OFFSET as u32, &buf)
        .map_err(|_| StorageError::WriteFailed)?;
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

fn read_membership(buf: &[u8; STORAGE_SIZE], offset: usize) -> Result<Option<StoredMembership>, StorageError> {
    let pubkey = read_pubkey(buf, offset)?;
    if pubkey.iter().all(|byte| *byte == 0xFF) {
        return Ok(None);
    }
    Ok(Some(StoredMembership {
        network_pubkey: pubkey,
        cert_capabilities: read_capabilities(buf, offset)?,
        cert_signature: read_signature(buf, offset)?,
    }))
}

fn read_pubkey(buf: &[u8; STORAGE_SIZE], offset: usize) -> Result<PubKey, StorageError> {
    let mut pubkey = [0u8; MEMBERSHIP_PUBKEY_SIZE];
    pubkey.copy_from_slice(&buf[offset..offset + MEMBERSHIP_PUBKEY_SIZE]);
    Ok(pubkey)
}

fn read_capabilities(buf: &[u8; STORAGE_SIZE], offset: usize) -> Result<u16, StorageError> {
    let start = offset + MEMBERSHIP_PUBKEY_SIZE;
    Ok(u16::from_le_bytes([buf[start], buf[start + 1]]))
}

fn read_signature(buf: &[u8; STORAGE_SIZE], offset: usize) -> Result<Signature, StorageError> {
    let start = offset + MEMBERSHIP_PUBKEY_SIZE + MEMBERSHIP_CAPABILITIES_SIZE;
    let mut signature = [0u8; MEMBERSHIP_SIGNATURE_SIZE];
    signature.copy_from_slice(&buf[start..start + MEMBERSHIP_SIGNATURE_SIZE]);
    Ok(signature)
}

fn write_membership(buf: &mut [u8; STORAGE_SIZE], offset: usize, membership: &StoredMembership) {
    write_pubkey(buf, offset, &membership.network_pubkey);
    write_capabilities(buf, offset, membership.cert_capabilities);
    write_signature(buf, offset, &membership.cert_signature);
}

fn write_pubkey(buf: &mut [u8; STORAGE_SIZE], offset: usize, pubkey: &PubKey) {
    buf[offset..offset + MEMBERSHIP_PUBKEY_SIZE].copy_from_slice(pubkey);
}

fn write_capabilities(buf: &mut [u8; STORAGE_SIZE], offset: usize, capabilities: u16) {
    let start = offset + MEMBERSHIP_PUBKEY_SIZE;
    buf[start..start + MEMBERSHIP_CAPABILITIES_SIZE].copy_from_slice(&capabilities.to_le_bytes());
}

fn write_signature(buf: &mut [u8; STORAGE_SIZE], offset: usize, signature: &Signature) {
    let start = offset + MEMBERSHIP_PUBKEY_SIZE + MEMBERSHIP_CAPABILITIES_SIZE;
    buf[start..start + MEMBERSHIP_SIGNATURE_SIZE].copy_from_slice(signature);
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

    #[test]
    fn test_provisioning_round_trip_v3() {
        let mut storage = MockStorage::new();
        let identity = NodeIdentity::from_bytes(&[7u8; 32]);
        let provisioning = ProvisioningState {
            committed: Some(StoredMembership {
                network_pubkey: [3u8; 32],
                cert_capabilities: 0x2211,
                cert_signature: [9u8; 64],
            }),
            staged: StagedEnrollment {
                authority_pubkey: Some([4u8; 32]),
                cert_capabilities: Some(0x3344),
                cert_signature: Some([8u8; 64]),
            },
        };

        save_provisioning(&mut storage, &identity, &provisioning).unwrap();
        let loaded = load_provisioning(&mut storage).unwrap();
        assert_eq!(loaded, provisioning);
        assert_eq!(load_identity(&mut storage).unwrap().pubkey(), identity.pubkey());
    }

    #[test]
    fn test_membership_verifies_for_identity() {
        let identity = NodeIdentity::from_bytes(&[1u8; 32]);
        let authority = NodeIdentity::from_bytes(&[2u8; 32]);
        let cert = NodeCertificate::issue(&authority, identity.pubkey(), 0x4455);
        let membership = StoredMembership {
            network_pubkey: authority.pubkey(),
            cert_capabilities: cert.capabilities,
            cert_signature: cert.network_signature,
        };

        assert!(membership.verifies_for(&identity));
    }

    #[test]
    fn test_staged_into_membership_requires_complete_fields() {
        let mut staged = StagedEnrollment::default();
        assert!(!staged.is_complete());
        assert!(staged.into_membership().is_none());

        staged.authority_pubkey = Some([1u8; 32]);
        staged.cert_capabilities = Some(0x1234);
        staged.cert_signature = Some([2u8; 64]);
        assert!(staged.is_complete());
        assert!(staged.into_membership().is_some());
    }

    #[test]
    fn test_commit_staged_rejects_incomplete_enrollment() {
        let identity = NodeIdentity::from_bytes(&[5u8; 32]);
        let mut provisioning = ProvisioningState::default();

        assert_eq!(
            commit_staged_enrollment(&identity, &mut provisioning),
            Err(EnrollmentError::IncompleteStagedEnrollment)
        );
    }

    #[test]
    fn test_commit_staged_rejects_invalid_certificate() {
        let identity = NodeIdentity::from_bytes(&[5u8; 32]);
        let mut provisioning = ProvisioningState {
            committed: None,
            staged: StagedEnrollment {
                authority_pubkey: Some([7u8; 32]),
                cert_capabilities: Some(0x9999),
                cert_signature: Some([8u8; 64]),
            },
        };

        assert_eq!(
            commit_staged_enrollment(&identity, &mut provisioning),
            Err(EnrollmentError::InvalidCertificate)
        );
    }

    #[test]
    fn test_commit_staged_rejects_when_already_enrolled() {
        let identity = NodeIdentity::from_bytes(&[1u8; 32]);
        let authority = NodeIdentity::from_bytes(&[2u8; 32]);
        let cert = NodeCertificate::issue(&authority, identity.pubkey(), 0x1234);
        let membership = StoredMembership {
            network_pubkey: authority.pubkey(),
            cert_capabilities: cert.capabilities,
            cert_signature: cert.network_signature,
        };

        let mut provisioning = ProvisioningState {
            committed: Some(membership),
            staged: StagedEnrollment {
                authority_pubkey: Some([4u8; 32]),
                cert_capabilities: Some(0x5678),
                cert_signature: Some([9u8; 64]),
            },
        };

        assert_eq!(
            commit_staged_enrollment(&identity, &mut provisioning),
            Err(EnrollmentError::AlreadyEnrolled)
        );
    }

    #[test]
    fn test_commit_staged_promotes_valid_membership() {
        let identity = NodeIdentity::from_bytes(&[1u8; 32]);
        let authority = NodeIdentity::from_bytes(&[2u8; 32]);
        let cert = NodeCertificate::issue(&authority, identity.pubkey(), 0x4242);
        let mut provisioning = ProvisioningState {
            committed: None,
            staged: StagedEnrollment {
                authority_pubkey: Some(authority.pubkey()),
                cert_capabilities: Some(cert.capabilities),
                cert_signature: Some(cert.network_signature),
            },
        };

        let committed = commit_staged_enrollment(&identity, &mut provisioning).unwrap();
        assert_eq!(committed.cert_capabilities, 0x4242);
        assert_eq!(provisioning.committed, Some(committed));
        assert_eq!(provisioning.staged, StagedEnrollment::default());
    }

    #[test]
    fn test_effective_capabilities_uses_valid_committed_membership() {
        let identity = NodeIdentity::from_bytes(&[1u8; 32]);
        let authority = NodeIdentity::from_bytes(&[2u8; 32]);
        let cert = NodeCertificate::issue(&authority, identity.pubkey(), 0x7777);
        let mut provisioning = ProvisioningState {
            committed: Some(StoredMembership {
                network_pubkey: authority.pubkey(),
                cert_capabilities: cert.capabilities,
                cert_signature: cert.network_signature,
            }),
            staged: StagedEnrollment::default(),
        };

        assert_eq!(effective_capabilities(&identity, &mut provisioning, 0x1111), 0x7777);
    }

    #[test]
    fn test_effective_capabilities_drops_invalid_committed_membership() {
        let identity = NodeIdentity::from_bytes(&[1u8; 32]);
        let mut provisioning = ProvisioningState {
            committed: Some(StoredMembership {
                network_pubkey: [7u8; 32],
                cert_capabilities: 0x7777,
                cert_signature: [9u8; 64],
            }),
            staged: StagedEnrollment::default(),
        };

        assert_eq!(effective_capabilities(&identity, &mut provisioning, 0x1111), 0x1111);
        assert!(provisioning.committed.is_none());
    }
}
