//! Shared onboarding markers and certificate primitives.
//!
//! These types are transport-neutral and can be used by firmware, host tools,
//! and future simulator/onboarding harnesses.

use crate::crypto::identity::{
    network_addr_of, short_addr_of, verify, NetworkAddr, NodeIdentity, PubKey, ShortAddr, Signature,
};

/// Sentinel network address advertised by unenrolled (OnboardingReady) devices.
pub use crate::crypto::identity::ONBOARDING_READY_NETWORK_ADDR;

/// Stable byte signature used by onboarding-capable Constellation devices.
pub const CONSTELLATION_PROTOCOL_SIGNATURE: &[u8] = b"constellation:protocol:v1";
/// Marker exposed by unenrolled devices that are ready to be onboarded.
pub const ONBOARDING_READY_MARKER: &[u8] = b"constellation:onboarding-ready:v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkMarker<'a> {
    OnboardingReady,
    NetworkPubkey(&'a PubKey),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeCertificate {
    pub pubkey: PubKey,
    pub capabilities: u16,
    pub network_signature: Signature,
}

impl NodeCertificate {
    /// Bytes covered by the network authority signature.
    pub fn signable_bytes(&self) -> [u8; 34] {
        let mut out = [0u8; 34];
        out[..32].copy_from_slice(&self.pubkey);
        out[32..34].copy_from_slice(&self.capabilities.to_le_bytes());
        out
    }

    pub fn short_addr(&self) -> ShortAddr {
        short_addr_of(&self.pubkey)
    }

    pub fn verify_against_network(&self, network_pubkey: &PubKey) -> bool {
        verify(
            network_pubkey,
            &self.signable_bytes(),
            &self.network_signature,
        )
    }

    pub fn issue(network_authority: &NodeIdentity, node_pubkey: PubKey, capabilities: u16) -> Self {
        let mut cert = Self {
            pubkey: node_pubkey,
            capabilities,
            network_signature: [0u8; 64],
        };
        cert.network_signature = network_authority.sign(&cert.signable_bytes());
        cert
    }

    /// Wire format: `[authority_pubkey: 32][cert_capabilities: 2][cert_signature: 64]`.
    pub const CERT_DATA_SIZE: usize = 32 + 2 + 64;

    /// Serialize the certificate into a fixed-size byte array.
    ///
    /// Layout: `[authority_pubkey: 32][capabilities: 2][signature: 64]`.
    /// The authority pubkey is the network key that signed this certificate.
    pub fn to_cert_bytes(&self, authority_pubkey: &PubKey) -> [u8; Self::CERT_DATA_SIZE] {
        let mut out = [0u8; Self::CERT_DATA_SIZE];
        out[..32].copy_from_slice(authority_pubkey);
        out[32..34].copy_from_slice(&self.capabilities.to_le_bytes());
        out[34..].copy_from_slice(&self.network_signature);
        out
    }

    /// Parse a certificate from its wire format.
    ///
    /// Returns `Some((NodeCertificate, authority_pubkey))` on success.
    pub fn from_cert_bytes(bytes: &[u8]) -> Option<(Self, PubKey)> {
        if bytes.len() != Self::CERT_DATA_SIZE {
            return None;
        }
        let authority_pubkey: PubKey = bytes[..32].try_into().ok()?;
        let capabilities = u16::from_le_bytes([bytes[32], bytes[33]]);
        let mut network_signature = [0u8; 64];
        network_signature.copy_from_slice(&bytes[34..]);
        Some((
            Self {
                pubkey: [0u8; 32], // not available in cert bytes
                capabilities,
                network_signature,
            },
            authority_pubkey,
        ))
    }
}

/// Derive the network address from a network marker.
///
/// Returns `ONBOARDING_READY_NETWORK_ADDR` for `OnboardingReady` devices,
/// or `network_addr_of(pubkey)` for enrolled devices.
pub fn network_addr_of_marker(marker: &NetworkMarker<'_>) -> NetworkAddr {
    match marker {
        NetworkMarker::OnboardingReady => ONBOARDING_READY_NETWORK_ADDR,
        NetworkMarker::NetworkPubkey(pubkey) => network_addr_of(pubkey),
    }
}

pub fn is_constellation_protocol_signature(bytes: &[u8]) -> bool {
    bytes == CONSTELLATION_PROTOCOL_SIGNATURE
}

pub fn parse_network_marker(bytes: &[u8]) -> Option<NetworkMarker<'_>> {
    if bytes == ONBOARDING_READY_MARKER {
        return Some(NetworkMarker::OnboardingReady);
    }
    if bytes.len() == 32 {
        let pubkey: &PubKey = bytes.try_into().ok()?;
        return Some(NetworkMarker::NetworkPubkey(pubkey));
    }
    None
}

// ── Discovery advertising payload ────────────────────────────────────────────

/// Constellation's BLE manufacturer-specific company identifier.
///
/// Used in the AD type 0xFF structure so scanners can identify
/// Constellation devices before establishing a GATT connection.
pub const CONSTELLATION_COMPANY_ID: u16 = 0x1234;

/// Size of the Constellation manufacturer payload within the AD structure.
///
/// Layout: `[short_addr: 8][capabilities: 2][network_addr: 8]`.
pub const DISCOVERY_PAYLOAD_SIZE: usize = 18;

/// Parsed discovery information from a Constellation BLE advertisement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoveryInfo {
    pub short_addr: ShortAddr,
    pub capabilities: u16,
    pub network_addr: NetworkAddr,
}

/// Serialize a discovery payload into a byte buffer.
///
/// The caller is responsible for wrapping this in an AD structure with
/// `company_identifier = CONSTELLATION_COMPANY_ID`.
pub fn serialize_discovery(
    short_addr: &ShortAddr,
    capabilities: u16,
    network_addr: &NetworkAddr,
    buf: &mut [u8],
) -> Option<usize> {
    if buf.len() < DISCOVERY_PAYLOAD_SIZE {
        return None;
    }
    buf[0..8].copy_from_slice(short_addr);
    buf[8..10].copy_from_slice(&capabilities.to_le_bytes());
    buf[10..18].copy_from_slice(network_addr);
    Some(DISCOVERY_PAYLOAD_SIZE)
}

/// Deserialize a discovery payload from manufacturer data bytes.
///
/// `data` should be the payload *after* the company identifier has been
/// stripped by the caller, or the full 20-byte manufacturer data
/// (including 2-byte CID) if `skip_cid` is true.
pub fn deserialize_discovery(data: &[u8]) -> Option<DiscoveryInfo> {
    if data.len() < DISCOVERY_PAYLOAD_SIZE {
        return None;
    }
    let mut short_addr = [0u8; 8];
    short_addr.copy_from_slice(&data[0..8]);
    let capabilities = u16::from_le_bytes([data[8], data[9]]);
    let mut network_addr = [0u8; 8];
    network_addr.copy_from_slice(&data[10..18]);
    Some(DiscoveryInfo {
        short_addr,
        capabilities,
        network_addr,
    })
}

/// Parse discovery information from a raw BLE advertising data buffer.
///
/// Walks AD structures looking for a ManufacturerSpecificData entry with
/// `CONSTELLATION_COMPANY_ID`, then extracts the discovery payload.
pub fn parse_discovery_from_adv(data: &[u8]) -> Option<DiscoveryInfo> {
    let mut i = 0;
    while i + 1 < data.len() {
        let len = data[i] as usize;
        if len == 0 || i + 1 + len > data.len() {
            break;
        }
        let ad_type = data[i + 1];
        if ad_type == 0xFF && len >= 3 {
            let company_id = u16::from_le_bytes([data[i + 2], data[i + 3]]);
            if company_id == CONSTELLATION_COMPANY_ID {
                let payload_start = i + 4;
                let payload_end = i + 1 + len;
                if payload_start < payload_end {
                    return deserialize_discovery(&data[payload_start..payload_end]);
                }
            }
        }
        i += 1 + len;
    }
    None
}

/// Parse discovery information from manufacturer data including the CID prefix.
///
/// Input format: `[company_id: 2 LE][short_addr: 8][capabilities: 2 LE][network_addr: 8]`.
/// Returns `None` if the company ID doesn't match or the payload is too short.
pub fn parse_discovery_from_manufacturer_data(data: &[u8]) -> Option<DiscoveryInfo> {
    if data.len() < 20 {
        return None;
    }
    let company_id = u16::from_le_bytes([data[0], data[1]]);
    if company_id != CONSTELLATION_COMPANY_ID {
        return None;
    }
    deserialize_discovery(&data[2..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_addr_of_marker_returns_sentinel_for_onboarding_ready() {
        let marker = NetworkMarker::OnboardingReady;
        assert_eq!(network_addr_of_marker(&marker), ONBOARDING_READY_NETWORK_ADDR);
    }

    #[test]
    fn network_addr_of_marker_returns_addr_for_network_pubkey() {
        let pubkey = [0x99u8; 32];
        let marker = NetworkMarker::NetworkPubkey(&pubkey);
        assert_eq!(network_addr_of_marker(&marker), network_addr_of(&pubkey));
    }

    #[test]
    fn cert_bytes_roundtrip() {
        let authority = NodeIdentity::from_bytes(&[0xAAu8; 32]);
        let node_pubkey = [0xBBu8; 32];
        let cert = NodeCertificate::issue(&authority, node_pubkey, 0x1234);

        let bytes = cert.to_cert_bytes(&authority.pubkey());
        let (parsed, parsed_authority) = NodeCertificate::from_cert_bytes(&bytes).unwrap();

        assert_eq!(parsed_authority, authority.pubkey());
        assert_eq!(parsed.capabilities, cert.capabilities);
        assert_eq!(parsed.network_signature, cert.network_signature);
        // pubkey is not stored in cert bytes (it's read from a separate GATT characteristic)
        assert_eq!(parsed.pubkey, [0u8; 32]);
    }

    #[test]
    fn cert_bytes_roundtrip_preserves_verify() {
        let authority = NodeIdentity::from_bytes(&[0xCCu8; 32]);
        let node_pubkey = [0xDDu8; 32];
        let cert = NodeCertificate::issue(&authority, node_pubkey, 0x5678);

        let bytes = cert.to_cert_bytes(&authority.pubkey());
        let (parsed, parsed_authority) = NodeCertificate::from_cert_bytes(&bytes).unwrap();

        // Reconstruct a full certificate for verification
        let full_cert = NodeCertificate {
            pubkey: node_pubkey,
            capabilities: parsed.capabilities,
            network_signature: parsed.network_signature,
        };
        assert!(full_cert.verify_against_network(&parsed_authority));
    }

    #[test]
    fn cert_bytes_rejects_wrong_length() {
        assert!(NodeCertificate::from_cert_bytes(&[]).is_none());
        assert!(NodeCertificate::from_cert_bytes(&[0u8; 10]).is_none());
        assert!(NodeCertificate::from_cert_bytes(&[0u8; 97]).is_none());
        assert!(NodeCertificate::from_cert_bytes(&[0u8; 99]).is_none());
        assert!(NodeCertificate::from_cert_bytes(&[0u8; 100]).is_none());
    }

    #[test]
    fn cert_bytes_layout() {
        let authority = NodeIdentity::from_bytes(&[0x11u8; 32]);
        let cert = NodeCertificate::issue(&authority, [0x22u8; 32], 0xABCD);
        let bytes = cert.to_cert_bytes(&authority.pubkey());

        // First 32 bytes = authority pubkey
        assert_eq!(&bytes[..32], &authority.pubkey());
        // Next 2 bytes = capabilities LE
        assert_eq!(&bytes[32..34], &[0xCD, 0xAB]);
        // Last 64 bytes = signature
        assert_eq!(&bytes[34..], &cert.network_signature);
    }

    #[test]
    fn cert_data_size_constant() {
        assert_eq!(NodeCertificate::CERT_DATA_SIZE, 98);
        assert_eq!(NodeCertificate::CERT_DATA_SIZE, 32 + 2 + 64);
    }

    // ── Discovery advertising tests ──────────────────────────────────────

    #[test]
    fn serialize_discovery_roundtrip() {
        let short_addr = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let network_addr = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11];
        let mut buf = [0u8; DISCOVERY_PAYLOAD_SIZE];
        let written = serialize_discovery(&short_addr, 0x1234, &network_addr, &mut buf).unwrap();
        assert_eq!(written, DISCOVERY_PAYLOAD_SIZE);

        let info = deserialize_discovery(&buf).unwrap();
        assert_eq!(info.short_addr, short_addr);
        assert_eq!(info.capabilities, 0x1234);
        assert_eq!(info.network_addr, network_addr);
    }

    #[test]
    fn serialize_discovery_onboarding_ready_network_addr() {
        let short_addr = [0x11u8; 8];
        let mut buf = [0u8; DISCOVERY_PAYLOAD_SIZE];
        serialize_discovery(&short_addr, 0, &ONBOARDING_READY_NETWORK_ADDR, &mut buf).unwrap();

        let info = deserialize_discovery(&buf).unwrap();
        assert_eq!(info.network_addr, ONBOARDING_READY_NETWORK_ADDR);
        assert_eq!(info.network_addr, [0xFFu8; 8]);
    }

    #[test]
    fn serialize_discovery_rejects_short_buffer() {
        let short_addr = [0u8; 8];
        let network_addr = [0u8; 8];
        let mut buf = [0u8; 10]; // too small
        assert!(serialize_discovery(&short_addr, 0, &network_addr, &mut buf).is_none());
    }

    #[test]
    fn deserialize_discovery_rejects_short_payload() {
        assert!(deserialize_discovery(&[0u8; 17]).is_none());
        assert!(deserialize_discovery(&[0u8; 10]).is_none());
        assert!(deserialize_discovery(&[]).is_none());
    }

    #[test]
    fn parse_discovery_from_adv_extracts_constellation() {
        let short_addr = [0x42u8; 8];
        let capabilities = 0x5678;
        let network_addr = [0xABu8; 8];

        // Build manufacturer payload: [CID LE][short_addr][caps LE][network_addr]
        let mut mfr_payload = [0u8; DISCOVERY_PAYLOAD_SIZE];
        serialize_discovery(&short_addr, capabilities, &network_addr, &mut mfr_payload).unwrap();

        // Build ADV data: Flags + ManufacturerSpecificData
        let mut adv = [0u8; 31];
        // Flags: len=2, type=0x01, flags=0x06
        adv[0] = 0x02; // length: 2 bytes follow
        adv[1] = 0x01; // AD type: Flags
        adv[2] = 0x06; // LE General Discoverable + BR/EDR Not Supported
        // ManufacturerSpecificData: len=1(type)+2(CID)+payload
        let mfr_ad_len = 1 + 2 + DISCOVERY_PAYLOAD_SIZE; // type + CID + payload
        adv[3] = mfr_ad_len as u8; // 21
        adv[4] = 0xFF; // AD type: ManufacturerSpecificData
        adv[5] = (CONSTELLATION_COMPANY_ID & 0xFF) as u8;
        adv[6] = ((CONSTELLATION_COMPANY_ID >> 8) & 0xFF) as u8;
        adv[7..7 + DISCOVERY_PAYLOAD_SIZE].copy_from_slice(&mfr_payload);

        let adv_end = 7 + DISCOVERY_PAYLOAD_SIZE;
        let info = parse_discovery_from_adv(&adv[..adv_end]).unwrap();
        assert_eq!(info.short_addr, short_addr);
        assert_eq!(info.capabilities, capabilities);
        assert_eq!(info.network_addr, network_addr);
    }

    #[test]
    fn parse_discovery_from_adv_ignores_wrong_company_id() {
        let short_addr = [0x42u8; 8];
        let mut mfr_payload = [0u8; DISCOVERY_PAYLOAD_SIZE];
        serialize_discovery(&short_addr, 0, &ONBOARDING_READY_NETWORK_ADDR, &mut mfr_payload).unwrap();

        let mut adv = [0u8; 31];
        adv[0] = 0x02;
        adv[1] = 0x01;
        adv[2] = 0x06;
        let mfr_len = 1 + 1 + 2 + DISCOVERY_PAYLOAD_SIZE;
        adv[3] = mfr_len as u8;
        adv[4] = 0xFF;
        adv[5] = 0xFF; // wrong CID
        adv[6] = 0xFF;
        adv[7..7 + DISCOVERY_PAYLOAD_SIZE].copy_from_slice(&mfr_payload);

        assert!(parse_discovery_from_adv(&adv[..7 + DISCOVERY_PAYLOAD_SIZE]).is_none());
    }

    #[test]
    fn parse_discovery_from_adv_handles_truncated_mfr_payload() {
        let mut adv = [0u8; 10];
        adv[0] = 0x02;
        adv[1] = 0x01;
        adv[2] = 0x06;
        // Manufacturer data with only CID, no payload
        adv[3] = 0x03; // len
        adv[4] = 0xFF; // type
        adv[5] = 0x34; // CID low
        adv[6] = 0x12; // CID high

        assert!(parse_discovery_from_adv(&adv[..7]).is_none());
    }

    #[test]
    fn parse_discovery_from_adv_handles_no_manufacturer_data() {
        let mut adv = [0u8; 10];
        adv[0] = 0x02;
        adv[1] = 0x01;
        adv[2] = 0x06;
        // No manufacturer data at all

        assert!(parse_discovery_from_adv(&adv[..3]).is_none());
    }

    #[test]
    fn parse_discovery_from_manufacturer_data_valid() {
        let short_addr = [0x42u8; 8];
        let capabilities = 0x1234;
        let network_addr = [0xABu8; 8];

        // Build full manufacturer data: [CID LE][payload]
        let mut data = [0u8; 20];
        data[0] = (CONSTELLATION_COMPANY_ID & 0xFF) as u8;
        data[1] = ((CONSTELLATION_COMPANY_ID >> 8) & 0xFF) as u8;
        let mut payload = [0u8; DISCOVERY_PAYLOAD_SIZE];
        serialize_discovery(&short_addr, capabilities, &network_addr, &mut payload).unwrap();
        data[2..].copy_from_slice(&payload);

        let info = parse_discovery_from_manufacturer_data(&data).unwrap();
        assert_eq!(info.short_addr, short_addr);
        assert_eq!(info.capabilities, capabilities);
        assert_eq!(info.network_addr, network_addr);
    }

    #[test]
    fn parse_discovery_from_manufacturer_data_wrong_cid() {
        let mut data = [0u8; 20];
        data[0] = 0xFF; // wrong CID
        data[1] = 0xFF;

        assert!(parse_discovery_from_manufacturer_data(&data).is_none());
    }

    #[test]
    fn parse_discovery_from_manufacturer_data_too_short() {
        assert!(parse_discovery_from_manufacturer_data(&[]).is_none());
        assert!(parse_discovery_from_manufacturer_data(&[0u8; 10]).is_none());
        assert!(parse_discovery_from_manufacturer_data(&[0u8; 19]).is_none());
    }

    #[test]
    fn parse_discovery_from_manufacturer_data_onboarding_ready() {
        let short_addr = [0x11u8; 8];
        let mut data = [0u8; 20];
        data[0] = (CONSTELLATION_COMPANY_ID & 0xFF) as u8;
        data[1] = ((CONSTELLATION_COMPANY_ID >> 8) & 0xFF) as u8;
        let mut payload = [0u8; DISCOVERY_PAYLOAD_SIZE];
        serialize_discovery(&short_addr, 0, &ONBOARDING_READY_NETWORK_ADDR, &mut payload).unwrap();
        data[2..].copy_from_slice(&payload);

        let info = parse_discovery_from_manufacturer_data(&data).unwrap();
        assert_eq!(info.network_addr, ONBOARDING_READY_NETWORK_ADDR);
        assert_eq!(info.network_addr, [0xFFu8; 8]);
    }
}
