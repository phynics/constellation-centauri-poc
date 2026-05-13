//! Shared onboarding markers and certificate primitives.
//!
//! These types are transport-neutral and can be used by firmware, host tools,
//! and future simulator/onboarding harnesses.

use crate::crypto::identity::{short_addr_of, verify, NodeIdentity, PubKey, ShortAddr, Signature};

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
        verify(network_pubkey, &self.signable_bytes(), &self.network_signature)
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
