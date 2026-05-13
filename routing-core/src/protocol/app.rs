//! Routed application/infrastructure payload families carried by mesh packets.

use crate::crypto::encryption::{self, CryptoError};
use crate::crypto::identity::{NodeIdentity, PubKey, ShortAddr};

use super::packet::PacketError;

pub const INFRA_KIND_PING: u8 = 0x01;
pub const INFRA_KIND_PONG: u8 = 0x02;
pub const INFRA_KIND_TRACEROUTE_PROBE: u8 = 0x03;
pub const INFRA_KIND_TRACEROUTE_REPLY: u8 = 0x04;

pub const APP_KIND_USER_DATA: u8 = 0x05;

pub const APP_CONTENT_TYPE_UTF8: u8 = 0x01;
pub const CRYPTO_SUITE_X25519_CHACHA20POLY1305: u8 = 0x01;

pub const NONCE_LEN: usize = 12;
pub const AUTH_TAG_LEN: usize = 16;
pub const FRAGMENT_HEADER_LEN: usize = 6;

#[derive(Debug)]
pub enum AppError {
    Packet(PacketError),
    Crypto(CryptoError),
    InvalidPayload,
    BufferTooSmall,
}

impl From<PacketError> for AppError {
    fn from(value: PacketError) -> Self {
        Self::Packet(value)
    }
}

impl From<CryptoError> for AppError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InfraKind {
    Ping,
    Pong,
    TracerouteProbe,
    TracerouteReply,
}

impl InfraKind {
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Ping => INFRA_KIND_PING,
            Self::Pong => INFRA_KIND_PONG,
            Self::TracerouteProbe => INFRA_KIND_TRACEROUTE_PROBE,
            Self::TracerouteReply => INFRA_KIND_TRACEROUTE_REPLY,
        }
    }

    pub fn from_byte(value: u8) -> Result<Self, AppError> {
        match value {
            INFRA_KIND_PING => Ok(Self::Ping),
            INFRA_KIND_PONG => Ok(Self::Pong),
            INFRA_KIND_TRACEROUTE_PROBE => Ok(Self::TracerouteProbe),
            INFRA_KIND_TRACEROUTE_REPLY => Ok(Self::TracerouteReply),
            _ => Err(AppError::InvalidPayload),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FragmentInfo {
    pub index: u16,
    pub count: u16,
    pub content_len: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InfraFrame {
    pub kind: InfraKind,
    pub payload: heapless::Vec<u8, 192>,
}

impl InfraFrame {
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, AppError> {
        let needed = 1 + 2 + self.payload.len();
        if buf.len() < needed {
            return Err(AppError::BufferTooSmall);
        }
        buf[0] = self.kind.to_byte();
        buf[1..3].copy_from_slice(&(self.payload.len() as u16).to_le_bytes());
        buf[3..3 + self.payload.len()].copy_from_slice(self.payload.as_slice());
        Ok(needed)
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self, AppError> {
        if buf.len() < 3 {
            return Err(AppError::InvalidPayload);
        }
        let kind = InfraKind::from_byte(buf[0])?;
        let payload_len = u16::from_le_bytes([buf[1], buf[2]]) as usize;
        if buf.len() < 3 + payload_len {
            return Err(AppError::InvalidPayload);
        }
        let mut payload = heapless::Vec::new();
        payload
            .extend_from_slice(&buf[3..3 + payload_len])
            .map_err(|_| AppError::BufferTooSmall)?;
        Ok(Self { kind, payload })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedAppFrame {
    pub content_type: u8,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: heapless::Vec<u8, 224>,
}

impl EncryptedAppFrame {
    pub fn encrypt_user_data(
        sender: &NodeIdentity,
        recipient_pubkey: &PubKey,
        nonce: [u8; NONCE_LEN],
        content_type: u8,
        plaintext: &[u8],
    ) -> Result<Self, AppError> {
        let mut inner = [0u8; 192];
        let inner_len = serialize_user_data_inner(content_type, plaintext, &mut inner)?;
        let mut encrypted = [0u8; 256];
        let written = encryption::encrypt(
            sender,
            recipient_pubkey,
            &inner[..inner_len],
            &nonce,
            &mut encrypted,
        )?;

        let mut ciphertext = heapless::Vec::new();
        ciphertext
            .extend_from_slice(&encrypted[..written])
            .map_err(|_| AppError::BufferTooSmall)?;

        Ok(Self {
            content_type,
            nonce,
            ciphertext,
        })
    }

    pub fn decrypt_user_data(
        &self,
        recipient: &NodeIdentity,
        sender_pubkey: &PubKey,
        output: &mut [u8],
    ) -> Result<(u8, usize), AppError> {
        let mut plaintext = [0u8; 192];
        let written = encryption::decrypt(
            recipient,
            sender_pubkey,
            self.ciphertext.as_slice(),
            &mut plaintext,
        )?;
        parse_user_data_inner(&plaintext[..written], output)
    }

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, AppError> {
        let needed = 1 + 1 + 2 + self.ciphertext.len();
        if buf.len() < needed {
            return Err(AppError::BufferTooSmall);
        }
        buf[0] = CRYPTO_SUITE_X25519_CHACHA20POLY1305;
        buf[1] = self.content_type;
        buf[2..4].copy_from_slice(&(self.ciphertext.len() as u16).to_le_bytes());
        buf[4..4 + self.ciphertext.len()].copy_from_slice(self.ciphertext.as_slice());
        Ok(needed)
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self, AppError> {
        if buf.len() < 4 || buf[0] != CRYPTO_SUITE_X25519_CHACHA20POLY1305 {
            return Err(AppError::InvalidPayload);
        }
        let content_type = buf[1];
        let ct_len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
        if buf.len() < 4 + ct_len || ct_len < NONCE_LEN + AUTH_TAG_LEN {
            return Err(AppError::InvalidPayload);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&buf[4..4 + NONCE_LEN]);
        let mut ciphertext = heapless::Vec::new();
        ciphertext
            .extend_from_slice(&buf[4..4 + ct_len])
            .map_err(|_| AppError::BufferTooSmall)?;
        Ok(Self {
            content_type,
            nonce,
            ciphertext,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PingPayload {
    pub request_id: [u8; 8],
    pub origin_time_ms: u64,
}

impl PingPayload {
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, AppError> {
        if buf.len() < 16 {
            return Err(AppError::BufferTooSmall);
        }
        buf[..8].copy_from_slice(&self.request_id);
        buf[8..16].copy_from_slice(&self.origin_time_ms.to_le_bytes());
        Ok(16)
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self, AppError> {
        if buf.len() < 16 {
            return Err(AppError::InvalidPayload);
        }
        let mut request_id = [0u8; 8];
        request_id.copy_from_slice(&buf[..8]);
        Ok(Self {
            request_id,
            origin_time_ms: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PongPayload {
    pub request_id: [u8; 8],
    pub responder_addr: ShortAddr,
    pub received_ttl: u8,
}

impl PongPayload {
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, AppError> {
        if buf.len() < 17 {
            return Err(AppError::BufferTooSmall);
        }
        buf[..8].copy_from_slice(&self.request_id);
        buf[8..16].copy_from_slice(&self.responder_addr);
        buf[16] = self.received_ttl;
        Ok(17)
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self, AppError> {
        if buf.len() < 17 {
            return Err(AppError::InvalidPayload);
        }
        let mut request_id = [0u8; 8];
        request_id.copy_from_slice(&buf[..8]);
        let mut responder_addr = [0u8; 8];
        responder_addr.copy_from_slice(&buf[8..16]);
        Ok(Self {
            request_id,
            responder_addr,
            received_ttl: buf[16],
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TracerouteProbePayload {
    pub trace_id: [u8; 8],
    pub probe_seq: u8,
    pub reply_to: ShortAddr,
    pub max_hops: u8,
}

impl TracerouteProbePayload {
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, AppError> {
        if buf.len() < 18 {
            return Err(AppError::BufferTooSmall);
        }
        buf[..8].copy_from_slice(&self.trace_id);
        buf[8] = self.probe_seq;
        buf[9..17].copy_from_slice(&self.reply_to);
        buf[17] = self.max_hops;
        Ok(18)
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self, AppError> {
        if buf.len() < 18 {
            return Err(AppError::InvalidPayload);
        }
        let mut trace_id = [0u8; 8];
        trace_id.copy_from_slice(&buf[..8]);
        let mut reply_to = [0u8; 8];
        reply_to.copy_from_slice(&buf[9..17]);
        Ok(Self {
            trace_id,
            probe_seq: buf[8],
            reply_to,
            max_hops: buf[17],
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TracerouteReplyPayload {
    pub trace_id: [u8; 8],
    pub probe_seq: u8,
    pub reporter_addr: ShortAddr,
    pub reporter_caps: u16,
    pub observed_hop_count: u8,
    pub is_destination: bool,
}

impl TracerouteReplyPayload {
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, AppError> {
        if buf.len() < 21 {
            return Err(AppError::BufferTooSmall);
        }
        buf[..8].copy_from_slice(&self.trace_id);
        buf[8] = self.probe_seq;
        buf[9..17].copy_from_slice(&self.reporter_addr);
        buf[17..19].copy_from_slice(&self.reporter_caps.to_le_bytes());
        buf[19] = self.observed_hop_count;
        buf[20] = u8::from(self.is_destination);
        Ok(21)
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self, AppError> {
        if buf.len() < 21 {
            return Err(AppError::InvalidPayload);
        }
        let mut trace_id = [0u8; 8];
        trace_id.copy_from_slice(&buf[..8]);
        let mut reporter_addr = [0u8; 8];
        reporter_addr.copy_from_slice(&buf[9..17]);
        Ok(Self {
            trace_id,
            probe_seq: buf[8],
            reporter_addr,
            reporter_caps: u16::from_le_bytes([buf[17], buf[18]]),
            observed_hop_count: buf[19],
            is_destination: buf[20] != 0,
        })
    }
}

fn serialize_user_data_inner(
    content_type: u8,
    plaintext: &[u8],
    buf: &mut [u8],
) -> Result<usize, AppError> {
    let needed = 1 + 1 + 2 + plaintext.len();
    if buf.len() < needed {
        return Err(AppError::BufferTooSmall);
    }
    buf[0] = APP_KIND_USER_DATA;
    buf[1] = content_type;
    buf[2..4].copy_from_slice(&(plaintext.len() as u16).to_le_bytes());
    buf[4..4 + plaintext.len()].copy_from_slice(plaintext);
    Ok(needed)
}

fn parse_user_data_inner(buf: &[u8], output: &mut [u8]) -> Result<(u8, usize), AppError> {
    if buf.len() < 4 || buf[0] != APP_KIND_USER_DATA {
        return Err(AppError::InvalidPayload);
    }
    let content_type = buf[1];
    let len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
    if buf.len() < 4 + len || output.len() < len {
        return Err(AppError::BufferTooSmall);
    }
    output[..len].copy_from_slice(&buf[4..4 + len]);
    Ok((content_type, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infra_ping_roundtrip() {
        let ping = PingPayload {
            request_id: [0x11; 8],
            origin_time_ms: 42,
        };
        let mut payload = heapless::Vec::new();
        let mut payload_buf = [0u8; 32];
        let n = ping.serialize(&mut payload_buf).unwrap();
        payload.extend_from_slice(&payload_buf[..n]).unwrap();
        let frame = InfraFrame {
            kind: InfraKind::Ping,
            payload,
        };
        let mut buf = [0u8; 64];
        let written = frame.serialize(&mut buf).unwrap();
        let decoded = InfraFrame::deserialize(&buf[..written]).unwrap();
        assert_eq!(decoded.kind, InfraKind::Ping);
        assert_eq!(
            PingPayload::deserialize(decoded.payload.as_slice()).unwrap(),
            ping
        );
    }

    #[test]
    fn encrypted_user_data_roundtrip() {
        let sender = NodeIdentity::from_bytes(&[1u8; 32]);
        let recipient = NodeIdentity::from_bytes(&[2u8; 32]);
        let frame = EncryptedAppFrame::encrypt_user_data(
            &sender,
            &recipient.pubkey(),
            [7u8; NONCE_LEN],
            APP_CONTENT_TYPE_UTF8,
            b"hello",
        )
        .unwrap();

        let mut buf = [0u8; 256];
        let mut out = [0u8; 64];
        let written = frame.serialize(&mut buf).unwrap();
        let decoded = EncryptedAppFrame::deserialize(&buf[..written]).unwrap();
        let (content_type, plain_len) = decoded
            .decrypt_user_data(&recipient, &sender.pubkey(), &mut out)
            .unwrap();
        assert_eq!(content_type, APP_CONTENT_TYPE_UTF8);
        assert_eq!(&out[..plain_len], b"hello");
    }
}
