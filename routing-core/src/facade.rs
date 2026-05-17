//! Lightweight routed-session facade for host crates.
//!
//! Purpose: compose packet, app-frame, crypto, and routing-table operations
//! into a small stateful API that host crates can call without re-wiring core
//! protocol pieces themselves.
//!
//! Design decisions:
//! - Keep routed-packet build/receive/relay orchestration in shared core rather
//!   than duplicating host-specific composition logic.
//! - Reuse canonical routed-envelope and routed-decision types from
//!   `message.rs` so this module stays a composition layer instead of a shadow
//!   protocol model.
//! - Expose compact transport-ready plans instead of owning host I/O directly.

use heapless::Vec;

use crate::config::HEADER_SIZE;
use crate::crypto::identity::{NodeIdentity, ShortAddr};
use crate::message::{route_message, RoutedDecision, RoutedEnvelope};
use crate::node::roles::Capabilities;
use crate::protocol::app::{
    AppError, EncryptedAppFrame, InfraFrame, InfraKind, PingPayload, PongPayload,
    APP_CONTENT_TYPE_UTF8,
};
use crate::protocol::packet::{
    build_packet_with_message_id, PacketError, PacketHeader, FLAG_BROADCAST, PACKET_TYPE_FRAME_APP,
    PACKET_TYPE_FRAME_INFRA,
};
use crate::routing::table::RoutingTable;
use crate::transport::TransportAddr;

pub const ROUTED_PACKET_MAX_LEN: usize = 512;
pub const ROUTED_PLAINTEXT_MAX_LEN: usize = 192;

pub use crate::message::{broadcast_destination, ForwardPlan};

pub struct MeshFacade<'a> {
    table: &'a mut RoutingTable,
    identity: &'a NodeIdentity,
    local_capabilities: Capabilities,
}

#[derive(Debug)]
pub enum FacadeError {
    DestinationUnknown,
    DestinationPubkeyUnknown,
    NoRoute,
    Packet(PacketError),
    App(AppError),
}

impl From<PacketError> for FacadeError {
    fn from(value: PacketError) -> Self {
        Self::Packet(value)
    }
}

impl From<AppError> for FacadeError {
    fn from(value: AppError) -> Self {
        Self::App(value)
    }
}

#[derive(Clone, Copy)]
pub struct RoutedTxPlan {
    pub next_hop_transport: TransportAddr,
    pub len: usize,
    pub packet: [u8; ROUTED_PACKET_MAX_LEN],
    pub message_id: [u8; 8],
}

#[derive(Clone, Copy)]
pub struct DeliveredUtf8App {
    pub source: ShortAddr,
    pub message_id: [u8; 8],
    pub len: usize,
    pub plaintext: [u8; ROUTED_PLAINTEXT_MAX_LEN],
}

#[derive(Clone, Copy)]
pub enum DeliveredInfra {
    Ping {
        source: ShortAddr,
        payload: PingPayload,
        pong: Option<RoutedTxPlan>,
    },
    Pong {
        source: ShortAddr,
        payload: PongPayload,
    },
    Other {
        source: ShortAddr,
        kind: InfraKind,
        payload_len: usize,
    },
}

pub enum RoutedReceiveOutcome {
    InvalidPacket,
    SignatureFailed {
        source: ShortAddr,
    },
    TtlExpired {
        destination: ShortAddr,
    },
    Duplicate {
        message_id: [u8; 8],
    },
    NoRoute {
        destination: ShortAddr,
        observe_broadcast: bool,
        should_retain_for_lpn: bool,
    },
    Forward {
        source: ShortAddr,
        destination: ShortAddr,
        ttl: u8,
        hop_count: u8,
        plan: RoutedTxPlan,
    },
    MissingSenderPubkey {
        source: ShortAddr,
    },
    DeliveredAppUtf8(DeliveredUtf8App),
    DeliveredInfra(DeliveredInfra),
    UnsupportedLocalApp {
        source: ShortAddr,
        content_type: u8,
        len: usize,
    },
    DecryptFailed {
        source: ShortAddr,
        error: AppError,
    },
    UnsupportedLocalPacket {
        source: ShortAddr,
        packet_type: u8,
    },
    InvalidLocalPayload {
        source: ShortAddr,
        packet_type: u8,
    },
}

pub trait RoutedReceiveObserver {
    fn on_invalid_packet(&mut self) {}
    fn on_signature_failed(&mut self, _source: ShortAddr) {}
    fn on_ttl_expired(&mut self, _destination: ShortAddr) {}
    fn on_duplicate(&mut self, _message_id: [u8; 8]) {}
    fn on_no_route(
        &mut self,
        _destination: ShortAddr,
        _observe_broadcast: bool,
        _should_retain_for_lpn: bool,
    ) {
    }
    fn on_forward(
        &mut self,
        _source: ShortAddr,
        _destination: ShortAddr,
        _ttl: u8,
        _hop_count: u8,
        _plan: RoutedTxPlan,
    ) {
    }
    fn on_missing_sender_pubkey(&mut self, _source: ShortAddr) {}
    fn on_delivered_app_utf8(&mut self, _app: DeliveredUtf8App) {}
    fn on_delivered_infra(&mut self, _infra: DeliveredInfra) {}
    fn on_unsupported_local_app(&mut self, _source: ShortAddr, _content_type: u8, _len: usize) {}
    fn on_decrypt_failed(&mut self, _source: ShortAddr, _error: AppError) {}
    fn on_unsupported_local_packet(&mut self, _source: ShortAddr, _packet_type: u8) {}
    fn on_invalid_local_payload(&mut self, _source: ShortAddr, _packet_type: u8) {}
}

pub fn observe_routed_receive_outcome<O: RoutedReceiveObserver>(
    outcome: RoutedReceiveOutcome,
    observer: &mut O,
) {
    match outcome {
        RoutedReceiveOutcome::InvalidPacket => observer.on_invalid_packet(),
        RoutedReceiveOutcome::SignatureFailed { source } => observer.on_signature_failed(source),
        RoutedReceiveOutcome::TtlExpired { destination } => observer.on_ttl_expired(destination),
        RoutedReceiveOutcome::Duplicate { message_id } => observer.on_duplicate(message_id),
        RoutedReceiveOutcome::NoRoute {
            destination,
            observe_broadcast,
            should_retain_for_lpn,
        } => observer.on_no_route(destination, observe_broadcast, should_retain_for_lpn),
        RoutedReceiveOutcome::Forward {
            source,
            destination,
            ttl,
            hop_count,
            plan,
        } => observer.on_forward(source, destination, ttl, hop_count, plan),
        RoutedReceiveOutcome::MissingSenderPubkey { source } => {
            observer.on_missing_sender_pubkey(source)
        }
        RoutedReceiveOutcome::DeliveredAppUtf8(app) => observer.on_delivered_app_utf8(app),
        RoutedReceiveOutcome::DeliveredInfra(infra) => observer.on_delivered_infra(infra),
        RoutedReceiveOutcome::UnsupportedLocalApp {
            source,
            content_type,
            len,
        } => observer.on_unsupported_local_app(source, content_type, len),
        RoutedReceiveOutcome::DecryptFailed { source, error } => {
            observer.on_decrypt_failed(source, error)
        }
        RoutedReceiveOutcome::UnsupportedLocalPacket {
            source,
            packet_type,
        } => observer.on_unsupported_local_packet(source, packet_type),
        RoutedReceiveOutcome::InvalidLocalPayload {
            source,
            packet_type,
        } => observer.on_invalid_local_payload(source, packet_type),
    }
}

impl<'a> MeshFacade<'a> {
    pub fn new(
        table: &'a mut RoutingTable,
        identity: &'a NodeIdentity,
        local_capabilities: Capabilities,
    ) -> Self {
        Self {
            table,
            identity,
            local_capabilities,
        }
    }

    pub fn decide(&mut self, msg: RoutedEnvelope) -> RoutedDecision {
        let destination_is_low_power = self
            .table
            .find_peer(&msg.destination)
            .map(|peer| peer.capabilities.is_low_power_endpoint())
            .unwrap_or(false);
        decide_routed_message(
            self.table,
            self.local_capabilities,
            destination_is_low_power,
            *self.identity.short_addr(),
            msg,
        )
    }

    pub fn plan_utf8_message(
        &mut self,
        destination: ShortAddr,
        message_id: [u8; 8],
        nonce: [u8; 12],
        plaintext: &[u8],
    ) -> Result<RoutedTxPlan, FacadeError> {
        build_encrypted_user_data_tx(
            self.table,
            self.identity,
            destination,
            message_id,
            nonce,
            plaintext,
        )
    }

    pub fn plan_ping(
        &mut self,
        destination: ShortAddr,
        request_id: [u8; 8],
        origin_time_ms: u64,
    ) -> Result<RoutedTxPlan, FacadeError> {
        build_ping_tx(
            self.table,
            self.identity,
            destination,
            request_id,
            origin_time_ms,
        )
    }

    pub fn receive(
        &mut self,
        peer_transport_addr: TransportAddr,
        packet: &[u8],
    ) -> RoutedReceiveOutcome {
        handle_inbound_routed_packet(
            self.table,
            self.identity,
            self.local_capabilities,
            peer_transport_addr,
            packet,
        )
    }
}

pub fn decide_routed_message(
    table: &mut RoutingTable,
    local_capabilities: Capabilities,
    destination_is_low_power: bool,
    local_addr: ShortAddr,
    msg: RoutedEnvelope,
) -> RoutedDecision {
    route_message(
        table,
        local_capabilities,
        destination_is_low_power,
        local_addr,
        &msg,
    )
}

pub fn build_encrypted_user_data_tx(
    table: &RoutingTable,
    identity: &NodeIdentity,
    destination: ShortAddr,
    message_id: [u8; 8],
    nonce: [u8; 12],
    plaintext: &[u8],
) -> Result<RoutedTxPlan, FacadeError> {
    let destination_entry = table
        .find_peer(&destination)
        .ok_or(FacadeError::DestinationUnknown)?;
    if destination_entry.pubkey == [0u8; 32] {
        return Err(FacadeError::DestinationPubkeyUnknown);
    }
    let (_, next_hop_transport) = table
        .forwarding_candidates(&destination)
        .first()
        .copied()
        .ok_or(FacadeError::NoRoute)?;

    let encrypted = EncryptedAppFrame::encrypt_user_data(
        identity,
        &destination_entry.pubkey,
        nonce,
        APP_CONTENT_TYPE_UTF8,
        plaintext,
    )?;
    let mut payload = [0u8; 256];
    let payload_len = encrypted.serialize(&mut payload)?;

    let mut packet = [0u8; ROUTED_PACKET_MAX_LEN];
    let len = build_packet_with_message_id(
        identity,
        PACKET_TYPE_FRAME_APP,
        0,
        destination,
        message_id,
        &payload[..payload_len],
        &mut packet,
    )?;

    Ok(RoutedTxPlan {
        next_hop_transport,
        len,
        packet,
        message_id,
    })
}

pub fn build_ping_tx(
    table: &RoutingTable,
    identity: &NodeIdentity,
    destination: ShortAddr,
    request_id: [u8; 8],
    origin_time_ms: u64,
) -> Result<RoutedTxPlan, FacadeError> {
    let (_, next_hop_transport) = table
        .forwarding_candidates(&destination)
        .first()
        .copied()
        .ok_or(FacadeError::NoRoute)?;

    let ping = PingPayload {
        request_id,
        origin_time_ms,
    };
    let mut ping_buf = [0u8; 32];
    let ping_len = ping.serialize(&mut ping_buf)?;
    let mut infra_payload = Vec::new();
    infra_payload
        .extend_from_slice(&ping_buf[..ping_len])
        .map_err(|_| FacadeError::App(AppError::BufferTooSmall))?;
    let infra = InfraFrame {
        kind: InfraKind::Ping,
        payload: infra_payload,
    };
    let mut payload = [0u8; 256];
    let payload_len = infra.serialize(&mut payload)?;

    let mut packet = [0u8; ROUTED_PACKET_MAX_LEN];
    let len = build_packet_with_message_id(
        identity,
        PACKET_TYPE_FRAME_INFRA,
        0,
        destination,
        request_id,
        &payload[..payload_len],
        &mut packet,
    )?;

    Ok(RoutedTxPlan {
        next_hop_transport,
        len,
        packet,
        message_id: request_id,
    })
}

pub fn handle_inbound_routed_packet(
    table: &mut RoutingTable,
    local_identity: &NodeIdentity,
    local_capabilities: Capabilities,
    peer_transport_addr: TransportAddr,
    packet: &[u8],
) -> RoutedReceiveOutcome {
    let Ok((header, payload)) = PacketHeader::deserialize(packet) else {
        return RoutedReceiveOutcome::InvalidPacket;
    };

    let sender_pubkey = table
        .peers
        .iter()
        .find(|p| p.transport_addr == peer_transport_addr || p.short_addr == header.src)
        .map(|p| p.pubkey);

    if let Some(sender_pubkey) = sender_pubkey {
        if !header.verify(&sender_pubkey, payload) {
            return RoutedReceiveOutcome::SignatureFailed { source: header.src };
        }
    }

    let destination_is_low_power = table
        .find_peer(&header.dst)
        .map(|peer| peer.capabilities.is_low_power_endpoint())
        .unwrap_or(false);

    match decide_routed_message(
        table,
        local_capabilities,
        destination_is_low_power,
        *local_identity.short_addr(),
        RoutedEnvelope {
            destination: header.dst,
            is_broadcast: header.flags & FLAG_BROADCAST != 0,
            message_id: header.message_id,
            ttl: header.ttl,
            hop_count: header.hop_count,
        },
    ) {
        RoutedDecision::TtlExpired => RoutedReceiveOutcome::TtlExpired {
            destination: header.dst,
        },
        RoutedDecision::Duplicate => RoutedReceiveOutcome::Duplicate {
            message_id: header.message_id,
        },
        RoutedDecision::NoRoute {
            observe_broadcast,
            should_retain_for_lpn,
        } => RoutedReceiveOutcome::NoRoute {
            destination: header.dst,
            observe_broadcast,
            should_retain_for_lpn,
        },
        RoutedDecision::Forward(plan) => {
            let Some((_, next_hop_transport)) = plan.candidates.first().copied() else {
                return RoutedReceiveOutcome::NoRoute {
                    destination: header.dst,
                    observe_broadcast: false,
                    should_retain_for_lpn: false,
                };
            };
            let mut forwarded = [0u8; ROUTED_PACKET_MAX_LEN];
            if packet.len() > forwarded.len() {
                return RoutedReceiveOutcome::InvalidPacket;
            }
            forwarded[..packet.len()].copy_from_slice(packet);
            let Ok((mut fwd_header, fwd_payload)) =
                PacketHeader::deserialize(&forwarded[..packet.len()])
            else {
                return RoutedReceiveOutcome::InvalidPacket;
            };
            let len = HEADER_SIZE + fwd_payload.len();
            fwd_header.ttl = fwd_header.ttl.saturating_sub(1);
            fwd_header.hop_count = fwd_header.hop_count.saturating_add(1);
            if fwd_header.serialize(&mut forwarded).is_err() {
                return RoutedReceiveOutcome::InvalidPacket;
            }
            RoutedReceiveOutcome::Forward {
                source: header.src,
                destination: header.dst,
                ttl: fwd_header.ttl,
                hop_count: fwd_header.hop_count,
                plan: RoutedTxPlan {
                    next_hop_transport,
                    len,
                    packet: forwarded,
                    message_id: header.message_id,
                },
            }
        }
        RoutedDecision::DeliveredLocal => match header.packet_type {
            PACKET_TYPE_FRAME_INFRA => match InfraFrame::deserialize(payload) {
                Ok(frame) => match frame.kind {
                    InfraKind::Ping => {
                        let Ok(ping) = PingPayload::deserialize(frame.payload.as_slice()) else {
                            return RoutedReceiveOutcome::InvalidLocalPayload {
                                source: header.src,
                                packet_type: header.packet_type,
                            };
                        };
                        let pong = build_pong_response_tx(
                            table,
                            local_identity,
                            header.src,
                            ping.request_id,
                            header.ttl,
                        );
                        RoutedReceiveOutcome::DeliveredInfra(DeliveredInfra::Ping {
                            source: header.src,
                            payload: ping,
                            pong: pong.ok(),
                        })
                    }
                    InfraKind::Pong => {
                        let Ok(pong) = PongPayload::deserialize(frame.payload.as_slice()) else {
                            return RoutedReceiveOutcome::InvalidLocalPayload {
                                source: header.src,
                                packet_type: header.packet_type,
                            };
                        };
                        RoutedReceiveOutcome::DeliveredInfra(DeliveredInfra::Pong {
                            source: header.src,
                            payload: pong,
                        })
                    }
                    kind => RoutedReceiveOutcome::DeliveredInfra(DeliveredInfra::Other {
                        source: header.src,
                        kind,
                        payload_len: frame.payload.len(),
                    }),
                },
                Err(_) => RoutedReceiveOutcome::InvalidLocalPayload {
                    source: header.src,
                    packet_type: header.packet_type,
                },
            },
            PACKET_TYPE_FRAME_APP => {
                let Some(sender_pubkey) = sender_pubkey else {
                    return RoutedReceiveOutcome::MissingSenderPubkey { source: header.src };
                };
                match EncryptedAppFrame::deserialize(payload) {
                    Ok(frame) => {
                        let mut plaintext = [0u8; ROUTED_PLAINTEXT_MAX_LEN];
                        match frame.decrypt_user_data(
                            local_identity,
                            &sender_pubkey,
                            &mut plaintext,
                        ) {
                            Ok((APP_CONTENT_TYPE_UTF8, len)) => {
                                RoutedReceiveOutcome::DeliveredAppUtf8(DeliveredUtf8App {
                                    source: header.src,
                                    message_id: header.message_id,
                                    len,
                                    plaintext,
                                })
                            }
                            Ok((content_type, len)) => RoutedReceiveOutcome::UnsupportedLocalApp {
                                source: header.src,
                                content_type,
                                len,
                            },
                            Err(err) => RoutedReceiveOutcome::DecryptFailed {
                                source: header.src,
                                error: err,
                            },
                        }
                    }
                    Err(_) => RoutedReceiveOutcome::InvalidLocalPayload {
                        source: header.src,
                        packet_type: header.packet_type,
                    },
                }
            }
            packet_type => RoutedReceiveOutcome::UnsupportedLocalPacket {
                source: header.src,
                packet_type,
            },
        },
    }
}

fn build_pong_response_tx(
    table: &RoutingTable,
    identity: &NodeIdentity,
    destination: ShortAddr,
    request_id: [u8; 8],
    received_ttl: u8,
) -> Result<RoutedTxPlan, FacadeError> {
    let (_, next_hop_transport) = table
        .forwarding_candidates(&destination)
        .first()
        .copied()
        .ok_or(FacadeError::NoRoute)?;

    let pong = PongPayload {
        request_id,
        responder_addr: *identity.short_addr(),
        received_ttl,
    };
    let mut pong_payload_buf = [0u8; 32];
    let pong_payload_len = pong.serialize(&mut pong_payload_buf)?;
    let mut infra_payload = Vec::new();
    infra_payload
        .extend_from_slice(&pong_payload_buf[..pong_payload_len])
        .map_err(|_| FacadeError::App(AppError::BufferTooSmall))?;
    let infra = InfraFrame {
        kind: InfraKind::Pong,
        payload: infra_payload,
    };
    let mut payload = [0u8; 256];
    let payload_len = infra.serialize(&mut payload)?;

    let mut packet = [0u8; ROUTED_PACKET_MAX_LEN];
    let len = build_packet_with_message_id(
        identity,
        PACKET_TYPE_FRAME_INFRA,
        0,
        destination,
        request_id,
        &payload[..payload_len],
        &mut packet,
    )?;

    Ok(RoutedTxPlan {
        next_hop_transport,
        len,
        packet,
        message_id: request_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::NodeIdentity;
    use crate::routing::bloom::BloomFilter;
    use crate::routing::table::{PeerEntry, RoutingTable, TRUST_DIRECT};

    fn identity(seed: u8) -> NodeIdentity {
        let mut secret = [0u8; 32];
        secret[0] = seed;
        secret[31] = seed.wrapping_add(0x80);
        NodeIdentity::from_bytes(&secret)
    }

    fn transport(seed: u8) -> TransportAddr {
        TransportAddr::ble([seed; 6])
    }

    #[test]
    fn build_ping_tx_uses_next_hop_from_routing_table() {
        let sender = identity(1);
        let destination = *identity(9).short_addr();
        let next_hop = transport(7);
        let mut table = RoutingTable::new(*sender.short_addr());
        let _ = table.peers.push(PeerEntry {
            pubkey: [9; 32],
            short_addr: destination,
            capabilities: Capabilities::new(0),
            bloom: BloomFilter::new(),
            transport_addr: next_hop,
            last_seen_ticks: 1,
            hop_count: 0,
            trust: TRUST_DIRECT,
            learned_from: [0; 8],
        });

        let tx = build_ping_tx(&table, &sender, destination, [0xAB; 8], 123).unwrap();
        let (header, payload) = PacketHeader::deserialize(&tx.packet[..tx.len]).unwrap();

        assert_eq!(tx.next_hop_transport, next_hop);
        assert_eq!(header.dst, destination);
        assert_eq!(header.packet_type, PACKET_TYPE_FRAME_INFRA);
        let infra = InfraFrame::deserialize(payload).unwrap();
        assert_eq!(infra.kind, InfraKind::Ping);
    }

    #[test]
    fn inbound_packet_returns_forward_plan_for_non_local_destination() {
        let sender = identity(1);
        let relay = identity(2);
        let destination = identity(3);
        let src_transport = transport(1);
        let dst_transport = transport(3);

        let mut relay_table = RoutingTable::new(*relay.short_addr());
        let _ = relay_table.peers.push(PeerEntry {
            pubkey: sender.pubkey(),
            short_addr: *sender.short_addr(),
            capabilities: Capabilities::new(0),
            bloom: BloomFilter::new(),
            transport_addr: src_transport,
            last_seen_ticks: 1,
            hop_count: 0,
            trust: TRUST_DIRECT,
            learned_from: [0; 8],
        });
        let _ = relay_table.peers.push(PeerEntry {
            pubkey: destination.pubkey(),
            short_addr: *destination.short_addr(),
            capabilities: Capabilities::new(0),
            bloom: BloomFilter::new(),
            transport_addr: dst_transport,
            last_seen_ticks: 1,
            hop_count: 0,
            trust: TRUST_DIRECT,
            learned_from: [0; 8],
        });

        let mut payload = [0u8; 8];
        payload.copy_from_slice(b"forward!");
        let mut packet = [0u8; ROUTED_PACKET_MAX_LEN];
        let len = build_packet_with_message_id(
            &sender,
            PACKET_TYPE_FRAME_APP,
            0,
            *destination.short_addr(),
            [0x11; 8],
            &payload,
            &mut packet,
        )
        .unwrap();

        match handle_inbound_routed_packet(
            &mut relay_table,
            &relay,
            Capabilities::new(0),
            src_transport,
            &packet[..len],
        ) {
            RoutedReceiveOutcome::Forward {
                plan,
                ttl,
                hop_count,
                ..
            } => {
                assert_eq!(plan.next_hop_transport, dst_transport);
                let (forwarded_header, _) =
                    PacketHeader::deserialize(&plan.packet[..plan.len]).unwrap();
                assert_eq!(ttl, forwarded_header.ttl);
                assert_eq!(hop_count, forwarded_header.hop_count);
                assert_eq!(
                    forwarded_header.ttl,
                    crate::config::DEFAULT_TTL.saturating_sub(1)
                );
                assert_eq!(forwarded_header.hop_count, 1);
            }
            _ => panic!("expected forward outcome"),
        }
    }
}
