use std::collections::HashSet;
use std::collections::VecDeque;
use std::error::Error;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use blew::central::CentralEvent;
use blew::gatt::props::{AttributePermissions, CharacteristicProperties};
use blew::gatt::service::{GattCharacteristic, GattService};
use blew::l2cap::Psm;
use blew::peripheral::{AdvertisingConfig, PeripheralRequest, PeripheralStateEvent};
use blew::{Central, Peripheral};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex as AsyncMutex;
use rand::RngCore as _;
use routing_core::behavior::{build_h2h_payload, run_initiator_h2h_once};
use routing_core::crypto::identity::NodeIdentity;
use routing_core::facade::{DeliveredInfra, MeshFacade, RoutedReceiveOutcome};
use routing_core::network::H2hResponder;
use routing_core::network::{H2hInitiator, SESSION_KIND_H2H, SESSION_KIND_ROUTED};
use routing_core::onboarding::{
    is_constellation_protocol_signature, parse_discovery_from_manufacturer_data,
    parse_network_marker, NetworkMarker, NodeCertificate, ONBOARDING_READY_NETWORK_ADDR,
};
use routing_core::protocol::app::NONCE_LEN;
use routing_core::protocol::h2h::H2hFrame;
use routing_core::routing::table::RoutingTable;
use tokio::io::AsyncReadExt as _;
use tokio::sync::mpsc as tokio_mpsc;
use tokio::sync::watch;
use tokio::time::{Duration, Instant};
use tokio_stream::StreamExt as _;

use super::constants::{
    AUTHORITY_PUBKEY_CHAR_UUID, CAPABILITIES_CHAR_UUID, CERT_CAPABILITIES_CHAR_UUID,
    CERT_SIGNATURE_CHAR_UUID, COMMIT_ENROLLMENT_CHAR_UUID, L2CAP_PSM_CHAR_UUID,
    NETWORK_MARKER_CHAR_UUID, NODE_PUBKEY_CHAR_UUID, ONBOARDING_SERVICE_UUID,
    PROTOCOL_SIGNATURE_CHAR_UUID, SHORT_ADDR_CHAR_UUID,
};
use super::network::{transport_addr_for_device_id, AcceptedSession, MacInitiator, MacResponder};
use crate::diagnostics::state::{DiscoveredPeer, SharedState};
use crate::node::storage::{regenerate_network_authority, LocalNodeRecord};
use crate::onboarding::marker_summary;
use crate::runtime::CompanionCommand;

const DISCOVERY_SCAN_INTERVAL: Duration = Duration::from_secs(2);
const DISCOVERY_SCAN_WINDOW_MS: u64 = 750;
const MESH_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(10);
const MAX_INSPECTIONS_PER_PASS: usize = 2;

pub async fn run(
    shared: Arc<Mutex<SharedState>>,
    mut local_node: LocalNodeRecord,
    mut shutdown_rx: watch::Receiver<bool>,
    cmd_rx: mpsc::Receiver<CompanionCommand>,
) -> Result<(), Box<dyn Error>> {
    let central: Central = Central::new().await?;
    let peripheral: Peripheral = Peripheral::new().await?;
    let central = Arc::new(central);
    let mut initiator = MacInitiator::new(Arc::clone(&central));
    let known_devices = initiator.known_devices();

    central
        .wait_ready(std::time::Duration::from_secs(5))
        .await?;
    peripheral
        .wait_ready(std::time::Duration::from_secs(5))
        .await?;

    let (l2cap_psm, mut l2cap_channels) = peripheral.l2cap_listener().await?;
    let (accepted_tx, accepted_rx) = tokio_mpsc::channel(8);

    peripheral
        .add_service(&GattService {
            uuid: ONBOARDING_SERVICE_UUID,
            primary: true,
            characteristics: vec![
                GattCharacteristic {
                    uuid: PROTOCOL_SIGNATURE_CHAR_UUID,
                    properties: CharacteristicProperties::READ,
                    permissions: AttributePermissions::READ,
                    value: vec![],
                    descriptors: vec![],
                },
                GattCharacteristic {
                    uuid: NETWORK_MARKER_CHAR_UUID,
                    properties: CharacteristicProperties::READ,
                    permissions: AttributePermissions::READ,
                    value: vec![],
                    descriptors: vec![],
                },
                GattCharacteristic {
                    uuid: NODE_PUBKEY_CHAR_UUID,
                    properties: CharacteristicProperties::READ,
                    permissions: AttributePermissions::READ,
                    value: vec![],
                    descriptors: vec![],
                },
                GattCharacteristic {
                    uuid: CAPABILITIES_CHAR_UUID,
                    properties: CharacteristicProperties::READ,
                    permissions: AttributePermissions::READ,
                    value: vec![],
                    descriptors: vec![],
                },
                GattCharacteristic {
                    uuid: SHORT_ADDR_CHAR_UUID,
                    properties: CharacteristicProperties::READ,
                    permissions: AttributePermissions::READ,
                    value: vec![],
                    descriptors: vec![],
                },
                GattCharacteristic {
                    uuid: L2CAP_PSM_CHAR_UUID,
                    properties: CharacteristicProperties::READ,
                    permissions: AttributePermissions::READ,
                    value: vec![],
                    descriptors: vec![],
                },
            ],
        })
        .await?;

    let mut requests = peripheral
        .take_requests()
        .ok_or("peripheral request stream already taken")?;
    let mut peripheral_state = peripheral.state_events();
    let mut central_events = central.events();

    peripheral
        .start_advertising(&AdvertisingConfig {
            local_name: "constellation-companion".into(),
            service_uuids: vec![ONBOARDING_SERVICE_UUID],
        })
        .await?;

    let routing_table = Arc::new(AsyncMutex::new(RoutingTable::new(local_node.short_addr)));
    let uptime = Arc::new(AsyncMutex::new(0u32));
    let responder_shared = Arc::clone(&shared);
    let responder_table = Arc::clone(&routing_table);
    let responder_uptime = Arc::clone(&uptime);
    let responder_identity = NodeIdentity::from_bytes(&local_node.secret);
    let responder_caps = local_node.capabilities;
    tokio::task::spawn_local(async move {
        let mut responder = MacResponder::new(accepted_rx);
        run_companion_responder(
            responder_shared,
            &mut responder,
            &responder_identity,
            responder_caps,
            responder_table,
            responder_uptime,
        )
        .await;
    });

    {
        let mut state = shared.lock().unwrap();
        state.scanning = true;
        state.advertising = true;
        state.push_event("BLE scan + advertising started");
    }

    let mut inspected: HashSet<String> = HashSet::new();
    let mut queued_for_inspection: HashSet<String> = HashSet::new();
    let mut inspection_queue: VecDeque<String> = VecDeque::new();
    let cmd_rx = Arc::new(Mutex::new(cmd_rx));
    let mut next_discovery_scan = Instant::now();
    let mut next_mesh_maintenance = Instant::now();

    loop {
        if let Ok(command) = cmd_rx.lock().unwrap().try_recv() {
            match command {
                CompanionCommand::EnrollSelected(device_id) => {
                    shared
                        .lock()
                        .unwrap()
                        .push_event(format!("enrolling {device_id}..."));
                    match enroll_device(&central, &shared, &local_node, &device_id).await {
                        Ok(()) => {
                            shared.lock().unwrap().push_event(format!(
                                "commit sent to {device_id}; waiting for reboot + rediscovery"
                            ));
                            inspected.remove(&device_id);
                            queued_for_inspection.remove(&device_id);
                            inspection_queue.push_back(device_id);
                        }
                        Err(err) => {
                            let mut state = shared.lock().unwrap();
                            state.set_peer_error(device_id.clone(), err.to_string());
                            state.push_event(format!("enroll {device_id} failed: {err}"));
                        }
                    }
                }
                CompanionCommand::ResetNetworkKey => {
                    shared
                        .lock()
                        .unwrap()
                        .push_event("regenerating local network authority...".to_string());
                    match regenerate_network_authority() {
                        Ok(updated) => {
                            local_node = updated;
                            let mut state = shared.lock().unwrap();
                            state.update_local_network_authority(
                                local_node.authority_pubkey,
                                marker_summary(&local_node.network_marker),
                            );
                            state.push_event(format!(
                                "new local authority pubkey {}",
                                hex(&local_node.authority_pubkey)
                            ));
                        }
                        Err(err) => {
                            shared.lock().unwrap().push_event(format!(
                                "failed to regenerate network authority: {err}"
                            ));
                        }
                    }
                }
                CompanionCommand::SendPing { short_addr } => {
                    shared
                        .lock()
                        .unwrap()
                        .push_event(format!("sending ping to {:02x?}", &short_addr[..4]));
                    match send_ping_to_peer(
                        &initiator,
                        &shared,
                        &routing_table,
                        &local_node,
                        short_addr,
                    )
                    .await
                    {
                        Ok(request_id) => {
                            shared
                                .lock()
                                .unwrap()
                                .push_event(format!("ping {} sent", hex(&request_id)));
                        }
                        Err(err) => {
                            shared
                                .lock()
                                .unwrap()
                                .push_event(format!("ping failed: {err}"));
                        }
                    }
                }
                CompanionCommand::SendMessage { short_addr, body } => {
                    shared.lock().unwrap().push_event(format!(
                        "sending mesh message to {:02x?}: {}",
                        &short_addr[..4],
                        body.chars().take(32).collect::<String>()
                    ));
                    match send_message_to_peer(
                        &initiator,
                        &shared,
                        &routing_table,
                        &local_node,
                        short_addr,
                        &body,
                    )
                    .await
                    {
                        Ok(message_id) => {
                            shared
                                .lock()
                                .unwrap()
                                .push_event(format!("message {} sent", hex(&message_id),));
                        }
                        Err(err) => {
                            shared
                                .lock()
                                .unwrap()
                                .push_event(format!("mesh message failed: {err}"));
                        }
                    }
                }
            }
        }

        if Instant::now() >= next_discovery_scan {
            initiator.scan(DISCOVERY_SCAN_WINDOW_MS).await;
            {
                let mut state = shared.lock().unwrap();
                for device_id in known_devices.lock().unwrap().values() {
                    let peer = DiscoveredPeer {
                        id: device_id.to_string(),
                        short_addr: None,
                        name: None,
                        rssi: None,
                        last_seen_unix_secs: now_secs(),
                        has_onboarding_service: true,
                        has_constellation_signature: false,
                        onboarding_ready: false,
                        network_pubkey_hex: None,
                        network_addr: None,
                        node_pubkey_hex: None,
                        capabilities: None,
                        last_error: None,
                    };
                    state.upsert_peer(peer);
                }
            }
            let discovered_ids: Vec<_> = known_devices.lock().unwrap().values().cloned().collect();
            for device_id in discovered_ids {
                let id = device_id.to_string();
                if !inspected.contains(&id) && queued_for_inspection.insert(id.clone()) {
                    inspection_queue.push_back(id);
                }
            }

            for _ in 0..MAX_INSPECTIONS_PER_PASS {
                let Some(device_id) = inspection_queue.pop_front() else {
                    break;
                };
                queued_for_inspection.remove(&device_id);
                if !inspected.contains(&device_id) {
                    if let Err(err) = inspect_device(&central, &shared, &device_id).await {
                        let mut state = shared.lock().unwrap();
                        state.set_peer_error(device_id.clone(), err.to_string());
                        state.push_event(format!("inspect {} failed: {err}", device_id));
                    } else {
                        inspected.insert(device_id);
                    }
                }
            }

            next_discovery_scan = Instant::now() + DISCOVERY_SCAN_INTERVAL;
        }

        if Instant::now() >= next_mesh_maintenance {
            let identity = NodeIdentity::from_bytes(&local_node.secret);
            run_initiator_h2h_once(
                &mut initiator,
                &identity,
                local_node.capabilities,
                &routing_table,
                &uptime,
            )
            .await;
            update_routing_snapshot(&shared, &routing_table, &uptime).await;
            next_mesh_maintenance = Instant::now() + MESH_MAINTENANCE_INTERVAL;
        }

        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            event = central_events.next() => {
                let Some(event) = event else { break; };
                match event {
                    CentralEvent::AdapterStateChanged { powered } => {
                        shared.lock().unwrap().push_event(format!("central adapter powered={powered}"));
                    }
                    CentralEvent::DeviceDiscovered(device) => {
                        if device.services.iter().any(|uuid| *uuid == ONBOARDING_SERVICE_UUID) {
                            let transport_addr = transport_addr_for_device_id(&device.id);
                            known_devices
                                .lock()
                                .unwrap()
                                .insert(transport_addr, device.id.clone());
                            let id = device.id.to_string();

                            // Parse manufacturer data for short_addr, capabilities, network_addr
                            let (short_addr, capabilities, network_addr, onboarding_ready) =
                                device.manufacturer_data.as_ref().and_then(|data| {
                                    parse_discovery_from_manufacturer_data(data).map(|info| {
                                        (Some(info.short_addr), Some(info.capabilities), Some(info.network_addr), info.network_addr == ONBOARDING_READY_NETWORK_ADDR)
                                    })
                                }).unwrap_or((None, None, None, false));

                            shared.lock().unwrap().upsert_peer(DiscoveredPeer {
                                id: id.clone(),
                                short_addr,
                                name: device.name.clone(),
                                rssi: device.rssi,
                                last_seen_unix_secs: now_secs(),
                                has_onboarding_service: true,
                                has_constellation_signature: false,
                                onboarding_ready,
                                network_pubkey_hex: None, // still need GATT read for full pubkey
                                network_addr,
                                node_pubkey_hex: None,
                                capabilities,
                                last_error: None,
                            });
                            if !inspected.contains(&id) && queued_for_inspection.insert(id.clone()) {
                                inspection_queue.push_back(id);
                            }
                        }
                    }
                    CentralEvent::DeviceConnected { device_id } => {
                        shared.lock().unwrap().push_event(format!("connected to {device_id}"));
                    }
                    CentralEvent::DeviceDisconnected { device_id, cause } => {
                        shared.lock().unwrap().push_event(format!("disconnected from {device_id}: {:?}", cause));
                    }
                    CentralEvent::CharacteristicNotification { .. } => {}
                }
            }
            state_event = peripheral_state.next() => {
                let Some(state_event) = state_event else { break; };
                match state_event {
                    PeripheralStateEvent::AdapterStateChanged { powered } => {
                        shared.lock().unwrap().push_event(format!("peripheral adapter powered={powered}"));
                    }
                    PeripheralStateEvent::SubscriptionChanged { client_id, char_uuid, subscribed } => {
                        shared.lock().unwrap().push_event(format!(
                            "subscription client={client_id} char={char_uuid} subscribed={subscribed}"
                        ));
                    }
                }
            }
            incoming = l2cap_channels.next() => {
                let Some(result) = incoming else { break; };
                match result {
                    Ok((device_id, mut channel)) => {
                        let transport_addr = transport_addr_for_device_id(&device_id);
                        let mut buf = [0u8; 512];
                        match channel.read(&mut buf).await {
                            Ok(len) if len >= 2 => {
                                let kind = buf[0];
                                let initial_payload = buf[..len].to_vec();
                                if kind == SESSION_KIND_H2H {
                                    let _ = accepted_tx.send(AcceptedSession {
                                        device_id,
                                        transport_addr,
                                        channel,
                                        initial_payload,
                                    }).await;
                                } else if kind == SESSION_KIND_ROUTED {
                                    handle_companion_routed_packet(
                                        &shared,
                                        &initiator,
                                        &routing_table,
                                        &local_node,
                                        transport_addr,
                                        &initial_payload[1..],
                                    ).await;
                                    let _ = channel.close().await;
                                } else {
                                    shared.lock().unwrap().push_event(format!(
                                        "unknown session kind {} from {}",
                                        kind,
                                        device_id
                                    ));
                                    let _ = channel.close().await;
                                }
                            }
                            Ok(_) => {
                                shared.lock().unwrap().push_event(format!(
                                    "short l2cap session from {}",
                                    device_id
                                ));
                                let _ = channel.close().await;
                            }
                            Err(err) => {
                                shared.lock().unwrap().push_event(format!(
                                    "l2cap read error from {}: {}",
                                    device_id,
                                    err
                                ));
                            }
                        }
                    }
                    Err(err) => {
                        shared.lock().unwrap().push_event(format!("l2cap accept error: {err}"));
                    }
                }
            }
            request = requests.next() => {
                let Some(request) = request else { break; };
                handle_peripheral_request(&local_node, l2cap_psm, request, &shared);
            }
        }
    }

    let _ = central.stop_scan().await;
    let _ = peripheral.stop_advertising().await;
    {
        let mut state = shared.lock().unwrap();
        state.scanning = false;
        state.advertising = false;
        state.push_event("BLE scan + advertising stopped");
    }
    Ok(())
}

fn handle_peripheral_request(
    local_node: &LocalNodeRecord,
    l2cap_psm: Psm,
    request: PeripheralRequest,
    shared: &Arc<Mutex<SharedState>>,
) {
    match request {
        PeripheralRequest::Read {
            client_id,
            char_uuid,
            responder,
            ..
        } => {
            let value = if char_uuid == PROTOCOL_SIGNATURE_CHAR_UUID {
                local_node.protocol_signature.clone()
            } else if char_uuid == NETWORK_MARKER_CHAR_UUID {
                local_node.network_marker.clone()
            } else if char_uuid == NODE_PUBKEY_CHAR_UUID {
                local_node.pubkey.to_vec()
            } else if char_uuid == CAPABILITIES_CHAR_UUID {
                local_node.capabilities.to_le_bytes().to_vec()
            } else if char_uuid == SHORT_ADDR_CHAR_UUID {
                local_node.short_addr.to_vec()
            } else if char_uuid == L2CAP_PSM_CHAR_UUID {
                l2cap_psm.value().to_le_bytes().to_vec()
            } else {
                Vec::new()
            };
            responder.respond(value);
            shared
                .lock()
                .unwrap()
                .push_event(format!("served read {char_uuid} to {client_id}"));
        }
        PeripheralRequest::Write {
            client_id,
            char_uuid,
            responder,
            ..
        } => {
            if let Some(responder) = responder {
                responder.success();
            }
            shared
                .lock()
                .unwrap()
                .push_event(format!("ignored write {char_uuid} from {client_id}"));
        }
    }
}

async fn enroll_device(
    central: &Arc<Central>,
    shared: &Arc<Mutex<SharedState>>,
    local_node: &LocalNodeRecord,
    device_id: &str,
) -> Result<(), Box<dyn Error>> {
    let authority_identity = NodeIdentity::from_bytes(&local_node.authority_secret);
    let device_id = blew::types::DeviceId::from(device_id.to_owned());

    shared.lock().unwrap().push_event(format!("connecting to {device_id}..."));
    central.connect(&device_id).await?;
    shared.lock().unwrap().push_event(format!("discovering services for {device_id}..."));
    central.discover_services(&device_id).await?;

    shared.lock().unwrap().push_event(format!("reading node identity from {device_id}..."));
    let node_pubkey = central
        .read_characteristic(&device_id, NODE_PUBKEY_CHAR_UUID)
        .await?;
    let capabilities = central
        .read_characteristic(&device_id, CAPABILITIES_CHAR_UUID)
        .await?;
    if node_pubkey.len() != 32 || capabilities.len() != 2 {
        let _ = central.disconnect(&device_id).await;
        return Err("device did not expose a valid onboarding payload".into());
    }

    let mut node_pubkey_arr = [0u8; 32];
    node_pubkey_arr.copy_from_slice(&node_pubkey);
    let node_capabilities = u16::from_le_bytes([capabilities[0], capabilities[1]]);
    let certificate =
        NodeCertificate::issue(&authority_identity, node_pubkey_arr, node_capabilities);

    shared.lock().unwrap().push_event(format!("writing authority pubkey to {device_id}..."));
    central
        .write_characteristic(
            &device_id,
            AUTHORITY_PUBKEY_CHAR_UUID,
            local_node.authority_pubkey.to_vec(),
            blew::central::WriteType::WithResponse,
        )
        .await?;
    shared.lock().unwrap().push_event(format!("writing cert capabilities to {device_id}..."));
    central
        .write_characteristic(
            &device_id,
            CERT_CAPABILITIES_CHAR_UUID,
            certificate.capabilities.to_le_bytes().to_vec(),
            blew::central::WriteType::WithResponse,
        )
        .await?;
    shared.lock().unwrap().push_event(format!("writing cert signature to {device_id}..."));
    central
        .write_characteristic(
            &device_id,
            CERT_SIGNATURE_CHAR_UUID,
            certificate.network_signature.to_vec(),
            blew::central::WriteType::WithResponse,
        )
        .await?;
    shared.lock().unwrap().push_event(format!("committing enrollment for {device_id}..."));
    central
        .write_characteristic(
            &device_id,
            COMMIT_ENROLLMENT_CHAR_UUID,
            vec![1],
            blew::central::WriteType::WithResponse,
        )
        .await?;

    let _ = central.disconnect(&device_id).await;
    shared.lock().unwrap().push_event(format!(
        "commit acknowledged for {}; expecting device reboot before next inspection",
        device_id
    ));
    Ok(())
}

async fn inspect_device(
    central: &Central,
    shared: &Arc<Mutex<SharedState>>,
    device_id: &str,
) -> Result<(), Box<dyn Error>> {
    let device_id = blew::types::DeviceId::from(device_id);
    shared.lock().unwrap().push_event(format!("inspecting {device_id}..."));
    central.connect(&device_id).await?;
    let _ = central.discover_services(&device_id).await?;

    let protocol = central
        .read_characteristic(&device_id, PROTOCOL_SIGNATURE_CHAR_UUID)
        .await?;
    let marker = central
        .read_characteristic(&device_id, NETWORK_MARKER_CHAR_UUID)
        .await?;
    let pubkey = central
        .read_characteristic(&device_id, NODE_PUBKEY_CHAR_UUID)
        .await?;
    let capabilities = central
        .read_characteristic(&device_id, CAPABILITIES_CHAR_UUID)
        .await?;
    let short_addr = central
        .read_characteristic(&device_id, SHORT_ADDR_CHAR_UUID)
        .await?;

    let peer_id = device_id.to_string();
    let protocol = trim_trailing_nuls(&protocol);
    let marker = trim_trailing_nuls(&marker);
    let (onboarding_ready, network_pubkey_hex) = match parse_network_marker(marker) {
        Some(NetworkMarker::OnboardingReady) => (true, None),
        Some(NetworkMarker::NetworkPubkey(pubkey)) => (false, Some(hex(pubkey))),
        None => (false, None),
    };

    let mut state = shared.lock().unwrap();
    state.update_peer_inspection(
        peer_id.clone(),
        if short_addr.len() == 8 {
            let mut addr = [0u8; 8];
            addr.copy_from_slice(&short_addr);
            Some(addr)
        } else {
            None
        },
        is_constellation_protocol_signature(protocol),
        onboarding_ready,
        if pubkey.len() == 32 {
            Some(hex(&pubkey))
        } else {
            None
        },
        if capabilities.len() == 2 {
            Some(u16::from_le_bytes([capabilities[0], capabilities[1]]))
        } else {
            None
        },
    );
    if let Some(network_pubkey_hex) = network_pubkey_hex {
        state.set_peer_network_pubkey(peer_id.clone(), network_pubkey_hex);
    }
    state.push_event(format!("inspected peer {device_id}"));
    drop(state);

    let _ = central.disconnect(&device_id).await;
    Ok(())
}

async fn run_companion_responder(
    shared: Arc<Mutex<SharedState>>,
    responder: &mut MacResponder,
    identity: &NodeIdentity,
    capabilities: u16,
    routing_table: Arc<AsyncMutex<NoopRawMutex, RoutingTable>>,
    uptime: Arc<AsyncMutex<NoopRawMutex, u32>>,
) -> ! {
    loop {
        match responder.receive_h2h().await {
            Ok(inbound) => {
                let partner_short = match inbound.peer_payload.full_pubkey {
                    Some(pk) => routing_core::crypto::identity::short_addr_of(&pk),
                    None => {
                        let table = routing_table.lock().await;
                        table
                            .peers
                            .iter()
                            .find(|p| p.transport_addr == inbound.peer_transport_addr)
                            .map(|p| p.short_addr)
                            .unwrap_or([0u8; 8])
                    }
                };

                let response = build_h2h_payload(
                    identity,
                    capabilities,
                    &uptime,
                    &routing_table,
                    &partner_short,
                )
                .await;

                {
                    let mut table = routing_table.lock().await;
                    table.update_peer_from_h2h(
                        &inbound.peer_payload,
                        partner_short,
                        inbound.peer_transport_addr,
                        embassy_time::Instant::now().as_ticks(),
                    );
                }

                if responder.send_h2h_response(&response).await.is_ok() {
                    shared
                        .lock()
                        .unwrap()
                        .push_event(format!("mesh sync from {:02x?}", &partner_short[..4]));
                }

                loop {
                    match responder.receive_h2h_frame().await {
                        Ok(H2hFrame::SessionDone) => break,
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }

                update_routing_snapshot(&shared, &routing_table, &uptime).await;
                let _ = responder.finish_h2h_session().await;
            }
            Err(err) => {
                shared
                    .lock()
                    .unwrap()
                    .push_event(format!("mesh responder error: {err:?}"));
            }
        }
    }
}

async fn update_routing_snapshot(
    shared: &Arc<Mutex<SharedState>>,
    routing_table: &AsyncMutex<NoopRawMutex, RoutingTable>,
    uptime: &AsyncMutex<NoopRawMutex, u32>,
) {
    let peers = {
        let table = routing_table.lock().await;
        table
            .peers
            .iter()
            .map(|peer| crate::diagnostics::state::RoutingPeerView {
                short_addr: peer.short_addr,
                capabilities: peer.capabilities,
                trust: peer.trust,
                hop_count: peer.hop_count,
                last_seen_ticks: peer.last_seen_ticks,
                transport_len: peer.transport_addr.len,
            })
            .collect::<Vec<_>>()
    };
    let uptime_secs = *uptime.lock().await;
    shared
        .lock()
        .unwrap()
        .update_routing_snapshot(uptime_secs, peers);
}

async fn send_message_to_peer(
    initiator: &MacInitiator,
    shared: &Arc<Mutex<SharedState>>,
    routing_table: &Arc<AsyncMutex<NoopRawMutex, RoutingTable>>,
    local_node: &LocalNodeRecord,
    destination: [u8; 8],
    body: &str,
) -> Result<[u8; 8], Box<dyn Error>> {
    let mut message_id = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut message_id);
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let tx = {
        let table = routing_table.lock().await;
        let mut table = table;
        let identity = NodeIdentity::from_bytes(&local_node.secret);
        let mut mesh = MeshFacade::new(&mut table, &identity, local_node.capabilities);
        mesh.plan_utf8_message(destination, message_id, nonce, body.as_bytes())
            .map_err(|err| format!("send plan error: {err:?}"))?
    };

    let destination_label = {
        let state = shared.lock().unwrap();
        state
            .peers
            .iter()
            .find(|peer| peer.short_addr == Some(destination))
            .map(|peer| peer.id.clone())
            .unwrap_or_else(|| format!("{:02x?}", &destination[..4]))
    };
    shared.lock().unwrap().push_event(format!(
        "routing toward {} via next hop transport_len={}",
        destination_label, tx.next_hop_transport.len
    ));

    initiator
        .send_routed_packet(tx.next_hop_transport, &tx.packet[..tx.len])
        .await
        .map_err(|_| "failed to send routed packet")?;
    Ok(message_id)
}

async fn send_ping_to_peer(
    initiator: &MacInitiator,
    shared: &Arc<Mutex<SharedState>>,
    routing_table: &Arc<AsyncMutex<NoopRawMutex, RoutingTable>>,
    local_node: &LocalNodeRecord,
    destination: [u8; 8],
) -> Result<[u8; 8], Box<dyn Error>> {
    let mut request_id = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut request_id);
    let tx = {
        let table = routing_table.lock().await;
        let mut table = table;
        let identity = NodeIdentity::from_bytes(&local_node.secret);
        let mut mesh = MeshFacade::new(&mut table, &identity, local_node.capabilities);
        mesh.plan_ping(destination, request_id, now_secs().saturating_mul(1000))
            .map_err(|err| format!("failed to build ping packet: {err:?}"))?
    };
    shared.lock().unwrap().push_event(format!(
        "ping routed via next hop transport_len={}",
        tx.next_hop_transport.len
    ));
    initiator
        .send_routed_packet(tx.next_hop_transport, &tx.packet[..tx.len])
        .await
        .map_err(|_| "failed to send ping packet")?;
    Ok(request_id)
}

async fn handle_companion_routed_packet(
    shared: &Arc<Mutex<SharedState>>,
    _initiator: &MacInitiator,
    routing_table: &Arc<AsyncMutex<NoopRawMutex, RoutingTable>>,
    local_node: &LocalNodeRecord,
    peer_transport_addr: routing_core::transport::TransportAddr,
    packet: &[u8],
) {
    match {
        let mut table = routing_table.lock().await;
        let identity = NodeIdentity::from_bytes(&local_node.secret);
        let mut mesh = MeshFacade::new(&mut table, &identity, local_node.capabilities);
        mesh.receive(peer_transport_addr, packet)
    } {
        RoutedReceiveOutcome::InvalidPacket => shared
            .lock()
            .unwrap()
            .push_event("invalid routed packet header".to_string()),
        RoutedReceiveOutcome::SignatureFailed { source } => shared.lock().unwrap().push_event(
            format!("routed signature verify failed from {:02x?}", &source[..4]),
        ),
        RoutedReceiveOutcome::Forward { destination, .. } => shared.lock().unwrap().push_event(
            format!(
                "non-local routed packet for {:02x?} reached companion; forwarding not implemented here",
                &destination[..4]
            ),
        ),
        RoutedReceiveOutcome::Duplicate { .. } => shared
            .lock()
            .unwrap()
            .push_event("duplicate routed packet dropped".to_string()),
        RoutedReceiveOutcome::NoRoute { .. } => shared
            .lock()
            .unwrap()
            .push_event("no route for inbound non-local packet".to_string()),
        RoutedReceiveOutcome::TtlExpired { .. } => shared
            .lock()
            .unwrap()
            .push_event("inbound non-local packet ttl expired".to_string()),
        RoutedReceiveOutcome::DeliveredInfra(DeliveredInfra::Ping { source, payload, .. }) => {
            shared.lock().unwrap().push_event(format!(
                "ping from {:02x?} req={} sent_ms={}",
                &source[..4],
                hex(&payload.request_id),
                payload.origin_time_ms
            ));
        }
        RoutedReceiveOutcome::DeliveredInfra(DeliveredInfra::Pong { payload, .. }) => {
            shared.lock().unwrap().push_event(format!(
                "pong from {:02x?} req={} recv_ttl={}",
                &payload.responder_addr[..4],
                hex(&payload.request_id),
                payload.received_ttl
            ));
        }
        RoutedReceiveOutcome::DeliveredInfra(DeliveredInfra::Other { source, kind, .. }) => {
            shared
                .lock()
                .unwrap()
                .push_event(format!("infra {:?} from {:02x?}", kind, &source[..4]));
        }
        RoutedReceiveOutcome::DeliveredAppUtf8(app) => {
            let text = String::from_utf8_lossy(&app.plaintext[..app.len]).into_owned();
            shared
                .lock()
                .unwrap()
                .push_event(format!("app from {:02x?}: {}", &app.source[..4], text));
        }
        RoutedReceiveOutcome::UnsupportedLocalApp {
            source,
            content_type,
            len,
        } => shared.lock().unwrap().push_event(format!(
            "app from {:02x?} content_type={} bytes={}",
            &source[..4],
            content_type,
            len
        )),
        RoutedReceiveOutcome::DecryptFailed { error, .. } => shared
            .lock()
            .unwrap()
            .push_event(format!("app decrypt failed: {:?}", error)),
        RoutedReceiveOutcome::MissingSenderPubkey { .. } => shared
            .lock()
            .unwrap()
            .push_event("missing sender pubkey for app packet".to_string()),
        RoutedReceiveOutcome::UnsupportedLocalPacket { packet_type, .. } => shared
            .lock()
            .unwrap()
            .push_event(format!("unsupported routed packet_type={}", packet_type)),
        RoutedReceiveOutcome::InvalidLocalPayload { packet_type, .. } => shared
            .lock()
            .unwrap()
            .push_event(format!("failed to decode local payload for packet_type={}", packet_type)),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn trim_trailing_nuls(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|byte| *byte != 0)
        .map(|idx| idx + 1)
        .unwrap_or(0);
    &bytes[..end]
}

#[cfg(test)]
mod tests {
    use routing_core::onboarding::{
        parse_discovery_from_manufacturer_data, CONSTELLATION_COMPANY_ID,
        DISCOVERY_PAYLOAD_SIZE, ONBOARDING_READY_NETWORK_ADDR, serialize_discovery,
    };

    #[test]
    fn parse_manufacturer_data_valid() {
        let short_addr = [0x42u8; 8];
        let capabilities = 0x1234;
        let network_addr = [0xABu8; 8];

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
    fn parse_manufacturer_data_wrong_company_id() {
        let mut data = [0u8; 20];
        data[0] = 0xFF; // wrong CID
        data[1] = 0xFF;

        assert!(parse_discovery_from_manufacturer_data(&data).is_none());
    }

    #[test]
    fn parse_manufacturer_data_too_short() {
        assert!(parse_discovery_from_manufacturer_data(&[]).is_none());
        assert!(parse_discovery_from_manufacturer_data(&[0u8; 10]).is_none());
        assert!(parse_discovery_from_manufacturer_data(&[0u8; 19]).is_none());
    }

    #[test]
    fn parse_manufacturer_data_onboarding_ready() {
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
