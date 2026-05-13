use std::collections::HashSet;
use std::error::Error;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use blew::central::{CentralEvent, ScanFilter};
use blew::gatt::props::{AttributePermissions, CharacteristicProperties};
use blew::gatt::service::{GattCharacteristic, GattService};
use blew::peripheral::{AdvertisingConfig, PeripheralRequest, PeripheralStateEvent};
use blew::{Central, Peripheral};
use routing_core::crypto::identity::NodeIdentity;
use routing_core::onboarding::{
    is_constellation_protocol_signature, parse_network_marker, NetworkMarker, NodeCertificate,
};
use tokio::sync::watch;
use tokio_stream::StreamExt as _;

use super::constants::{
    AUTHORITY_PUBKEY_CHAR_UUID, CAPABILITIES_CHAR_UUID, CERT_CAPABILITIES_CHAR_UUID,
    CERT_SIGNATURE_CHAR_UUID, COMMIT_ENROLLMENT_CHAR_UUID, NETWORK_MARKER_CHAR_UUID,
    NODE_PUBKEY_CHAR_UUID, ONBOARDING_SERVICE_UUID, PROTOCOL_SIGNATURE_CHAR_UUID, SHORT_ADDR_CHAR_UUID,
};
use crate::diagnostics::state::{DiscoveredPeer, SharedState};
use crate::node::storage::LocalNodeRecord;
use crate::runtime::CompanionCommand;

pub async fn run(
    shared: Arc<Mutex<SharedState>>,
    local_node: LocalNodeRecord,
    mut shutdown_rx: watch::Receiver<bool>,
    cmd_rx: mpsc::Receiver<CompanionCommand>,
) -> Result<(), Box<dyn Error>> {
    let central: Central = Central::new().await?;
    let peripheral: Peripheral = Peripheral::new().await?;
    let central = Arc::new(central);

    central.wait_ready(std::time::Duration::from_secs(5)).await?;
    peripheral.wait_ready(std::time::Duration::from_secs(5)).await?;

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
            ],
        })
        .await?;

    let mut requests = peripheral.take_requests().ok_or("peripheral request stream already taken")?;
    let mut peripheral_state = peripheral.state_events();
    let mut central_events = central.events();

    peripheral
        .start_advertising(&AdvertisingConfig {
            local_name: "constellation-companion".into(),
            service_uuids: vec![ONBOARDING_SERVICE_UUID],
        })
        .await?;
    {
        let mut state = shared.lock().unwrap();
        state.scanning = true;
        state.advertising = true;
        state.push_event("BLE scan + advertising started");
    }

    central
        .start_scan(ScanFilter {
            services: vec![ONBOARDING_SERVICE_UUID],
            ..Default::default()
        })
        .await?;

    let mut inspected: HashSet<String> = HashSet::new();
    let cmd_rx = Arc::new(Mutex::new(cmd_rx));

    loop {
        if let Ok(command) = cmd_rx.lock().unwrap().try_recv() {
            match command {
                CompanionCommand::EnrollSelected(device_id) => {
                    shared.lock().unwrap().push_event(format!("enrolling {device_id}..."));
                    match enroll_device(&central, &shared, &local_node, &device_id).await {
                        Ok(()) => {
                            shared.lock().unwrap().push_event(format!("commit sent to {device_id}; waiting for reboot + rediscovery"));
                            inspected.remove(&device_id);
                        }
                        Err(err) => {
                            let mut state = shared.lock().unwrap();
                            state.set_peer_error(device_id.clone(), err.to_string());
                            state.push_event(format!("enroll {device_id} failed: {err}"));
                        }
                    }
                }
            }
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
                        let peer = DiscoveredPeer {
                            id: device.id.to_string(),
                            name: device.name.clone(),
                            rssi: device.rssi,
                            last_seen_unix_secs: now_secs(),
                            has_onboarding_service: device.services.iter().any(|svc| *svc == ONBOARDING_SERVICE_UUID),
                            has_constellation_signature: false,
                            onboarding_ready: false,
                            network_pubkey_hex: None,
                            node_pubkey_hex: None,
                            capabilities: None,
                            last_error: None,
                        };
                        {
                            let mut state = shared.lock().unwrap();
                            state.upsert_peer(peer);
                        }
                        if inspected.insert(device.id.to_string()) {
                            if let Err(err) = inspect_device(&central, &shared, &device.id).await {
                                let mut state = shared.lock().unwrap();
                                state.set_peer_error(device.id.to_string(), err.to_string());
                                state.push_event(format!("inspect {} failed: {err}", device.id));
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
            request = requests.next() => {
                let Some(request) = request else { break; };
                handle_peripheral_request(&local_node, request, &shared);
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
            } else {
                Vec::new()
            };
            responder.respond(value);
            shared.lock().unwrap().push_event(format!("served read {char_uuid} to {client_id}"));
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
            shared.lock().unwrap().push_event(format!("ignored write {char_uuid} from {client_id}"));
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

    central.connect(&device_id).await?;
    central.discover_services(&device_id).await?;

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
    let certificate = NodeCertificate::issue(&authority_identity, node_pubkey_arr, node_capabilities);

    central
        .write_characteristic(
            &device_id,
            AUTHORITY_PUBKEY_CHAR_UUID,
            local_node.authority_pubkey.to_vec(),
            blew::central::WriteType::WithResponse,
        )
        .await?;
    central
        .write_characteristic(
            &device_id,
            CERT_CAPABILITIES_CHAR_UUID,
            certificate.capabilities.to_le_bytes().to_vec(),
            blew::central::WriteType::WithResponse,
        )
        .await?;
    central
        .write_characteristic(
            &device_id,
            CERT_SIGNATURE_CHAR_UUID,
            certificate.network_signature.to_vec(),
            blew::central::WriteType::WithResponse,
        )
        .await?;
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
    device_id: &blew::types::DeviceId,
) -> Result<(), Box<dyn Error>> {
    central.connect(device_id).await?;
    let _ = central.discover_services(device_id).await?;

    let protocol = central
        .read_characteristic(device_id, PROTOCOL_SIGNATURE_CHAR_UUID)
        .await?;
    let marker = central
        .read_characteristic(device_id, NETWORK_MARKER_CHAR_UUID)
        .await?;
    let pubkey = central.read_characteristic(device_id, NODE_PUBKEY_CHAR_UUID).await?;
    let capabilities = central
        .read_characteristic(device_id, CAPABILITIES_CHAR_UUID)
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
        is_constellation_protocol_signature(protocol),
        onboarding_ready,
        if pubkey.len() == 32 { Some(hex(&pubkey)) } else { None },
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

    let _ = central.disconnect(device_id).await;
    Ok(())
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
