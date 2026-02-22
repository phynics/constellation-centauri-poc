use trouble_host_macros::{gatt_server, gatt_service};

/// Constellation Mesh GATT Server
#[gatt_server]
pub struct ConstellationServer {
    pub mesh_service: MeshService,
}

/// Main mesh service for heartbeat and packet exchange
#[gatt_service(uuid = "12345678-9abc-def0-1234-56789abcdef1")]
pub struct MeshService {
    /// Full heartbeat payload (71 bytes)
    /// Contains: pubkey (32), capabilities (2), uptime (4), bloom (32), generation (1)
    #[characteristic(uuid = "12345678-9abc-def0-1234-56789abcdef2", read)]
    pub heartbeat: [u8; 71],

    /// Mesh packet exchange (write for incoming, notify for outgoing)
    /// Max size: 512 bytes (covers header + small payload)
    #[characteristic(uuid = "12345678-9abc-def0-1234-56789abcdef3", write, notify)]
    pub packets: [u8; 512],
}
