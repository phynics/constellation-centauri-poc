//! Companion local-node storage.
//!
//! Purpose: persist and reload the companion's local node identity and host-side
//! metadata from the filesystem.
//!
//! Design decisions:
//! - Keep filesystem layout and local-record concerns in the companion crate;
//!   shared-core should stay storage-neutral.
use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use rand::RngCore as _;
use routing_core::crypto::identity::{NodeIdentity, PubKey, ShortAddr};
use routing_core::node::roles::Capabilities;
use routing_core::onboarding::{CONSTELLATION_PROTOCOL_SIGNATURE, ONBOARDING_READY_MARKER};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct LocalNodeRecord {
    pub secret: [u8; 32],
    pub pubkey: PubKey,
    pub short_addr: ShortAddr,
    pub authority_secret: [u8; 32],
    pub authority_pubkey: PubKey,
    pub capabilities: Capabilities,
    pub protocol_signature: Vec<u8>,
    pub network_marker: Vec<u8>,
    pub storage_dir: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct PersistedNode {
    secret_hex: String,
    #[serde(default)]
    authority_secret_hex: String,
    capabilities: u16,
    network_marker_hex: String,
}

pub fn load_or_create_local_node() -> Result<LocalNodeRecord, Box<dyn Error>> {
    let storage_dir = storage_dir()?;
    fs::create_dir_all(&storage_dir)?;
    let path = node_path(&storage_dir);

    let persisted = if path.exists() {
        serde_json::from_slice::<PersistedNode>(&fs::read(&path)?)?
    } else {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        let persisted = PersistedNode {
            secret_hex: hex(&secret),
            authority_secret_hex: hex(&new_secret()),
            capabilities: Capabilities::MOBILE | Capabilities::APPLICATION,
            network_marker_hex: hex(ONBOARDING_READY_MARKER),
        };
        fs::write(&path, serde_json::to_vec_pretty(&persisted)?)?;
        persisted
    };

    let secret = decode_fixed_32(&persisted.secret_hex)?;
    let identity = NodeIdentity::from_bytes(&secret);
    let authority_secret = if persisted.authority_secret_hex.is_empty() {
        let authority_secret = new_secret();
        let repaired = PersistedNode {
            secret_hex: persisted.secret_hex.clone(),
            authority_secret_hex: hex(&authority_secret),
            capabilities: persisted.capabilities,
            network_marker_hex: persisted.network_marker_hex.clone(),
        };
        fs::write(&path, serde_json::to_vec_pretty(&repaired)?)?;
        authority_secret
    } else {
        decode_fixed_32(&persisted.authority_secret_hex)?
    };
    let authority_identity = NodeIdentity::from_bytes(&authority_secret);
    let network_marker = decode_hex(&persisted.network_marker_hex)?;

        Ok(LocalNodeRecord {
        secret,
        pubkey: identity.pubkey(),
        short_addr: *identity.short_addr(),
        authority_secret,
        authority_pubkey: authority_identity.pubkey(),
        capabilities: Capabilities::new(persisted.capabilities),
        protocol_signature: CONSTELLATION_PROTOCOL_SIGNATURE.to_vec(),
        network_marker,
        storage_dir,
    })
}

pub fn regenerate_network_authority() -> Result<LocalNodeRecord, Box<dyn Error>> {
    let storage_dir = storage_dir()?;
    fs::create_dir_all(&storage_dir)?;
    let path = node_path(&storage_dir);

    let persisted = if path.exists() {
        serde_json::from_slice::<PersistedNode>(&fs::read(&path)?)?
    } else {
        load_or_create_local_node()?;
        serde_json::from_slice::<PersistedNode>(&fs::read(&path)?)?
    };

    let repaired = PersistedNode {
        secret_hex: persisted.secret_hex,
        authority_secret_hex: hex(&new_secret()),
        capabilities: persisted.capabilities,
        network_marker_hex: hex(ONBOARDING_READY_MARKER),
    };
    fs::write(&path, serde_json::to_vec_pretty(&repaired)?)?;
    load_or_create_local_node()
}

fn storage_dir() -> Result<PathBuf, Box<dyn Error>> {
    if let Ok(dir) = env::var("CONSTELLATION_COMPANION_HOME") {
        return Ok(PathBuf::from(dir));
    }
    let home = env::var("HOME")?;
    Ok(Path::new(&home).join(".constellation").join("companion"))
}

fn node_path(storage_dir: &Path) -> PathBuf {
    storage_dir.join("node.json")
}

fn new_secret() -> [u8; 32] {
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    secret
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn decode_fixed_32(hex_str: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let bytes = decode_hex(hex_str)?;
    Ok(bytes
        .try_into()
        .map_err(|_| "expected 32-byte secret key")?)
}

fn decode_hex(hex_str: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if hex_str.len() % 2 != 0 {
        return Err("hex string has odd length".into());
    }
    let mut out = Vec::with_capacity(hex_str.len() / 2);
    let chars: Vec<u8> = hex_str.as_bytes().to_vec();
    for idx in (0..chars.len()).step_by(2) {
        let hi = from_hex(chars[idx])?;
        let lo = from_hex(chars[idx + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn from_hex(byte: u8) -> Result<u8, Box<dyn Error>> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid hex digit".into()),
    }
}
