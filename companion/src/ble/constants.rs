#![allow(dead_code)]

use uuid::Uuid;

pub const ONBOARDING_SERVICE_UUID: Uuid = Uuid::from_u128(0x43d7aa10_5f4b_4c84_a100_000000000001);
pub const PROTOCOL_SIGNATURE_CHAR_UUID: Uuid =
    Uuid::from_u128(0x43d7aa10_5f4b_4c84_a100_000000000002);
pub const NETWORK_MARKER_CHAR_UUID: Uuid = Uuid::from_u128(0x43d7aa10_5f4b_4c84_a100_000000000003);
pub const NODE_PUBKEY_CHAR_UUID: Uuid = Uuid::from_u128(0x43d7aa10_5f4b_4c84_a100_000000000004);
pub const CAPABILITIES_CHAR_UUID: Uuid = Uuid::from_u128(0x43d7aa10_5f4b_4c84_a100_000000000005);
pub const SHORT_ADDR_CHAR_UUID: Uuid = Uuid::from_u128(0x43d7aa10_5f4b_4c84_a100_000000000006);
pub const L2CAP_PSM_CHAR_UUID: Uuid = Uuid::from_u128(0x43d7aa10_5f4b_4c84_a100_000000000007);
pub const AUTHORITY_PUBKEY_CHAR_UUID: Uuid =
    Uuid::from_u128(0x43d7aa10_5f4b_4c84_a100_000000000008);
pub const CERT_CAPABILITIES_CHAR_UUID: Uuid =
    Uuid::from_u128(0x43d7aa10_5f4b_4c84_a100_000000000009);
pub const CERT_SIGNATURE_CHAR_UUID: Uuid = Uuid::from_u128(0x43d7aa10_5f4b_4c84_a100_00000000000a);
pub const COMMIT_ENROLLMENT_CHAR_UUID: Uuid =
    Uuid::from_u128(0x43d7aa10_5f4b_4c84_a100_00000000000b);
pub const CERT_DATA_CHAR_UUID: Uuid = Uuid::from_u128(0x43d7aa10_5f4b_4c84_a100_00000000000c);
