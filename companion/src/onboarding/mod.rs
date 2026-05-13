pub fn marker_summary(bytes: &[u8]) -> String {
    match routing_core::onboarding::parse_network_marker(bytes) {
        Some(routing_core::onboarding::NetworkMarker::OnboardingReady) => {
            "onboarding-ready".to_string()
        }
        Some(routing_core::onboarding::NetworkMarker::NetworkPubkey(pubkey)) => {
            let mut out = String::from("network-pubkey:");
            for byte in &pubkey[..4] {
                use std::fmt::Write as _;
                let _ = write!(&mut out, "{byte:02x}");
            }
            out
        }
        None => format!("raw:{} bytes", bytes.len()),
    }
}
