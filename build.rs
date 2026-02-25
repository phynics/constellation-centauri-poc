use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::fs;

fn main() {
    println!("cargo:rustc-link-arg-bins=-Tlinkall.x");

    // Build fingerprint: hash key source files so both devices can confirm
    // they're running identical firmware.
    let mut hasher = DefaultHasher::new();
    for path in &[
        "src/main.rs",
        "src/routing/table.rs",
        "src/protocol/h2h.rs",
        "src/config.rs",
    ] {
        if let Ok(contents) = fs::read(path) {
            path.hash(&mut hasher);
            contents.hash(&mut hasher);
        }
        // Re-run build script if any of these change
        println!("cargo:rerun-if-changed={}", path);
    }
    let hash = hasher.finish();
    // Emit as 8-char hex string
    println!("cargo:rustc-env=BUILD_FINGERPRINT={:016x}", hash);
}
