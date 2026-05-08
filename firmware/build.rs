use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};

fn main() {
    println!("cargo:rustc-link-arg-bins=-Tlinkall.x");

    // Build fingerprint: hash key source files so both devices can confirm
    // they're running identical firmware.
    let mut hasher = DefaultHasher::new();
    for path in &[
        "src/main.rs",
        "../routing-core/src/routing/table.rs",
        "../routing-core/src/protocol/h2h.rs",
        "../routing-core/src/config.rs",
    ] {
        if let Ok(contents) = fs::read(path) {
            path.hash(&mut hasher);
            contents.hash(&mut hasher);
        }
        println!("cargo:rerun-if-changed={}", path);
    }
    let hash = hasher.finish();
    println!("cargo:rustc-env=BUILD_FINGERPRINT={:016x}", hash);
}
