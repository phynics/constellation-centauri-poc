#![no_std]
#![no_main]

use {esp_alloc as _, esp_backtrace as _};

pub mod config;
pub mod crypto;
pub mod node;
pub mod protocol;
pub mod routing;
pub mod transport;

// Note: Entry point configuration is blocked by esp-hal 1.0 API changes.
// The `entry` macro location has changed. This will be resolved in Phase 5
// when we integrate the full embassy executor setup.
//
// For now, the module skeleton compiles correctly. To proceed with development:
// 1. All core modules (crypto, protocol, routing) compile
// 2. Phase 1 implementation can continue without running on hardware
// 3. Hardware entry point will be fixed when setting up embassy tasks

#[no_mangle]
pub extern "C" fn main() -> ! {
    // Placeholder - will be replaced with proper entry point in Phase 5
    loop {}
}