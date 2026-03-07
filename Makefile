.PHONY: all sim check check-firmware check-core fmt clippy clean flash flash-release

# Default chip target
CHIP ?= esp32c6

# ── Simulator ─────────────────────────────────────────────────────────────────

sim:
	cargo run -p sim

sim-release:
	cargo run -p sim --release

# ── Type-checking ──────────────────────────────────────────────────────────────

check: check-core check-sim

check-core:
	cargo check -p routing-core

check-sim:
	cargo check -p sim

check-firmware:
	cd firmware && cargo check --no-default-features --features=$(CHIP)

# ── Format & lint ─────────────────────────────────────────────────────────────

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy -p routing-core
	cargo clippy -p sim
	cd firmware && cargo clippy --no-default-features --features=$(CHIP)

# ── Flash (firmware only) ─────────────────────────────────────────────────────

flash:
	cd firmware && cargo $(CHIP)

flash-release:
	cd firmware && cargo $(CHIP)

# ── Housekeeping ──────────────────────────────────────────────────────────────

clean:
	cargo clean
