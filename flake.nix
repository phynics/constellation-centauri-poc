{
  description = "Flake for Rust ESP-IDF setup with espup";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs";

  outputs = { self, nixpkgs }: let
    TOOLCHAIN_VERSION = "1.93.0.0"; # Toolchain version
    TOOLCHAIN_TARGETS = "esp32s3"; # Comma or space separated list of targets [esp32,esp32c2,esp32c3,esp32c6,esp32h2,esp32s2,esp32s3,esp32p4,all]
    TOOLCHAIN_INSTALL_DIR = "."; # Installation directory for the export-esp.sh file
    EXPORT_FILE = "${TOOLCHAIN_INSTALL_DIR}/export-esp.sh";

    # Common shell configuration shared across systems
    sharedShell = pkgs: pkgs.mkShell {
      buildInputs = with pkgs; [
          espup
          rustup
          openssl
          pkg-config
          ldproxy
          cargo-generate
          espflash
          platformio
      ];
      shellHook = ''
        export TOOLCHAIN_INSTALL_DIR=${TOOLCHAIN_INSTALL_DIR}
        export EXPORT_FILE=${EXPORT_FILE}

        # Ensure the toolchain directory exists
        mkdir -p ${TOOLCHAIN_INSTALL_DIR}

        if [ ! -f "${EXPORT_FILE}" ]; then
          echo "Installing ESP toolchain version ${TOOLCHAIN_VERSION}..."
          espup install \
            --toolchain-version ${TOOLCHAIN_VERSION} \
            --export-file "${EXPORT_FILE}" \
            --name esp \
            --targets "${TOOLCHAIN_TARGETS}"
        fi
        echo "Sourcing ESP environment from ${EXPORT_FILE}..."
        source "${EXPORT_FILE}"
      '';
    };
  in {
    # Development shells
    devShells = {
      x86_64-linux.default = sharedShell nixpkgs.legacyPackages.x86_64-linux;
      aarch64-darwin.default = sharedShell nixpkgs.legacyPackages.aarch64-darwin;
    };
  };
}

