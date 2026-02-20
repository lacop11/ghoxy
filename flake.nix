{
  description = "Ghoxy: GitHub API proxy with better authentication";

  # TODO: Do we want to pin to specific hash?
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, ... }@inputs:

    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-darwin"
      ];
      forEachSupportedSystem =
        f:
        inputs.nixpkgs.lib.genAttrs supportedSystems (
          system:
          f {
            pkgs = import inputs.nixpkgs {
              inherit system;
              overlays = [
                inputs.self.overlays.default
              ];
            };
          }
        );
    in
    {
      overlays.default = final: prev: {
        rustToolchain =
          let
            fenixPkgs = inputs.fenix.packages.${prev.stdenv.hostPlatform.system};
            stableToolchain = fenixPkgs.fromToolchainFile {
              file = ./rust-toolchain.toml;
              sha256 = "sha256-sqSWJDUxc+zaz1nBWMAJKTAGBuGWP25GCftIOlCEAtA=";
            };
          in
          fenixPkgs.combine [
            # Latest rustfmt, we want some nightly/unstable features.
            # This does not impact the produced binaries so there is no risk.
            fenixPkgs.latest.rustfmt
            # Stable everything else/
            stableToolchain
          ];
      };

      devShells = forEachSupportedSystem (
        { pkgs }:
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              rustToolchain
              cargo-deny
              cargo-watch
              rust-analyzer
              # TODO: Might be needed.
              # openssl
              # pkg-config
            ];

            env = {
              # Required by rust-analyzer
              RUST_SRC_PATH = "${pkgs.rustToolchain}/lib/rustlib/src/rust/library";
            };
          };
        }
      );
    };
}
