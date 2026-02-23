{
  description = "Ghoxy: GitHub API proxy with better authentication";

  # TODO: Do we want to pin to specific hash?
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    pre-commit-hooks = {
      url = "github:cachix/pre-commit-hooks.nix";
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

      checks = forEachSupportedSystem (
        { pkgs }:
        {
          pre-commit-check = inputs.pre-commit-hooks.lib.${pkgs.system}.run {
            src = ./.;
            hooks = {
              nixpkgs-fmt.enable = true;

              rustfmt = {
                enable = true;
                entry = pkgs.lib.mkForce "${pkgs.rustToolchain}/bin/cargo fmt -- --check --color=always";
                pass_filenames = false;
              };
              cargo-check = {
                enable = true;
                entry = pkgs.lib.mkForce "${pkgs.rustToolchain}/bin/cargo check";
                pass_filenames = false;
              };
              cargo-clippy = {
                enable = true;
                entry = pkgs.lib.mkForce "${pkgs.rustToolchain}/bin/cargo clippy -- -D warnings";
                pass_filenames = false;
              };
            };
          };
        }
      );

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

            shellHook = ''
              ${self.checks.${pkgs.system}.pre-commit-check.shellHook}
            '';
          };
        }
      );

      formatter = forEachSupportedSystem (
        { pkgs }:
        pkgs.writeShellApplication {
          name = "formatter";
          runtimeInputs = with pkgs; [
            nixfmt
            rustToolchain
          ];
          text = ''
            nixfmt flake.nix
            cargo fmt --all
          '';
        }
      );
    };
}
