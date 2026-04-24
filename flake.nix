{
  description = "u2f-enclave: FIDO2 authenticator running as a confidential VM (SEV-SNP)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      forAllSystems = nixpkgs.lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
      ];
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };
          # The enclave crate targets bare metal; nixpkgs' rustc does not ship
          # core/alloc for x86_64-unknown-none, so pull a stable toolchain
          # that does.
          rust = pkgs.rust-bin.stable.latest.default.override {
            extensions = [ "rust-src" ];
            targets = [ "x86_64-unknown-none" ];
          };
        in
        {
          default = pkgs.mkShell {
            packages = [
              rust
              pkgs.libfido2 # smoke-libfido2.sh
            ];
          };
        }
      );

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixfmt-tree);
    };
}
