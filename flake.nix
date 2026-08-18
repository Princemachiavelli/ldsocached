{
  description = "LD_AUDIT-based resolver cache for Nix store binaries";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, ... }@inputs:
    let
      inherit (inputs.nixpkgs) lib;

      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      forEachSupportedSystem =
        f:
        lib.genAttrs supportedSystems (
          system:
          f {
            inherit system;
            pkgs = import inputs.nixpkgs {
              inherit system;
              config.allowUnfree = true;
            };
          }
        );
      linuxSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forEachLinuxSystem =
        f:
        lib.genAttrs linuxSystems (
          system:
          f {
            inherit system;
            pkgs = import inputs.nixpkgs {
              inherit system;
              config.allowUnfree = true;
            };
          }
        );
    in
    {
      packages = forEachSupportedSystem (
        { pkgs, ... }:
        rec {
          default = nix-ld-cache;
          nix-ld-cache = pkgs.callPackage ./nix-ld-cache/package.nix { };
        }
      );

      nixosModules = rec {
        default = nix-ld-cache;
        nix-ld-cache = ./default.nix;
      };

      checks = forEachLinuxSystem (
        { pkgs, system }:
        let
          package = self.packages.${system}.default.override {
            enableAuditDebug = true;
            enableAuditDaemonless = true;
          };
        in
        {
          module-environment = pkgs.testers.runNixOSTest (
            import ./tests/module-environment.nix {
              inherit self pkgs package;
            }
          );
          cache-learning = pkgs.testers.runNixOSTest (
            import ./tests/cache-learning.nix {
              inherit self pkgs package;
            }
          );
        }
      );

      overlays.default = prev: final: {
        nix-ld-cache = prev.callPackage ./nix-ld-cache/package.nix { };
      };

      devShells = forEachSupportedSystem (
        { pkgs, system }:
        {
          default = pkgs.mkShellNoCC {
            packages = with pkgs; [
              cc
              self.formatter.${system}
            ];
          };
        }
      );

      formatter = forEachSupportedSystem ({ pkgs, ... }: pkgs.nixfmt);
    };
}
