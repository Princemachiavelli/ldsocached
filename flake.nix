{
  description = "LD_AUDIT-based resolver cache for Nix store binaries";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  # Pinned only to build a binary against an older glibc family for the
  # regression test in tests/cache-learning.nix: the audit module must load
  # into such processes without dragging in a second glibc (SYSCALL_ONLY.md).
  inputs.nixpkgs-oldglibc.url = "github:NixOS/nixpkgs/nixos-23.05";

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

      checks =
        forEachLinuxSystem (
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
                oldGlibcApp = inputs.nixpkgs-oldglibc.legacyPackages.${system}.hello;
              }
            );
          }
        )
        // {
          # aarch64-linux guest on an aarch64-darwin host: qemu-common.nix's
          # host/guest matrix picks -accel hvf here, so the VM test runs
          # accelerated on Apple Silicon directly instead of nested inside
          # the (unaccelerated, TCG-only) apple-virt Linux builder.
          aarch64-darwin =
            let
              hostPkgs = import inputs.nixpkgs {
                system = "aarch64-darwin";
                config.allowUnfree = true;
              };
              linuxPkgs = import inputs.nixpkgs {
                system = "aarch64-linux";
                config.allowUnfree = true;
              };
              package = self.packages.aarch64-linux.default.override {
                enableAuditDebug = true;
                enableAuditDaemonless = true;
              };
              # Fail loudly if HVF is ever unavailable instead of silently
              # falling back to TCG and reproducing the nested-virt timeout.
              forceHvf = {
                defaults.virtualisation.qemu.forceAccel = lib.mkForce true;
              };
            in
            {
              module-environment = hostPkgs.testers.runNixOSTest {
                imports = [
                  (import ./tests/module-environment.nix {
                    inherit self package;
                    pkgs = linuxPkgs;
                  })
                  forceHvf
                ];
              };
              cache-learning = hostPkgs.testers.runNixOSTest {
                imports = [
                  (import ./tests/cache-learning.nix {
                    inherit self package;
                    pkgs = linuxPkgs;
                    oldGlibcApp = inputs.nixpkgs-oldglibc.legacyPackages.aarch64-linux.hello;
                  })
                  forceHvf
                ];
              };
            };
        };

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
