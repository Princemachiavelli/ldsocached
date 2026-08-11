{
  self,
  pkgs,
  package,
}:
{ ... }:
{
  name = "ldsocached-module-environment";

  nodes.machine =
    { ... }:
    {
      imports = [ self.nixosModules.default ];

      programs.nix-ld-cache = {
        enable = true;
        debug = true;
        inherit package;
      };

      nix.settings.experimental-features = [
        "configurable-impure-env"
        "nix-command"
      ];

      users.users.alice = {
        isNormalUser = true;
      };

      systemd.services.capture-ldsocached-env = {
        wantedBy = [ "multi-user.target" ];
        after = [ "nix-ld-cache.service" ];
        serviceConfig.Type = "oneshot";
        script = ''
          env | sort > /tmp/ldsocached-system-env
        '';
      };

      environment.systemPackages = [
        package
        pkgs.shadow
      ];

      system.stateVersion = "25.05";
    };

  testScript = ''
    start_all()

    machine.wait_for_unit("nix-ld-cache.service")
    machine.wait_until_succeeds("test -f /tmp/ldsocached-system-env")

    machine.succeed("test -S /run/nix-ld-cache/learn.sock")
    machine.succeed("test -d /var/cache/nix-ld-cache")
    machine.succeed("grep -F 'DefaultEnvironment=LD_AUDIT=' /etc/systemd/system.conf")
    machine.succeed("grep -F 'DefaultEnvironment=LD_AUDIT=' /etc/systemd/user.conf")
    machine.succeed("grep -F 'LD_AUDIT=' /tmp/ldsocached-system-env")
    machine.succeed("su - alice -c 'env' | grep '^LD_AUDIT=.*/libnix-ld-cache-audit.so$'")
    machine.succeed("su - alice -c 'env' | grep '^NIX_LD_AUDIT_SOCKET=/run/nix-ld-cache/learn.sock$'")
  '';
}
