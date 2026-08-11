{
  self,
  pkgs,
  package,
}:
let
  demoApp = pkgs.stdenv.mkDerivation {
    pname = "ldsocached-demo-app";
    version = "0.1.0";

    dontUnpack = true;
    dontConfigure = true;

    buildPhase = ''
      cat > demo-lib.c <<'EOF'
      int demo_value(void) {
        return 7;
      }
      EOF

      cat > demo-app.c <<'EOF'
      #include <stdio.h>
      #include <unistd.h>

      int demo_value(void);

      int main(void) {
        printf("demo-%d\n", demo_value());
        fflush(stdout);
        sleep(1);
        return 0;
      }
      EOF

      $CC -fPIC -shared -Wl,-soname,libdemo.so -o libdemo.so demo-lib.c
      $CC -o demo-app demo-app.c -L. -ldemo -Wl,-rpath,$out/lib
    '';

    installPhase = ''
      mkdir -p $out/bin $out/lib
      cp demo-app $out/bin/
      cp libdemo.so $out/lib/
    '';
  };
in
{ ... }:
{
  name = "ldsocached-cache-learning";

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

      systemd.services.ldsocached-demo-run = {
        serviceConfig = {
          Type = "oneshot";
          User = "alice";
        };
        script = ''
          ${demoApp}/bin/demo-app >> /tmp/ldsocached-demo.out 2>> /tmp/ldsocached-demo.err
        '';
      };

      environment.systemPackages = [
        package
        demoApp
        pkgs.findutils
        pkgs.gnugrep
      ];

      system.stateVersion = "25.05";
    };

  testScript = ''
    start_all()

    machine.wait_for_unit("nix-ld-cache.service")
    machine.succeed("rm -f /var/cache/nix-ld-cache/*.tsv")
    machine.succeed("rm -f /tmp/ldsocached-demo.out /tmp/ldsocached-demo.err")

    machine.succeed("systemctl start ldsocached-demo-run.service")
    machine.wait_until_succeeds("grep '^demo-7$' /tmp/ldsocached-demo.out")
    machine.succeed("grep -F 'cache miss requester=${demoApp}/bin/demo-app soname=libdemo.so' /tmp/ldsocached-demo.err")
    machine.succeed("grep -F 'learned requester=${demoApp}/bin/demo-app soname=libdemo.so' /tmp/ldsocached-demo.err")
    machine.succeed("grep -R --fixed-strings '${demoApp}/lib/libdemo.so' /var/cache/nix-ld-cache")

    machine.succeed("systemctl start ldsocached-demo-run.service")
    machine.wait_until_succeeds("test \"$(grep -c '^demo-7$' /tmp/ldsocached-demo.out)\" = 2")
  '';
}
