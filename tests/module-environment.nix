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
        pkgs.gcc
      ];

      system.stateVersion = "25.05";
    };

  testScript = ''
    start_all()

    machine.wait_for_unit("nix-ld-cache.service")
    machine.wait_until_succeeds("test -f /tmp/ldsocached-system-env")

    machine.succeed("test -S /run/nix-ld-cache/learn.sock")
    machine.succeed("test -d /var/cache/nix-ld-cache")

    with subtest("the shared cache is a real world-readable directory"):
        # Not a symlink into /var/cache/private: that is what CacheDirectory=
        # plus DynamicUser= produces, and it is unreadable by clients.
        machine.succeed("test ! -L /var/cache/nix-ld-cache")
        machine.succeed("su - alice -c 'test -r /var/cache/nix-ld-cache'")
        machine.succeed("su - alice -c 'ls /var/cache/nix-ld-cache >/dev/null'")
        owner = machine.succeed("stat -c '%U:%G:%a' /var/cache/nix-ld-cache").strip()
        assert owner == "root:nix-ld-cache-readers:775", f"unexpected cache dir mode: {owner}"

    with subtest("the daemon writes via group membership, not CacheDirectory="):
        # systemctl show does not expose SupplementalGroups, and the unit's
        # effective groups are the thing that actually matters: assert the
        # running process holds the shared group and can write the cache.
        pid = machine.succeed(
            "systemctl show -p MainPID --value nix-ld-cache.service"
        ).strip()
        gid = machine.succeed(f"grep '^Groups:' /proc/{pid}/status").split()[1:]
        want = machine.succeed("getent group nix-ld-cache-readers | cut -d: -f3").strip()
        assert want in gid, f"daemon lacks the shared group: Groups={gid} want={want}"
        machine.succeed(
            "test \"$(stat -c %G /var/cache/nix-ld-cache)\" = nix-ld-cache-readers"
        )
        # A committed entry proves the write path works end to end.
        machine.succeed("test -n \"$(ls -A /var/cache/nix-ld-cache)\"")

    machine.succeed("grep -F 'LD_AUDIT=/run/current-system/sw/lib/nix-ld-cache.so' /etc/systemd/system.conf")
    machine.succeed("grep -F 'LD_AUDIT=/run/current-system/sw/lib/nix-ld-cache.so' /etc/systemd/user.conf")
    machine.succeed("grep -F 'LD_AUDIT=/run/current-system/sw/lib/nix-ld-cache.so' /tmp/ldsocached-system-env")
    machine.succeed("test -L /run/current-system/sw/lib/nix-ld-cache.so")
    machine.succeed(
        "test \"$(readlink /run/current-system/sw/lib/nix-ld-cache.so)\" = "
        "'${package}/lib/nix-ld-cache.so'"
    )
    machine.succeed("su - alice -c 'env' | grep '^LD_AUDIT=/run/current-system/sw/lib/nix-ld-cache.so$'")
    machine.succeed("su - alice -c 'env' | grep '^NIX_LD_AUDIT_SOCKET=/run/nix-ld-cache/learn.sock$'")

    with subtest("the static TLS surplus offset is exported everywhere LD_AUDIT is"):
        # Loading any audit module reserves a link-map namespace out of the fixed
        # static TLS surplus, breaking dlopen of initial-exec TLS consumers.
        machine.succeed(
            "su - alice -c 'env' | grep '^GLIBC_TUNABLES=glibc.rtld.optional_static_tls='"
        )
        machine.succeed("grep -F 'GLIBC_TUNABLES=' /etc/systemd/system.conf")
        machine.succeed("grep -F 'GLIBC_TUNABLES=' /etc/systemd/user.conf")
        # The daemon must not inherit it, nor audit itself.
        env = machine.succeed(
            "tr '\\0' '\\n' < /proc/$(systemctl show -p MainPID --value nix-ld-cache.service)/environ"
        )
        assert not any(
            line.startswith("LD_AUDIT=") and len(line) > len("LD_AUDIT=")
            for line in env.splitlines()
        ), f"daemon inherited LD_AUDIT: {env}"

    with subtest("dlopen of an initial-exec TLS library still works under LD_AUDIT"):
        # Regression guard: this is the failure mode that broke nix-daemon.
        machine.succeed(
            "su - alice -c '${pkgs.gcc}/bin/gcc -fPIC -shared -o /tmp/libietls.so "
            "-x c - <<EOF\n"
            "__thread int slot[512];\n"
            "int probe(void) { return slot[0]; }\n"
            "EOF'"
        )
        machine.succeed(
            "su - alice -c '${pkgs.gcc}/bin/gcc -o /tmp/dlprobe -ldl "
            "-x c - <<EOF\n"
            "#include <dlfcn.h>\n"
            "#include <stdio.h>\n"
            "int main(void) {\n"
            "  void *h = dlopen(\"/tmp/libietls.so\", RTLD_NOW);\n"
            "  if (h == NULL) { printf(\"dlopen-failed: %s\\n\", dlerror()); return 1; }\n"
            "  printf(\"dlopen-ok\\n\");\n"
            "  return 0;\n"
            "}\n"
            "EOF'"
        )
        out = machine.succeed("su - alice -c /tmp/dlprobe")
        assert "dlopen-ok" in out, f"dlopen under LD_AUDIT failed: {out}"
  '';
}
