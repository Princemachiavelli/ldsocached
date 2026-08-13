{
  self,
  pkgs,
  package,
}:
let
  demoLib = pkgs.stdenv.mkDerivation {
    pname = "ldsocached-demo-lib";
    version = "0.1.0";

    dontUnpack = true;
    dontConfigure = true;

    buildPhase = ''
      cat > demo-lib.c <<'EOF'
      int demo_value(void) {
        return 7;
      }
      EOF

      $CC -fPIC -shared -Wl,-soname,libdemo.so -o libdemo.so demo-lib.c
    '';

    installPhase = ''
      mkdir -p $out/lib
      cp libdemo.so $out/lib/
    '';
  };

  # Same DT_SONAME, different contents. Forging a soname is exactly what the
  # daemon must not accept as proof of a resolution.
  evilLib = pkgs.stdenv.mkDerivation {
    pname = "ldsocached-evil-lib";
    version = "0.1.0";

    dontUnpack = true;
    dontConfigure = true;

    buildPhase = ''
      cat > evil-lib.c <<'EOF'
      int demo_value(void) {
        return 666;
      }
      EOF

      $CC -fPIC -shared -Wl,-soname,libdemo.so -o libdemo.so evil-lib.c
    '';

    installPhase = ''
      mkdir -p $out/lib
      cp libdemo.so $out/lib/
    '';
  };

  demoApp = pkgs.stdenv.mkDerivation {
    pname = "ldsocached-demo-app";
    version = "0.1.0";

    dontUnpack = true;
    dontConfigure = true;

    buildPhase = ''
      cat > demo-app.c <<'EOF'
      #include <stdio.h>

      int demo_value(void);

      int main(void) {
        printf("demo-%d\n", demo_value());
        fflush(stdout);
        return 0;
      }
      EOF

      $CC -o demo-app demo-app.c -L${demoLib}/lib -ldemo \
        -Wl,-rpath,${demoLib}/lib -Wl,--enable-new-dtags
    '';

    installPhase = ''
      mkdir -p $out/bin
      cp demo-app $out/bin/
    '';
  };

  # Submits a resolution request as an unprivileged user. The protocol carries
  # only {requester, soname}, so a client cannot name a path at all -- this
  # exercises that the daemon derives the answer regardless of who asks.
  forgeClaim = pkgs.writers.writePython3Bin "ldsocached-forge-claim" { } ''
    import socket
    import struct
    import sys

    requester, soname = sys.argv[1:3]
    fields = [x.encode() for x in (requester, soname)]
    header = struct.pack("<IIII", 0x4E4C4348, 2, *[len(x) for x in fields])

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect("/run/nix-ld-cache/learn.sock")
    sock.sendall(header + b"".join(fields))
    sock.close()
  '';

  # Holds many connections open without sending, to test that a stalled client
  # burst cannot starve legitimate submissions.
  stallClients = pkgs.writers.writePython3Bin "ldsocached-stall-clients" { } ''
    import socket
    import sys
    import time

    held = []
    for _ in range(int(sys.argv[1])):
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect("/run/nix-ld-cache/learn.sock")
            held.append(sock)
        except OSError:
            break

    print(len(held), flush=True)
    time.sleep(30)
  '';
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
        forgeClaim
        stallClients
        pkgs.python3
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

    with subtest("a genuine resolution is learned and committed"):
        machine.succeed("systemctl start ldsocached-demo-run.service")
        machine.wait_until_succeeds("grep '^demo-7$' /tmp/ldsocached-demo.out")
        machine.succeed(
            "grep -F 'cache miss requester=${demoApp}/bin/demo-app soname=libdemo.so' "
            "/tmp/ldsocached-demo.err"
        )
        machine.wait_until_succeeds(
            "grep -R --fixed-strings '${demoLib}/lib/libdemo.so' /var/cache/nix-ld-cache"
        )

    with subtest("the cached entry replays and the program still works"):
        machine.succeed("systemctl start ldsocached-demo-run.service")
        machine.wait_until_succeeds(
            "test \"$(grep -c '^demo-7$' /tmp/ldsocached-demo.out)\" = 2"
        )

    with subtest("a client cannot name the path that gets cached"):
        # The submitter asks about libdemo.so for demo-app. The daemon derives
        # the answer from demo-app's own RUNPATH, so the evil library -- which
        # has the same DT_SONAME -- can never be what lands in the cache.
        machine.succeed(
            "su alice -c '${forgeClaim}/bin/ldsocached-forge-claim "
            "${demoApp}/bin/demo-app libdemo.so'"
        )
        machine.wait_until_succeeds(
            "grep -R --fixed-strings '${demoLib}/lib/libdemo.so' /var/cache/nix-ld-cache"
        )
        machine.fail(
            "grep -R --fixed-strings '${evilLib}/lib/libdemo.so' /var/cache/nix-ld-cache"
        )
        # The victim still resolves to the real library.
        machine.succeed("systemctl start ldsocached-demo-run.service")
        machine.wait_until_succeeds(
            "test \"$(grep -c '^demo-7$' /tmp/ldsocached-demo.out)\" = 3"
        )

    with subtest("a non-store requester is refused"):
        machine.succeed("cp ${demoApp}/bin/demo-app /tmp/demo-app-copy")
        machine.succeed(
            "su alice -c '${forgeClaim}/bin/ldsocached-forge-claim "
            "/tmp/demo-app-copy libdemo.so'"
        )
        machine.wait_until_succeeds("journalctl -u nix-ld-cache -g invalid-fields")

    with subtest("a soname the requester does not need is refused"):
        machine.succeed(
            "su alice -c '${forgeClaim}/bin/ldsocached-forge-claim "
            "${demoApp}/bin/demo-app libnotneeded.so.1'"
        )
        machine.wait_until_succeeds("journalctl -u nix-ld-cache -g reason=not-needed")

    with subtest("a non-store LD_LIBRARY_PATH entry disables caching"):
        machine.succeed("mkdir -p /tmp/mylibs")
        machine.succeed("cp ${evilLib}/lib/libdemo.so /tmp/mylibs/")
        out = machine.succeed(
            "su alice -c 'LD_LIBRARY_PATH=/tmp/mylibs NIX_LD_AUDIT_DEBUG=1 "
            "${demoApp}/bin/demo-app' 2>&1"
        )
        assert "demo-666" in out, f"expected glibc to prefer LD_LIBRARY_PATH, got: {out}"
        assert "reason=unsafe-ld-library-path" in out, f"expected skip, got: {out}"
        machine.fail(
            "grep -R --fixed-strings '/tmp/mylibs/libdemo.so' /var/cache/nix-ld-cache"
        )

    with subtest("a stalled client does not block other clients"):
        machine.succeed(
            "nohup python3 -c \"import socket,time; "
            "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); "
            "s.connect('/run/nix-ld-cache/learn.sock'); "
            "s.sendall(b'HCLN'); time.sleep(60)\" >/dev/null 2>&1 & sleep 1"
        )
        machine.succeed("rm -f /var/cache/nix-ld-cache/*.tsv")
        machine.succeed("systemctl start ldsocached-demo-run.service")
        machine.wait_until_succeeds(
            "grep -R --fixed-strings '${demoLib}/lib/libdemo.so' /var/cache/nix-ld-cache"
        )
        machine.wait_until_succeeds("journalctl -u nix-ld-cache -g reason=timeout")

    with subtest("concurrent clients produce no duplicate or torn lines"):
        machine.succeed("rm -f /var/cache/nix-ld-cache/*.tsv")
        machine.succeed(
            "su alice -c 'seq 30 | xargs -P 15 -I{} ${demoApp}/bin/demo-app' >/dev/null"
        )
        machine.wait_until_succeeds(
            "grep -R --fixed-strings '${demoLib}/lib/libdemo.so' /var/cache/nix-ld-cache"
        )
        # Each file is one requester+LD_LIBRARY_PATH scope, so the same soname
        # legitimately repeats across files. Only within-file dupes are a bug.
        dupes = machine.succeed(
            "for f in /var/cache/nix-ld-cache/*.tsv; do sort \"$f\" | uniq -d; done | wc -l"
        ).strip()
        assert dupes == "0", f"expected no duplicate cache lines, found {dupes}"
        bad = machine.succeed(
            "cat /var/cache/nix-ld-cache/*.tsv | grep -cvP '^[^\\t]+\\t/nix/store/' || true"
        ).strip()
        assert bad == "0", f"expected no malformed cache lines, found {bad}"

    with subtest("no socket configured means no cache writes at all"):
        # Without a privileged writer to vouch for a resolution, the module must
        # do nothing rather than author entries itself.
        machine.succeed("rm -f /var/cache/nix-ld-cache/*.tsv")
        out = machine.succeed(
            "su alice -c 'NIX_LD_AUDIT_SOCKET= NIX_LD_AUDIT_DEBUG=1 "
            "${demoApp}/bin/demo-app' 2>&1"
        )
        assert "demo-7" in out, f"expected the program to still work, got: {out}"
        assert "cache miss" in out, f"expected a miss to be logged, got: {out}"
        # Other processes still use the daemon, so only libdemo.so proves it:
        # nothing learned it without a socket to submit through.
        machine.fail(
            "grep -R --fixed-strings '${demoLib}/lib/libdemo.so' /var/cache/nix-ld-cache"
        )

    with subtest("the daemon survives connection exhaustion"):
        # Slots are allocated by search rather than indexed by fd, so stalled
        # clients well under the cap must not starve a legitimate submission.
        machine.succeed("rm -f /var/cache/nix-ld-cache/*.tsv")
        machine.succeed(
            "su alice -c '${stallClients}/bin/ldsocached-stall-clients 200' & sleep 3"
        )
        machine.succeed("systemctl start ldsocached-demo-run.service")
        machine.wait_until_succeeds(
            "grep -R --fixed-strings '${demoLib}/lib/libdemo.so' /var/cache/nix-ld-cache"
        )
  '';
}
