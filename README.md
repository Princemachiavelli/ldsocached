# nix-ld-cache

`nix-ld-cache` is an `LD_AUDIT` module plus a privileged cache writer that
caches successful `DT_NEEDED` resolutions for Nix-style immutable store paths.

Current behavior:

- On `LA_SER_ORIG`, look up a cached absolute path for the requesting object and
  soname pair. If a readable cached path exists, return it to the loader.
- On cache miss, let glibc continue.
- While glibc searches library paths, observe concrete candidate paths across
  `LD_LIBRARY_PATH`, `RUNPATH`, `ld.so.cache` and default directories.
- If one of those candidates becomes the object that was actually loaded, submit
  a learn event to the privileged writer over a Unix socket.
- The daemon validates that the requester needs the soname and the resolved
  path has a matching ELF soname before committing to the shared cache.

This is a prototype. It does not reproduce the in-tree glibc patch behavior
exactly because `LA_SER_ORIG` runs before the native `LD_LIBRARY_PATH` search.

Cache location:

- `NIX_LD_AUDIT_CACHE_DIR`, if set
- `$XDG_CACHE_HOME/nix-ld-cache`
- `$HOME/.cache/nix-ld-cache`
- `/var/tmp/nix-ld-cache-audit-$UID`

Shared-cache mode:

- NixOS module sets `NIX_LD_AUDIT_CACHE_DIR=/var/cache/nix-ld-cache`
- audit module submits writes to `NIX_LD_AUDIT_SOCKET`
- `nix-ld-cache-daemon` validates and writes shared entries
- NixOS module also sets `DefaultEnvironment=` for the system and user
  systemd managers, plus PAM session variables for login sessions
- service runs as a `DynamicUser` with a minimal capability set because it
  derives the peer process environment and auxv from `/proc/<pid>` instead of
  trusting the client
- the daemon service clears `LD_AUDIT` for itself to avoid self-auditing
- set `NIX_LD_AUDIT_DAEMONLESS=1` to bypass the socket and write directly to the
  per-user cache
- set `NIX_LD_AUDIT_DEBUG=1` to emit cache hits, misses and learn decisions to
  stderr, matching `LD_DEBUG`'s default output stream

Example build:

```sh
nix build .#nix-ld-cache
```

Example benchmark:

```sh
nix shell "nixpkgs#strace" "nixpkgs#ripgrep" -c \
  ./result/bin/nix-ld-cache-benchmark /path/to/binary --version
```

Example NixOS module use:

```nix
{
  imports = [ ./nixos-modules/nix-ld-cache ];

  programs.nix-ld-cache = {
    enable = true;
    debug = false;
  };
}
```
