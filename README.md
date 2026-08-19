# nix-ld-cache

`nix-ld-cache` is an `LD_AUDIT` module plus a privileged cache writer that
caches successful `DT_NEEDED` resolutions for Nix-style immutable store paths.

Current behavior:

- On `LA_SER_ORIG` (the only hook this module implements besides `la_version`),
  look up a cached absolute path for the requesting object and soname pair. If
  a readable cached path exists, return it to the loader — glibc's own search
  never runs for that call.
- On a cache miss, the module never observes glibc's real search at all (there
  is no `la_objopen`/`la_objclose` hook left to confirm what actually loaded).
  Instead it checks its own cacheability heuristic — does the requester carry
  `DT_RUNPATH` with no `DT_RPATH`, is `LD_LIBRARY_PATH` store-safe — and, if
  so, immediately submits a learn event to the privileged writer over a Unix
  socket, before glibc has tried a single directory. The submission carries
  only the requester, soname and `LD_LIBRARY_PATH` scope — never a claimed
  resolved path. The module then returns the name unchanged and lets glibc's
  real, unobserved search proceed.
- The daemon does not trust that claim, nor does it consult glibc's actual
  outcome in any way (there is no channel to it). It independently derives the
  resolution from the requester's own `DT_RUNPATH` (only when no `DT_RPATH` is
  present, per glibc's suppression rule) and `LD_LIBRARY_PATH`, and only
  commits when the outcome is unambiguous from that immutable data alone. A
  resolution reachable only through `ld.so.cache` or a default directory is
  refused rather than guessed, since neither is captured by the cache key. It
  also confirms the resolved file's own `DT_SONAME` matches before writing.

This is a prototype. It does not reproduce the in-tree glibc patch behavior
exactly because `LA_SER_ORIG` runs before the native `LD_LIBRARY_PATH` search.

## Freestanding audit module

`libnix-ld-cache-audit.so` is built freestanding (`-nostdlib -ffreestanding
-fno-builtin`, no libc) and asserted at build time to have zero `DT_NEEDED`
entries. This matters because `LD_AUDIT` loads and relocates the module before
any hook runs: if the module depended on glibc, the loader could pull a second,
possibly mismatched glibc into the audited process and fail before the module
gets a chance to opt out. Raw Linux syscall wrappers live in
`linux-syscall.h`; see `SYSCALL_ONLY.md` for the full rationale and the list of
libc facilities the module deliberately avoids (allocation, `getenv`,
`pthread_mutex_*`, stdio, ...). `nix-ld-cache-daemon`, by contrast, is an
ordinary glibc-linked binary — it never gets loaded into another process's
address space, so the constraint doesn't apply to it.

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
  systemd managers, plus `environment.sessionVariables` for interactive shells
- the daemon service runs as a `DynamicUser` with an empty capability set
  (`CapabilityBoundingSet = [ "" ]`); the shared cache directory is managed via
  `systemd.tmpfiles` rather than `CacheDirectory=`, and the socket via
  `RuntimeDirectory=` at a fixed, world-traversable path — under
  `DynamicUser=`, `CacheDirectory=` would instead land under
  `/var/cache/private/<unit>` (mode `0700`), unreachable by the very clients
  the cache exists to serve
- the daemon service clears `LD_AUDIT` for itself to avoid self-auditing
- set `NIX_LD_AUDIT_DAEMONLESS=1` to bypass the socket and write directly to the
  per-user cache
- set `NIX_LD_AUDIT_DEBUG=1` to emit cache hits, misses and learn decisions to
  stderr, matching `LD_DEBUG`'s default output stream

## Build-time feature flags

`enableAuditDebug` (default `true`) and `enableAuditDaemonless` (default
`false`) in `nix-ld-cache/package.nix` control whether the debug-logging and
daemonless code paths get compiled into `libnix-ld-cache-audit.so` at all.
They are preprocessor switches within the same freestanding translation
unit — debug logging formats into a static buffer and writes fd 2 with a raw
syscall, daemonless mode reimplements ELF parsing and cache writes with raw
syscalls, and both build with the same `-nostdlib` flags and zero-`DT_NEEDED`
assertion as the default build.

The corresponding runtime environment variables (`NIX_LD_AUDIT_DEBUG=1`,
`NIX_LD_AUDIT_DAEMONLESS=1`) only do anything if the loaded `.so` was actually
*built* with the matching flag. With the default package, `debug =
true`/`NIX_LD_AUDIT_DEBUG=1` works out of the box; `NIX_LD_AUDIT_DAEMONLESS=1`
still needs an explicit `package = pkgs.nix-ld-cache.override {
enableAuditDaemonless = true; }` (the flake's own checks do this).

Enabling these flags costs no measurable on-disk size in the current build —
the stripped `.so` is byte-identical in size (66416 bytes) across all four
flag combinations, even though the compiled code genuinely differs (confirmed
via section sizes and `strings`). What they do cost is address space per
loaded process: `enableAuditDaemonless` adds roughly 2.9 KB of `.text`/
`.rodata`, and `enableAuditDebug` adds roughly 0.9 KB of `.text` plus a 16 KB
static `debug_buf` in `.bss` (sizing rationale in the comment above its
declaration in `nix-ld-cache-audit.c`). `.bss` isn't stored in
the file and typically isn't backed by physical memory until touched, but it
is reserved virtual address space in every audited process. `enableAuditDebug`
defaults on because that cost is small and the visibility is worth it;
`enableAuditDaemonless` stays opt-in since it's a materially larger amount of
code duplicating logic the daemon already has.

## Example build

Linux only — the package is an ELF/GNU-ld freestanding audit module plus an
epoll/Linux-syscall daemon, so `packages`/`overlays.default` only cover
`x86_64-linux` and `aarch64-linux`. From a Linux host:

```sh
nix build .#nix-ld-cache
```

From a Darwin host, target the Linux system explicitly (needs a Linux
builder configured):

```sh
nix build .#packages.aarch64-linux.nix-ld-cache
```

## Example benchmark

`nix-ld-cache-benchmark` is wrapped with `strace` and `ripgrep` on its `PATH`
at build time, so no extra `nix shell` is needed:

```sh
nix build .#nix-ld-cache
./result/bin/nix-ld-cache-benchmark /path/to/binary --version
```

## Example NixOS module use

As a flake input:

```nix
{
  inputs.nix-ld-cache.url = "github:Princemachiavelli/ldsocached";

  outputs = { nixpkgs, nix-ld-cache, ... }: {
    nixosConfigurations.example = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        nix-ld-cache.nixosModules.default
        {
          # programs.nix-ld-cache.package defaults to pkgs.nix-ld-cache, which
          # only exists once this overlay is applied.
          nixpkgs.overlays = [ nix-ld-cache.overlays.default ];
          programs.nix-ld-cache = {
            enable = true;
            debug = false;
          };
        }
      ];
    };
  };
}
```

Or by importing `./module.nix` directly from a checkout.

## Testing

```sh
nix flake check
```

`checks.<system>.{module-environment,cache-learning}` run as NixOS VM tests
for `x86_64-linux` and `aarch64-linux`. `checks.aarch64-darwin` runs the same
two tests natively on Apple Silicon via QEMU's `-accel hvf`, instead of
nested inside an unaccelerated Linux builder VM.
