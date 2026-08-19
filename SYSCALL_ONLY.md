# Syscall-only audit module plan

## Status: implemented

The audit module is built freestanding (`-nostdlib -ffreestanding
-fno-builtin`) for x86_64-linux and aarch64-linux from day one, since both are
flake check targets. Raw syscall wrappers and the kernel ABI structs live in
`linux-syscall.h`; the build asserts the resulting object has no `DT_NEEDED`
entries and links with `-Wl,--no-undefined -Wl,-Bsymbolic`.

Deviations from the plan below, with reasons:

- Daemonless mode was ported in the same pass instead of staying behind a
  flag: the flake checks build with `enableAuditDaemonless = true` and
  exercise it, and it reuses every helper the daemon path needed anyway.
- Environment access reads `/proc/self/environ` once into a private mapping
  rather than chasing the initial stack; the module already depends on /proc
  for `/proc/self/exe`. glibc snapshots `LD_LIBRARY_PATH` at startup, so a
  one-shot snapshot matches loader semantics.
- `realpath` is implemented as `open(O_PATH)` + `readlink /proc/self/fd/N`
  instead of a userspace path walker.
- Heap allocation is gone: scope caches use fixed buffers, cache files are
  `mmap`ed instead of read into `malloc`ed buffers, and the strings returned
  to glibc (which it never frees) come from a never-freed mmap bump arena.
- Scope keys are streamed through FNV-1a instead of materialized; the hashed
  bytes stay identical to the daemon's `cache_scope_key()`.
- The regression test runs a `nixos-23.05` (older glibc) binary under the
  audit module inside the cache-learning VM test.

## Problem

The audit shared object currently depends on glibc. When `LD_AUDIT` points to
that object, glibc loads and relocates it before any audit hook can opt out. If
the target process uses a different glibc revision, the loader can pull two
glibc families into the process and fail before `la_version` or `la_objsearch`
runs.

Returning zero from `la_version` is too late for this failure mode. Removing
`RUNPATH` is also not a reliable NixOS fix because it makes the audit object's
dependencies resolve from target-specific state.

## Target property

`libnix-ld-cache-audit.so` should have no `DT_NEEDED` entries:

```sh
readelf -d "$out/lib/libnix-ld-cache-audit.so" | grep NEEDED
```

The command should produce no output. With no dynamic dependencies, the loader
can map the audit module without loading another libc.

## Scope

Keep the daemon-backed mode as the first milestone. Daemonless mode is optional
or can stay behind a feature flag until it is ported.

The audit object must not call libc functions, including:

- allocation: `malloc`, `realloc`, `free`, `strdup`, `asprintf`
- environment and path helpers: `getenv`, `realpath`, `readlink`
- I/O wrappers: `open`, `read`, `write`, `close`, `socket`, `connect`, `poll`
- synchronization: `pthread_mutex_*`
- string and memory helpers: `strlen`, `strcmp`, `memcpy`, `memchr`
- stdio and debug helpers: `fprintf`, `flockfile`

## Implementation plan

1. Build the audit object with freestanding flags:

   ```sh
   -nostdlib -ffreestanding -fno-builtin -fno-stack-protector
   ```

   Drop fortify and libc-oriented hardening flags that require libc symbols.

2. Add local Linux syscall wrappers for supported architectures. Start with
   `x86_64-linux`; add `aarch64-linux` after the first end-to-end pass.

3. Replace libc string and memory calls with small local helpers.

4. Replace heap allocation with fixed-size buffers or an `mmap` arena. Prefer
   bounded fixed buffers for startup-path code where possible.

5. Replace environment reads by parsing `/proc/self/environ` or the initial
   process environment if it can be reached safely without libc.

6. Replace path and file operations with raw syscalls:

   - `openat`
   - `read`
   - `newfstatat` or `fstat`
   - `readlinkat`
   - `close`
   - `access` equivalent via `faccessat2` or open probes

7. Replace daemon submission with raw `socket`, `connect`, `sendto` or `sendmsg`,
   `poll` and `close` syscalls.

8. Replace locking with a small futex lock or atomics. If a first version avoids
   shared mutable caches, no lock is needed.

9. Keep debug logging optional. If enabled, write directly to fd 2 with `write`.

10. Add a build-time assertion that the audit SO has no `DT_NEEDED` entries.

11. Add a regression test that runs an older-glibc binary with the audit module
    enabled and a fresh cache.

## Expected complexity

A minimal daemon-backed syscall-only audit module is moderate work. Expect a few
days for an initial x86_64 implementation and more time for full feature parity.
Porting daemonless mode is larger because it duplicates ELF parsing and cache
writing inside the audited process.
