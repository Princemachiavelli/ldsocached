# Review: nix-ld-cache audit module and daemon

Scope: `nix-ld-cache/nix-ld-cache-audit.c`, `nix-ld-cache/nix-ld-cache-daemon.c`,
`nix-ld-cache/protocol.h`, `nix-ld-cache/package.nix`, `default.nix`.

Status legend: **FIXED** / **PARTIAL** (gap remains) / **OPEN** / **NOT A BUG**.
Line references are against the current tree. Both NixOS checks pass.

## Critical

### C1. Daemon validation does not establish the resolution is genuine — FIXED
The daemon now derives the answer rather than checking a claim.
`derive_resolution()` (`daemon.c:812-885`) takes only `{requester, soname}` and
computes the resolution itself from data it reads under its own root: it confirms
`soname` is in the requester's real `DT_NEEDED`, requires `DT_RUNPATH` present
and `DT_RPATH` absent, requires every `LD_LIBRARY_PATH`/`RUNPATH` entry to be a
token-free store path, then takes the first hit walking `LD_LIBRARY_PATH` then
`DT_RUNPATH`. Resolutions it cannot reproduce (`ld.so.cache`, default dirs, any
`DT_RPATH`) are refused rather than guessed.

The client-supplied `path` field is **gone from the wire protocol**
(`protocol.h`, version 2), so there is no longer any claim to forge — the
strongest form of the recommended fix. `process_message()`
(`daemon.c:951-969`) validates the two remaining fields and passes them to
`derive_resolution()`.

Covered by `tests/cache-learning.nix` subtest "a client cannot name the path that
gets cached": an unprivileged submitter asks about `libdemo.so`, and the
same-`DT_SONAME` evil library never reaches the cache.

### C2. Store-path validation bypassable with `..` — FIXED
`path_is_safe_store_path()` (`daemon.c:202-231`) walks components and rejects any
`.`/`..` segment, closing the `strncmp`-prefix bypass.

Symlinks are now pinned rather than avoided. A symlink *inside* a store
directory is itself immutable — Nix hashes the link's target string, so both the
link and where it points are fixed by the store path, and following it is exactly
what glibc does. What must not be cached is a resolved target that lands outside
the store, since only the store provides the immutability the cache assumes. Both
read paths therefore `realpath()` and re-check the result:
`directory_holds_soname()` (`daemon.c:544-567`) and `load_elf_image()`
(`daemon.c:266-289`). An attacker-added store symlink pointing at a mutable path
is rejected at that check.

### C3. Newline injection into the shared cache file — FIXED
`path_is_safe_store_path()` rejects both `\n` and `\t` (`daemon.c:209`), and
`field_is_safe_soname()` rejects both plus `/` (`daemon.c:233-241`). With the
`path` field removed from the protocol, the only client-supplied strings are
requester and soname, and `process_message()` (`daemon.c:955-959`) validates
both. The committed path is daemon-derived and always a verified store path.

### C4. `SIGPIPE` kills audited processes — FIXED
`send_full()` (`audit.c:447-465`) uses `send(..., MSG_NOSIGNAL)` for every write.
Submit failures are ignored by the caller (`audit.c:587`), so a daemon-side
close, restart or backlog overflow cannot signal the client.

### C5. Peer PID used after it may have been recycled — FIXED
`accept_connections()` requests `SO_PEERPIDFD` (`daemon.c:1134-1137`) to bind a
pidfd to the peer atomically, and `peer_still_alive()` (`daemon.c:889-918`)
re-checks it after the `environ` read.

The fallback now **fails closed**: when `SO_PEERPIDFD` is unavailable (pre-6.5),
`peer_still_alive()` returns `false` (`daemon.c:894-896`) rather than silently
skipping the check. Without a pidfd there is no way to prove the pid was not
recycled, so the submission is refused instead of being keyed off a possibly
unrelated process's environment.

### C6. Blocking, single-threaded daemon with no timeouts — FIXED
Daemon side: non-blocking listener, epoll-driven loop (`main()`,
`daemon.c:1287-1310`), per-connection deadlines with `CONNECTION_TIMEOUT_MS`
(`daemon.c:26`) enforced by `expire_connections()` and `next_timeout_ms()`.

Client side, both remaining gaps closed:
- `submit_cache_entry()` now uses a **non-blocking `connect()` bounded by
  `poll()`** with a 200 ms budget (`audit.c:497-517`) plus a 1 s `SO_SNDTIMEO`
  (`audit.c:520-522`). A saturated daemon can no longer stall process startup.
- It is called **outside `state_lock`** (`audit.c:585-587`). The lock is now held
  only across the in-memory cache lookup (`audit.c:571-573`), so one slow
  submission cannot serialize other threads' resolutions.

Covered by the "a stalled client does not block other clients" subtest.

## High

### H1. Out-of-bounds read on a crafted ELF string table — FIXED
`parse_dynamic_info()` rejects a non-NUL-terminated string table
(`daemon.c:434-437`), with `strsz == 0` rejected just above, so `strsz - 1`
cannot underflow. Every offset is bounds-checked against `strsz`, so any in-range
offset terminates inside the mapping. `vaddr_to_offset()` guards its addition
against wraparound (`daemon.c:321-324`), and `elf_bounds_ok()` is overflow-safe.

### H2. Inherited `DT_RPATH` is not part of the cache key — FIXED
Both `requester_runpath_cacheable()` (`audit.c:191-229`) and
`derive_resolution()` (`daemon.c:812-885`) require `has_runpath && !has_rpath` on
the requester itself.

Verified against primary source, glibc 2.42 `elf/dl-load.c`
`_dl_map_new_object()` line 1977:

    if (loader == NULL || loader->l_info[DT_RUNPATH] == NULL)

That single condition gates the *entire* RPATH block — the ancestor `l_loader`
chain walk (line 1986) and the executable's own `DT_RPATH` (line 2001) alike. So
a requester carrying `DT_RUNPATH` provably had no RPATH, inherited or otherwise,
consulted for that resolution, and requesters without `DT_RUNPATH` are refused
outright. Gating on the requester alone is sufficient.

### H3. No cache invalidation when the system changes — NOT A BUG
Re-analysed and withdrawn. The original finding assumed a cached entry could
become wrong after a system update. It cannot, given the cacheability gate:

- A resolution is only ever derived from `LD_LIBRARY_PATH` and `DT_RUNPATH`, and
  only when **every** entry in both is a token-free `/nix/store` path
  (`search_path_is_cacheable()`, `daemon.c:502-536`).
- A hit must be found within those directories, and the resolved target must
  itself be a store path (C2). Store paths are content-addressed and immutable.
- `ld.so.cache` and the default directories — the only mutable inputs, and the
  only ones a system update changes — are never consulted, because any resolution
  that would have reached them is refused (`reason=no-hit-in-search-paths`).

Every input to a committed entry is therefore immutable, so a system update
cannot change the correct answer. The `libc.so.6` pinning scenario in the
original finding requires the old store path to be reachable via an unchanged
RUNPATH, in which case glibc would resolve it identically without the cache.
Folding an `ld.so.cache` hash into the key would discard every cache on each
system change to guard against nothing. Stale entries whose store path was
GC'd are handled by the `access(R_OK)` check (`audit.c:312`) and are an
efficiency concern, tracked as M3.

### H4. `la_objclose` does nothing, so cookies go stale — FIXED (obsolete)
Fixed by removal. The S1/S2 collapse deleted per-requester state entirely, so
there are no cookies to go stale and no list to grow: the module keys nothing on
the `link_map` address across calls. `la_objopen`, `la_objclose` and
`la_activity` are all gone.

### H5. Torn lines in the cache file — FIXED
Daemon path: `commit_cache_entry()` formats the whole line then issues a single
`write_full()` with a checked return (`daemon.c:742-775`).

The audit module's local `dprintf()` write path is **gone** — see N3. There is now
exactly one writer, and it is the privileged one.

Covered by the "concurrent clients produce no duplicate or torn lines" subtest
(15-way parallel load, zero within-file duplicates, zero malformed lines).

## Medium

- **M1. Missed pops leave stale pending requests. FIXED (obsolete).** Fixed by
  removal: the pending-request stack, candidate observation and the
  `la_objopen`/`la_activity` hooks no longer exist (S1/S2). The daemon derives
  the resolution, so there is nothing to observe and no queue to go stale.
- **M2. `lookup_cache_entry()` reopens and rescans per soname. FIXED.** The scope
  file is read once and memoized in `cached_scope` (`scope_cache_load()`,
  `audit.c:376-406`). Since glibc holds `dl_load_lock` across an entire
  `DT_NEEDED` search, one memoized scope covers every soname in the batch, so N
  sonames now cost one open and one read instead of N of each. The scan is an
  in-memory `memchr` walk that **stops at the first match**
  (`audit.c:409-444`) — the daemon writes each pair once, so the first match is
  the only match.
- **M3. Unbounded cache growth, no GC. OPEN.** `commit_cache_entry()`
  (`daemon.c:742-775`) dedupes before appending, but there is still no cap,
  compaction or pruning, and entries outlive store GC. Now the main remaining
  cache-lifecycle gap.
- **M4. Memory leak per cache hit. OPEN, documented.** `la_objsearch()` still
  returns an allocation glibc never frees (`audit.c:576-582`); confirmed against
  `_dl_audit_objsearch()` in glibc `elf/dl-audit.c:54-73`, which propagates the
  returned pointer with no ownership contract. The audit ABI offers no hook to
  reclaim it. Bounded at one allocation per distinct soname per process, and now
  noted in the source.
- **M5. hwcap fields. FIXED.** `AT_HWCAP`/`AT_HWCAP2`/`LD_HWCAP_MASK` and the
  `/proc/<pid>/auxv` read are gone; the dead `<sys/auxv.h>` include was also
  removed. The v2 scope key carries only requester and `LD_LIBRARY_PATH`.

  Capability consequence: the daemon reads exactly one `/proc/<pid>` file,
  `environ` (`capture_peer_environment()`, `daemon.c:931-948`), which is
  `PTRACE_MODE_READ`-gated — so `CAP_SYS_PTRACE` is genuinely required, see N1.
  `CAP_DAC_READ_SEARCH` (`default.nix`) is not exercised by any path reviewed
  (`/proc/<pid>` is world-searchable, store paths are mode 444). It may still
  matter under `hidepid` or unusual store permissions; worth re-auditing rather
  than assuming it is dead weight.
- **M6. Socket permission race. PARTIAL.** `listen_socket()` wraps `bind()` in an
  `umask(0111)`/restore pair (`daemon.c:1070-1102`), removing the
  bind-then-`chmod` window. Socket activation was not adopted: the unit is still
  `Type=simple` with the `DefaultDependencies=false` / `before=basic.target`
  ordering workarounds and the same early-boot "daemon not up yet" gap.
- **M7. `protocol.h` struct is read raw off the wire. FIXED.** A
  `static_assert` now pins the layout to four `uint32_t`s with no padding
  (`protocol.h:23-24`), so the property the wire format depends on is guaranteed
  at compile time rather than incidental.
- **M8. Hardening flags. FIXED.** Both binaries now build with
  `-D_FORTIFY_SOURCE=3 -fstack-protector-strong -Wl,-z,relro,-z,now`, plus
  `-fPIE -pie` for the daemon (`package.nix:24`, `27`). `-fvisibility=hidden`
  remains correctly omitted with a documented reason: it would hide the `la_*`
  hooks glibc resolves via `dlsym`.

## New findings (post-rewrite)

### N1. `pidfd_send_signal()` liveness probe needed CAP_KILL — FIXED
Introduced by the C5 fix and caught by the NixOS test hanging for its full
900 s timeout. `peer_still_alive()` probed the client with
`pidfd_send_signal(pidfd, 0, ...)`, but signalling a process owned by another
user requires `CAP_KILL`, which the unit deliberately does not hold — its set is
`CAP_DAC_READ_SEARCH | CAP_SYS_PTRACE` (`CapEff: 0x80004`). The probe therefore
failed with `EPERM` for *every* unprivileged client, so
`capture_peer_environment()` rejected the connection at accept time
(`reject reason=no-environ ... errno=1`) and nothing was ever committed.

Measured in the test VM, same syscalls under three unit configurations:

| unit configuration | `pidfd_send_signal` | `environ` read |
| --- | --- | --- |
| root, all capabilities | `0` | ok |
| `DynamicUser` + ptrace caps (this unit) | `-1 EPERM` | ok |
| same + `CAP_KILL` | `0` | ok |

Note the `environ` read succeeded in all three: the ptrace-gated read the unit's
comment warns about was never the failure — the liveness probe was.

Fixed at `daemon.c:889-918` by reading the `Pid:` field of
`/proc/self/fdinfo/<pidfd>`, which requires no capability and still detects
recycling (the kernel reports `Pid: -1` once the process is reaped, verified).
Preferred over granting `CAP_KILL`, which would widen the privilege set to fix a
read-only check.

### N2. `conns[]` indexed by file descriptor capped connections well below `MAX_CONNECTIONS` — FIXED
`accept_connections()` stored state at `conns[client]`, indexed by the raw fd
number, and rejected on `client >= MAX_CONNECTIONS`. Each live connection
consumes up to three fd numbers (client socket, `/proc/<pid>` dirfd, pidfd), so
the fd high-water mark hit 256 at roughly a third of the advertised capacity and
further clients were refused while `live_count` was nowhere near the cap.

Measured before the fix: 120 stalled unprivileged connections — under half of
`MAX_CONNECTIONS` — pinned the daemon's fd table to 256 (highest fd 256, 257 open
fds) and produced 46 `reason=too-many-connections` rejections. A local user could
hold the cache in a non-learning state indefinitely by re-bursting faster than
the 5 s timeout.

Fixed by decoupling slot index from fd value: slots are allocated by scanning for
a free entry (`daemon.c:1116-1130`), and the slot index travels in
`epoll_event.data.u32` (`daemon.c:1164-1167`) with `LISTEN_SLOT`
(`daemon.c:30`) distinguishing the listener. The main loop dispatches by slot and
skips already-closed slots (`daemon.c:1294-1307`). `LimitNOFILE=4096` is now set
explicitly in the unit, since the fd table must hold ~3× the connection cap.

Covered by the "the daemon survives connection exhaustion" subtest: 200 stalled
clients, and a legitimate submission still lands.

### N3. The daemonless fallback bypassed every daemon-side check — FIXED
`NIX_LD_AUDIT_DAEMONLESS`, or an unset `NIX_LD_AUDIT_SOCKET`, routed writes
through `write_cache_entry_local()`, which performed none of the daemon's
checks — no `DT_NEEDED` confirmation, no RUNPATH/RPATH gating, no store-path or
`\n`/`\t` validation, and an unchecked `dprintf()` (H5). That re-opened the
C1/C3 threat model behind an environment variable.

Fixed by deleting the local write path entirely. `NIX_LD_AUDIT_DAEMONLESS` is
gone, and with no socket configured `submit_cache_entry()` returns without doing
anything (`audit.c:473-477`), leaving the loader to resolve normally. There is
now exactly one writer — the privileged daemon — so the verification in
`derive_resolution()` cannot be bypassed by configuration.

Covered by the "no socket configured means no cache writes at all" subtest: the
program still runs and produces correct output, a miss is logged, and nothing is
written.

## Low

- `canonicalize_path()` dead branches — FIXED by removal. The function is gone;
  `requester_identity()` (`audit.c:172-184`) copies `l_name` directly and falls
  back to `/proc/self/exe` for the main executable, which is the only case that
  ever mattered.
- `runpath_checked` dead field — FIXED by removal, along with the whole
  `requester_state` struct (S1/S2).
- `debug_enabled()` calls `getenv()` per `debugf()` — FIXED. Resolved once and
  memoized (`audit.c:50-61`), which matters because this is the startup path the
  module exists to speed up.
- `la_version()` returns 0 for old glibc — FIXED. Now returns the caller's
  version when below `LAV_CURRENT` (`audit.c:538-543`), keeping the module usable
  rather than silently disabling itself.
- `requester_runpath_cacheable()` trusts a relocated `DT_STRTAB` pointer — FIXED.
  A sanity check rejects an implausibly low pointer before dereferencing
  (`audit.c:224-226`).
- `default.nix` assertions pinned `cacheDir`/`socketPath`, making them inert —
  FIXED. Both are now `readOnly` and derived from a single `runtimeName` binding
  shared with `CacheDirectory=`/`RuntimeDirectory=`, so there is one source of
  truth and no assertion needed.
- `configurable-impure-env` not asserted or documented — FIXED. An assertion now
  fires when `nixSandboxIntegration` is on without the experimental feature
  enabled, naming both remedies.
- `nix-ld-cache-benchmark` needs `strace`/`ripgrep` — FIXED. Wrapped with
  `makeWrapper` to prefix both onto `PATH` (`package.nix:39-40`).
- Setting `LD_AUDIT` globally costs an extra `.so` load on every `exec` — OPEN.
  Inherent to the design; worth measuring against the win.

## Simplifications

### S1. Daemon-side resolution collapses most of the audit module — DONE
With the daemon deriving the resolution (C1), the module no longer observes
candidates at all. Deleted: `pending_candidate`, `pending_request`, the
per-requester stack, `push_request`/`pop_request_top`/`clear_request_queues`,
`record_candidate`, `find_requester_state`/`get_or_create_requester_state`/
`forget_requester_state`, and the `la_objopen`, `la_objclose` and `la_activity`
hooks. `la_objsearch()` (`audit.c:546-589`) is now the only hook: look up the
cache, and on a miss fire `{requester, soname}` at the daemon.

The module went from 855 to 590 lines, and the deletions subsume H4 and M1
outright.

### S2. One pending slot instead of a list of stacks — DONE
Superseded by S1: there are no pending requests to track. The one piece of
retained state is a single memoized scope cache (`cached_scope`,
`audit.c:26-30`), which exists for M2 rather than for request tracking, and which
relies on the same `dl_load_lock` observation this item was based on.

### S3. Share code between the two binaries — PARTIAL
Still duplicated: `fnv1a64`, `xstrdup`, the scope-key format string, and the
`\t`-delimited cache-line parse. `mkdir_p` is now daemon-only (the module no
longer writes), and `path_is_absolute`/store-path checks have deliberately
diverged — the daemon's `path_is_safe_store_path()` is the security boundary
(C2/C3), while the module's is only a cacheability hint.

The scope-key format string is byte-identical in both files (`audit.c:273`,
`daemon.c:675-690`) and both carry "must stay byte-identical" comments, but the
hazard is unchanged in kind: a comment cannot prevent drift, and a mismatch is
invisible at runtime because entries simply land in a scope no client reads. This
is the highest-value remaining cleanup — moving the key derivation into one
shared translation unit would make the mismatch impossible rather than merely
discouraged.

### S4. Store the unhashed scope key in the file — OPEN
Still deferred in `TODO.md`. Both the writer (`daemon.c:742-775`) and reader
emit/parse two columns (`daemon.c:760`). Storing the key would let either side detect an S3
mismatch and any 64-bit FNV collision, and make the cache debuggable.

## Test coverage

`tests/cache-learning.nix`, 10 subtests, all passing:

1. genuine resolution learned and committed
2. cached entry replays, program still works
3. a client cannot name the path that gets cached (C1)
4. non-store requester refused (`invalid-fields`)
5. soname the requester does not need refused (`not-needed`)
6. non-store `LD_LIBRARY_PATH` disables caching (`unsafe-ld-library-path`)
7. stalled client does not block other clients (`reason=timeout`, C6)
8. concurrent clients produce no duplicate or torn lines (H5)
9. no socket configured means no cache writes at all (N3)
10. the daemon survives connection exhaustion (N2)

`tests/module-environment.nix` passes.

Two bugs in the concurrency subtest's own assertions were fixed along the way;
both had been masked because the subtest was unreachable while the daemon
rejected every client (N1):

- `sort /var/cache/nix-ld-cache/*.tsv | uniq -d` globbed all per-scope files into
  one stream. Each file is one requester × `LD_LIBRARY_PATH` scope, so a common
  soname legitimately recurs across files — measured 18 files with `libc.so.6` in
  12 of them, 0 within-file duplicates but 7 cross-file repeats, all counted as
  corruption. Now per-file.
- `grep -c ... *.tsv` prints `filename:count` per file when given multiple files,
  so `bad == "0"` could never have matched regardless of cache contents. Now
  piped through `cat`.

Remaining gaps: the pre-6.5 `SO_PEERPIDFD` fail-closed path (C5) is not
exercised, since the test kernel supports the option; cache growth and pruning
(M3) are untested because no pruning exists.
