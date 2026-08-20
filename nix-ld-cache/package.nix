{
  lib,
  stdenv,
  makeWrapper,
  strace,
  ripgrep,
  enableAuditDebug ? true,
  enableAuditDaemonless ? false,
}:

stdenv.mkDerivation {
  pname = "nix-ld-cache";
  version = "0.1.0";

  src = ./.;

  dontConfigure = true;

  nativeBuildInputs = [ makeWrapper ];

  buildPhase = ''
    runHook preBuild
    # No -fvisibility=hidden: it hides the la_* hooks and glibc then refuses to
    # load the module as an audit interface.
    audit_feature_flags="${lib.optionalString enableAuditDebug "-DNIX_LD_AUDIT_ENABLE_DEBUG=1"} ${
      lib.optionalString enableAuditDaemonless "-DNIX_LD_AUDIT_ENABLE_DAEMONLESS=1"
    }"
    # Freestanding: the audit module must not link or call libc, or it drags a
    # second glibc family into processes built against another one
    # (SYSCALL_ONLY.md). -fno-tree-loop-distribute-patterns keeps GCC from
    # rewriting the module's own memcpy/memset loops into recursive calls to
    # themselves. No fortify or stack-protector here: both emit references to
    # libc symbols that no longer exist at link time.
    audit_freestanding_flags="-nostdlib -nostartfiles -ffreestanding -fno-builtin -fno-stack-protector -fno-tree-loop-distribute-patterns${lib.optionalString stdenv.hostPlatform.isAarch64 " -mno-outline-atomics"}"
    audit_size_flags="-fno-plt -ffunction-sections -fdata-sections -fno-asynchronous-unwind-tables -fno-unwind-tables"
    audit_ld_flags="-Wl,--as-needed -Wl,--gc-sections -Wl,--hash-style=gnu -Wl,-z,relro,-z,now -Wl,-Bsymbolic -Wl,--no-undefined"
    # NIX_HARDENING_ENABLE is cleared for this one compile so the cc wrapper
    # does not re-inject fortify/stack-protector flags behind our back; the
    # daemon build below keeps the default hardening.
    NIX_HARDENING_ENABLE= $CC -fPIC -shared -Os $audit_feature_flags $audit_freestanding_flags \
      $audit_size_flags -Wall -Wextra $audit_ld_flags \
      -o libnix-ld-cache-audit.so nix-ld-cache-audit.c

    # The target property of the freestanding build: zero dynamic dependencies,
    # so the loader can map the module without loading any libc.
    if $READELF -d libnix-ld-cache-audit.so | grep -q 'NEEDED'; then
      echo "error: libnix-ld-cache-audit.so has DT_NEEDED entries:" >&2
      $READELF -d libnix-ld-cache-audit.so >&2
      exit 1
    fi

    $CC -O2 -Wall -Wextra -Wformat -Wformat-security \
      -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now \
      -o nix-ld-cache-daemon nix-ld-cache-daemon.c

    # Ordinary glibc-linked shared object: it is LD_PRELOADed only into
    # nix-daemon's own process, which is built against the same glibc, so
    # none of the freestanding constraints above apply here.
    $CC -O2 -Wall -Wextra -Wformat -Wformat-security -fPIC -shared \
      -D_FORTIFY_SOURCE=3 -fstack-protector-strong -Wl,-z,relro,-z,now \
      -o libnix-ld-cache-execinject.so nix-ld-cache-exec-inject.c -ldl
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out/bin $out/lib $out/share/doc/nix-ld-cache
    cp libnix-ld-cache-audit.so $out/lib/
    $STRIP --strip-unneeded $out/lib/libnix-ld-cache-audit.so
    ln -s libnix-ld-cache-audit.so $out/lib/nix-ld-cache.so
    cp libnix-ld-cache-execinject.so $out/lib/
    $STRIP --strip-unneeded $out/lib/libnix-ld-cache-execinject.so
    ln -s libnix-ld-cache-execinject.so $out/lib/nix-ld-cache-execinject.so
    cp nix-ld-cache-daemon $out/bin/
    cp benchmark.sh $out/bin/nix-ld-cache-benchmark
    chmod +x $out/bin/nix-ld-cache-benchmark
    wrapProgram $out/bin/nix-ld-cache-benchmark \
      --prefix PATH : ${
        lib.makeBinPath [
          strace
          ripgrep
        ]
      }
    runHook postInstall
  '';

  meta = with lib; {
    description = "LD_AUDIT-based resolver cache for Nix store binaries";
    platforms = platforms.linux;
    license = licenses.mit;
    maintainers = [ ];
  };
}
