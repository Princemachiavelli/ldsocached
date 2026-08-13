{
  lib,
  stdenv,
  makeWrapper,
  strace,
  ripgrep,
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
    $CC -fPIC -shared -O2 -Wall -Wextra -Wformat -Wformat-security \
      -D_FORTIFY_SOURCE=3 -fstack-protector-strong -Wl,-z,relro,-z,now \
      -o libnix-ld-cache-audit.so nix-ld-cache-audit.c -pthread
    $CC -O2 -Wall -Wextra -Wformat -Wformat-security \
      -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now \
      -o nix-ld-cache-daemon nix-ld-cache-daemon.c
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out/bin $out/lib $out/share/doc/nix-ld-cache
    cp libnix-ld-cache-audit.so $out/lib/
    cp nix-ld-cache-daemon $out/bin/
    cp benchmark.sh $out/bin/nix-ld-cache-benchmark
    chmod +x $out/bin/nix-ld-cache-benchmark
    wrapProgram $out/bin/nix-ld-cache-benchmark \
      --prefix PATH : ${lib.makeBinPath [ strace ripgrep ]}
    runHook postInstall
  '';

  meta = with lib; {
    description = "LD_AUDIT-based resolver cache for Nix store binaries";
    platforms = platforms.linux;
    license = licenses.mit;
    maintainers = [ ];
  };
}
