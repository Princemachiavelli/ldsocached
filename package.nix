{ lib, stdenv }:

stdenv.mkDerivation {
  pname = "nix-ld-cache";
  version = "0.1.0";

  src = ./.;

  dontConfigure = true;

  buildPhase = ''
    runHook preBuild
    $CC -D_GNU_SOURCE -fPIC -shared -O2 -Wall -Wextra -Wformat -Wformat-security \
      -o libnix-ld-cache-audit.so nix-ld-cache-audit.c -pthread
    $CC -D_GNU_SOURCE -O2 -Wall -Wextra -Wformat -Wformat-security \
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
    cp README.md $out/share/doc/nix-ld-cache/
    runHook postInstall
  '';

  meta = with lib; {
    description = "LD_AUDIT-based resolver cache for Nix store binaries";
    platforms = platforms.linux;
    license = licenses.mit;
    maintainers = [ ];
  };
}
