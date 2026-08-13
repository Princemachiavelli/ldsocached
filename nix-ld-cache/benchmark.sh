#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/../.." && pwd)

audit_so="${NIX_LD_AUDIT_SO:-$repo_root/result/lib/libnix-ld-cache-audit.so}"
if [[ $# -gt 1 && $1 == "--audit-so" ]]; then
  audit_so=$2
  shift 2
fi

if [[ $# -lt 1 ]]; then
  echo "usage: $0 [--audit-so /path/to/libnix-ld-cache-audit.so] command [args...]" >&2
  exit 1
fi

if [[ $1 == "--" ]]; then
  shift
fi

cmd=("$@")
target=$(command -v -- "${cmd[0]}" || true)
if [[ -z "$target" ]]; then
  echo "command not found: ${cmd[0]}" >&2
  exit 1
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

if [[ ! -f "$audit_so" ]]; then
  echo "building nix-ld-cache package"
  out_file="$tmpdir/build.out"
  nix build ".#nix-ld-cache" --no-link --print-out-paths >"$out_file"
  audit_pkg=$(tail -n1 "$out_file")
  audit_so="$audit_pkg/lib/libnix-ld-cache-audit.so"
fi

if ! command -v strace >/dev/null 2>&1; then
  echo "strace not found; run: nix shell \"nixpkgs#strace\" \"nixpkgs#ripgrep\"" >&2
  exit 1
fi

if ! command -v rg >/dev/null 2>&1; then
  echo "ripgrep not found; run: nix shell \"nixpkgs#strace\" \"nixpkgs#ripgrep\"" >&2
  exit 1
fi

baseline_log="$tmpdir/baseline.log"
cold_log="$tmpdir/cold.log"
warm_log="$tmpdir/warm.log"
cache_dir="$tmpdir/cache"
mkdir -p "$cache_dir"

echo "target: $target"
printf 'command:'
printf ' %q' "${cmd[@]}"
printf '\n'
echo "audit_so: $audit_so"
echo "cache_dir: $cache_dir"

env -u LD_AUDIT -u NIX_LD_AUDIT_CACHE_DIR -u NIX_LD_AUDIT_DEBUG \
  strace -f -qq -o "$baseline_log" -e trace=%file "${cmd[@]}"

env LD_AUDIT="$audit_so" NIX_LD_AUDIT_CACHE_DIR="$cache_dir" \
  strace -f -qq -o "$cold_log" -e trace=%file "${cmd[@]}"

env LD_AUDIT="$audit_so" NIX_LD_AUDIT_CACHE_DIR="$cache_dir" \
  strace -f -qq -o "$warm_log" -e trace=%file "${cmd[@]}"

summarize() {
  local label=$1
  local log=$2
  local open_enoent stat_enoent statx_enoent hwcaps_enoent

  open_enoent=$(rg -c 'openat\(.*= -1 ENOENT' "$log" || true)
  stat_enoent=$(rg -c 'newfstatat\(.*= -1 ENOENT' "$log" || true)
  statx_enoent=$(rg -c 'statx\(.*= -1 ENOENT' "$log" || true)
  hwcaps_enoent=$(rg -c 'glibc-hwcaps/.+= -1 ENOENT' "$log" || true)

  printf '%-8s openat_enoent=%s newfstatat_enoent=%s statx_enoent=%s glibc_hwcaps_enoent=%s\n' \
    "$label" "$open_enoent" "$stat_enoent" "$statx_enoent" "$hwcaps_enoent"
}

echo
summarize baseline "$baseline_log"
summarize cold "$cold_log"
summarize warm "$warm_log"

echo
echo "logs:"
echo "  $baseline_log"
echo "  $cold_log"
echo "  $warm_log"

echo
echo "top warm ENOENT paths:"
rg 'ENOENT' "$warm_log" | sed -E 's/^[0-9]+ //' | sort | uniq -c | sort -nr | head -20
