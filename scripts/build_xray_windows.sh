#!/usr/bin/env bash
#
# Builds the trimmed Xray core plus the tun2socks bridge as vless_core.exe.
#
# Output goes to Artifacts/, published alongside XRay.xcframework and XRay.aar
# so one release pins every platform to the same Xray-core version.
#
# No cgo and no gomobile, unlike the other two: this cross-compiles from macOS
# or Linux, so it needs no Windows runner.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE="$ROOT/third_party/xray-mobile"
OUT="$ROOT/Artifacts"
# amd64 only, matching the architecture wireguard_dart ships its service for.
# The consuming app has no arm64 Windows build to pair it with.
ARCH="${ARCH:-amd64}"

mkdir -p "$OUT"
cd "$MODULE"

echo "==> building vless_core.exe (windows/$ARCH)"
# -s -w strips the symbol and DWARF tables, matching the Android build; the
# binary carries a whole TCP/IP stack and the tables are most of what is left
# after that.
CGO_ENABLED=0 GOOS=windows GOARCH="$ARCH" go build \
  -trimpath \
  -ldflags="-s -w" \
  -o "$OUT/vless_core.exe" \
  ./cmd/vless_core

echo "==> wrote $OUT/vless_core.exe ($(du -h "$OUT/vless_core.exe" | cut -f1))"

# Fetched here as well as in CI so a local build produces everything the plugin
# needs: it resolves both files from this directory when no release carries
# them yet. Pinned by hash, not just version — this is the one dependency from
# outside GitHub, and it is a kernel driver.
WINTUN_VERSION="${WINTUN_VERSION:-0.14.1}"
WINTUN_SHA256="07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"

if [ ! -f "$OUT/wintun.dll" ]; then
  echo
  echo "==> fetching wintun $WINTUN_VERSION"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  curl -sSLf -o "$tmp/wintun.zip" \
    "https://www.wintun.net/builds/wintun-${WINTUN_VERSION}.zip"
  echo "${WINTUN_SHA256}  ${tmp}/wintun.zip" | shasum -a 256 -c - >/dev/null
  # Loaded by LoadLibraryEx with LOAD_LIBRARY_SEARCH_APPLICATION_DIR, so it
  # resolves next to whichever executable loads it — vless_core.exe, not the
  # Flutter runner. The plugin bundles both, which keeps them together.
  unzip -joq "$tmp/wintun.zip" "wintun/bin/${ARCH}/wintun.dll" -d "$OUT"
fi

echo
echo "==> wrote $OUT/wintun.dll ($(du -h "$OUT/wintun.dll" | cut -f1))"
