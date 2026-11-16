#!/usr/bin/env bash
#
# Builds the trimmed Xray core plus the tun2socks bridge as XRay.aar.
#
# Output goes to Artifacts/, published alongside XRay.xcframework so one
# release pins both platforms to the same Xray-core version.
#
# Requires the Android NDK. The ABIs match the app's abiFilters; building the
# ones it filters out only inflates the aar.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE="$ROOT/third_party/xray-mobile"
OUT="$ROOT/Artifacts"
# Matches minSdkVersion in the consuming app. A lower floor would let gomobile
# emit calls the app's own manifest says will never be available.
ANDROID_API="${ANDROID_API:-26}"
# Must match the app's ndkVersion. A different NDK links a different libc++.
NDK_VERSION="${NDK_VERSION:-28.2.13676358}"

export PATH="/opt/homebrew/bin:$PATH"
export PATH="$PATH:$(go env GOPATH)/bin"

NDK="${ANDROID_NDK_HOME:-$HOME/Library/Android/sdk/ndk/$NDK_VERSION}"
if [ ! -d "$NDK" ]; then
  echo "error: Android NDK not found at $NDK" >&2
  echo "  export ANDROID_NDK_HOME, or install NDK $NDK_VERSION via the SDK manager" >&2
  exit 1
fi
export ANDROID_NDK_HOME="$NDK"

# `gomobile version` reports "binary is out of date" even when bind works, so
# check for the binary rather than trusting its self-report.
command -v gomobile >/dev/null || { echo "error: gomobile not installed" >&2; exit 1; }


case "$(uname -s)" in
  Darwin) HOST_TAG="darwin-x86_64" ;;
  Linux)  HOST_TAG="linux-x86_64" ;;
  *) echo "error: unsupported host $(uname -s)" >&2; exit 1 ;;
esac

# gomobile stats this one clang once per Android arch it knows, regardless of
# -target, and blames whichever arch its map happens to yield first. A missing
# file therefore surfaces as a baffling "No compiler for 386". Check it here so
# the real problem is the thing that gets reported.
CLANG="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/bin/clang"
if [ ! -x "$CLANG" ]; then
  echo "error: NDK clang not found at $CLANG" >&2
  echo "  this NDK looks incomplete; it contains:" >&2
  ls -1 "$NDK" >&2 2>/dev/null || echo "    (cannot list $NDK)" >&2
  ls -1 "$NDK/toolchains/llvm/prebuilt" >&2 2>/dev/null || true
  exit 1
fi

mkdir -p "$OUT"
cd "$MODULE"

# Android 15 runs a 16 KB page size. A library aligned to the old 4 KB refuses
# to load there, and the failure is a crash at dlopen rather than a build
# error, so the alignment is verified below instead of assumed.
echo "==> building XRay.aar (api $ANDROID_API)"
gomobile bind -a \
  -target=android/arm,android/arm64,android/amd64 \
  -androidapi "$ANDROID_API" \
  -ldflags="-s -w -extldflags=-Wl,-z,max-page-size=16384" \
  -o "$OUT/XRay.aar" .

echo
echo "==> verifying 16 KB page alignment"
# Parses the ELF program headers rather than shelling out: llvm-readelf sits at
# a different path on every NDK layout, and unzip is absent from some build
# images. Both produced a silent failure in CI.
python3 "$ROOT/scripts/verify_aar_alignment.py" "$OUT/XRay.aar" \
  armeabi-v7a arm64-v8a x86_64

echo
echo "==> wrote $OUT/XRay.aar"
