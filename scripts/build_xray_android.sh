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
  Darwin) TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/darwin-x86_64" ;;
  Linux)  TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64" ;;
  *) echo "error: unsupported host $(uname -s)" >&2; exit 1 ;;
esac

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
READELF="$TOOLCHAIN/bin/llvm-readelf"
if [ ! -x "$READELF" ]; then
  echo "error: llvm-readelf not found at $READELF" >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
unzip -q "$OUT/XRay.aar" -d "$WORK"

rc=0
for abi in armeabi-v7a arm64-v8a x86_64; do
  so="$WORK/jni/$abi/libgojni.so"
  if [ ! -f "$so" ]; then
    echo "   FAIL $abi: libgojni.so missing from the aar" >&2
    rc=1
    continue
  fi
  align="$("$READELF" -l "$so" | awk '/LOAD/{print $NF; exit}')"
  if [ "$align" != "0x4000" ]; then
    echo "   FAIL $abi: LOAD alignment $align, expected 0x4000" >&2
    rc=1
    continue
  fi
  echo "   ok   $abi: alignment $align"
done
if [ "$rc" -ne 0 ]; then
  echo "   the aar would crash at dlopen on a 16 KB-page device" >&2
  exit 1
fi

echo
echo "==> wrote $OUT/XRay.aar"
