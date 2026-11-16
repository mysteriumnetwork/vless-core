#!/usr/bin/env python3
"""Checks that every native library in an aar is 16 KB page aligned.

Android 15 runs a 16 KB page size and refuses to load a library aligned to the
old 4 KB one. The failure is a crash at dlopen, not a build error, so it is
verified here rather than assumed.

Reads the ELF program headers directly: llvm-readelf lives at a different path
on every NDK layout, and unzip is not on every build image.
"""

import struct
import sys
import zipfile

EXPECTED_ALIGN = 0x4000
PT_LOAD = 1


def load_alignments(blob: bytes) -> list[int]:
    """Program-header alignments of the PT_LOAD segments in a 32/64-bit ELF."""
    if blob[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    is_64 = blob[4] == 2
    little = blob[5] == 1
    end = "<" if little else ">"

    if is_64:
        e_phoff, e_phentsize, e_phnum = (
            struct.unpack_from(end + "Q", blob, 0x20)[0],
            struct.unpack_from(end + "H", blob, 0x36)[0],
            struct.unpack_from(end + "H", blob, 0x38)[0],
        )
        type_off, align_off, fmt = 0, 0x30, end + "Q"
    else:
        e_phoff, e_phentsize, e_phnum = (
            struct.unpack_from(end + "I", blob, 0x1C)[0],
            struct.unpack_from(end + "H", blob, 0x2A)[0],
            struct.unpack_from(end + "H", blob, 0x2C)[0],
        )
        type_off, align_off, fmt = 0, 0x1C, end + "I"

    alignments = []
    for i in range(e_phnum):
        base = e_phoff + i * e_phentsize
        p_type = struct.unpack_from(end + "I", blob, base + type_off)[0]
        if p_type == PT_LOAD:
            alignments.append(struct.unpack_from(fmt, blob, base + align_off)[0])
    return alignments


def main(aar_path: str, abis: list[str]) -> int:
    failures = 0
    with zipfile.ZipFile(aar_path) as aar:
        names = set(aar.namelist())
        for abi in abis:
            entry = f"jni/{abi}/libgojni.so"
            if entry not in names:
                print(f"   FAIL {abi}: {entry} missing from the aar", file=sys.stderr)
                failures += 1
                continue
            try:
                alignments = load_alignments(aar.read(entry))
            except ValueError as exc:
                print(f"   FAIL {abi}: {exc}", file=sys.stderr)
                failures += 1
                continue
            if not alignments:
                print(f"   FAIL {abi}: no PT_LOAD segments", file=sys.stderr)
                failures += 1
                continue
            worst = min(alignments)
            if worst < EXPECTED_ALIGN:
                print(
                    f"   FAIL {abi}: LOAD alignment {hex(worst)}, "
                    f"expected at least {hex(EXPECTED_ALIGN)}",
                    file=sys.stderr,
                )
                failures += 1
                continue
            print(f"   ok   {abi}: alignment {hex(worst)}")

    if failures:
        print("   the aar would crash at dlopen on a 16 KB-page device", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: verify_aar_alignment.py <aar> <abi>...", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1], sys.argv[2:]))
