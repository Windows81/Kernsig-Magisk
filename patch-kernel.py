#!/usr/bin/env python3
"""Patch a Surface Duo ARM64 kernel image to accept unsigned modules.

Offline patcher: unpack boot.img yourself (magiskboot unpack), pass the
extracted `kernel` file here, then repack. Nothing is flashed automatically.
Exit 0 on success or when already patched, 1 on mismatch, 64 on bad usage.
"""
import os
import sys

BASES = [0x100B5C, 0x100B24]
ORIG = [bytes.fromhex("b40f8092"), bytes.fromhex("c2010035")]
PATCH = [bytes.fromhex("800280d2"), bytes.fromhex("0e000014")]
LABELS = ["err=-ENOKEY -> err=0", "cbnz w2 -> b (skip check)"]


def read(path):
    with open(path, "rb") as f:
        return bytearray(f.read())


def main(argv):
    if not argv or "-h" in argv or "--help" in argv:
        print(__doc__)
        return 0 if argv else 64
    path = argv[0]
    data = read(path)
    if len(data) < BASES[-1] + 4:
        print("patch-kernel: image too short", file=sys.stderr)
        return 1
    done = []
    for off, orig, new, label in zip(BASES, ORIG, PATCH, LABELS):
        cur = bytes(data[off:off + 4])
        if cur == orig:
            data[off:off + 4] = new
            done.append("patched " + label)
        elif cur == new:
            done.append("already " + label)
        else:
            print(f"patch-kernel: unexpected bytes at 0x{off:X}: {cur.hex()} (expected {orig.hex()})", file=sys.stderr)
            return 1
    out = path + ".patched"
    with open(out, "wb") as f:
        f.write(data)
    for line in done:
        print("patch-kernel: " + line)
    print("patch-kernel: wrote " + out + " (repack manually; no auto-flash)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
