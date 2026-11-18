#!/usr/bin/env python3
"""Locate and patch both unsigned-module rejection sites in an ARM64 kernel image.

Anchored on the unique `module verification failed` printk literal, then:
  1. require exactly one such string in the image;
  2. require exactly one ADRP+ADD xref to it;
  3. require exactly one add_taint(13, 0) call sequence near the xref;
  4. require exactly one -ENOKEY materialisation near the xref.

Every step is decoded and counted. Any ambiguity aborts with exit 1 - the
tool never guesses which bytes to write. Exit 0 on success or already-patched,
64 on bad usage. Nothing is flashed automatically.
"""
import sys

VERIFY = b"module verification failed"


def sx(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def find_all(data, needle):
    out, pos = [], 0
    while True:
        i = data.find(needle, pos)
        if i < 0:
            return out
        out.append(i)
        pos = i + 1


def xrefs(data, page, low):
    out = []
    for i in range(0, len(data) - 3, 4):
        w = int.from_bytes(data[i:i + 4], "little")
        if (w & 0x9F000000) != 0x90000000:
            continue
        imm = ((((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3))
        imm = sx(imm, 21) << 12
        if ((i & ~0xFFF) + imm) != page:
            continue
        for k in range(1, 25):
            j = i + 4 * k
            if j + 4 > len(data):
                break
            w2 = int.from_bytes(data[j:j + 4], "little")
            if (w2 & 0x1F000000) == 0x11000000 and ((w2 >> 10) & 0xFFF) == low:
                out.append((i, j))
    return out


def movz_imm13_rd(w):
    """If w decodes as `mov wRd, #13` or `mov wRd, #0` (the post-patch form),
    return Rd, else None."""
    imm = (w >> 5) & 0xFFFF
    if (w & 0xFF800000) == 0x52800000 and imm in (13, 0):
        return w & 0x1F
    return None

def movz_imm_of(w):
    return (w >> 5) & 0xFFFF


def movn_imm125_rd(w):
    """If w decodes as `movn x/wRd, #125` (any width, hw=0), return (Rd, is64), else None."""
    if ((w >> 5) & 0xFFFF) == 125:
        if (w & 0xFF000000) == 0x92000000:  # MOVN 64-bit
            return (w & 0x1F, True)
        if (w & 0xFF000000) == 0x12000000:  # MOVN 32-bit
            return (w & 0x1F, False)
    return None


def taint_sites(data, lo, hi):
    """Find add_taint(13, 0) call sequences; return (offset, Rd) pairs."""
    out = []
    for i in range(lo, hi - 8, 4):
        w = int.from_bytes(data[i:i + 4], "little")
        w2 = int.from_bytes(data[i + 4:i + 8], "little")
        if w2 != 0x2A1F03E1:  # mov w1, wzr
            continue
        rd = movz_imm13_rd(w)
        if rd is not None:
            out.append((i, rd, movz_imm_of(w)))
    return out


def enokey_sites(data, lo, hi):
    out = []
    for i in range(lo, hi - 3, 4):
        w = int.from_bytes(data[i:i + 4], "little")
        d = movn_imm125_rd(w)
        if d is not None:
            out.append((i, d))  # (Rd, is64)
    return out


def main(argv):
    if not argv or "-h" in argv or "--help" in argv:
        print(__doc__)
        return 0 if argv else 64
    try:
        with open(argv[0], "rb") as f:
            data = bytearray(f.read())
    except OSError as e:
        print(f"patch: cannot read {argv[0]}: {e.strerror or e}", file=sys.stderr)
        return 1
    strs = find_all(data, VERIFY)
    if len(strs) != 1:
        print(f"patch: expected 1 verification string, got {len(strs)}", file=sys.stderr)
        return 1
    fmt = strs[0] - 6  # \x01 + level char + "%s: "
    refs = xrefs(data, fmt & ~0xFFF, fmt & 0xFFF)
    if len(refs) != 1:
        print(f"patch: expected 1 string xref, got {len(refs)}", file=sys.stderr)
        return 1
    xref = refs[0][0]
    lo, hi = max(0, xref - 0x2000), min(len(data), xref + 0x1000)
    taints = taint_sites(data, lo, hi)
    errors = enokey_sites(data, lo, hi)
    if len(taints) == 1 and taints[0][2] == 0 and not errors:
        print("patch: already patched (taint zero present, no -ENOKEY site)")
        return 0
    if len(taints) != 1:
        print(f"patch: expected 1 taint call near xref, got {len(taints)}", file=sys.stderr)
        return 1
    if not errors:
        print("patch: no -ENOKEY site near xref", file=sys.stderr)
        return 1
    # The compiler may tail-duplicate the error arm (e.g. LG V50 has two
    # identical movn x21,#125). Patch either every copy or none.
    if len(set(d for _, d in errors)) != 1:
        print(f"patch: -ENOKEY sites differ: {[(hex(o), d) for o, d in errors]}", file=sys.stderr)
        return 1
    t_imm = taints[0][2]
    e_rd = errors[0][1][0]

    if t_imm != 13:
        print(f"patch: taint site at 0x{taints[0][0]:X} holds 0 but -ENOKEY sites remain; refusing a mixed image", file=sys.stderr)
        return 1
    t_off, t_rd = taints[0][0], taints[0][1]
    plan = [(t_off, 0x52800000 | t_rd, movz_imm13_rd)]
    for off, _ in errors:
        plan.append((off, 0x52800000 | e_rd, lambda w: (w & 0x1F) if movn_imm125_rd(w) else None))

    already = 0
    edits = []
    for off, new_w, decode in plan:
        cur = int.from_bytes(data[off:off + 4], "little")
        if cur == new_w:
            already += 1
            continue
        if decode(cur) is None:
            print(f"patch: unexpected bytes at 0x{off:X}: {cur:08x}", file=sys.stderr)
            return 1
        edits.append((off, new_w))
    for off, new_w in edits:
        data[off:off + 4] = new_w.to_bytes(4, "little")

    out = argv[0] + ".patched"
    open(out, "wb").write(data)
    state = "already patched" if already == len(plan) else "patched"
    print(f"patch: xref=0x{xref:X} taint=0x{t_off:X} err={[hex(o) for o, _ in errors]}")
    print(f"patch: {state} -> {out} (repack manually; nothing is flashed)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
