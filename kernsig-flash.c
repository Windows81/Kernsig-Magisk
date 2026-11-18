/* kernsig-flash - locate and patch both unsigned-module rejection sites in an
 * ARM64 kernel image. Port of patch-kernel.py, single file, no dependencies.
 *
 * Anchored on the unique `module verification failed` printk literal, then:
 *   1. require exactly one such string in the image;
 *   2. require exactly one ADRP+ADD xref to it;
 *   3. require exactly one add_taint(13, 0) call sequence near the xref;
 *   4. require one or more, all identical, -ENOKEY materialisations near it.
 *
 * Any step that is missing or ambiguous aborts without writing anything.
 * Exit 0 on success or already-patched, 1 on any mismatch, 64 on bad usage.
 * Writes a sibling .patched file; nothing is flashed automatically.
 */
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const unsigned char VERIFY[] = "module verification failed";
#define VLEN (sizeof(VERIFY) - 1)
#define WIN_BACK  0x2000
#define WIN_FWD   0x1000

static uint64_t sx21(uint64_t v, int bits) {
    uint64_t sign = 1ULL << (bits - 1);
    return (v & sign) ? v | (~0ULL << bits) : v;
}

static uint32_t rd32(const unsigned char *p) {
    uint32_t w;
    memcpy(&w, p, 4);
    return w;
}

static int is_adrp(uint32_t w, uint64_t *imm) {
    if ((w & 0x9F000000u) != 0x90000000u) return 0;
    uint64_t immlo = (w >> 29) & 0x3;
    uint64_t immhi = (w >> 5) & 0x7FFFF;
    uint64_t v = (immhi << 2) | immlo;
    v = sx21(v & 0x1FFFFF, 21);
    *imm = v << 12;
    return 1;
}

static int is_add_imm(uint32_t w, uint32_t low12) {
    if ((w & 0x1F000000u) != 0x11000000u) return 0;
    return ((w >> 10) & 0xFFFu) == low12;
}

/* MOVZ 32-bit, hw=0, imm16 in {0,13} -> Rd, or -1. 13 = TAINT_UNSIGNED_MODULE;
 * 0 is the post-patch form, so a re-run can recognise its own work. */
static int movz_imm13_rd(uint32_t w) {
    unsigned imm = (w >> 5) & 0xFFFFu;
    if ((w & 0xFF800000u) == 0x52800000u && (imm == 13 || imm == 0))
        return (int)(w & 0x1Fu);
    return -1;
}

/* MOVN (32/64-bit), hw=0, imm16==125 -> Rd, else -1. 125's ones-complement is
 * 0x...FFFFFF82, i.e. -ENOKEY (errno 126). */
static int movn_imm125_rd(uint32_t w) {
    if (((w >> 5) & 0xFFFFu) != 125) return -1;
    if ((w & 0xFF000000u) == 0x92000000u) return (int)(w & 0x1Fu);  /* 64-bit */
    if ((w & 0xFF000000u) == 0x12000000u) return (int)(w & 0x1Fu);  /* 32-bit */
    return -1;
}

struct sites { size_t off[64]; int rd[64]; int imm[64]; size_t n; };

static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static int taint_sites(const unsigned char *d, size_t lo, size_t hi, struct sites *out) {
    out->n = 0;
    for (size_t i = lo; i + 8 <= hi; i += 4) {
        uint32_t w = rd32(d + i);
        if (rd32(d + i + 4) != 0x2A1F03E1u) continue;      /* mov w1, wzr */
        int rd = movz_imm13_rd(w);
        if (rd < 0) continue;
        if (out->n == 64) die("patch: too many taint candidates near xref");
        out->off[out->n] = i; out->rd[out->n] = rd;
        out->imm[out->n] = (int)((w >> 5) & 0xFFFFu); out->n++;
    }
    return 0;
}

static int enokey_sites(const unsigned char *d, size_t lo, size_t hi, struct sites *out) {
    out->n = 0;
    for (size_t i = lo; i + 4 <= hi; i += 4) {
        int rd = movn_imm125_rd(rd32(d + i));
        if (rd < 0) continue;
        if (out->n == 64) die("patch: too many -ENOKEY candidates near xref");
        out->off[out->n] = i; out->rd[out->n] = rd; out->n++;
    }
    return 0;
}

static int all_same_rd(const struct sites *s) {
    for (size_t i = 1; i < s->n; i++)
        if (s->rd[i] != s->rd[0]) return 0;
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 2 || strstr(argv[1], "-h") || strstr(argv[1], "--help")) {
        fprintf(stderr,
            "kernsig-flash KERNEL.bin\n"
            "Locates and patches both unsigned-module rejection sites, anchored on the\n"
            "'module verification failed' literal. Writes KERNEL.bin.patched.\n"
            "Exit 0 ok, 1 refused, 64 bad usage. Nothing is flashed.\n");
        return argc == 2 ? 0 : 64;
    }
    const char *path = argv[1];
    FILE *f = fopen(path, "rb");
    if (!f) die("kernsig-flash: cannot open %s", path);
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || (uint64_t)sz < 0x2000) die("kernsig-flash: image too small");
    unsigned char *d = malloc(sz);
    if (!d) die("kernsig-flash: out of memory");
    if (fread(d, 1, sz, f) != (size_t)sz) die("kernsig-flash: short read");
    fclose(f);

    /* 1. unique verification string */
    size_t str_off = (size_t)-1, count = 0;
    for (size_t i = 0; i + VLEN <= (size_t)sz; i++)
        if (memcmp(d + i, VERIFY, VLEN) == 0) { count++; str_off = i; }
    if (count != 1) die("patch: expected 1 verification string, got %zu", count);
    if (str_off < 6) die("patch: verification string too close to start");

    /* 2. unique code xref to it (fmt literal is strlen+6 before it) */
    size_t fmt = str_off - 6;
    uint64_t page = fmt & ~0xFFFULL, low = fmt & 0xFFFULL;
    size_t xref = (size_t)-1;
    for (size_t i = 0; i + 4 <= (size_t)sz; i += 4) {
        uint64_t imm;
        if (!is_adrp(rd32(d + i), &imm)) continue;
        if ((i & ~0xFFFULL) + imm != page) continue;
        for (size_t k = 1; k < 25 && i + 4 * k + 4 <= (size_t)sz; k++) {
            if (is_add_imm(rd32(d + i + 4 * k), (uint32_t)low)) {
                if (xref != (size_t)-1)
                    die("patch: expected 1 string xref, got at least 2 (0x%zx, 0x%zx)", xref, i);
                xref = i;
                break;
            }
        }
    }
    if (xref == (size_t)-1) die("patch: no string xref found");

    /* 3. unique add_taint(13, 0) call near the xref */
    size_t lo = xref > WIN_BACK ? xref - WIN_BACK : 0;
    size_t hi = xref + WIN_FWD < (size_t)sz ? xref + WIN_FWD : (size_t)sz;
    struct sites taint, err;
    taint_sites(d, lo, hi, &taint);

    /* 4. all -ENOKEY copies must be identical (err arm may be duplicated) */
    enokey_sites(d, lo, hi, &err);

    if (taint.n == 1 && taint.imm[0] == 0 && err.n == 0) {
        printf("patch: already patched (taint zero present, no -ENOKEY site)\n");
        free(d);
        return 0;
    }
    if (taint.n != 1)
        die("patch: expected 1 taint call near xref, got %zu", taint.n);
    if (err.n == 0) die("patch: no -ENOKEY site near xref");
    if (!all_same_rd(&err))
        die("patch: -ENOKEY sites differ in register");

    /* verify every site before writing anything */
    if (taint.imm[0] != 13)
        die("patch: taint site at 0x%zx holds 0 but -ENOKEY sites remain; refusing a mixed image", taint.off[0]);

    size_t t_off = taint.off[0];
    size_t already = 0;
    uint32_t t_new = 0x52800000u | (uint32_t)taint.rd[0];
    if (rd32(d + t_off) == t_new) already++;
    else if (movz_imm13_rd(rd32(d + t_off)) < 0)
        die("patch: unexpected bytes at 0x%zx: %08x", t_off, rd32(d + t_off));
    for (size_t i = 0; i < err.n; i++) {
        uint32_t e_new = 0x52800000u | (uint32_t)err.rd[i];
        if (rd32(d + err.off[i]) == e_new) already++;
        else if (movn_imm125_rd(rd32(d + err.off[i])) < 0)
            die("patch: unexpected bytes at 0x%zx: %08x", err.off[i], rd32(d + err.off[i]));
    }

    /* write */
    uint32_t *p = (uint32_t *)(d + t_off);
    if (rd32(d + t_off) != t_new) *p = t_new;
    for (size_t i = 0; i < err.n; i++) {
        uint32_t e_new = 0x52800000u | (uint32_t)err.rd[i];
        uint32_t *q = (uint32_t *)(d + err.off[i]);
        if (rd32(d + err.off[i]) != e_new) *q = e_new;
    }

    char out_path[4096];
    snprintf(out_path, sizeof(out_path), "%s.patched", path);
    FILE *o = fopen(out_path, "wb");
    if (!o) die("kernsig-flash: cannot write %s", out_path);
    fwrite(d, 1, sz, o);
    fclose(o);

    printf("patch: xref=0x%zx taint=0x%zx err=[", xref, t_off);
    for (size_t i = 0; i < err.n; i++) printf("%s0x%zx", i ? ", " : "", err.off[i]);
    printf("]\npatch: %s -> %s (repack manually; nothing is flashed)\n",
           already == err.n + 1 ? "already patched" : "patched", out_path);
    return 0;
}
