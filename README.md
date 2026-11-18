# KernSig Research

A small package from the headless Talon work, built by Hy4 through live REPL analysis of a Surface Duo kernel. It documents and demonstrates one thing: how the kernel's unsigned-module rejection is wired, and the edits that turn it into an acceptance path. It is a research artefact for a device you own, not a turnkey bypass for arbitrary phones.

The analysis went through the source first and the disassembly second. The source side was edited only to make the two edits visible against source; it was never compiled and is an illustration, not the mechanism. The device is patched by rewriting instructions.

## How the source edits map to the assembly edits

- `int err = -ENOKEY;` ([module.c:2791](https://github.com/microsoft/surface-duo-oss-kernel.msm-4..14/blob/msm-4.14/kernel/module.c#L2791)) → the Duo build materialises −ENOKEY inside the error arm at `0x100b5c` as `movn x20, #125`. The tool rewrites it as `mov w20, #0` — the same edit, placed where the compiler put the constant. This accepts the module unconditionally.
- `if (flags == 0 && …` ([module.c:2799](https://github.com/microsoft/surface-duo-oss-kernel.msm-4..14/blob/msm-4.14/kernel/module.c#L2799)) → the flags half of that guard compiled to `cbnz w2, 0x100b5c` at `0x100b24`. Making it an unconditional `b 0x100b5c` is the same edit as `if (0 && …)`; the marker block is never entered and the loader falls to the non-strict `err == -ENOKEY && !sig_enforce` path ([module.c:2813](https://github.com/microsoft/surface-duo-oss-kernel.msm-4..14/blob/msm-4.14/kernel/module.c#L2813)), which accepts the module when signature enforcement is off (the default).
- The warning the kernel prints for an unsigned module comes from an `add_taint(13, 0)` call in the error path, compiled at `0x10155c` as `mov w23, #13`. Zeroing that constant clears the `TAINT_UNSIGNED_MODULE` flag (13). There is no single source line for this call — it is inlined from `module.c`'s error arm — so it cannot be expressed in the source patch.

`patches/source-c.patch` shows the two source edits for readability. `patches/assembly.patch` shows the two assembly edits with real encodings (`0x1400000e` for `b 0x100b5c`, `0x52800014` for `mov w20, #0`). One of the first two edits is enough to accept the module; the tool applies the `0x100b5c` zero plus the `0x10155c` zero, which accepts the module and silences the warning.

## The exact functions and blocks

`module_sig_check`, from the `msm-4.14` branch (the analysis copy was byte-identical to that branch, `sha256 a4e4f99f5…`):

```c
/* kernel/module.c, L2789–L2814 — the two edits are marked */
static int module_sig_check(struct load_info *info, int flags)
{
	int err = -ENOKEY;                      /* edit 1: -> 0 */
	const unsigned long markerlen = sizeof(MODULE_SIG_STRING) - 1;
	const void *mod = info->hdr;

	/*
	 * Require flags == 0, as a module with version information
	 * removed is no longer the module that was signed
	 */
	if (flags == 0 &&                      /* edit 2: -> if (0 && … */
	    info->len > markerlen &&
	    memcmp(mod + info->len - markerlen, MODULE_SIG_STRING, markerlen) == 0) {
		/* We truncate the module to discard the signature */
		info->len -= markerlen;
		err = mod_verify_sig(mod, &info->len);
	}

	if (!err) {
		info->sig_ok = true;                 /* L2809: acceptance path */
		return 0;
	}
```

```c
/* include/linux/module.h, L28 */
#define MODULE_SIG_STRING "~Module signature appended~\n"
```

| Offset | Original | Patched | Source edit |
| --- | --- | --- | --- |
| `0x100b24` | `cbnz w2, 0x100b5c` | `b 0x100b5c` | edit 2 |
| `0x100b5c` | `movn x20, #125` (−ENOKEY) | `mov w20, #0` | edit 1 |
| `0x10155c` | `mov w23, #13` (`TAINT_UNSIGNED_MODULE`) | `mov w23, #0` | not expressible there |

`patch-kernel.py` locates the `0x100b5c` and `0x10155c` sites from the `module verification failed` string: one unique string, one unique code xref, one unique `add_taint(13, 0)` call, and one unique −ENOKEY site. Any step that is missing or ambiguous aborts with an error, so the tool never guesses where to write. It has been objdump-verified on the Surface Duo kernel, and both tools are rerun-safe (a re-run reports `already patched`). The LG V50 build has two identical −ENOKEY sites (the compiler tail-duplicated the error arm); the locator patches any number of byte-identical sites or none. The Samsung A54/A35 builds materialise −ENOKEY differently and are refused rather than patched; kernels without the verification string have nothing to patch. Unpack `boot.img` yourself, run the script on the `kernel` file, inspect the result, and repack and flash only if you choose — nothing is flashed automatically.

## Which kernels work

Tested on seven Android kernel images (all raw ARM64). The locator refuses any image it cannot uniquely decode. "Works" means both patch sites were found and rewritten and the output was verified with objdump.

| Kernel | verify string | Locator result | Topology |
| --- | --- | --- | --- |
| Surface Duo (build 2022.902.48, msm-4.14) | present @`0x186d0f1` | both sites patched; repacked kernel sha256 `55e1e3bf…` verified end-to-end | `cbnz w2`@`0x100b24` → error arm · `b.cc`@`0x100b38` → error arm · `cbz w0`@`0x100b58` → success |
| LG V50 (4.14.355 OpenELA; community rebuild of LG source, **NOT stock firmware**) | present @`0x25e3fd4` | both sites patched (two identical −ENOKEY copies, both rewritten); output byte-identical between the Python and C tools | same three-branch shape: `cbnz w2`@`0xf464c` · `b.cc`@`0xf465c` · `cbz w0`@`0xf4684` |
| Samsung A54 (SM-A546B, PE/EFI stub; supplied by user) | present @`0x17a733b` | refused: no marker xref, no `MOVN #125` (−ENOKEY) near the xref | unverifiable (no anchor) |
| Samsung A35 (SM-A356E, OneUI8 KSUN GKI; community repack, **NOT stock firmware**) | present @`0x18622af` | refused: no marker xref, no `MOVN #125` near the xref | unverifiable |
| Samsung S22 (SM-S901E, OneUI8 KSUN GKI) | absent | refused | — |
| Motorola Razr Fold (2026) | absent | refused | — |
| LineageOS 24.0 (Galaxy S23 FE, GKI) | absent | refused | — |

Notes:

- GKI kernels (i.e. everything except the Duo and the LG V50 build) either carry no verification string at all (S22, Razr Fold, LineageOS) or carry the string without a code path this locator can anchor on with certainty (A54, A35).
- "Works" describes the tested image only. Community rebuilds and repacks are not verified stock firmware for those devices.
- The three-branch topology (flags guard → length guard → memcmp==0 → success) is confirmed on exactly two kernels (Duo, LG V50). A `cmp x8, #28/29` byte scan across the A54/A35 images returned hundreds of hits and is not a valid discriminator, so those two remain unverified rather than absent.

## On the phone

`kernsig-flash` is the same locator as single-file C, built as a static aarch64 binary that runs on a stock Android (no Python, no libraries). Build it yourself with `gcc -O2 -static -o kernsig-flash kernsig-flash.c`, or use the prebuilt `kernsig-flash` committed at the repo root (`sha256 20845ec4232863a711df4e95fe3385a7adee9a41c11f752090f91268a1207448`). It exits 0 on success (or when the image already carries the patch), 1 on any mismatch or ambiguity, and writes `KERNEL.bin.patched` next to the input.

`kernsig-flash-android.zip` (`sha256 b5db361357af91948bce245849fc3a344464fa9b9492e91748e2d1febd4056d5`) is the same tool packaged as an on-device kit: `flash.sh`, `kernsig-flash` and `INSTALL.txt`. On a rooted phone it unpacks your boot image with Magisk's `magiskboot`, patches the kernel, repacks, then unpacks the result again and compares the kernel against the patched one as a built-in proof. It never writes to a block device and never flashes for you — flashing the patched image is a manual step (`fastboot flash boot_a boot_a.patched.img`, or `boot_b`, or your recovery's image-flash feature). Verified end-to-end against a copy of the Surface Duo `boot_a.img`: the kernel inside the repacked image is byte-identical to the one the binary patches directly.

Caveats: rooted device with an unlocked bootloader only. A/B slots mean you must flash the correct slot. Android 13+ split-GKI devices may carry the kernel in `init_boot` instead of `boot` — this kit does not handle that split. The locator only patches kernels that decode exactly like the analysed builds (Surface Duo and LG V50 verified; the rest are refused). A locked or verified-boot device will not boot a repacked image.

## Sources

- [`kernel/module.c` on branch `msm-4.14`](https://github.com/microsoft/surface-duo-oss-kernel.msm-4..14/blob/msm-4.14/kernel/module.c#L2789) — `module_sig_check`, with [the `err = -ENOKEY` line](https://github.com/microsoft/surface-duo-oss-kernel.msm-4..14/blob/msm-4.14/kernel/module.c#L2791), [the `if (flags == 0 &&` line](https://github.com/microsoft/surface-duo-oss-kernel.msm-4..14/blob/msm-4.14/kernel/module.c#L2799), [the `if (!err)` line](https://github.com/microsoft/surface-duo-oss-kernel.msm-4..14/blob/msm-4.14/kernel/module.c#L2807) and [the `err == -ENOKEY && !sig_enforce` line](https://github.com/microsoft/surface-duo-oss-kernel.msm-4..14/blob/msm-4.14/kernel/module.c#L2813). Note the file defines a second `module_sig_check` at L2819, for builds without `CONFIG_MODULE_SIG`.
- [`include/linux/module.h` on branch `msm-4.14`](https://github.com/microsoft/surface-duo-oss-kernel.msm-4..14/blob/msm-4.14/include/linux/module.h#L28) — `MODULE_SIG_STRING`, the `~Module signature appended~\n` marker the tool anchors on.
- The device build tree (build `2022.902.48`) is pulled with `repo init -u https://github.com/microsoft/surface-duo-oss-kernel.manifest -b surfaceduo/11/2022.902.48 && repo sync`; see [`surfaceduo/kernel.md`](https://github.com/microsoft/surface-duo-oss/blob/main/surfaceduo/kernel.md). These per-build trees live behind the manifest, which is why the branch links above point at `msm-4.14`, the branch our local copy matches exactly.
- [Linux module signing documentation](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html) — background on what the check is for.
