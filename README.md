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

`patch-kernel.py` locates the `0x100b5c` and `0x10155c` sites from the `module verification failed` string: one unique string, one unique code xref, one unique `add_taint(13, 0)` call, and one unique −ENOKEY site. Any step that is missing or ambiguous aborts with an error, so the tool never guesses where to write. It has been objdump-verified on the Surface Duo kernel. The LG V50 build has two identical −ENOKEY sites, and the Samsung A54/A35 builds materialise −ENOKEY differently, so those are refused rather than patched; kernels without the verification string have nothing to patch. Unpack `boot.img` yourself, run the script on the `kernel` file, inspect the result, and repack and flash only if you choose — nothing is flashed automatically.

## Sources

- [`kernel/module.c` on branch `msm-4.14`](https://github.com/microsoft/surface-duo-oss-kernel.msm-4..14/blob/msm-4.14/kernel/module.c#L2789) — `module_sig_check`, with [the `err = -ENOKEY` line](https://github.com/microsoft/surface-duo-oss-kernel.msm-4..14/blob/msm-4.14/kernel/module.c#L2791), [the `if (flags == 0 &&` line](https://github.com/microsoft/surface-duo-oss-kernel.msm-4..14/blob/msm-4.14/kernel/module.c#L2799), [the `if (!err)` line](https://github.com/microsoft/surface-duo-oss-kernel.msm-4..14/blob/msm-4.14/kernel/module.c#L2807) and [the `err == -ENOKEY && !sig_enforce` line](https://github.com/microsoft/surface-duo-oss-kernel.msm-4..14/blob/msm-4.14/kernel/module.c#L2813). Note the file defines a second `module_sig_check` at L2819, for builds without `CONFIG_MODULE_SIG`.
- [`include/linux/module.h` on branch `msm-4.14`](https://github.com/microsoft/surface-duo-oss-kernel.msm-4..14/blob/msm-4.14/include/linux/module.h#L28) — `MODULE_SIG_STRING`, the `~Module signature appended~\n` marker the tool anchors on.
- The device build tree (build `2022.902.48`) is pulled with `repo init -u https://github.com/microsoft/surface-duo-oss-kernel.manifest -b surfaceduo/11/2022.902.48 && repo sync`; see [`surfaceduo/kernel.md`](https://github.com/microsoft/surface-duo-oss/blob/main/surfaceduo/kernel.md). These per-build trees live behind the manifest, which is why the branch links above point at `msm-4.14`, the branch our local copy matches exactly.
- [Linux module signing documentation](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html) — background on what the check is for.
