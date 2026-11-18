# KernSig Research

A small package from the headless Talon work, built by Hy4 through live REPL analysis of a Surface Duo kernel. It documents and demonstrates one thing: how the kernel's unsigned-module rejection is wired, and the two edits that turn it into an acceptance path. It is a research artefact for a device you own, not a turnkey bypass for arbitrary phones.

The source patch is in `patches/source-c.patch`: `err` starts at 0 instead of −ENOKEY, and the signature-check `if` is forced false. The assembly patch is in `patches/assembly.patch`: two instructions in `module_sig_check` — `cbnz` becomes an unconditional branch past the check, and the −ENOKEY assignment becomes zero. Both are shown as diffs because seeing them side by side is the point; only one location is actually needed for the load to succeed, the second removes the warning path.

`patch-kernel.py` locates both patch sites from the `module verification failed` string: one unique string, one unique code xref, one unique `add_taint(13, 0)` call, and one unique −ENOKEY site. Any step that is missing or ambiguous aborts with an error, so the tool never guesses where to write. It has been objdump-verified on the Surface Duo kernel, where it patches both sites cleanly. The LG V50 build has two identical −ENOKEY sites, and the Samsung A54/A35 builds materialise −ENOKEY differently, so those are refused rather than patched; kernels without the verification string have nothing to patch. Unpack boot.img yourself, run the script on the `kernel` file, inspect the result, and repack and flash only if you choose — nothing is flashed automatically.

## Sources

- [Surface Duo OSS kernel, branch `msm-4.14`](https://github.com/microsoft/surface-duo-oss-kernel.msm-4..14) — the vendor source this device is built from.
- [`kernel/module.c`](https://github.com/microsoft/surface-duo-oss-kernel.msm-4..14/blob/msm-4.14/kernel/module.c) — `module_sig_check` and `load_module`, where both patches land.
- [`include/linux/module.h`](https://github.com/microsoft/surface-duo-oss-kernel.msm-4..14/blob/msm-4.14/include/linux/module.h) — `MODULE_SIG_STRING` (`~Module signature appended~`).
- [Linux module signing documentation](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html) — background on what the check is for.
