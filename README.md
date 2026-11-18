# KernSig Research

A small package from the headless Talon work, built by Hy4 through live REPL analysis of a Surface Duo kernel. It documents and demonstrates one thing: how the kernel's unsigned-module rejection is wired, and the two edits that turn it into an acceptance path. It is a research artefact for a device you own, not a turnkey bypass for arbitrary phones.

The source patch is in `patches/source-c.patch`: `err` starts at 0 instead of −ENOKEY, and the signature-check `if` is forced false. The assembly patch is in `patches/assembly.patch`: two instructions in `module_sig_check` — `cbnz` becomes an unconditional branch past the check, and the −ENOKEY assignment becomes zero. Both are shown as diffs because seeing them side by side is the point; only one location is actually needed for the load to succeed, the second removes the warning path.

`patch-kernel.py` is an offline demonstrator for the extracted Surface Duo kernel image. Unpack boot.img yourself, run the script on the `kernel` file, inspect the result, and repack and flash only if you choose — nothing is flashed automatically. The tool is specific to the analysed 4.14 Surface Duo build; other kernels need their own offsets, and kernels without the verification string have nothing to patch.
