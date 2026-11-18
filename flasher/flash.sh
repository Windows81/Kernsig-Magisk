#!/bin/sh
# flash.sh - patch an extracted Android boot.img to accept unsigned modules.
#
# Usage:
#   sh flash.sh <boot.img> [output.img]
#   sh flash.sh -h
#
# What it does:
#   1. Copies <boot.img> into a private temp directory.
#   2. Unpacks it with magiskboot (auto-detects compression).
#   3. Runs kernsig-flash on the kernel (string-anchored locator; refuses
#      any kernel whose sites are missing or ambiguous - nothing is written
#      to your files unless every site is verified first).
#   4. Repacks boot-patched.img, then unpacks it again and compares the
#      kernel inside against the patched one as a built-in proof.
#
# What it never does:
#   - never writes to a block device; your phone is not flashed by this script.
#   - the final flash is a manual step printed at the end.
#
# Requirements: magiskboot (ships with Magisk, at /data/adb/magisk/magiskboot)
# and kernsig-flash (the static aarch64 binary next to this script, or
# $KERNSIG_FLASH in the environment). Run as root: su -c 'sh flash.sh ...'.
# Works on booted, rooted phones; also works from a PC-connected adb shell.
# Exit 0 ok, 1 refused/failed, 64 bad usage.

set -eu

PATH="/data/adb/magisk:/data/adb:$PATH"
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
KS_BIN=${KERNSIG_FLASH:-"$SELF_DIR/kernsig-flash"}
MB=${MAGISKBOOT:-}

die() { echo "flash: $*" >&2; exit 1; }
print_help() { sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

case "${1:-}" in -h|--help|"") [ $# -ge 1 ] && print_help; echo "flash: expected a boot.img (try -h)" >&2; exit 64;; esac
[ $# -le 2 ] || { echo "flash: expected at most 2 arguments (try -h)" >&2; exit 64; }
[ -f "$1" ] || die "no such file: $1"
IMG=$1
OUT=${2:-"$IMG.patched"}
case "$OUT" in "$IMG") die "output must not be the input, or the original would be destroyed" ;; esac

if [ -z "$MB" ]; then
  if command -v magiskboot >/dev/null 2>&1; then MB=$(command -v magiskboot)
  elif [ -x /data/adb/magisk/magiskboot ]; then MB=/data/adb/magisk/magiskboot
  else die "magiskboot not found; install Magisk or set \$MAGISKBOOT"; fi
fi
[ -x "$KS_BIN" ] || die "kernsig-flash not found at $KS_BIN; set \$KERNSIG_FLASH"

WORK=$(mktemp -d "${TMPDIR:-/data/local/tmp}/kernsig-XXXXXX") || die "cannot create a temp dir under ${TMPDIR:-/data/local/tmp} (set \$TMPDIR to a writable path)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/out" "$WORK/proof"

cp -- "$IMG" "$WORK/boot.img"
copy="$WORK/boot.img"
(
  cd "$WORK/out"
  "$MB" unpack "$copy" >/dev/null
  [ -f kernel ] || die "no kernel component in $IMG (GKI devices may need vendor_boot/init_boot instead)"
  "$KS_BIN" kernel
  mv kernel.patched kernel
  "$MB" repack "$copy" "$WORK/patched.img" >/dev/null
)

# proof: the repacked image carries the patch
(cd "$WORK/proof" && "$MB" unpack "$WORK/patched.img" >/dev/null)
cmp -s "$WORK/proof/kernel" "$WORK/out/kernel" || die "repacked image does not contain the patched kernel"

mv -- "$WORK/patched.img" "$OUT"
echo "flash: wrote $OUT (kernel patched, image verified)"
echo "flash: this tool never writes to a block device."
echo "flash: to boot it, flash the image yourself - for slot A:"
echo "flash:   fastboot flash boot_a \"$OUT\""
echo "flash: (use boot_b for slot B, or your recovery's flash-image feature; on Android 13+ with split GKI, the kernel may live in init_boot instead)"
