#!/usr/bin/env bash
# Z-1.Q.2 — does any plaintext survive on disk after a session? (T09, T10)
#
#   tools/forensic.sh            # auto: image mode when it can mount, else directory mode
#   tools/forensic.sh image      # loopback ext4 image, scanned raw after unmount (needs sudo)
#   tools/forensic.sh dir        # a directory under $TMPDIR, scanned file by file
#
# Image mode is the real test: a small filesystem is created, one full Edit session runs on
# it (seal → erase original → open into workspace → edit with temp/lock files → reseal →
# wipe), the filesystem is unmounted, and the *raw image bytes* — data blocks, free space,
# the journal — are searched for a marker that existed only in the plaintext. Directory mode
# runs the same session but can only look at files that still exist, which is what a machine
# without loop mounts can do.
#
# Exit 0: the marker is nowhere. Exit 1: it was found (with where). Exit 2: setup problem.
set -euo pipefail

cd "$(dirname "$0")/.."
MODE="${1:-auto}"
SIZE_MB="${FORENSIC_IMAGE_MB:-96}"
ROUNDS="${FORENSIC_ROUNDS:-3}"

note() { printf '\033[1;34m[forensic]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[forensic] FAIL\033[0m %s\n' "$*"; exit 1; }

can_mount() { command -v mkfs.ext4 >/dev/null && sudo -n true 2>/dev/null; }
if [ "$MODE" = auto ]; then
  if can_mount; then MODE=image; else MODE=dir; fi
fi

note "building zbacs (release)"
cargo build --release -p zbacs-cli --locked >/dev/null
ZBACS=target/release/zbacs

# A marker no other file on the machine contains.
MARKER="ZBACS-FORENSIC-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/zbacs-forensic.XXXXXX")"
trap 'cleanup' EXIT
cleanup() {
  if [ "${MOUNTED:-0}" = 1 ]; then sudo umount "$WORK/mnt" 2>/dev/null || true; fi
  rm -rf "$WORK"
}

case "$MODE" in
  image)
    can_mount || { echo "image mode needs mkfs.ext4 and passwordless sudo"; exit 2; }
    note "image mode: ${SIZE_MB} MB ext4 loopback at $WORK/disk.img"
    dd if=/dev/zero of="$WORK/disk.img" bs=1M count="$SIZE_MB" status=none
    mkfs.ext4 -q -F "$WORK/disk.img"
    mkdir -p "$WORK/mnt"
    sudo mount -o loop "$WORK/disk.img" "$WORK/mnt"
    MOUNTED=1
    sudo chown "$(id -u):$(id -g)" "$WORK/mnt"
    BASE="$WORK/mnt/zbacs"
    ;;
  dir)
    note "directory mode: $WORK/base (free space is NOT scanned — use image mode for that)"
    BASE="$WORK/base"
    ;;
  *) echo "usage: $0 [auto|image|dir]"; exit 2 ;;
esac

note "running $ROUNDS Edit session round(s) with marker $MARKER"
"$ZBACS" forensic-session --base "$BASE" --marker "$MARKER" --rounds "$ROUNDS"
sync

# Negative control: a plaintext that is written and then merely unlinked (no overwrite) must
# be found by the scan below, or the scan proves nothing. In image mode this is exactly the
# free-space case; in directory mode a file that is simply left behind.
CONTROL="ZBACS-CONTROL-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
mkdir -p "$BASE/control"
printf 'leaked %s\n' "$CONTROL" > "$BASE/control/leak.txt"
sync
if [ "$MODE" = image ]; then rm -f "$BASE/control/leak.txt"; sync; fi

found=0
if [ "$MODE" = image ]; then
  sudo umount "$WORK/mnt"; MOUNTED=0
  sync
  note "scanning the raw image ($(du -h "$WORK/disk.img" | cut -f1)) for the marker"
  hits=$(grep -a -o -b -- "$MARKER" "$WORK/disk.img" | head -5 || true)
  if [ -n "$hits" ]; then
    found=1
    echo "$hits" | sed 's/^/       byte offset /'
  fi
  # a second, independent look: printable strings
  if strings -n 16 "$WORK/disk.img" | grep -q -- "$MARKER"; then found=1; fi
else
  note "scanning every file left under $BASE"
  if grep -a -r -l -- "$MARKER" "$BASE" 2>/dev/null | sed 's/^/       /' | grep .; then found=1; fi
fi

# The container itself must be there and must be opaque.
sealed=$(find "$WORK" -name '*.zbacs' 2>/dev/null | head -1 || true)
if [ "$MODE" = image ]; then
  note "container stays on the image; its bytes were part of the raw scan"
elif [ -z "$sealed" ]; then
  fail "no .zbacs left behind — the session did not run as expected"
fi

# the control must be visible to the same scan, or the method is broken (exit 2, not a pass)
if [ "$MODE" = image ]; then
  grep -a -q -- "$CONTROL" "$WORK/disk.img" || { echo "control leak not seen in the raw image — scan is blind"; exit 2; }
else
  grep -a -r -q -- "$CONTROL" "$BASE" || { echo "control leak not seen — scan is blind"; exit 2; }
fi
note "control: a merely-deleted plaintext IS visible to this scan (method works)"

if [ "$found" = 1 ]; then
  fail "the plaintext marker survives on disk ($MODE mode) — T09/T10 violated"
fi
note "ok: no plaintext left behind ($MODE mode, $ROUNDS rounds)"
