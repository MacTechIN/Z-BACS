#!/usr/bin/env bash
# Run the zbacs-core fuzz targets (Z-1.C.3). Needs: rustup nightly + cargo-fuzz.
#   tools/fuzz.sh            # 5 minutes per target (smoke)
#   tools/fuzz.sh 24h        # the Z-1.C.3 gate: 24h wall clock split across targets, 4 workers each
#   tools/fuzz.sh 10m header # one target
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DUR="${1:-5m}"; ONLY="${2:-}"
TARGETS=(header header_signed open_mutated envelope)
[[ -n "$ONLY" ]] && TARGETS=("$ONLY")
secs() { case "$1" in *h) echo $(( ${1%h} * 3600 ));; *m) echo $(( ${1%m} * 60 ));; *) echo "${1%s}";; esac; }
PER=$(( $(secs "$DUR") / ${#TARGETS[@]} ))
cd "$ROOT/crates/zbacs-core"
cargo +nightly fuzz build
for t in "${TARGETS[@]}"; do
  echo "== $t for ${PER}s"
  cargo +nightly fuzz run "$t" -- -max_total_time="$PER" -jobs=4 -workers=4 -max_len=8192 2>&1 | tail -3
  if ls fuzz/artifacts/"$t"/ 2>/dev/null | grep -q .; then
    echo "!! crash artifacts for $t:"; ls fuzz/artifacts/"$t"/; exit 1
  fi
done
echo "== no crashes"
