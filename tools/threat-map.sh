#!/usr/bin/env bash
# Z-1.Q.3 — every threat in docs/threat_model.md (T01..T23) has a test that names it.
#   tools/threat-map.sh            # CI `ux` job
# A threat is covered when at least one test function is named `t<NN>_…` / `test_t<NN>_…`
# (Rust or Solidity), or when the EVIDENCE table below names an existing test function for
# it. Anything else fails: a threat without a test that names it is a threat nobody will
# notice regressing. Out-of-scope threats are listed as such, with the reason.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Threats whose evidence is a test not named after them (renaming would only churn history).
declare -A EVIDENCE=(
  [01]="t20_each_version_gets_a_fresh_dek_and_nonce_prefix"     # random 256-bit DEK, no password to guess
  [10]="a_temp_and_rename_save_is_detected"                     # app temp files / rename saves stay in the workspace
  [12]="a_tampered_backup_is_refused_everywhere_it_can_be_touched recovery_code_shape_and_parsing"
  [13]="name_padding_hides_length_and_roundtrips"               # no names or lengths on chain
)
# Threats the project declares out of scope (docs/threat_model.md); no test can cover them.
declare -A OUT_OF_SCOPE=(
  [08]="screen capture: outside the trust boundary; traceability only (Z-2.G.4 watermark)"
)

SOURCES=(crates apps/agent/src-tauri apps/relay contracts/test spikes/aa-passkey/test)
fail=0
for n in $(seq -w 1 23); do
  if [ -n "${OUT_OF_SCOPE[$n]:-}" ]; then
    printf 'T%s  out of scope: %s\n' "$n" "${OUT_OF_SCOPE[$n]}"
    continue
  fi
  named=$( { grep -rIE --include='*.rs' --include='*.sol' -o "fn (test_)?t0*${n}_[a-zA-Z0-9_]+" "${SOURCES[@]}" 2>/dev/null || true; } | wc -l)
  extra=0
  missing=""
  for f in ${EVIDENCE[$n]:-}; do
    if grep -rIqE --include='*.rs' --include='*.sol' "fn ${f}\b" "${SOURCES[@]}"; then
      extra=$((extra + 1))
    else
      missing="$missing $f"
    fi
  done
  if [ -n "$missing" ]; then
    printf 'T%s  FAIL: evidence test not found:%s\n' "$n" "$missing"
    fail=1
  elif [ "$named" -eq 0 ] && [ "$extra" -eq 0 ]; then
    printf 'T%s  FAIL: no test names this threat\n' "$n"
    fail=1
  else
    printf 'T%s  %d named test(s)%s\n' "$n" "$named" "$([ "$extra" -gt 0 ] && echo ", $extra listed evidence" || true)"
  fi
done
[ "$fail" -eq 0 ] && echo "threat-map: ok (T01..T23)" || { echo "threat-map: FAILED"; exit 1; }
