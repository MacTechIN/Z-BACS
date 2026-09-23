#!/usr/bin/env bash
# Z-1.H.7 integration tests: build the contracts, then run zbacs-chain against a real Anvil.
#   tools/chain-it.sh
# The tests skip themselves if Foundry is missing, so this script is the way to be sure they ran.
set -euo pipefail
export PATH="$HOME/.foundry/bin:$PATH"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

command -v forge >/dev/null || { echo "forge not found — run tools/setup.sh"; exit 1; }
command -v anvil >/dev/null || { echo "anvil not found — run tools/setup.sh"; exit 1; }

echo "== building contracts (the Rust bindings are generated from these artifacts)"
(cd "$ROOT/contracts" && forge build)

echo "== refreshing the checked-in artifact copies in crates/zbacs-chain/abi"
for name in FileRegistry AccessPolicy AuditLog P256Validator ERC1967Proxy; do
  cp "$ROOT/contracts/out/$name.sol/$name.json" "$ROOT/crates/zbacs-chain/abi/$name.json"
done

echo "== zbacs-chain against Anvil"
cd "$ROOT"
cargo test -p zbacs-chain -- --nocapture
