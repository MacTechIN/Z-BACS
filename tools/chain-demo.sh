#!/usr/bin/env bash
# Z-BACS chain walkthrough on a local Anvil node.
#   tools/chain-demo.sh          # run the scenario, show the on-chain evidence, stop Anvil
#   tools/chain-demo.sh --keep   # leave Anvil running on :8545 so you can poke it with cast
# Explained in docs/chain_guide.md.
set -euo pipefail

export PATH="$HOME/.foundry/bin:$PATH"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RPC="http://127.0.0.1:8545"
KEEP=0; [[ "${1:-}" == "--keep" ]] && KEEP=1

for bin in anvil forge cast; do
  command -v "$bin" >/dev/null || { echo "missing $bin — run tools/setup.sh"; exit 1; }
done

started=0
if ! cast chain-id --rpc-url "$RPC" >/dev/null 2>&1; then
  echo "== starting local chain (anvil, chainId 31337, 1 block per transaction)"
  anvil --silent >/dev/null 2>&1 &
  ANVIL_PID=$!
  started=1
  for _ in $(seq 1 50); do cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.1; done
else
  echo "== using already-running node at $RPC"
fi
cleanup() { if [[ $started -eq 1 && $KEEP -eq 0 ]]; then kill "$ANVIL_PID" 2>/dev/null || true; fi; }
trap cleanup EXIT

echo "== chain id: $(cast chain-id --rpc-url "$RPC")   block before: $(cast block-number --rpc-url "$RPC")"

cd "$ROOT/contracts"
forge script script/Demo.s.sol --rpc-url "$RPC" --broadcast -vv 2>&1 \
  | awk '/== Logs ==/{f=1; next} /## Setting up/{f=0} /ONCHAIN EXECUTION COMPLETE/{print "  (all transactions mined)"} f'

POLICY=$(jq -r .policy out/demo.json)
AUDIT=$(jq -r .audit out/demo.json)
FILE_ID=$(jq -r .fileId out/demo.json)
GRANT_ID=$(jq -r .grantId out/demo.json)

echo
echo "== on-chain evidence (read with cast, no keys needed)"
echo "   blocks mined: $(cast block-number --rpc-url "$RPC")  (one per transaction: 3 deploys + register + grant + open + 2 audit + revoke)"
echo "   AccessPolicy.isValid(grantId) -> $(cast call "$POLICY" 'isValid(bytes32)(bool)' "$GRANT_ID" --rpc-url "$RPC")"
echo "   events emitted by AccessPolicy (topic0 = keccak256 of the event signature, decoded from the ABI):"
declare -A EVENT_NAME
while IFS=$'\t' read -r name sig; do
  EVENT_NAME[$(cast keccak "$sig")]="$name"
done < <(jq -r '.abi[] | select(.type=="event") | [.name, (.name + "(" + ([.inputs[].type] | join(",")) + ")")] | @tsv' out/AccessPolicy.sol/AccessPolicy.json)
while IFS=$'\t' read -r block topic0 tx; do
  printf "     block %d  %-8s tx %s…\n" "$((block))" "${EVENT_NAME[$topic0]:-?}" "${tx:0:14}"
done < <(cast logs --rpc-url "$RPC" --from-block 0 --address "$POLICY" --json | jq -r '.[] | [.blockNumber, .topics[0], .transactionHash] | @tsv')
echo "   audit entries (AuditLog): $(cast logs --rpc-url "$RPC" --from-block 0 --address "$AUDIT" --json | jq 'length')"

# Z-1.H.3 budget: one audit entry must cost <= 30,000 gas as a whole transaction.
ALICE_PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
AUDIT_GAS=$(cast send "$AUDIT" 'log(bytes32,uint8,bytes32,bytes32)' "$FILE_ID" 2 \
  0x3333333333333333333333333333333333333333333333333333333333333333 \
  0x4444444444444444444444444444444444444444444444444444444444444444 \
  --rpc-url "$RPC" --private-key "$ALICE_PK" | awk '/^gasUsed/{print $2}')
printf "   AuditLog.log gas: %s (budget 30000)" "$AUDIT_GAS"
if [[ "$AUDIT_GAS" -le 30000 ]]; then echo "  OK"; else echo "  OVER BUDGET"; exit 1; fi

LAST_TX=$(cast logs --rpc-url "$RPC" --from-block 0 --address "$POLICY" --json | jq -r '.[-1].transactionHash')
echo
echo "== last transaction (the revoke), as any block explorer would show it:"
cast tx "$LAST_TX" --rpc-url "$RPC" | grep -E "^(blockNumber|from|to|gas |gasPrice|hash|nonce) " | sed 's/^/   /'
echo "   receipt status: $(cast receipt "$LAST_TX" status --rpc-url "$RPC")   gasUsed: $(cast receipt "$LAST_TX" gasUsed --rpc-url "$RPC")"

if [[ $KEEP -eq 1 ]]; then
  echo
  echo "== anvil left running at $RPC (pid ${ANVIL_PID:-?}). Try:"
  echo "   cast block latest --rpc-url $RPC"
  echo "   cast call $POLICY 'isValid(bytes32)(bool)' $GRANT_ID --rpc-url $RPC"
  echo "   kill ${ANVIL_PID:-<pid>}   # when done"
fi
