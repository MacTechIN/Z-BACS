#!/usr/bin/env node
// OR-2: measure whether the RIP-7212 / EIP-7951 P256VERIFY precompile is live on
// the chains Z-BACS targets, and whether the Daimo p256-verifier fallback is deployed.
//
//   node scripts/probe-rip7212.mjs [--json]
//
// Method per chain:
//   1. eth_call P256VERIFY with a freshly generated valid vector  -> 32-byte 0x..01 when active
//   2. eth_call with a corrupted r                                -> empty return (never reverts)
//   3. eth_estimateGas against the precompile vs. an empty address, as a sanity signal
//      only -- an empty account returns 0x for any input, so the return values above are
//      what decides. The exact precompile gas charge is measured with gasleft() in
//      test/Rip7212.t.sol instead, because eth_estimateGas is distorted by EIP-7623
//      calldata floor pricing.
import {plainVector} from './p256-vector.mjs';

const P256VERIFY = '0x0000000000000000000000000000000000000100';
const EMPTY_CONTROL = '0x0000000000000000000000000000000000000fff';
// github.com/daimo-eth/p256-verifier — same address on every chain it is deployed to
const DAIMO_VERIFIER = '0xc2b78104907F722DABAc4C69f826a522B2754De4';

const CHAINS = [
  {name: 'Base Sepolia', rpc: process.env.BASE_SEPOLIA_RPC_URL ?? 'https://sepolia.base.org'},
  {name: 'Base Mainnet', rpc: process.env.BASE_RPC_URL ?? 'https://mainnet.base.org'},
  {name: 'OP Sepolia', rpc: process.env.OP_SEPOLIA_RPC_URL ?? 'https://sepolia.optimism.io'},
  {name: 'Ethereum Sepolia', rpc: process.env.ETH_SEPOLIA_RPC_URL ?? 'https://ethereum-sepolia-rpc.publicnode.com'},
  {name: 'Anvil (local)', rpc: process.env.ANVIL_RPC_URL ?? 'http://127.0.0.1:8545', optional: true},
];

let nextId = 1;
async function rpc(url, method, params) {
  const res = await fetch(url, {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({jsonrpc: '2.0', id: nextId++, method, params}),
    signal: AbortSignal.timeout(20_000),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const body = await res.json();
  if (body.error) throw new Error(`${method}: ${body.error.message}`);
  return body.result;
}

const strip = (h) => h.replace(/^0x/, '');
const encode = (v) => '0x' + [v.hash, v.r, v.s, v.x, v.y].map(strip).join('');

function corrupt(v) {
  const flipped = (BigInt(v.r) ^ 1n).toString(16).padStart(64, '0');
  return {...v, r: '0x' + flipped};
}

async function probeChain(chain, vector) {
  const out = {chain: chain.name, rpc: chain.rpc};
  out.chainId = Number(await rpc(chain.rpc, 'eth_chainId', []));

  const valid = encode(vector);
  out.validReturn = await rpc(chain.rpc, 'eth_call', [{to: P256VERIFY, data: valid}, 'latest']);
  out.invalidReturn = await rpc(chain.rpc, 'eth_call',
    [{to: P256VERIFY, data: encode(corrupt(vector))}, 'latest']);

  const [gasPrecompile, gasControl] = await Promise.all([
    rpc(chain.rpc, 'eth_estimateGas', [{to: P256VERIFY, data: valid}]),
    rpc(chain.rpc, 'eth_estimateGas', [{to: EMPTY_CONTROL, data: valid}]),
  ]);
  out.gasDelta = Number(gasPrecompile) - Number(gasControl);

  const code = await rpc(chain.rpc, 'eth_getCode', [DAIMO_VERIFIER, 'latest']);
  out.daimoVerifier = code && code !== '0x' ? `deployed (${(strip(code).length / 2)} bytes)` : 'not deployed';

  const returnsOne = /^0x0*1$/.test(out.validReturn);
  const rejects = out.invalidReturn === '0x' || /^0x0+$/.test(out.invalidReturn);
  out.precompile = returnsOne && rejects
    ? 'ACTIVE'
    : returnsOne
      ? 'ACTIVE (does not reject a corrupted signature -- investigate)'
      : 'INACTIVE';
  return out;
}

const vector = plainVector();
const results = [];
for (const chain of CHAINS) {
  try {
    results.push(await probeChain(chain, vector));
  } catch (err) {
    if (chain.optional) {
      results.push({chain: chain.name, precompile: `skipped (${err.message})`});
    } else {
      results.push({chain: chain.name, rpc: chain.rpc, precompile: `ERROR: ${err.message}`});
    }
  }
}

if (process.argv.includes('--json')) {
  console.log(JSON.stringify({measuredAt: new Date().toISOString(), vector, results}, null, 2));
} else {
  console.log(`P256VERIFY ${P256VERIFY} — measured ${new Date().toISOString()}\n`);
  for (const r of results) {
    console.log(`${r.chain}${r.chainId ? ` (chainId ${r.chainId})` : ''}: ${r.precompile}`);
    if (r.gasDelta !== undefined) {
      console.log(`  valid -> ${r.validReturn}`);
      console.log(`  invalid -> ${r.invalidReturn || '0x'}`);
      console.log(`  eth_estimateGas delta vs empty account: ${r.gasDelta} (informational; see test/Rip7212.t.sol for the real charge)`);
      console.log(`  daimo p256-verifier fallback: ${r.daimoVerifier}`);
    }
  }
}
