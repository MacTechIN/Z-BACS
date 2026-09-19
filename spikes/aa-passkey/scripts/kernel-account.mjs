#!/usr/bin/env node
// Z-0.H.2 stage 1: passkey -> Kernel v3.1 smart account (WebAuthn validator) -> signed
// ERC-4337 v0.7 UserOperation, using permissionless.js exactly as the Approve app will.
//
//   node scripts/kernel-account.mjs [--out vectors/userop.json] [--rpc URL] [--send [--precompile]]
//
// No bundler key is needed: the counterfactual address and factory data come from the
// public Base Sepolia RPC, and the resulting UserOperation is written to a JSON file that
// test/PasskeyUserOp.t.sol replays through the real EntryPoint on a Base Sepolia fork.
// With PIMLICO_API_KEY set, `--send` submits a UserOperation from the same passkey account
// through the Pimlico bundler + testnet paymaster; `--precompile` re-encodes the WebAuthn
// signature with usePrecompiled=true.
import {writeFileSync} from 'node:fs';
import {
  concatHex,
  createPublicClient,
  decodeAbiParameters,
  encodeAbiParameters,
  encodeFunctionData,
  http,
  keccak256,
  pad,
  parseGwei,
  toHex,
} from 'viem';
import {baseSepolia} from 'viem/chains';
import {entryPoint07Address, getUserOperationHash} from 'viem/account-abstraction';
import {toKernelSmartAccount} from 'permissionless/accounts';
import {createSoftwarePasskey} from './virtual-authenticator.mjs';

const args = process.argv.slice(2);
const opt = (flag, dflt) => {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : dflt;
};
const OUT = opt('--out', 'vectors/userop.json');
const RPC = opt('--rpc', process.env.BASE_SEPOLIA_RPC_URL ?? 'https://sepolia.base.org');
const SEND = args.includes('--send');
const PRECOMPILE = args.includes('--precompile');

// The fork test etches a recorder contract at this fixed address, so the call target is
// known before the UserOperation is signed.
const TARGET = '0x000000000000000000000000000000000000BEEF';
const TARGET_ABI = [{type: 'function', name: 'record', inputs: [{name: 'value', type: 'bytes32'}], outputs: []}];

const client = createPublicClient({chain: baseSepolia, transport: http(RPC)});
const entryPoint = {address: entryPoint07Address, version: '0.7'};

const passkey = createSoftwarePasskey();
const account = await toKernelSmartAccount({
  client,
  owners: [passkey.account],
  entryPoint,
  version: '0.3.1',
});

const sender = await account.getAddress();
const {factory, factoryData} = await account.getFactoryArgs();
const nonce = await account.getNonce();
const isDeployed = await account.isDeployed();

const recorded = keccak256(toHex(`zbacs passkey userop ${new Date().toISOString()}`));
const callData = await account.encodeCalls([
  {to: TARGET, value: 0n, data: encodeFunctionData({abi: TARGET_ABI, functionName: 'record', args: [recorded]})},
]);

const userOperation = {
  sender,
  nonce,
  factory: isDeployed ? undefined : factory,
  factoryData: isDeployed ? undefined : factoryData,
  callData,
  // Fixed limits: the fork test measures actual usage. Deploy + WebAuthn verification
  // through the Solidity P-256 fallback needs the most headroom.
  callGasLimit: 300_000n,
  verificationGasLimit: 1_500_000n,
  preVerificationGas: 100_000n,
  maxFeePerGas: parseGwei('1'),
  maxPriorityFeePerGas: parseGwei('0.1'),
  signature: '0x',
};

const userOpHash = getUserOperationHash({
  userOperation,
  entryPointAddress: entryPoint.address,
  entryPointVersion: '0.7',
  chainId: baseSepolia.id,
});
// permissionless.js encodes the WebAuthn assertion for Kernel's validator, but hard-codes
// usePrecompiled=false (its own TODO). The fork test also replays a re-encoded copy with
// usePrecompiled=true to measure the RIP-7212 saving.
const signature = await account.signUserOperation(userOperation);
const signaturePrecompiled = reencodeWithPrecompile(signature);

const packed = {
  sender,
  nonce: toHex(nonce),
  initCode: userOperation.factory ? concatHex([factory, factoryData]) : '0x',
  callData,
  accountGasLimits: concatHex([
    pad(toHex(userOperation.verificationGasLimit), {size: 16}),
    pad(toHex(userOperation.callGasLimit), {size: 16}),
  ]),
  preVerificationGas: toHex(userOperation.preVerificationGas),
  gasFees: concatHex([
    pad(toHex(userOperation.maxPriorityFeePerGas), {size: 16}),
    pad(toHex(userOperation.maxFeePerGas), {size: 16}),
  ]),
  paymasterAndData: '0x',
  signature,
};

const output = {
  generatedAt: new Date().toISOString(),
  chainId: baseSepolia.id,
  entryPoint: entryPoint.address,
  kernelVersion: '0.3.1',
  passkey: {credentialId: passkey.credentialId, publicKey: passkey.publicKey, rpId: passkey.rpId, origin: passkey.origin},
  target: TARGET,
  recorded,
  userOpHash,
  wasDeployed: isDeployed,
  packed,
  signaturePrecompiled,
};
writeFileSync(OUT, JSON.stringify(output, null, 2) + '\n');

console.log(`passkey credential: ${passkey.credentialId}`);
console.log(`public key x=${passkey.publicKey.x}\n           y=${passkey.publicKey.y}`);
console.log(`Kernel v3.1 account (counterfactual): ${sender} deployed=${isDeployed}`);
console.log(`factory: ${factory} (${(factoryData.length - 2) / 2} bytes init data)`);
console.log(`userOpHash: ${userOpHash}`);
console.log(`signature: ${(signature.length - 2) / 2} bytes (WebAuthn assertion, usePrecompiled=false)`);
console.log(`wrote ${OUT}`);

if (SEND) {
  const apiKey = process.env.PIMLICO_API_KEY;
  if (!apiKey) {
    console.error('--send needs PIMLICO_API_KEY (put it in spikes/aa-passkey/.env and run with node --env-file=.env)');
    process.exit(2);
  }
  const {createSmartAccountClient} = await import('permissionless');
  const {createPimlicoClient} = await import('permissionless/clients/pimlico');
  const pimlicoUrl = `https://api.pimlico.io/v2/${baseSepolia.id}/rpc?apikey=${apiKey}`;
  const pimlico = createPimlicoClient({transport: http(pimlicoUrl), entryPoint});

  if (PRECOMPILE) {
    // Override permissionless' hard-coded usePrecompiled=false so the bundler's validation
    // tracer and the on-chain validator both take the RIP-7212 path (T21 / ERC-7562 check).
    const signUserOperation = account.signUserOperation.bind(account);
    account.signUserOperation = async (p) => reencodeWithPrecompile(await signUserOperation(p));
    const getStubSignature = account.getStubSignature.bind(account);
    account.getStubSignature = async () => reencodeWithPrecompile(await getStubSignature());
  }

  // The Pimlico paymaster sponsors gas on testnets, so the counterfactual account needs no
  // balance. Same passkey, same Kernel account; the bundler estimates gas itself.
  const smartAccountClient = createSmartAccountClient({
    account,
    chain: baseSepolia,
    bundlerTransport: http(pimlicoUrl),
    paymaster: pimlico,
    userOperation: {
      estimateFeesPerGas: async () => (await pimlico.getUserOperationGasPrice()).fast,
    },
  });
  console.log(`submitting via Pimlico bundler (usePrecompiled=${PRECOMPILE}) ...`);
  const hash = await smartAccountClient.sendUserOperation({
    calls: [{to: TARGET, value: 0n, data: encodeFunctionData({abi: TARGET_ABI, functionName: 'record', args: [recorded]})}],
  });
  console.log(`userOpHash: ${hash}`);
  const receipt = await smartAccountClient.waitForUserOperationReceipt({hash, timeout: 120_000});
  console.log(`included: tx ${receipt.receipt.transactionHash} block ${receipt.receipt.blockNumber} success=${receipt.success}`);
  console.log(`actualGasUsed=${receipt.actualGasUsed} actualGasCost=${receipt.actualGasCost} wei (sponsored)`);
  console.log(`account code deployed: ${(await client.getCode({address: sender}))?.length > 2}`);
  console.log(`https://sepolia.basescan.org/tx/${receipt.receipt.transactionHash}`);
}

/** Re-encode Kernel's WebAuthn signature tuple with usePrecompiled=true. */
function reencodeWithPrecompile(sig) {
  const types = [
    {name: 'authenticatorData', type: 'bytes'},
    {name: 'clientDataJSON', type: 'string'},
    {name: 'responseTypeLocation', type: 'uint256'},
    {name: 'r', type: 'uint256'},
    {name: 's', type: 'uint256'},
    {name: 'usePrecompiled', type: 'bool'},
  ];
  const [authenticatorData, clientDataJSON, responseTypeLocation, r, s] = decodeAbiParameters(types, sig);
  return encodeAbiParameters(types, [authenticatorData, clientDataJSON, responseTypeLocation, r, s, true]);
}
