// Generates P-256 (secp256r1) test vectors: a plain (hash, r, s, x, y) tuple for the
// RIP-7212 precompile, and a WebAuthn-shaped assertion as a platform authenticator
// (Windows Hello / Touch ID) would produce it.
//
// NOTE: node:crypto `sign(null, data, ecKey)` hashes `data` with SHA-256 before signing
// (verified against the on-chain verifiers — signing a digest with `null` yields a
// signature over sha256(digest), which every on-chain verifier rejects). Always pass the
// pre-image and let node hash it once, then report that same SHA-256 as the message hash.
import {createHash, generateKeyPairSync, sign} from 'node:crypto';

export const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

const hex32 = (v) => '0x' + v.toString(16).padStart(64, '0');
const sha256 = (data) => createHash('sha256').update(data).digest();
const b64url = (buf) => Buffer.from(buf).toString('base64url');

/** ECDSA over sha256(message), with s normalised to the lower half (EIP-2 style). */
export function signMessage(privateKey, message) {
  const raw = sign('sha256', message, {key: privateKey, dsaEncoding: 'ieee-p1363'});
  const r = BigInt('0x' + raw.subarray(0, 32).toString('hex'));
  let s = BigInt('0x' + raw.subarray(32).toString('hex'));
  if (s > P256_N / 2n) s = P256_N - s;
  return {hash: '0x' + sha256(message).toString('hex'), r: hex32(r), s: hex32(s)};
}

function keyPair() {
  const {privateKey, publicKey} = generateKeyPairSync('ec', {namedCurve: 'prime256v1'});
  // SPKI DER for P-256 ends with 0x04 || X(32) || Y(32)
  const der = publicKey.export({format: 'der', type: 'spki'});
  const point = der.subarray(der.length - 64);
  return {
    privateKey,
    x: '0x' + point.subarray(0, 32).toString('hex'),
    y: '0x' + point.subarray(32).toString('hex'),
  };
}

/** A plain (hash, r, s, x, y) vector for the P256VERIFY precompile. */
export function plainVector(message = 'zbacs rip-7212 probe') {
  const {privateKey, x, y} = keyPair();
  return {...signMessage(privateKey, Buffer.from(message)), x, y};
}

/**
 * A WebAuthn assertion over `challenge` (32 raw bytes). The authenticator signs
 * sha256(authenticatorData || sha256(clientDataJSON)).
 */
export function webauthnVector(challenge, origin = 'https://zbacs.local', rpId = 'zbacs.local') {
  const {privateKey, x, y} = keyPair();

  const clientDataJSON = JSON.stringify({
    type: 'webauthn.get',
    challenge: b64url(challenge),
    origin,
    crossOrigin: false,
  });
  // rpIdHash(32) | flags(1): UP|UV|BE|BS | signCount(4)
  const authenticatorData = Buffer.concat([
    sha256(rpId),
    Buffer.from([0x1d]),
    Buffer.from([0, 0, 0, 1]),
  ]);
  const signedOver = Buffer.concat([authenticatorData, sha256(clientDataJSON)]);
  const {hash, r, s} = signMessage(privateKey, signedOver);

  return {
    challenge: '0x' + Buffer.from(challenge).toString('hex'),
    authenticatorData: '0x' + authenticatorData.toString('hex'),
    clientDataJSON,
    challengeIndex: clientDataJSON.indexOf('"challenge":'),
    typeIndex: clientDataJSON.indexOf('"type":'),
    digest: hash,
    r,
    s,
    x,
    y,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  // node scripts/p256-vector.mjs [--out vectors/p256.json]
  const {randomBytes} = await import('node:crypto');
  const {writeFileSync} = await import('node:fs');
  const fixture = {
    generatedAt: new Date().toISOString(),
    plain: plainVector(),
    webauthn: webauthnVector(randomBytes(32)),
  };
  const i = process.argv.indexOf('--out');
  if (i >= 0) {
    writeFileSync(process.argv[i + 1], JSON.stringify(fixture, null, 2) + '\n');
    console.log(`wrote ${process.argv[i + 1]}`);
  } else {
    console.log(JSON.stringify(fixture, null, 2));
  }
}
