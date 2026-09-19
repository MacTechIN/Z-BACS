// A software passkey: emulates a platform authenticator (Windows Hello / Touch ID)
// with a node:crypto P-256 key so that the passkey -> smart account -> UserOp path can
// be exercised headlessly. The real Agent will replace `getFn` with the OS WebAuthn API
// (Z-0.A.1 / Z-1.A.2); everything downstream stays identical.
//
// SECURITY: test-only. The private key never leaves process memory and is never written
// to disk.
import {createHash, generateKeyPairSync, sign} from 'node:crypto';
import {toWebAuthnAccount} from 'viem/account-abstraction';

const sha256 = (data) => createHash('sha256').update(data).digest();
const b64url = (buf) => Buffer.from(buf).toString('base64url');
const toArrayBuffer = (buf) => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);

// authenticatorData flags: UP (0x01) | UV (0x04) | BE (0x08) | BS (0x10) -- a synced
// platform passkey with user verification, which is what Windows Hello reports.
const FLAGS_UP_UV_BE_BS = 0x1d;

/**
 * Creates a software passkey bound to `rpId`/`origin` and returns a viem
 * WebAuthnAccount for it, plus the raw public key for on-chain registration.
 */
export function createSoftwarePasskey({rpId = 'zbacs.local', origin = 'https://zbacs.local'} = {}) {
  const {privateKey, publicKey} = generateKeyPairSync('ec', {namedCurve: 'prime256v1'});
  // SPKI DER for P-256 ends with 0x04 || X(32) || Y(32)
  const der = publicKey.export({format: 'der', type: 'spki'});
  const point = der.subarray(der.length - 64);
  const x = '0x' + point.subarray(0, 32).toString('hex');
  const y = '0x' + point.subarray(32).toString('hex');
  // Credential IDs are opaque 16..64-byte blobs chosen by the authenticator.
  const credentialId = b64url(sha256(der).subarray(0, 32));
  let signCount = 0;

  /** Stand-in for `navigator.credentials.get()`. */
  const getFn = async (requestOptions) => {
    const challenge = Buffer.from(requestOptions.publicKey.challenge);
    const clientDataJSON = Buffer.from(JSON.stringify({
      type: 'webauthn.get',
      challenge: b64url(challenge),
      origin,
      crossOrigin: false,
    }));
    signCount += 1;
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(signCount);
    const authenticatorData = Buffer.concat([sha256(rpId), Buffer.from([FLAGS_UP_UV_BE_BS]), counter]);
    // Authenticators sign sha256(authenticatorData || sha256(clientDataJSON)) and return
    // an ASN.1 DER signature; ox parses it and normalises `s` to the lower half.
    const signature = sign('sha256', Buffer.concat([authenticatorData, sha256(clientDataJSON)]), privateKey);
    return {
      id: credentialId,
      type: 'public-key',
      response: {
        clientDataJSON: toArrayBuffer(clientDataJSON),
        authenticatorData: toArrayBuffer(authenticatorData),
        signature: toArrayBuffer(signature),
        userHandle: null,
      },
    };
  };

  const account = toWebAuthnAccount({
    credential: {id: credentialId, publicKey: `0x04${x.slice(2)}${y.slice(2)}`},
    getFn,
    rpId,
  });

  return {account, credentialId, publicKey: {x, y}, rpId, origin};
}
