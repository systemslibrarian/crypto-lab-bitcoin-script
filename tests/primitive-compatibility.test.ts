import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  checkSig, concat, CURVE_N, derToRS, hexToBytes, inspectSignature, legacySighash,
  makeKeyPair, rsToDER, secp, SIGHASH_ALL, sighashPreimage, signSighash,
  signSighashHighS, type SpendContext,
} from '../src/engine';
import { p2pkhScriptPubKey, serializeScript } from '../src/script';

const secret = hexToBytes('00'.repeat(31) + '01');
const owner = makeKeyPair(secret);
const context: SpendContext = {
  version: 1, prevTxid: new Uint8Array(32), vout: 0, sequence: 0xffffffff,
  subscript: serializeScript(p2pkhScriptPubKey(owner.pubKeyHash)), outValue: 1000n,
  outScript: serializeScript(p2pkhScriptPubKey(owner.pubKeyHash)), locktime: 0,
};
const preimage = sighashPreimage(context);
const sighash = legacySighash(context);
// OpenSSL hashes this once more during ECDSA, independently checking Bitcoin's
// double-SHA256. Feeding the final sighash instead is a deliberate triple-hash control.
const firstHash = createHash('sha256').update(preimage).digest();
// SEC 1 ecPublicKey / secp256k1 SubjectPublicKeyInfo with a compressed SEC 1 key.
const publicKey = createPublicKey({
  key: Buffer.concat([Buffer.from('3036301006072a8648ce3d020106052b8104000a032200', 'hex'), owner.pub]),
  format: 'der', type: 'spki',
});
const affine = secp.Point.fromBytes(owner.pub).toAffine();
const b64 = (n: bigint) => Buffer.from(n.toString(16).padStart(64, '0'), 'hex').toString('base64url');
const privateKey = createPrivateKey({
  key: { kty: 'EC', crv: 'secp256k1', x: b64(affine.x), y: b64(affine.y),
    d: Buffer.from(secret).toString('base64url') }, format: 'jwk',
});
const scalarBytes = (n: bigint) => hexToBytes(n.toString(16).padStart(64, '0'));
const withType = (der: Uint8Array) => concat(der, Uint8Array.of(SIGHASH_ALL));

describe('Noble 3 Bitcoin signature compatibility with native OpenSSL', () => {
  it('signs the already double-hashed transaction, without adding a third hash', () => {
    const wire = signSighash(sighash, secret);
    const der = wire.slice(0, -1);
    expect(wire[wire.length - 1]).toBe(SIGHASH_ALL);
    expect(verify('sha256', firstHash, publicKey, der)).toBe(true);
    expect(verify('sha256', sighash, publicKey, der)).toBe(false);
    const changed = Buffer.from(firstHash); changed[0] ^= 1;
    expect(verify('sha256', changed, publicKey, der)).toBe(false);
    expect(inspectSignature(wire).lowS).toBe(true);
  });

  it('verifies a native signature on the double-hashed preimage and rejects a different transaction', () => {
    const der = sign('sha256', firstHash, privateKey);
    const wire = withType(der);
    expect(checkSig(wire, owner.pub, sighash, false)).toBe(true);
    expect(checkSig(wire, owner.pub, sighash)).toBe(inspectSignature(wire).lowS);
    expect(checkSig(wire, owner.pub, legacySighash({ ...context, outValue: 1001n }), false)).toBe(false);
  });

  it('retains high-S mathematical validity while the default policy rejects it', () => {
    const wire = signSighashHighS(sighash, secret);
    expect(verify('sha256', firstHash, publicKey, wire.slice(0, -1))).toBe(true);
    expect(inspectSignature(wire).lowS).toBe(false);
    expect(checkSig(wire, owner.pub, sighash)).toBe(false);
    expect(checkSig(wire, owner.pub, sighash, false)).toBe(true);
  });

  it('detects the SDK default-prehash trap in both signing and verification', () => {
    const extraHashed = secp.Signature.fromBytes(secp.sign(sighash, secret), 'compact');
    const wrongWire = withType(rsToDER(scalarBytes(extraHashed.r), scalarBytes(extraHashed.s)));
    expect(verify('sha256', firstHash, publicKey, wrongWire.slice(0, -1))).toBe(false);
    expect(checkSig(wrongWire, owner.pub, sighash)).toBe(false);
    const { r, s } = derToRS(signSighash(sighash, secret).slice(0, -1));
    const compact = new secp.Signature(r, s).toBytes('compact');
    expect(compact.length).toBe(64);
    expect(secp.verify(compact, sighash, owner.pub)).toBe(false);
    expect(secp.verify(compact, sighash, owner.pub, { prehash: false, format: 'compact' })).toBe(true);
  });

  it('keeps malformed keys and zero/out-of-range signature scalars fail-closed', () => {
    const wire = signSighash(sighash, secret);
    expect(checkSig(wire, new Uint8Array(33), sighash)).toBe(false);
    expect(checkSig(wire, owner.pub.slice(0, 32), sighash)).toBe(false);
    for (const [r, s] of [[0n, 1n], [1n, 0n], [CURVE_N, 1n], [1n, CURVE_N]]) {
      expect(checkSig(withType(rsToDER(scalarBytes(r), scalarBytes(s))), owner.pub, sighash, false)).toBe(false);
    }
    const first = makeKeyPair(); const second = makeKeyPair();
    expect(secp.utils.isValidSecretKey(first.priv)).toBe(true);
    expect(first.pub.length).toBe(33);
    expect(first.priv).not.toEqual(second.priv);
    expect(checkSig(wire, second.pub, sighash)).toBe(false);
  });
});
