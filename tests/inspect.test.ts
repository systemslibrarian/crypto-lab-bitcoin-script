import { describe, it, expect } from 'vitest';
import {
  makeKeyPair,
  hexToBytes,
  bytesToHex,
  bytesEqual,
  concat,
  p2pkhAddress,
  hash160Pipeline,
  hash160,
  sighashSegments,
  sighashPreimage,
  legacySighash,
  sha256d,
  inspectSignature,
  signSighash,
  signSighashHighS,
  checkSig,
  parseCompressedPubKey,
  SpendContext,
} from '../src/engine';
import { serializeScript, p2pkhScriptPubKey } from '../src/script';
import { buildScenarios } from '../src/scenario';

const one = (() => {
  const b = new Uint8Array(32);
  b[31] = 1;
  return b;
})();

describe('Base58Check address bridge', () => {
  it('derives the textbook privkey=1 P2PKH address', () => {
    const kp = makeKeyPair(one);
    expect(p2pkhAddress(kp.pubKeyHash)).toBe('1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH');
  });
});

describe('HASH160 pipeline', () => {
  it('SHA-256 then RIPEMD-160 equals hash160', () => {
    const kp = makeKeyPair(one);
    const p = hash160Pipeline(kp.pub);
    expect(p.sha256.length).toBe(32);
    expect(p.ripemd160.length).toBe(20);
    expect(bytesEqual(p.ripemd160, hash160(kp.pub))).toBe(true);
    expect(bytesToHex(p.ripemd160)).toBe('751e76e8199196d454941c45d1b3a323f1433bd6');
  });
});

describe('sighash segments', () => {
  const kp = makeKeyPair(one);
  const ctx: SpendContext = {
    version: 1,
    prevTxid: new Uint8Array(32),
    vout: 0,
    sequence: 0xffffffff,
    subscript: serializeScript(p2pkhScriptPubKey(kp.pubKeyHash)),
    outValue: 1000n,
    outScript: serializeScript(p2pkhScriptPubKey(kp.pubKeyHash)),
    locktime: 0,
  };

  it('concatenated segments equal the preimage, and double-SHA256 equals the sighash', () => {
    const joined = concat(...sighashSegments(ctx).map((s) => s.bytes));
    expect(bytesToHex(joined)).toBe(bytesToHex(sighashPreimage(ctx)));
    expect(bytesToHex(sha256d(joined))).toBe(bytesToHex(legacySighash(ctx)));
  });

  it('ends with the SIGHASH_ALL hash-type segment 01000000', () => {
    const segs = sighashSegments(ctx);
    expect(segs[segs.length - 1].label).toBe('hash type');
    expect(bytesToHex(segs[segs.length - 1].bytes)).toBe('01000000');
  });
});

describe('signature inspection', () => {
  const kp = makeKeyPair();
  const sighash = new Uint8Array(32).fill(7);

  it('decodes a real signature: low-S, SIGHASH_ALL, supported', () => {
    const sig = signSighash(sighash, kp.priv);
    const info = inspectSignature(sig);
    expect(info.ok).toBe(true);
    expect(info.hashType).toBe(0x01);
    expect(info.hashTypeName).toBe('SIGHASH_ALL');
    expect(info.hashTypeSupported).toBe(true);
    expect(info.lowS).toBe(true);
    expect(info.rHex).toHaveLength(64);
    expect(info.sHex).toHaveLength(64);
  });

  it('flags a high-S signature, which policy rejects but raw ECDSA accepts', () => {
    const sig = signSighashHighS(sighash, kp.priv);
    const info = inspectSignature(sig);
    expect(info.ok).toBe(true);
    expect(info.lowS).toBe(false);
    expect(checkSig(sig, kp.pub, sighash)).toBe(false); // BIP-146 policy (default lowS)
    expect(checkSig(sig, kp.pub, sighash, false)).toBe(true); // mathematically valid
  });

  it('fails closed on malformed DER without throwing', () => {
    const info = inspectSignature(hexToBytes('3003020101' + '01'));
    expect(info.ok).toBe(false);
    expect(info.error).toBeTruthy();
  });
});

describe('parseCompressedPubKey', () => {
  it('accepts a real compressed key and rejects malformed ones', () => {
    const kp = makeKeyPair();
    expect(() => parseCompressedPubKey(kp.pub)).not.toThrow();
    expect(() => parseCompressedPubKey(new Uint8Array(33))).toThrow(); // 0x00 prefix
    expect(() => parseCompressedPubKey(kp.pub.slice(0, 20))).toThrow(); // wrong length
    expect(() => parseCompressedPubKey(concat(Uint8Array.of(0x02), new Uint8Array(32)))).toThrow(); // not on curve
  });
});

describe('inspector values match the scenarios the UI shows', () => {
  const owner = makeKeyPair();
  const attacker = makeKeyPair();
  const s = buildScenarios(owner, attacker);

  it('wrong-key: the offered key hashes to something other than the committed pubKeyHash', () => {
    const sc = s['wrong-key'];
    const offered = hexToBytes(sc.offeredPubHex);
    expect(bytesToHex(hash160(offered))).not.toBe(sc.ownerPubKeyHashHex);
  });

  it('forged-sig: the offered key matches but the signature is invalid', () => {
    const sc = s['forged-sig'];
    const offered = hexToBytes(sc.offeredPubHex);
    expect(bytesToHex(hash160(offered))).toBe(sc.ownerPubKeyHashHex);
    const sig = sc.scriptSig[0];
    if (sig.kind !== 'push') throw new Error('expected sig push');
    expect(checkSig(sig.bytes, offered, sc.execSighash)).toBe(false);
  });
});
