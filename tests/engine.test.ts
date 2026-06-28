import { describe, it, expect } from 'vitest';
import {
  makeKeyPair,
  hash160,
  bytesToHex,
  hexToBytes,
  rsToDER,
  derToRS,
  signSighash,
  checkSig,
  legacySighash,
  SpendContext,
  secp,
} from '../src/engine';
import {
  execute,
  serializeScript,
  p2pkhScriptPubKey,
  p2pkScriptPubKey,
  p2pkScriptSig,
  scriptToString,
} from '../src/script';
import { buildScenarios } from '../src/scenario';

const one = (() => {
  const b = new Uint8Array(32);
  b[31] = 1;
  return b;
})();

describe('engine: real Bitcoin known-answers', () => {
  it('derives the canonical compressed pubkey + HASH160 for privkey = 1', () => {
    const kp = makeKeyPair(one);
    expect(bytesToHex(kp.pub)).toBe(
      '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    );
    // HASH160 of that key is the well-known address 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH.
    expect(bytesToHex(kp.pubKeyHash)).toBe('751e76e8199196d454941c45d1b3a323f1433bd6');
  });

  it('HASH160 is always 20 bytes', () => {
    expect(hash160(hexToBytes('deadbeef')).length).toBe(20);
  });
});

describe('DER encoding round-trips', () => {
  it('encodes and decodes an (r, s) pair', () => {
    const kp = makeKeyPair();
    const sig = secp.sign(new Uint8Array(32).fill(7), kp.priv);
    const r = hexToBytes(sig.r.toString(16).padStart(64, '0'));
    const s = hexToBytes(sig.s.toString(16).padStart(64, '0'));
    const der = rsToDER(r, s);
    expect(der[0]).toBe(0x30); // SEQUENCE
    const back = derToRS(der);
    expect(back.r).toBe(sig.r);
    expect(back.s).toBe(sig.s);
  });
});

describe('legacy sighash', () => {
  const kp = makeKeyPair(one);
  const ctx = (value: bigint): SpendContext => ({
    version: 1,
    prevTxid: new Uint8Array(32),
    vout: 0,
    sequence: 0xffffffff,
    subscript: serializeScript(p2pkhScriptPubKey(kp.pubKeyHash)),
    outValue: value,
    outScript: serializeScript(p2pkhScriptPubKey(kp.pubKeyHash)),
    locktime: 0,
  });

  it('is deterministic for the same transaction', () => {
    expect(bytesToHex(legacySighash(ctx(1000n)))).toBe(bytesToHex(legacySighash(ctx(1000n))));
  });
  it('changes when any field (the output value) changes', () => {
    expect(bytesToHex(legacySighash(ctx(1000n)))).not.toBe(bytesToHex(legacySighash(ctx(2000n))));
  });
});

describe('sign / checkSig predicate', () => {
  it('a real signature verifies; a different key and a different message do not', () => {
    const owner = makeKeyPair();
    const attacker = makeKeyPair();
    const sighash = new Uint8Array(32).fill(9);
    const sig = signSighash(sighash, owner.priv);

    expect(checkSig(sig, owner.pub, sighash)).toBe(true);
    expect(checkSig(sig, attacker.pub, sighash)).toBe(false); // wrong key
    expect(checkSig(sig, owner.pub, new Uint8Array(32).fill(8))).toBe(false); // wrong message
  });

  it('rejects garbage rather than throwing', () => {
    const kp = makeKeyPair();
    expect(checkSig(hexToBytes('00'), kp.pub, new Uint8Array(32))).toBe(false);
    expect(checkSig(new Uint8Array(40), kp.pub, new Uint8Array(32))).toBe(false);
  });
});

describe('P2PK executes end to end', () => {
  it('accepts a valid P2PK spend', () => {
    const kp = makeKeyPair();
    const sighash = new Uint8Array(32).fill(3);
    const sig = signSighash(sighash, kp.priv);
    const res = execute(p2pkScriptSig(sig), p2pkScriptPubKey(kp.pub), { sighash });
    expect(scriptToString(p2pkScriptPubKey(kp.pub))).toBe('<pubKey> OP_CHECKSIG');
    expect(res.success).toBe(true);
  });
});

describe('the four P2PKH scenarios behave as the demo claims', () => {
  const owner = makeKeyPair();
  const attacker = makeKeyPair();
  const s = buildScenarios(owner, attacker);

  it('valid spend: stack ends TRUE', () => {
    const r = execute(s.valid.scriptSig, s.valid.scriptPubKey, { sighash: s.valid.execSighash });
    expect(r.success).toBe(true);
    expect(r.steps.some((x) => x.status === 'verify-pass' && x.token === 'OP_CHECKSIG')).toBe(true);
  });

  it('wrong key: OP_EQUALVERIFY aborts before the signature is ever checked', () => {
    const r = execute(s['wrong-key'].scriptSig, s['wrong-key'].scriptPubKey, {
      sighash: s['wrong-key'].execSighash,
    });
    expect(r.success).toBe(false);
    const abort = r.steps.find((x) => x.status === 'abort');
    expect(abort?.token).toBe('OP_EQUALVERIFY');
    // execution stopped, so OP_CHECKSIG never ran
    expect(r.steps.some((x) => x.token === 'OP_CHECKSIG')).toBe(false);
  });

  it('forged signature: passes the key check but OP_CHECKSIG is FALSE', () => {
    const r = execute(s['forged-sig'].scriptSig, s['forged-sig'].scriptPubKey, {
      sighash: s['forged-sig'].execSighash,
    });
    expect(r.success).toBe(false);
    expect(r.steps.some((x) => x.token === 'OP_EQUALVERIFY' && x.status === 'verify-pass')).toBe(
      true,
    );
    expect(r.steps.some((x) => x.token === 'OP_CHECKSIG' && x.status === 'verify-fail')).toBe(true);
  });

  it('tampered transaction: the real signature no longer verifies', () => {
    const r = execute(s['tampered-tx'].scriptSig, s['tampered-tx'].scriptPubKey, {
      sighash: s['tampered-tx'].execSighash,
    });
    expect(r.success).toBe(false);
    expect(r.steps.some((x) => x.token === 'OP_CHECKSIG' && x.status === 'verify-fail')).toBe(true);
    expect(s['tampered-tx'].tx.tamperedValue).toBe(true);
  });

  it('every scenario’s expectSuccess matches actual execution', () => {
    for (const sc of Object.values(s)) {
      const r = execute(sc.scriptSig, sc.scriptPubKey, { sighash: sc.execSighash });
      expect(r.success).toBe(sc.expectSuccess);
    }
  });
});
