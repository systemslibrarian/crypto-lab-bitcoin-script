// engine.ts — the real cryptography behind the demo, built on the audited
// @noble libraries. Covers: secp256k1 keys, HASH160 (RIPEMD160∘SHA256), DER
// signature encoding/decoding, a real legacy SIGHASH_ALL preimage over a
// concrete one-input/one-output transaction, ECDSA signing, and the OP_CHECKSIG
// verification predicate.
//
// Everything here is real Bitcoin math. The signature scheme is ECDSA over
// secp256k1 with low-S enforced (BIP-146) and strict-ish DER (BIP-66). The
// sighash is the genuine legacy algorithm. This is for EDUCATION — keys are
// generated per session in memory and never persisted; do not guard real funds.

import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha2';
import { ripemd160 } from '@noble/hashes/legacy';
import { hmac } from '@noble/hashes/hmac';

// @noble/secp256k1 v2 needs a synchronous HMAC-SHA256 wired up for RFC-6979
// deterministic ECDSA (otherwise only the async signer is available).
secp.etc.hmacSha256Sync = (key: Uint8Array, ...msgs: Uint8Array[]): Uint8Array =>
  hmac(sha256, key, secp.etc.concatBytes(...msgs));

// ---------------------------------------------------------------------------
// byte helpers
// ---------------------------------------------------------------------------
export function bytesToHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
}
export function hexToBytes(h: string): Uint8Array {
  const clean = h.startsWith('0x') ? h.slice(2) : h;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}
export function concat(...a: Uint8Array[]): Uint8Array {
  const n = a.reduce((s, x) => s + x.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const x of a) {
    out.set(x, o);
    o += x.length;
  }
  return out;
}
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
export function hash160(b: Uint8Array): Uint8Array {
  return ripemd160(sha256(b));
}
function dsha256(b: Uint8Array): Uint8Array {
  return sha256(sha256(b));
}

// little-endian integer serializers used by transaction encoding
function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  b[0] = n & 0xff;
  b[1] = (n >>> 8) & 0xff;
  b[2] = (n >>> 16) & 0xff;
  b[3] = (n >>> 24) & 0xff;
  return b;
}
function u64le(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  let v = n;
  for (let i = 0; i < 8; i++) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
}
function varint(n: number): Uint8Array {
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return concat(Uint8Array.of(0xfd), u32le(n).slice(0, 2));
  return concat(Uint8Array.of(0xfe), u32le(n));
}
function bigintTo32be(n: bigint): Uint8Array {
  let h = n.toString(16);
  if (h.length > 64) throw new Error('integer too large for 32 bytes');
  h = h.padStart(64, '0');
  return hexToBytes(h);
}

// ---------------------------------------------------------------------------
// keys
// ---------------------------------------------------------------------------
export interface KeyPair {
  priv: Uint8Array;
  pub: Uint8Array; // 33-byte compressed public key
  pubKeyHash: Uint8Array; // HASH160(pub)
}

export function makeKeyPair(priv?: Uint8Array): KeyPair {
  const sk = priv ?? secp.utils.randomPrivateKey();
  const pub = secp.getPublicKey(sk, true);
  return { priv: sk, pub, pubKeyHash: hash160(pub) };
}

// ---------------------------------------------------------------------------
// DER encoding (BIP-66 shape). @noble v2 only exposes compact (r||s), so the
// Bitcoin-flavoured DER wrapper is built here — and it is exactly the part a
// student wants to see, not hide in a library.
// ---------------------------------------------------------------------------
function derInt(be32: Uint8Array): Uint8Array {
  // strip leading zero bytes, but keep one if the high bit would otherwise set
  let i = 0;
  while (i < be32.length - 1 && be32[i] === 0) i++;
  let v = be32.slice(i);
  if (v[0] & 0x80) v = concat(Uint8Array.of(0x00), v);
  return concat(Uint8Array.of(0x02, v.length), v);
}
export function rsToDER(r: Uint8Array, s: Uint8Array): Uint8Array {
  const body = concat(derInt(r), derInt(s));
  return concat(Uint8Array.of(0x30, body.length), body);
}
export function derToRS(der: Uint8Array): { r: bigint; s: bigint } {
  if (der[0] !== 0x30) throw new Error('bad DER: no sequence');
  let p = 2;
  if (der[p] !== 0x02) throw new Error('bad DER: r not an integer');
  p++;
  const rlen = der[p++];
  const r = der.slice(p, p + rlen);
  p += rlen;
  if (der[p] !== 0x02) throw new Error('bad DER: s not an integer');
  p++;
  const slen = der[p++];
  const s = der.slice(p, p + slen);
  const toBig = (x: Uint8Array) => (x.length ? BigInt('0x' + bytesToHex(x)) : 0n);
  return { r: toBig(r), s: toBig(s) };
}

// ---------------------------------------------------------------------------
// transaction + legacy SIGHASH_ALL
// ---------------------------------------------------------------------------
export const SIGHASH_ALL = 0x01;

export interface SpendContext {
  version: number;
  prevTxid: Uint8Array; // 32 bytes, internal byte order
  vout: number;
  sequence: number;
  /** scriptPubKey of the output being spent — the "subscript" signed over. */
  subscript: Uint8Array;
  outValue: bigint; // satoshis sent to the destination
  outScript: Uint8Array; // destination scriptPubKey
  locktime: number;
}

/** Serialize the transaction for signing input 0 with SIGHASH_ALL, then append
 *  the 4-byte hash type. This is the exact legacy preimage Bitcoin double-SHA256s. */
export function sighashPreimage(ctx: SpendContext): Uint8Array {
  return concat(
    u32le(ctx.version),
    varint(1),
    ctx.prevTxid,
    u32le(ctx.vout),
    varint(ctx.subscript.length),
    ctx.subscript,
    u32le(ctx.sequence),
    varint(1),
    u64le(ctx.outValue),
    varint(ctx.outScript.length),
    ctx.outScript,
    u32le(ctx.locktime),
    u32le(SIGHASH_ALL), // hash type, little-endian 4 bytes
  );
}

export function legacySighash(ctx: SpendContext): Uint8Array {
  return dsha256(sighashPreimage(ctx));
}

// ---------------------------------------------------------------------------
// sign / verify
// ---------------------------------------------------------------------------
/** ECDSA-sign a 32-byte sighash, low-S, and return the Bitcoin scriptSig push:
 *  DER(r,s) || hashType. */
export function signSighash(sighash: Uint8Array, priv: Uint8Array): Uint8Array {
  const sig = secp.sign(sighash, priv); // RFC-6979 deterministic, low-S by default
  const der = rsToDER(bigintTo32be(sig.r), bigintTo32be(sig.s));
  return concat(der, Uint8Array.of(SIGHASH_ALL));
}

/** OP_CHECKSIG's predicate: does `sigWithType` (DER||hashType) verify `pub`
 *  against `sighash`? Mirrors consensus: any malformed/out-of-range/forged
 *  signature simply yields false rather than throwing. */
export function checkSig(sigWithType: Uint8Array, pub: Uint8Array, sighash: Uint8Array): boolean {
  if (sigWithType.length < 9) return false;
  try {
    const der = sigWithType.slice(0, sigWithType.length - 1); // drop hash-type byte
    const { r, s } = derToRS(der);
    const sig = new secp.Signature(r, s); // throws if r or s ∉ [1, n)
    return secp.verify(sig.toCompactRawBytes(), sighash, pub);
  } catch {
    return false;
  }
}

export { secp };
