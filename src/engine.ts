// engine.ts — the real cryptography behind the demo, built on the audited
// @noble libraries. Covers: secp256k1 keys, HASH160 (RIPEMD160∘SHA256), DER
// signature encoding/decoding/inspection, a real legacy SIGHASH_ALL preimage
// (exposed as labelled segments) over a concrete one-input/one-output
// transaction, ECDSA signing, Base58Check P2PKH addresses, and the OP_CHECKSIG
// verification predicate.
//
// Everything here is real Bitcoin math. The signature scheme is ECDSA over
// secp256k1 with low-S enforced (BIP-146) and DER encoding (BIP-66). The sighash
// is the genuine legacy algorithm. This is for EDUCATION — keys are generated
// per session in memory and never persisted; do not guard real funds.

import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha2';
import { ripemd160 } from '@noble/hashes/legacy';
import { hmac } from '@noble/hashes/hmac';

// @noble/secp256k1 v2 needs a synchronous HMAC-SHA256 wired up for RFC-6979
// deterministic ECDSA (otherwise only the async signer is available).
secp.etc.hmacSha256Sync = (key: Uint8Array, ...msgs: Uint8Array[]): Uint8Array =>
  hmac(sha256, key, secp.etc.concatBytes(...msgs));

const N = secp.CURVE.n;
const HALF_N = N / 2n;

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
  if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) throw new Error('invalid hex');
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
export function sha256d(b: Uint8Array): Uint8Array {
  return sha256(sha256(b));
}
export function hash160(b: Uint8Array): Uint8Array {
  return ripemd160(sha256(b));
}

/** The two intermediate steps of HASH160, for the pipeline visualizer. */
export function hash160Pipeline(b: Uint8Array): { sha256: Uint8Array; ripemd160: Uint8Array } {
  const s = sha256(b);
  return { sha256: s, ripemd160: ripemd160(s) };
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
// Base58Check (for the P2PKH address bridge)
// ---------------------------------------------------------------------------
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58encode(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let str = '1'.repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) str += B58[digits[i]];
  return str;
}
export function base58check(payload: Uint8Array): string {
  return base58encode(concat(payload, sha256d(payload).slice(0, 4)));
}
/** mainnet P2PKH address: Base58Check(0x00 || pubKeyHash). */
export function p2pkhAddress(pubKeyHash: Uint8Array): string {
  return base58check(concat(Uint8Array.of(0x00), pubKeyHash));
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

/** Validate/normalize a compressed public key (33 bytes, 0x02/0x03 prefix, on
 *  curve). Throws on anything malformed so callers can fail closed. */
export function parseCompressedPubKey(bytes: Uint8Array): Uint8Array {
  if (bytes.length !== 33) throw new Error('compressed public key must be 33 bytes');
  if (bytes[0] !== 0x02 && bytes[0] !== 0x03) throw new Error('prefix must be 0x02 or 0x03');
  secp.Point.fromBytes(bytes); // throws if not on the curve
  return bytes;
}

// ---------------------------------------------------------------------------
// DER encoding/decoding (BIP-66 shape). @noble v2 only exposes compact (r||s),
// so the Bitcoin-flavoured DER wrapper is built here — and it is exactly the
// part a student wants to see, not hide in a library.
// ---------------------------------------------------------------------------
function derInt(be32: Uint8Array): Uint8Array {
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
  if (der[1] !== der.length - 2) throw new Error('bad DER: length mismatch');
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
  if (p + slen !== der.length) throw new Error('bad DER: trailing bytes');
  const toBig = (x: Uint8Array) => (x.length ? BigInt('0x' + bytesToHex(x)) : 0n);
  return { r: toBig(r), s: toBig(s) };
}

export const SIGHASH_TYPES: Record<number, string> = {
  0x01: 'SIGHASH_ALL',
  0x02: 'SIGHASH_NONE',
  0x03: 'SIGHASH_SINGLE',
  0x81: 'SIGHASH_ALL | ANYONECANPAY',
  0x82: 'SIGHASH_NONE | ANYONECANPAY',
  0x83: 'SIGHASH_SINGLE | ANYONECANPAY',
};

export interface SigInspection {
  ok: boolean; // structurally parseable as DER || hashType
  derHex: string;
  rHex: string;
  sHex: string;
  hashType: number;
  hashTypeName: string;
  hashTypeSupported: boolean;
  lowS: boolean;
  error?: string;
}

/** Decode a scriptSig signature (DER || hashType) into inspectable fields. */
export function inspectSignature(sigWithType: Uint8Array): SigInspection {
  const blank: SigInspection = {
    ok: false,
    derHex: bytesToHex(sigWithType),
    rHex: '',
    sHex: '',
    hashType: sigWithType.length ? sigWithType[sigWithType.length - 1] : 0,
    hashTypeName: 'n/a',
    hashTypeSupported: false,
    lowS: false,
  };
  try {
    if (sigWithType.length < 9) throw new Error('signature too short');
    const hashType = sigWithType[sigWithType.length - 1];
    const der = sigWithType.slice(0, sigWithType.length - 1);
    const { r, s } = derToRS(der);
    return {
      ok: true,
      derHex: bytesToHex(der),
      rHex: bytesToHex(bigintTo32be(r)),
      sHex: bytesToHex(bigintTo32be(s)),
      hashType,
      hashTypeName: SIGHASH_TYPES[hashType] ?? `unknown (0x${hashType.toString(16)})`,
      hashTypeSupported: hashType === SIGHASH_ALL,
      lowS: s <= HALF_N,
    };
  } catch (e) {
    return { ...blank, error: (e as Error).message };
  }
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

export interface SighashSegment {
  label: string;
  bytes: Uint8Array;
  note: string;
}

/** The legacy SIGHASH_ALL preimage, broken into the fields that get
 *  concatenated and double-SHA256'd. The UI renders this as an annotated table
 *  and diffs the segments between the original and tampered transactions. */
export function sighashSegments(ctx: SpendContext): SighashSegment[] {
  return [
    { label: 'version', bytes: u32le(ctx.version), note: 'transaction version (4-byte LE)' },
    { label: 'input count', bytes: varint(1), note: 'number of inputs (varint)' },
    { label: 'prev txid', bytes: ctx.prevTxid, note: 'outpoint being spent (32 bytes, internal order)' },
    { label: 'prev vout', bytes: u32le(ctx.vout), note: 'output index in that tx (4-byte LE)' },
    { label: 'subscript len', bytes: varint(ctx.subscript.length), note: 'length of the script being signed (varint)' },
    { label: 'subscript', bytes: ctx.subscript, note: 'the scriptPubKey being spent (the P2PKH lock)' },
    { label: 'sequence', bytes: u32le(ctx.sequence), note: 'input sequence number (4-byte LE)' },
    { label: 'output count', bytes: varint(1), note: 'number of outputs (varint)' },
    { label: 'output value', bytes: u64le(ctx.outValue), note: 'amount in satoshis (8-byte LE)' },
    { label: 'output script len', bytes: varint(ctx.outScript.length), note: 'length of the destination script (varint)' },
    { label: 'output script', bytes: ctx.outScript, note: 'destination scriptPubKey' },
    { label: 'locktime', bytes: u32le(ctx.locktime), note: 'transaction locktime (4-byte LE)' },
    { label: 'hash type', bytes: u32le(SIGHASH_ALL), note: 'SIGHASH_ALL appended before hashing (4-byte LE)' },
  ];
}

export function sighashPreimage(ctx: SpendContext): Uint8Array {
  return concat(...sighashSegments(ctx).map((s) => s.bytes));
}

export function legacySighash(ctx: SpendContext): Uint8Array {
  return sha256d(sighashPreimage(ctx));
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

/** Like signSighash but flips s to n−s, producing a mathematically valid but
 *  non-standard HIGH-S signature (BIP-146 policy rejects it). For edge cases. */
export function signSighashHighS(sighash: Uint8Array, priv: Uint8Array): Uint8Array {
  const sig = secp.sign(sighash, priv);
  const highS = N - sig.s;
  const der = rsToDER(bigintTo32be(sig.r), bigintTo32be(highS));
  return concat(der, Uint8Array.of(SIGHASH_ALL));
}

/** OP_CHECKSIG's predicate: does `sigWithType` (DER||hashType) verify `pub`
 *  against `sighash`? Mirrors consensus: any malformed/out-of-range/forged
 *  signature simply yields false rather than throwing. `lowS` defaults to true
 *  (BIP-146 policy); pass false to see whether a high-S sig is otherwise valid. */
export function checkSig(
  sigWithType: Uint8Array,
  pub: Uint8Array,
  sighash: Uint8Array,
  lowS = true,
): boolean {
  if (sigWithType.length < 9) return false;
  try {
    const der = sigWithType.slice(0, sigWithType.length - 1); // drop hash-type byte
    const { r, s } = derToRS(der);
    const sig = new secp.Signature(r, s); // throws if r or s ∉ [1, n)
    return secp.verify(sig.toCompactRawBytes(), sighash, pub, { lowS });
  } catch {
    return false;
  }
}

export { secp, N as CURVE_N, HALF_N };
