// scenario.ts — wires the engine (keys, sighash, ECDSA) to the interpreter
// (scripts, execution) to produce the teaching scenarios the UI lets the
// student run. Each scenario is a complete, real spend attempt; the only thing
// that varies is which adversarial twist is applied.
//
//   valid       — the right key signs this transaction → ACCEPT
//   wrong-key   — an attacker offers their own key      → OP_EQUALVERIFY aborts
//   forged-sig  — attacker offers the owner's pubkey but
//                 a signature they couldn't have made   → OP_CHECKSIG false
//   tampered-tx — owner's real signature, but the output
//                 amount was edited after signing       → OP_CHECKSIG false
//
// Plus an "edge cases" group (high-S, malformed DER, swapped scriptSig order)
// that probes the boundary where the simplified teaching model meets real
// consensus/policy rules. Every failing scenario is the security model working.

import {
  KeyPair,
  SpendContext,
  SighashSegment,
  sighashSegments,
  legacySighash,
  signSighash,
  signSighashHighS,
  bytesToHex,
  hexToBytes,
} from './engine';
import {
  ScriptElement,
  p2pkhScriptPubKey,
  p2pkhScriptSig,
  serializeScript,
} from './script';

export type ScenarioId =
  | 'valid'
  | 'wrong-key'
  | 'forged-sig'
  | 'tampered-tx'
  | 'high-s'
  | 'bad-der'
  | 'swapped';

export const CANONICAL_IDS: ScenarioId[] = ['valid', 'wrong-key', 'forged-sig', 'tampered-tx'];
export const EDGE_IDS: ScenarioId[] = ['high-s', 'bad-der', 'swapped'];

export interface BuiltScenario {
  id: ScenarioId;
  title: string;
  group: 'canonical' | 'edge';
  twist: string;
  lesson: string;
  scriptSig: ScriptElement[];
  scriptPubKey: ScriptElement[];
  execSighash: Uint8Array; // the message OP_CHECKSIG verifies against
  expectSuccess: boolean;
  firstFailOp: string | null; // opcode where it first fails, for the matrix
  // transaction the verifier sees (post-tamper, if any):
  tx: {
    version: number;
    prevTxidHex: string;
    vout: number;
    sequence: number;
    outValueSats: bigint;
    locktime: number;
    tamperedValue: boolean;
  };
  offeredPubHex: string;
  ownerPubKeyHashHex: string;
  signedOver: string;
  // sighash inspector data:
  signedSegments: SighashSegment[];
  verifierSegments: SighashSegment[];
  signedSighashHex: string;
  execSighashHex: string;
  // matrix columns:
  keyMatches: boolean;
  sigMatches: boolean;
  sigSource: string;
}

const PREV_TXID = hexToBytes('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
const DEST_HASH = hexToBytes('89abcdef0123456789abcdef0123456789abcdef');
const DEST_SCRIPT = serializeScript(p2pkhScriptPubKey(DEST_HASH));

const OUT_VALUE = 50_000n; // 0.0005 BTC, in satoshis
const TAMPERED_VALUE = 100_000_000n; // attacker rewrites it to 1.0 BTC

function baseContext(owner: KeyPair, outValue: bigint, outScript: Uint8Array): SpendContext {
  return {
    version: 1,
    prevTxid: PREV_TXID,
    vout: 0,
    sequence: 0xffffffff,
    subscript: serializeScript(p2pkhScriptPubKey(owner.pubKeyHash)),
    outValue,
    outScript,
    locktime: 0,
  };
}

function txView(ctx: SpendContext, tamperedValue: boolean) {
  return {
    version: ctx.version,
    prevTxidHex: bytesToHex(ctx.prevTxid),
    vout: ctx.vout,
    sequence: ctx.sequence,
    outValueSats: ctx.outValue,
    locktime: ctx.locktime,
    tamperedValue,
  };
}

/** Build every scenario for a given owner/attacker key pair. */
export function buildScenarios(
  owner: KeyPair,
  attacker: KeyPair,
  opts: { outValue?: bigint; destHash?: Uint8Array } = {},
): Record<ScenarioId, BuiltScenario> {
  const outValue = opts.outValue ?? OUT_VALUE;
  const destScript = opts.destHash ? serializeScript(p2pkhScriptPubKey(opts.destHash)) : DEST_SCRIPT;
  const ctx = baseContext(owner, outValue, destScript);
  const sighash = legacySighash(ctx);
  const sighashHex = bytesToHex(sighash);
  const scriptPubKey = p2pkhScriptPubKey(owner.pubKeyHash);
  const ownerPubKeyHashHex = bytesToHex(owner.pubKeyHash);
  const baseSegs = sighashSegments(ctx);

  const common = {
    scriptPubKey,
    ownerPubKeyHashHex,
    signedSegments: baseSegs,
    verifierSegments: baseSegs,
    signedSighashHex: sighashHex,
    execSighashHex: sighashHex,
  };

  const ownerSig = signSighash(sighash, owner.priv);
  const valid: BuiltScenario = {
    ...common,
    id: 'valid',
    title: 'Valid spend',
    group: 'canonical',
    twist: 'The owner of the locked key signs this exact transaction.',
    lesson:
      'OP_EQUALVERIFY confirms the offered key hashes to the committed pubKeyHash, then OP_CHECKSIG confirms the signature. The stack ends with a truthy value — the spend is authorized.',
    scriptSig: p2pkhScriptSig(ownerSig, owner.pub),
    execSighash: sighash,
    expectSuccess: true,
    firstFailOp: null,
    tx: txView(ctx, false),
    offeredPubHex: bytesToHex(owner.pub),
    signedOver: 'this transaction (sighash matches)',
    keyMatches: true,
    sigMatches: true,
    sigSource: "owner's key, this tx",
  };

  const attackerSig = signSighash(sighash, attacker.priv);
  const wrongKey: BuiltScenario = {
    ...common,
    id: 'wrong-key',
    title: 'Wrong public key',
    group: 'canonical',
    twist: "An attacker offers their own key pair instead of the owner's.",
    lesson:
      "OP_HASH160 of the attacker's key does not equal the committed pubKeyHash, so OP_EQUALVERIFY aborts the script immediately — execution never even reaches the signature check.",
    scriptSig: p2pkhScriptSig(attackerSig, attacker.pub),
    execSighash: sighash,
    expectSuccess: false,
    firstFailOp: 'OP_EQUALVERIFY',
    tx: txView(ctx, false),
    offeredPubHex: bytesToHex(attacker.pub),
    signedOver: "this transaction, but with the attacker's key",
    keyMatches: false,
    sigMatches: false,
    sigSource: "attacker's key",
  };

  const forged = signSighash(sighash, attacker.priv);
  const forgedSig: BuiltScenario = {
    ...common,
    id: 'forged-sig',
    title: 'Forged signature',
    group: 'canonical',
    twist:
      "The attacker presents the owner's public key (it's public) with a signature they made from a different private key.",
    lesson:
      'OP_EQUALVERIFY passes — the public key is correct. But OP_CHECKSIG verifies the signature against that public key and it does not match, so it pushes FALSE and the spend is rejected. Without the private key, no valid signature can be produced.',
    scriptSig: p2pkhScriptSig(forged, owner.pub),
    execSighash: sighash,
    expectSuccess: false,
    firstFailOp: 'OP_CHECKSIG',
    tx: txView(ctx, false),
    offeredPubHex: bytesToHex(owner.pub),
    signedOver: "this transaction, but signed by the attacker's private key",
    keyMatches: true,
    sigMatches: false,
    sigSource: "attacker's key, owner's pubkey",
  };

  const tamperedValue = outValue < TAMPERED_VALUE ? TAMPERED_VALUE : outValue + 1n;
  const tampCtx = baseContext(owner, tamperedValue, destScript);
  const tamperedSighash = legacySighash(tampCtx);
  const tampered: BuiltScenario = {
    ...common,
    id: 'tampered-tx',
    title: 'Tampered transaction',
    group: 'canonical',
    twist:
      'The owner signed the original transaction; an attacker then edited the output amount after it was signed.',
    lesson:
      'The signature commits to the whole transaction via the sighash. Changing any field changes the sighash, so the owner’s real signature no longer verifies — OP_CHECKSIG pushes FALSE. Signatures make transactions tamper-evident.',
    scriptSig: p2pkhScriptSig(ownerSig, owner.pub), // signed over the ORIGINAL sighash
    execSighash: tamperedSighash, // verified against the TAMPERED transaction
    expectSuccess: false,
    firstFailOp: 'OP_CHECKSIG',
    tx: txView(tampCtx, true),
    offeredPubHex: bytesToHex(owner.pub),
    signedOver: 'the ORIGINAL transaction (0.0005 BTC), not the edited one',
    keyMatches: true,
    sigMatches: false,
    sigSource: 'owner, original tx only',
    // override the verifier sighash data with the tampered transaction
    verifierSegments: sighashSegments(tampCtx),
    execSighashHex: bytesToHex(tamperedSighash),
  };

  // ---- edge cases ----
  const highSSig = signSighashHighS(sighash, owner.priv);
  const highS: BuiltScenario = {
    ...common,
    id: 'high-s',
    title: 'High-S signature',
    group: 'edge',
    twist:
      "The owner signs correctly, but the signature's s value is the high variant (n − s) — mathematically valid, but non-standard.",
    lesson:
      'ECDSA has two valid s values for every signature (s and n − s). Bitcoin policy (BIP-146) requires the low one to stop signature malleability, so OP_CHECKSIG rejects the high-S form even though the raw ECDSA math checks out. The Signature decoder flags low-S = false.',
    scriptSig: p2pkhScriptSig(highSSig, owner.pub),
    execSighash: sighash,
    expectSuccess: false,
    firstFailOp: 'OP_CHECKSIG',
    tx: txView(ctx, false),
    offeredPubHex: bytesToHex(owner.pub),
    signedOver: 'this transaction, but with a malleated (high-S) signature',
    keyMatches: true,
    sigMatches: false,
    sigSource: 'owner, high-S form',
  };

  // a structurally-broken DER signature (claims an r length that overruns)
  const badDerSig = hexToBytes('30060209000102030405' + '01');
  const badDer: BuiltScenario = {
    ...common,
    id: 'bad-der',
    title: 'Malformed DER',
    group: 'edge',
    twist: 'The signature bytes are not valid DER (the r length field overruns the structure).',
    lesson:
      'Strict DER parsing (BIP-66) rejects ill-formed signatures before any curve math runs. The decoder fails closed, OP_CHECKSIG treats it as invalid and pushes FALSE — no exception, no guesswork.',
    scriptSig: p2pkhScriptSig(badDerSig, owner.pub),
    execSighash: sighash,
    expectSuccess: false,
    firstFailOp: 'OP_CHECKSIG',
    tx: txView(ctx, false),
    offeredPubHex: bytesToHex(owner.pub),
    signedOver: 'nothing — the bytes do not parse as a signature',
    keyMatches: true,
    sigMatches: false,
    sigSource: 'malformed bytes',
  };

  const swapped: BuiltScenario = {
    ...common,
    id: 'swapped',
    title: 'Swapped scriptSig order',
    group: 'edge',
    twist: 'The unlocking script pushes <pubKey> then <sig> — the reverse of the required order.',
    lesson:
      'P2PKH needs <sig> <pubKey> so that OP_DUP/OP_HASH160 operate on the public key. With the order swapped, OP_HASH160 hashes the signature instead, the result cannot equal the committed pubKeyHash, and OP_EQUALVERIFY aborts. Stack order is part of the contract.',
    scriptSig: p2pkhScriptSig(owner.pub, ownerSig).map((el) =>
      // relabel so the tokens read honestly after the swap
      el.kind === 'push' && el.label === 'signature'
        ? { ...el, label: 'public key' }
        : el.kind === 'push' && el.label === 'public key'
          ? { ...el, label: 'signature' }
          : el,
    ),
    execSighash: sighash,
    expectSuccess: false,
    firstFailOp: 'OP_EQUALVERIFY',
    tx: txView(ctx, false),
    offeredPubHex: bytesToHex(owner.pub),
    signedOver: 'this transaction, but the unlock pushes items in the wrong order',
    keyMatches: false,
    sigMatches: false,
    sigSource: 'owner, wrong push order',
  };

  return {
    valid,
    'wrong-key': wrongKey,
    'forged-sig': forgedSig,
    'tampered-tx': tampered,
    'high-s': highS,
    'bad-der': badDer,
    swapped,
  };
}
