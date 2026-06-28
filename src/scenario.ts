// scenario.ts — wires the engine (keys, sighash, ECDSA) to the interpreter
// (scripts, execution) to produce the four teaching scenarios the UI lets the
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
// The three failing scenarios are the whole point: each rejection is Bitcoin's
// security model working as designed, not an error.

import {
  KeyPair,
  SpendContext,
  legacySighash,
  signSighash,
  bytesToHex,
  hexToBytes,
} from './engine';
import {
  ScriptElement,
  p2pkhScriptPubKey,
  p2pkhScriptSig,
  serializeScript,
} from './script';

export type ScenarioId = 'valid' | 'wrong-key' | 'forged-sig' | 'tampered-tx';

export interface BuiltScenario {
  id: ScenarioId;
  title: string;
  twist: string; // one-line description of the adversarial change
  // what the student should take away from the (correct) outcome:
  lesson: string;
  scriptSig: ScriptElement[];
  scriptPubKey: ScriptElement[];
  execSighash: Uint8Array; // the message OP_CHECKSIG verifies against
  expectSuccess: boolean;
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
  signedOver: string; // what the offered signature actually committed to
}

// A fixed, obviously-fake previous output so the transaction is concrete and
// reproducible. (32 zero-ish bytes — this is demo data, not a real UTXO.)
const PREV_TXID = hexToBytes('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
// A fixed destination scriptPubKey (P2PKH to an arbitrary 20-byte hash).
const DEST_HASH = hexToBytes('89abcdef0123456789abcdef0123456789abcdef');
const DEST_SCRIPT = serializeScript(p2pkhScriptPubKey(DEST_HASH));

const OUT_VALUE = 50_000n; // 0.0005 BTC, in satoshis
const TAMPERED_VALUE = 100_000_000n; // attacker rewrites it to 1.0 BTC

function baseContext(owner: KeyPair, outValue: bigint): SpendContext {
  return {
    version: 1,
    prevTxid: PREV_TXID,
    vout: 0,
    sequence: 0xffffffff,
    subscript: serializeScript(p2pkhScriptPubKey(owner.pubKeyHash)), // funds locked to owner
    outValue,
    outScript: DEST_SCRIPT,
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

/** Build all four scenarios for a given owner/attacker key pair. */
export function buildScenarios(owner: KeyPair, attacker: KeyPair): Record<ScenarioId, BuiltScenario> {
  const ctx = baseContext(owner, OUT_VALUE);
  const sighash = legacySighash(ctx);
  const scriptPubKey = p2pkhScriptPubKey(owner.pubKeyHash);
  const ownerPubKeyHashHex = bytesToHex(owner.pubKeyHash);

  // valid — the owner signs their own spend
  const ownerSig = signSighash(sighash, owner.priv);
  const valid: BuiltScenario = {
    id: 'valid',
    title: 'Valid spend',
    twist: 'The owner of the locked key signs this exact transaction.',
    lesson:
      'OP_EQUALVERIFY confirms the offered key hashes to the committed pubKeyHash, then OP_CHECKSIG confirms the signature. The stack ends TRUE — the spend is authorized.',
    scriptSig: p2pkhScriptSig(ownerSig, owner.pub),
    scriptPubKey,
    execSighash: sighash,
    expectSuccess: true,
    tx: txView(ctx, false),
    offeredPubHex: bytesToHex(owner.pub),
    ownerPubKeyHashHex,
    signedOver: 'this transaction (sighash matches)',
  };

  // wrong-key — attacker offers their own public key
  const attackerSig = signSighash(sighash, attacker.priv);
  const wrongKey: BuiltScenario = {
    id: 'wrong-key',
    title: 'Wrong public key',
    twist: "An attacker offers their own key pair instead of the owner's.",
    lesson:
      "OP_HASH160 of the attacker's key does not equal the committed pubKeyHash, so OP_EQUALVERIFY aborts the script immediately — execution never even reaches the signature check.",
    scriptSig: p2pkhScriptSig(attackerSig, attacker.pub),
    scriptPubKey,
    execSighash: sighash,
    expectSuccess: false,
    tx: txView(ctx, false),
    offeredPubHex: bytesToHex(attacker.pub),
    ownerPubKeyHashHex,
    signedOver: "this transaction, but with the attacker's key",
  };

  // forged-sig — attacker presents the owner's (public!) key but cannot make
  // a matching signature, so they sign with a key they actually control.
  const forged = signSighash(sighash, attacker.priv);
  const forgedSig: BuiltScenario = {
    id: 'forged-sig',
    title: 'Forged signature',
    twist:
      "The attacker presents the owner's public key (it's public) with a signature they made from a different private key.",
    lesson:
      'OP_EQUALVERIFY passes — the public key is correct. But OP_CHECKSIG verifies the signature against that public key and it does not match, so it pushes FALSE and the spend is rejected. Without the private key, no valid signature can be produced.',
    scriptSig: p2pkhScriptSig(forged, owner.pub),
    scriptPubKey,
    execSighash: sighash,
    expectSuccess: false,
    tx: txView(ctx, false),
    offeredPubHex: bytesToHex(owner.pub),
    ownerPubKeyHashHex,
    signedOver: "this transaction, but signed by the attacker's private key",
  };

  // tampered-tx — owner signs the original, attacker edits the output amount
  const tampCtx = baseContext(owner, TAMPERED_VALUE);
  const tamperedSighash = legacySighash(tampCtx);
  const tampered: BuiltScenario = {
    id: 'tampered-tx',
    title: 'Tampered transaction',
    twist:
      'The owner signed the original transaction; an attacker then edited the output amount from 0.0005 BTC to 1.0 BTC.',
    lesson:
      'The signature commits to the whole transaction via the sighash. Changing any field changes the sighash, so the owner’s real signature no longer verifies — OP_CHECKSIG pushes FALSE. Signatures make transactions tamper-evident.',
    scriptSig: p2pkhScriptSig(ownerSig, owner.pub), // signed over the ORIGINAL sighash
    scriptPubKey,
    execSighash: tamperedSighash, // verified against the TAMPERED transaction
    expectSuccess: false,
    tx: txView(tampCtx, true),
    offeredPubHex: bytesToHex(owner.pub),
    ownerPubKeyHashHex,
    signedOver: 'the ORIGINAL transaction (0.0005 BTC), not the edited one',
  };

  return { valid, 'wrong-key': wrongKey, 'forged-sig': forgedSig, 'tampered-tx': tampered };
}
