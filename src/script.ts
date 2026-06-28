// script.ts — a small, deliberately inspectable Bitcoin Script stack machine.
//
// This is the teaching subject, so the interpreter is hand-rolled rather than
// hidden in a library: every opcode mutates a visible stack and emits a trace
// step the UI replays one box at a time. It implements exactly the opcodes the
// standard P2PK and P2PKH spending paths need:
//
//   OP_DUP  OP_HASH160  OP_EQUAL  OP_EQUALVERIFY  OP_CHECKSIG  + data pushes
//
// Real Bitcoin's OP_CHECKSIG recomputes the sighash from the transaction. Here
// the harness computes the sighash (engine.legacySighash) and hands it to the
// interpreter via ExecContext — the interpreter never lets attacker-controlled
// stack data pick its own message. That keeps the trust boundary honest while
// keeping the opcode set teachable.

import { bytesToHex, bytesEqual, hash160, checkSig } from './engine';

// ---- opcodes we model (real consensus byte values) ----
export const OPS = {
  OP_DUP: 0x76,
  OP_HASH160: 0xa9,
  OP_EQUAL: 0x87,
  OP_EQUALVERIFY: 0x88,
  OP_CHECKSIG: 0xac,
} as const;

export type OpName = keyof typeof OPS;

/** A script element: either a data push or an opcode. Pushes carry a human
 *  label ("signature", "public key", …) purely so the visualizer can name the
 *  bytes; the label never affects execution. */
export type ScriptElement =
  | { kind: 'push'; bytes: Uint8Array; label: string }
  | { kind: 'op'; op: OpName };

export interface StackItem {
  hex: string;
  label: string;
}

export type StepStatus = 'push' | 'op' | 'verify-pass' | 'verify-fail' | 'abort';

export interface TraceStep {
  n: number;
  token: string; // how this element prints in a script, e.g. "OP_DUP" or "<sig>"
  action: string; // plain-language description of what happened
  stackAfter: StackItem[];
  status: StepStatus;
  note?: string;
}

export interface ExecResult {
  steps: TraceStep[];
  success: boolean;
  finalStack: StackItem[];
  failReason?: string;
}

export interface ExecContext {
  /** The message OP_CHECKSIG verifies against (the transaction's sighash). */
  sighash: Uint8Array;
}

// ---- script builders ------------------------------------------------------
export function p2pkhScriptPubKey(pubKeyHash: Uint8Array): ScriptElement[] {
  return [
    { kind: 'op', op: 'OP_DUP' },
    { kind: 'op', op: 'OP_HASH160' },
    { kind: 'push', bytes: pubKeyHash, label: 'pubKeyHash' },
    { kind: 'op', op: 'OP_EQUALVERIFY' },
    { kind: 'op', op: 'OP_CHECKSIG' },
  ];
}
export function p2pkhScriptSig(sig: Uint8Array, pub: Uint8Array): ScriptElement[] {
  return [
    { kind: 'push', bytes: sig, label: 'signature' },
    { kind: 'push', bytes: pub, label: 'public key' },
  ];
}
export function p2pkScriptPubKey(pub: Uint8Array): ScriptElement[] {
  return [
    { kind: 'push', bytes: pub, label: 'public key' },
    { kind: 'op', op: 'OP_CHECKSIG' },
  ];
}
export function p2pkScriptSig(sig: Uint8Array): ScriptElement[] {
  return [{ kind: 'push', bytes: sig, label: 'signature' }];
}

// ---- pretty printing ------------------------------------------------------
export function tokenOf(el: ScriptElement): string {
  if (el.kind === 'op') return el.op;
  // a data push prints as the angle-bracketed thing it represents
  const named: Record<string, string> = {
    signature: '<sig>',
    'public key': '<pubKey>',
    pubKeyHash: '<pubKeyHash>',
  };
  return named[el.label] ?? `<${el.label}>`;
}
export function scriptToString(els: ScriptElement[]): string {
  return els.map(tokenOf).join(' ');
}

/** Serialize a script to the real Bitcoin byte string (single-byte pushdata,
 *  valid for every data element this demo uses since all are < 76 bytes). */
export function serializeScript(els: ScriptElement[]): Uint8Array {
  const out: number[] = [];
  for (const el of els) {
    if (el.kind === 'op') {
      out.push(OPS[el.op]);
    } else {
      if (el.bytes.length >= 0x4c) throw new Error('demo pushes are all < 76 bytes');
      out.push(el.bytes.length);
      out.push(...el.bytes);
    }
  }
  return new Uint8Array(out);
}

// ---- the interpreter ------------------------------------------------------
function isTruthy(item: StackItem | undefined): boolean {
  // Bitcoin: empty array and all-zero bytes are false; anything else is true.
  if (!item || item.hex === '') return false;
  return /[1-9a-f]/.test(item.hex);
}

/**
 * Execute scriptSig followed by scriptPubKey, recording a trace step per
 * element. Validity = no abort, and a single truthy value left on the stack.
 */
export function execute(
  scriptSig: ScriptElement[],
  scriptPubKey: ScriptElement[],
  ctx: ExecContext,
): ExecResult {
  const stack: { bytes: Uint8Array; label: string }[] = [];
  const steps: TraceStep[] = [];
  let n = 0;
  let aborted = false;
  let failReason: string | undefined;

  const snapshot = (): StackItem[] =>
    stack.map((s) => ({ hex: bytesToHex(s.bytes) || '(empty)', label: s.label }));

  const push = (token: string, action: string, status: StepStatus, note?: string) =>
    steps.push({ n: ++n, token, action, stackAfter: snapshot(), status, note });

  const all = [...scriptSig, ...scriptPubKey];

  for (const el of all) {
    if (aborted) break;
    const token = tokenOf(el);

    if (el.kind === 'push') {
      stack.push({ bytes: el.bytes, label: el.label });
      push(token, `Push the ${el.label} onto the stack.`, 'push');
      continue;
    }

    switch (el.op) {
      case 'OP_DUP': {
        const top = stack[stack.length - 1];
        if (!top) {
          aborted = true;
          failReason = 'OP_DUP on an empty stack';
          push(token, 'OP_DUP failed — the stack is empty.', 'abort', failReason);
          break;
        }
        stack.push({ bytes: top.bytes, label: top.label });
        push(token, `Duplicate the top item (the ${top.label}).`, 'op');
        break;
      }
      case 'OP_HASH160': {
        const top = stack.pop();
        if (!top) {
          aborted = true;
          failReason = 'OP_HASH160 on an empty stack';
          push(token, 'OP_HASH160 failed — the stack is empty.', 'abort', failReason);
          break;
        }
        const h = hash160(top.bytes);
        stack.push({ bytes: h, label: `HASH160(${top.label})` });
        push(token, `Replace the top item with HASH160 = RIPEMD160(SHA256(${top.label})).`, 'op');
        break;
      }
      case 'OP_EQUAL':
      case 'OP_EQUALVERIFY': {
        const a = stack.pop();
        const b = stack.pop();
        if (!a || !b) {
          aborted = true;
          failReason = `${el.op} needs two items`;
          push(token, `${el.op} failed — fewer than two items on the stack.`, 'abort', failReason);
          break;
        }
        const equal = bytesEqual(a.bytes, b.bytes);
        if (el.op === 'OP_EQUALVERIFY') {
          if (equal) {
            push(
              token,
              `The two hashes match — the offered key hashes to the committed pubKeyHash. Continue.`,
              'verify-pass',
            );
          } else {
            aborted = true;
            failReason = 'OP_EQUALVERIFY: the public key does not match the committed pubKeyHash';
            push(
              token,
              `The hashes differ — this key is NOT the one the funds were locked to. Script aborts.`,
              'abort',
              failReason,
            );
          }
        } else {
          stack.push(equal ? { bytes: Uint8Array.of(1), label: 'TRUE' } : { bytes: new Uint8Array(0), label: 'FALSE (empty)' });
          push(token, `Compare the two items and push ${equal ? 'TRUE' : 'FALSE'}.`, equal ? 'verify-pass' : 'verify-fail');
        }
        break;
      }
      case 'OP_CHECKSIG': {
        const pub = stack.pop();
        const sig = stack.pop();
        if (!pub || !sig) {
          aborted = true;
          failReason = 'OP_CHECKSIG needs a signature and a public key';
          push(token, 'OP_CHECKSIG failed — missing signature or public key.', 'abort', failReason);
          break;
        }
        const ok = checkSig(sig.bytes, pub.bytes, ctx.sighash);
        stack.push(ok ? { bytes: Uint8Array.of(1), label: 'TRUE' } : { bytes: new Uint8Array(0), label: 'FALSE (empty)' });
        if (ok) {
          push(token, `Verify the ECDSA signature over the transaction sighash with this public key — VALID. Push TRUE.`, 'verify-pass');
        } else {
          push(
            token,
            `Verify the ECDSA signature over the transaction sighash — INVALID. Push FALSE.`,
            'verify-fail',
            'The signature does not match this public key over this exact transaction.',
          );
        }
        break;
      }
    }
  }

  const top = stack[stack.length - 1];
  const success = !aborted && stack.length >= 1 && isTruthy(snapshotTop(top));
  if (!aborted && !success) {
    failReason = stack.length === 0 ? 'script left an empty stack' : 'top of stack is FALSE';
  }

  return { steps, success, finalStack: steps.length ? steps[steps.length - 1].stackAfter : [], failReason };
}

function snapshotTop(top: { bytes: Uint8Array; label: string } | undefined): StackItem | undefined {
  if (!top) return undefined;
  return { hex: bytesToHex(top.bytes), label: top.label };
}
