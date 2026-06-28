// ui.ts — all DOM construction and interaction. No crypto lives here; it calls
// engine/script/scenario. The page leads with the live lab (pick a scenario,
// inspect the real bytes, step the stack forward and back) and keeps the
// foundations and context below it.

import {
  makeKeyPair,
  KeyPair,
  bytesToHex,
  hexToBytes,
  hash160Pipeline,
  p2pkhAddress,
  inspectSignature,
  checkSig,
  CURVE_N,
} from './engine';
import {
  ScriptElement,
  execute,
  scriptToString,
  serializeScript,
  tokenOf,
  TraceStep,
  StackItem,
  p2pkScriptPubKey,
} from './script';
import {
  buildScenarios,
  BuiltScenario,
  ScenarioId,
  CANONICAL_IDS,
  EDGE_IDS,
} from './scenario';

// ---- tiny DOM helper ------------------------------------------------------
type Attrs = Record<string, string | number | boolean | ((e: Event) => void)>;
function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  ...children: (Node | string)[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = String(v);
    else if (k === 'html') node.innerHTML = String(v);
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v as EventListener);
    else if (typeof v === 'boolean') {
      if (k.startsWith('aria-')) node.setAttribute(k, String(v));
      else if (v) node.setAttribute(k, '');
    } else node.setAttribute(k, String(v));
  }
  for (const c of children) node.append(c);
  return node;
}

// ---- aria-live announcer (shared) ----
let liveSink: HTMLElement | null = null;
function announce(msg: string): void {
  if (liveSink) liveSink.textContent = msg;
}

// ---- formatting ----
function shortHex(hex: string, head = 10, tail = 8): string {
  if (hex.length <= head + tail + 1) return hex;
  return `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}
function satsToBtc(s: bigint): string {
  return `${(Number(s) / 1e8).toLocaleString('en-US', { maximumFractionDigits: 8 })} BTC`;
}

// ---- copy button + scrollable hex field ----
function copyButton(getText: () => string, label = 'Copy to clipboard'): HTMLButtonElement {
  const btn = h('button', { class: 'copy-btn secondary', type: 'button', 'aria-label': label, title: label }, '⧉');
  btn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(getText());
      announce('Copied to clipboard');
      btn.textContent = '✓';
      window.setTimeout(() => (btn.textContent = '⧉'), 1100);
    } catch {
      announce('Copy failed — your browser blocked clipboard access');
    }
  });
  return btn;
}
function hexField(label: string, hex: string): HTMLElement {
  return h('div', { class: 'hex-field' },
    h('div', { class: 'hex-field-head' }, h('span', { class: 'hex-label' }, label), copyButton(() => hex, `Copy ${label}`)),
    h('div', { class: 'hex-scroll', tabindex: '0', role: 'group', 'aria-label': `${label} (${hex.length / 2} bytes)` }, h('code', {}, hex || '(empty)')),
  );
}

// ===========================================================================
// static informational sections
// ===========================================================================
function section(kicker: string, title: string): HTMLElement {
  const sec = h('section', { class: 'lab-section' });
  sec.append(h('div', { class: 'section-heading-row' }, h('h2', {}, title), h('span', { class: 'section-kicker' }, kicker)));
  return sec;
}
function miniCard(title: string, body: string): HTMLElement {
  return h('div', { class: 'panel-card' }, h('strong', { class: 'mini-card-title' }, title), h('p', { class: 'mini-card-body' }, body));
}
function patternCard(title: string, lock: string, unlock: string, body: string): HTMLElement {
  return h('div', { class: 'panel-card pattern-card' },
    h('strong', { class: 'mini-card-title' }, title),
    h('div', { class: 'pattern-script' }, h('span', { class: 'pattern-label' }, 'lock'), h('code', {}, lock)),
    h('div', { class: 'pattern-script' }, h('span', { class: 'pattern-label' }, 'unlock'), h('code', {}, unlock)),
    h('p', { class: 'mini-card-body' }, body),
  );
}
function note(text: string): HTMLElement {
  return h('p', { class: 'lab-note' }, text);
}

function hero(): HTMLElement {
  const toggle = h('button', { class: 'theme-toggle', id: 'theme-toggle', type: 'button', 'aria-label': 'Toggle color theme', title: 'Toggle theme' });
  toggle.textContent = '🌙';
  const d = h('details', {});
  d.append(
    h('summary', {}, 'How to read this lab'),
    h('p', {}, 'A locking script (scriptPubKey) sets the spending condition; an unlocking script (scriptSig) tries to satisfy it. To validate, Bitcoin runs scriptSig then scriptPubKey on one shared stack. If the script finishes without aborting and leaves a truthy value on top, the spend is authorized. Pick a scenario below, open the inspectors to see the real bytes, then Step the execution forward and back.'),
  );
  return h('header', { class: 'hero-panel' },
    toggle,
    h('p', { class: 'hero-eyebrow' }, 'Bitcoin · Script · Digital signatures'),
    h('h1', {}, 'Bitcoin Script: locking and unlocking coins'),
    h('p', { class: 'hero-lede' }, 'Every bitcoin is guarded by a tiny stack program. Build a real Pay-to-Public-Key-Hash lock, sign a transaction with secp256k1/ECDSA, then step through OP_DUP · OP_HASH160 · OP_EQUALVERIFY · OP_CHECKSIG — inspecting every byte — to see why the right key spends, and the wrong key, a forged signature, or a tampered transaction does not.'),
    h('span', { class: 'hero-metric' }, 'Real secp256k1 · real HASH160 · real legacy sighash · real DER — no backend, no fake math'),
    d,
  );
}

function whatIsSection(): HTMLElement {
  const s = section('Foundations', 'What is Bitcoin Script?');
  s.append(
    h('p', {}, 'Bitcoin Script is a deliberately small, stack-based language with no loops — every script is guaranteed to terminate and its cost is predictable before it runs. That restraint is the security model: the network must agree, forever, on whether a script succeeds.'),
    h('div', { class: 'reuse-grid' },
      miniCard('Stack machine', 'Opcodes push and pop one shared stack. Data goes on; operations like OP_HASH160 or OP_CHECKSIG consume it and push results.'),
      miniCard('No Turing-completeness', 'No loops, no jumps. Unlike Ethereum’s gas-metered EVM, Bitcoin avoids unbounded execution by construction.'),
      miniCard('Secure by restraint', 'A smaller language is a smaller attack surface. Most coins are guarded by a few standard “template” scripts nodes recognize.'),
    ),
  );
  return s;
}
function patternsSection(): HTMLElement {
  const owner = makeKeyPair();
  const s = section('Templates', 'Common script patterns');
  s.append(
    h('p', {}, 'A few standard templates cover almost all spending conditions. This lab runs the two classic ones; modern Taproot is summarized for context.'),
    h('div', { class: 'playground-grid' },
      patternCard('P2PK — Pay to Public Key', scriptToString(p2pkScriptPubKey(owner.pub)).replace(/<pubKey>/, `<pubKey ${shortHex(bytesToHex(owner.pub), 8, 6)}>`), '<sig>', 'The earliest pattern: lock directly to a public key, unlock with one signature. Simple, but the full key sits in the output and is larger on-chain.'),
      patternCard('P2PKH — Pay to Public Key Hash', 'OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG', '<sig> <pubKey>', 'Historically the most common pattern, and the one this lab executes. The output commits only to a 20-byte hash; the key is revealed only when spending.'),
      patternCard('P2TR — Pay to Taproot (modern)', 'OP_1 <32-byte tweaked key>', '<schnorr sig>   (key path)', 'Taproot uses Schnorr signatures and a tweaked key. A simple spend looks like any other Taproot spend, improving privacy; complex conditions hide in a Merkle tree.'),
    ),
    note('What this lab is not: it does not implement Taproot/Schnorr key tweaks, multisig (OP_CHECKMULTISIG), timelocks, or a full node’s consensus rules. It focuses on the single-signature P2PKH path end to end.'),
  );
  return s;
}
function securitySection(): HTMLElement {
  const s = section('Properties', 'Security properties & limitations');
  s.append(
    h('div', { class: 'reuse-grid' },
      miniCard('Predictable & bounded', 'No loops means validation always halts and its cost is known up front — no denial-of-service via runaway scripts.'),
      miniCard('Signatures commit to the tx', 'OP_CHECKSIG verifies a signature over the transaction’s sighash. Edit any signed field and the signature breaks — the “tampered transaction” scenario.'),
      miniCard('Historical foot-guns', 'OP_CHECKMULTISIG pops one extra item (a permanent quirk); an early integer-overflow bug once let someone create billions of BTC. Simplicity reduces, but never eliminates, bugs.'),
      miniCard('Taproot improvements', 'Schnorr enables key aggregation, making a cooperative multisig look like a single ordinary spend — better privacy and efficiency.'),
    ),
  );
  return s;
}
function realWorldSection(): HTMLElement {
  const s = section('In the wild', 'Where these scripts show up');
  s.append(
    h('div', { class: 'reuse-grid' },
      miniCard('Multisig (m-of-n)', 'OP_CHECKMULTISIG (or aggregated Schnorr under Taproot) requires several signatures — shared custody and exchange cold storage.'),
      miniCard('Timelocks', 'OP_CHECKLOCKTIMEVERIFY / OP_CHECKSEQUENCEVERIFY make a branch spendable only after a time or block height — vaults and refunds.'),
      miniCard('Lightning HTLCs', 'Hashed Time-Locked Contracts combine a hash preimage with a timelock to route payments trustlessly across channels.'),
    ),
    note('Pair this with the Bitcoin Wallet demo (keys → addresses) and ECDSA Forge (signatures up close) to connect the whole picture.'),
  );
  return s;
}

// ---- small helpers for tables ----
function kv(key: string, value: string, hint: string): HTMLElement {
  return h('div', { class: 'kv-row' }, h('span', { class: 'kv-key' }, key), h('code', { class: 'kv-value' }, value), h('span', { class: 'kv-hint' }, hint));
}
function row(k: string, v: string): HTMLElement {
  return h('tr', {}, h('td', {}, k), h('td', { class: 'mono' }, v));
}
function statusChip(ok: boolean, okText: string, badText: string): HTMLElement {
  return h('span', { class: 'scenario-status ' + (ok ? 'scenario-status--valid' : 'scenario-status--invalid') }, ok ? `✓ ${okText}` : `✗ ${badText}`);
}

// ===========================================================================
// the interactive core (state controller)
// ===========================================================================
function interactive(): HTMLElement {
  let customPriv: Uint8Array | null = null;
  let customOutValue: bigint | null = null;
  let owner: KeyPair = makeKeyPair(customPriv ?? undefined);
  let attacker: KeyPair = makeKeyPair();
  let scenarios = build();
  let currentId: ScenarioId = 'valid';
  let steps: TraceStep[] = [];
  let cursor = 0;
  let timer: number | undefined;
  let speed = 850;

  function build(): Record<ScenarioId, BuiltScenario> {
    return buildScenarios(owner, attacker, { outValue: customOutValue ?? undefined });
  }
  function current(): BuiltScenario {
    return scenarios[currentId];
  }
  function combinedElements(): ScriptElement[] {
    const sc = current();
    return [...sc.scriptSig, ...sc.scriptPubKey];
  }
  function recompute(): void {
    const sc = current();
    steps = execute(sc.scriptSig, sc.scriptPubKey, { sighash: sc.execSighash }).steps;
    cursor = 0;
    stopAuto();
  }
  function rebuildKeys(): void {
    owner = makeKeyPair(customPriv ?? undefined);
    attacker = makeKeyPair();
    scenarios = build();
    recompute();
    renderAll();
  }

  // --- elements ---
  const keyPanel = h('div', { class: 'panel-card key-panel' });
  const scenarioBtns = h('div', { class: 'scenario-buttons', role: 'group', 'aria-label': 'Choose a spend scenario' });
  const scenarioBlurb = h('div', { class: 'scenario-blurb' });
  const txPanel = h('div', { class: 'panel-card tx-panel' });
  const scriptPanel = h('div', { class: 'panel-card script-panel' });
  const inspectors = h('div', { class: 'inspectors' });
  const tokenStrip = h('div', { class: 'token-strip', role: 'group', 'aria-label': 'Script tokens — click one to jump to that step' });
  const stackView = h('div', { class: 'stack-view', role: 'group', 'aria-label': 'Script execution stack' });
  const stepDesc = h('div', { class: 'step-desc', role: 'status', 'aria-live': 'polite' });
  const stepDiff = h('div', { class: 'step-diff' });
  const verdict = h('div', { class: 'verdict', role: 'status', 'aria-live': 'polite' });
  const matrixWrap = h('div', { class: 'matrix-wrap' });
  const scrubber = h('input', { type: 'range', class: 'scrubber', min: '0', max: '0', value: '0', 'aria-label': 'Execution step' }) as HTMLInputElement;
  const backBtn = h('button', { type: 'button', class: 'secondary' }, '◀ Back');
  const stepBtn = h('button', { type: 'button' }, 'Step ▶');
  const autoBtn = h('button', { type: 'button', class: 'secondary' }, 'Auto-run');
  const resetBtn = h('button', { type: 'button', class: 'secondary' }, '↺ Reset');
  const speedSel = h('select', { class: 'speed-sel', 'aria-label': 'Auto-run speed' }) as HTMLSelectElement;
  speedSel.append(
    h('option', { value: '1400' }, 'Slow'),
    h('option', { value: '850', selected: true }, 'Normal'),
    h('option', { value: '400' }, 'Fast'),
  );

  // --- key panel + advanced drawer ---
  function renderKeyPanel(): void {
    const addr = p2pkhAddress(owner.pubKeyHash);
    keyPanel.replaceChildren(
      h('div', { class: 'panel-head' }, h('strong', {}, 'Owner key pair'), h('button', { type: 'button', class: 'secondary regen-btn', onclick: () => { customPriv = null; customOutValue = null; rebuildKeys(); announce('Generated a fresh key pair'); } }, '⟳ New keys')),
      kv('private key', shortHex(bytesToHex(owner.priv), 12, 10), 'secret — held by the owner only'),
      kv('public key', shortHex(bytesToHex(owner.pub), 12, 10), '33-byte compressed point on secp256k1'),
      kv('pubKeyHash', bytesToHex(owner.pubKeyHash), 'HASH160(pubKey) — what the lock commits to'),
      kv('P2PKH address', addr, 'Base58Check(0x00 ‖ pubKeyHash) — the 1… address'),
      advancedDrawer(),
      note('Keys are generated fresh in your browser and never stored or sent anywhere. Educational only.'),
    );
  }

  function advancedDrawer(): HTMLElement {
    const d = h('details', { class: 'advanced' });
    const privIn = h('input', { type: 'text', class: 'adv-input', id: 'adv-priv', placeholder: '64 hex chars (1 … n−1)', spellcheck: false }) as HTMLInputElement;
    const valIn = h('input', { type: 'text', class: 'adv-input', id: 'adv-val', placeholder: 'satoshis, e.g. 50000', spellcheck: false }) as HTMLInputElement;
    const err = h('p', { class: 'adv-err', role: 'alert' });
    if (customPriv) privIn.value = bytesToHex(customPriv);
    if (customOutValue !== null) valIn.value = String(customOutValue);

    const apply = () => {
      err.textContent = '';
      let priv: Uint8Array | null = null;
      let out: bigint | null = null;
      const pv = privIn.value.trim();
      if (pv) {
        try {
          const b = hexToBytes(pv);
          if (b.length !== 32) throw new Error('private key must be 32 bytes (64 hex)');
          const n = BigInt('0x' + bytesToHex(b));
          if (n <= 0n || n >= CURVE_N) throw new Error('private key must be in 1 … n−1');
          priv = b;
        } catch (e) {
          err.textContent = `Private key: ${(e as Error).message}`;
          return;
        }
      }
      const vv = valIn.value.trim();
      if (vv) {
        if (!/^\d+$/.test(vv)) { err.textContent = 'Output value must be a whole number of satoshis'; return; }
        out = BigInt(vv);
        if (out > 2_100_000_000_000_000n) { err.textContent = 'Output value exceeds the 21M BTC cap'; return; }
      }
      customPriv = priv;
      customOutValue = out;
      rebuildKeys();
      announce('Applied custom inputs');
    };

    d.append(
      h('summary', {}, 'Advanced: custom inputs'),
      h('p', { class: 'adv-help' }, 'Drive the same real pipeline with your own values. Everything is validated strictly; nothing is persisted.'),
      h('div', { class: 'adv-grid' },
        h('label', { class: 'adv-label', for: 'adv-priv' }, 'Owner private key (hex)'), privIn,
        h('label', { class: 'adv-label', for: 'adv-val' }, 'Output value (sats)'), valIn,
      ),
      err,
      h('div', { class: 'adv-actions' },
        h('button', { type: 'button', onclick: apply }, 'Apply'),
        h('button', { type: 'button', class: 'secondary', onclick: () => { customPriv = null; customOutValue = null; rebuildKeys(); announce('Reset to the canonical scenarios'); } }, 'Reset to canonical'),
      ),
    );
    return d;
  }

  // --- scenario picker ---
  function scenarioButton(id: ScenarioId): HTMLButtonElement {
    const sc = scenarios[id];
    return h('button', {
      type: 'button',
      class: 'scenario-btn' + (id === currentId ? ' is-active' : '') + (sc.expectSuccess ? ' good' : ' bad') + (sc.group === 'edge' ? ' edge' : ''),
      'aria-pressed': id === currentId,
      onclick: () => { currentId = id; recompute(); renderAll(); },
    }, sc.title);
  }
  function renderScenarioButtons(): void {
    scenarioBtns.replaceChildren(
      h('span', { class: 'pick-group-label' }, 'Canonical'),
      h('div', { class: 'scenario-row' }, ...CANONICAL_IDS.map(scenarioButton)),
      h('span', { class: 'pick-group-label' }, 'Edge cases'),
      h('div', { class: 'scenario-row' }, ...EDGE_IDS.map(scenarioButton)),
    );
  }
  function renderScenarioBlurb(): void {
    const sc = current();
    scenarioBlurb.replaceChildren(
      h('p', { class: 'twist' }, sc.twist),
      h('p', { class: 'expectation' },
        statusChip(sc.expectSuccess, 'should ACCEPT', 'should REJECT'),
        h('span', { class: 'signed-over' }, ` signature commits to: ${sc.signedOver}`),
      ),
    );
  }

  // --- tx + script panels ---
  function renderTxPanel(): void {
    const t = current().tx;
    txPanel.replaceChildren(
      h('strong', {}, 'Transaction being verified'),
      h('div', { class: 'table-wrap' }, h('table', { class: 'math-table' }, h('tbody', {},
        row('version', String(t.version)),
        row('input', `${shortHex(t.prevTxidHex, 10, 8)} : ${t.vout}`),
        h('tr', {}, h('td', {}, 'output value'), h('td', { class: 'mono' + (t.tamperedValue ? ' tampered' : '') }, `${t.outValueSats.toLocaleString('en-US')} sat (${satsToBtc(t.outValueSats)})${t.tamperedValue ? '  ⚠ edited after signing' : ''}`)),
        row('locktime', String(t.locktime)),
      ))),
    );
  }
  function renderScriptPanel(): void {
    const sc = current();
    scriptPanel.replaceChildren(
      h('div', { class: 'script-line' }, h('span', { class: 'script-tag unlock' }, 'scriptSig (unlock)'), h('code', {}, scriptToString(sc.scriptSig))),
      h('div', { class: 'script-line' }, h('span', { class: 'script-tag lock' }, 'scriptPubKey (lock)'), h('code', {}, scriptToString(sc.scriptPubKey))),
      hexField('scriptPubKey bytes', bytesToHex(serializeScript(sc.scriptPubKey))),
    );
  }

  // --- inspectors ---
  function sighashInspector(sc: BuiltScenario): HTMLElement {
    const rows = sc.verifierSegments.map((seg, i) => {
      const vhex = bytesToHex(seg.bytes);
      const signed = sc.signedSegments[i];
      const changed = signed && bytesToHex(signed.bytes) !== vhex;
      return h('tr', { class: changed ? 'seg-changed' : '' },
        h('td', {}, seg.label),
        h('td', { class: 'mono seg-bytes' }, vhex || '∅', ...(changed ? [h('span', { class: 'seg-was' }, ` (signed: ${bytesToHex(signed.bytes) || '∅'})`)] : [])),
        h('td', { class: 'seg-note' }, seg.note),
      );
    });
    const preimage = bytesToHex(serializeSegments(sc.verifierSegments));
    const body = h('div', {},
      h('p', { class: 'insp-help' }, 'The legacy SIGHASH_ALL preimage is these fields concatenated, then double-SHA256’d. The 32-byte result is what ECDSA signs.'),
      h('div', { class: 'table-wrap' }, h('table', { class: 'math-table seg-table' }, h('thead', {}, h('tr', {}, h('th', {}, 'field'), h('th', {}, 'bytes'), h('th', {}, 'meaning'))), h('tbody', {}, ...rows))),
      hexField('preimage (verifier)', preimage),
      hexField('sighash = SHA256(SHA256(preimage))', sc.execSighashHex),
      ...(sc.signedSighashHex !== sc.execSighashHex
        ? [note(`The owner’s signature was made over a different sighash (${shortHex(sc.signedSighashHex, 10, 8)}) — the one for the original transaction — so it can’t match the edited one above. That is exactly why OP_CHECKSIG fails.`)]
        : []),
    );
    return inspectorDetails('🧾 Sighash inspector — what gets signed', body, sc.tx.tamperedValue);
  }

  function signatureInspector(sc: BuiltScenario): HTMLElement {
    const sigEl = sc.scriptSig.find((e) => e.kind === 'push' && e.label === 'signature');
    const sigBytes = sigEl && sigEl.kind === 'push' ? sigEl.bytes : new Uint8Array(0);
    const offeredPub = hexToBytes(sc.offeredPubHex);
    const info = inspectSignature(sigBytes);
    const verifyPolicy = checkSig(sigBytes, offeredPub, sc.execSighash);
    const verifyRaw = checkSig(sigBytes, offeredPub, sc.execSighash, false);
    let body: HTMLElement;
    if (!info.ok) {
      body = h('div', {},
        h('p', { class: 'insp-help' }, 'These bytes do not parse as a DER signature, so OP_CHECKSIG rejects them before any curve math runs (BIP-66 strict DER).'),
        kv('raw bytes', shortHex(info.derHex, 16, 8), 'the malformed signature'),
        kv('parse error', info.error ?? 'invalid', 'fails closed — no exception thrown'),
        h('p', { class: 'verify-line' }, statusChip(false, '', 'OP_CHECKSIG → FALSE')),
      );
    } else {
      body = h('div', {},
        h('p', { class: 'insp-help' }, 'A Bitcoin signature is DER(r, s) followed by a 1-byte hash type. OP_CHECKSIG strips the hash type, then verifies (r, s) against the sighash and public key.'),
        hexField('DER signature', info.derHex),
        kv('r', shortHex(info.rHex, 12, 10), '32-byte ECDSA component'),
        kv('s', shortHex(info.sHex, 12, 10), '32-byte ECDSA component'),
        h('div', { class: 'insp-flags' },
          statusChip(info.lowS, 'low-S (BIP-146)', 'high-S (non-standard)'),
          statusChip(info.hashTypeSupported, info.hashTypeName, info.hashTypeName),
        ),
        h('p', { class: 'verify-line' }, statusChip(verifyPolicy, 'verifies under policy', 'rejected by policy'),
          ...(verifyPolicy !== verifyRaw ? [h('span', { class: 'verify-aside' }, ' — but the raw ECDSA math does check out; only the low-S policy rejects it')] : [])),
      );
    }
    return inspectorDetails('✍ Signature decoder — DER, r/s, low-S, verify', body, false);
  }

  function hash160Inspector(sc: BuiltScenario): HTMLElement {
    const offeredPub = hexToBytes(sc.offeredPubHex);
    const pipe = hash160Pipeline(offeredPub);
    const offeredHash = bytesToHex(pipe.ripemd160);
    const committed = sc.ownerPubKeyHashHex;
    const match = offeredHash === committed;
    const body = h('div', {},
      h('p', { class: 'insp-help' }, 'OP_HASH160 hashes the offered public key and OP_EQUALVERIFY compares it to the pubKeyHash baked into the lock. They must match for the script to continue.'),
      hexField('offered pubKey (33 bytes)', sc.offeredPubHex),
      h('div', { class: 'pipe-row' }, h('span', { class: 'pipe-arrow' }, '↓ SHA-256'), h('code', {}, shortHex(bytesToHex(pipe.sha256), 14, 10))),
      h('div', { class: 'pipe-row' }, h('span', { class: 'pipe-arrow' }, '↓ RIPEMD-160'), h('code', {}, offeredHash)),
      h('div', { class: 'pipe-compare' },
        h('div', {}, h('span', { class: 'pipe-cap' }, 'HASH160(offered key)'), h('code', { class: match ? '' : 'mismatch' }, offeredHash)),
        h('div', {}, h('span', { class: 'pipe-cap' }, 'committed pubKeyHash'), h('code', {}, committed)),
      ),
      h('p', { class: 'verify-line' }, statusChip(match, 'match → OP_EQUALVERIFY passes', 'mismatch → OP_EQUALVERIFY aborts')),
    );
    return inspectorDetails('🔑 HASH160 pipeline — key → pubKeyHash', body, !match);
  }

  function inspectorDetails(summary: string, body: HTMLElement, open: boolean): HTMLElement {
    const d = h('details', { class: 'inspector' });
    if (open) d.setAttribute('open', '');
    d.append(h('summary', {}, summary), body);
    return d;
  }

  function renderInspectors(): void {
    const sc = current();
    inspectors.replaceChildren(sighashInspector(sc), signatureInspector(sc), hash160Inspector(sc));
  }

  // --- token rail (click-to-jump) ---
  function renderTokenStrip(): void {
    const els = combinedElements();
    const boundary = current().scriptSig.length;
    const activeElIndex = cursor - 1;
    const children: Node[] = [];
    els.forEach((el, i) => {
      if (i === boundary) children.push(h('span', { class: 'token-sep', 'aria-hidden': true }, '‖'));
      const executed = i < cursor;
      const active = i === activeElIndex;
      const target = Math.min(i + 1, steps.length);
      children.push(h('button', {
        type: 'button',
        class: 'token' + (executed ? ' executed' : '') + (active ? ' active' : ''),
        'aria-label': `Jump to step ${target}: ${tokenOf(el)}`,
        onclick: () => { stopAuto(); cursor = target; renderAll(); },
      }, tokenOf(el)));
    });
    tokenStrip.replaceChildren(...children);
  }

  // --- stack column ---
  function statusTint(label: string): string {
    if (/^TRUE/.test(label)) return ' is-true';
    if (/^FALSE/.test(label)) return ' is-false';
    return '';
  }
  function renderStack(): void {
    const shown: StackItem[] = cursor > 0 && steps[cursor - 1] ? steps[cursor - 1].stackAfter : [];
    const boxes = shown.map((item, idx) => {
      const isTop = idx === shown.length - 1;
      return h('div', { class: 'stack-item' + (isTop ? ' top' : '') + statusTint(item.label) },
        h('span', { class: 'stack-item-label' }, item.label),
        h('code', { class: 'stack-item-hex' }, shortHex(item.hex, 12, 10)),
      );
    }).reverse();
    stackView.replaceChildren(
      h('div', { class: 'stack-caption' }, shown.length ? `stack (${shown.length} item${shown.length === 1 ? '' : 's'}, top first)` : 'stack is empty — press Step ▶'),
      ...(boxes.length ? boxes : [h('div', { class: 'stack-empty' }, '∅')]),
    );
  }

  // --- step description + diff ---
  function renderStepDesc(): void {
    if (cursor === 0) {
      stepDesc.className = 'step-desc';
      stepDesc.replaceChildren(h('span', {}, 'Press Step ▶ to execute the first element of the script.'));
      return;
    }
    const st = steps[cursor - 1];
    stepDesc.className = 'step-desc step-' + st.status;
    stepDesc.replaceChildren(
      h('span', { class: 'step-token' }, `${st.n}. ${st.token}`),
      h('span', { class: 'step-action' }, st.action),
      ...(st.note ? [h('span', { class: 'step-note' }, st.note)] : []),
    );
  }
  function chips(items: StackItem[], cls: string): HTMLElement[] {
    return items.map((it) => h('span', { class: 'diff-chip ' + cls }, `${it.label}: ${shortHex(it.hex, 8, 6)}`));
  }
  function renderStepDiff(): void {
    if (cursor === 0) { stepDiff.replaceChildren(); return; }
    const st = steps[cursor - 1];
    stepDiff.replaceChildren(
      h('div', { class: 'diff-row' }, h('span', { class: 'diff-label' }, 'popped'), ...(st.popped.length ? chips(st.popped, 'pop') : [h('span', { class: 'diff-none' }, '—')])),
      h('div', { class: 'diff-row' }, h('span', { class: 'diff-label' }, 'pushed'), ...(st.pushed.length ? chips(st.pushed, 'push') : [h('span', { class: 'diff-none' }, '—')])),
    );
  }

  // --- verdict ---
  function renderVerdict(): void {
    const sc = current();
    const done = cursor >= steps.length && steps.length > 0;
    if (!done) { verdict.className = 'verdict'; verdict.replaceChildren(); return; }
    const r = execute(sc.scriptSig, sc.scriptPubKey, { sighash: sc.execSighash });
    if (r.success) {
      verdict.className = 'verdict verdict-accept';
      verdict.replaceChildren(h('div', { class: 'verdict-head' }, '✓ Script ACCEPTED — spend is authorized'), h('p', {}, sc.lesson));
    } else {
      verdict.className = 'verdict verdict-reject';
      verdict.replaceChildren(
        h('div', { class: 'verdict-head' }, '✗ Script REJECTED — spend refused'),
        h('p', {}, sc.lesson),
        h('p', { class: 'verdict-security' }, '🛡 This rejection is the system working correctly — the funds stay protected.'),
        ...(r.failReason ? [h('p', { class: 'verdict-reason' }, `reason: ${r.failReason}`)] : []),
      );
    }
  }

  // --- comparison matrix ---
  function renderMatrix(): void {
    const ids: ScenarioId[] = [...CANONICAL_IDS, ...EDGE_IDS];
    const head = h('tr', {}, ...['scenario', 'offered key', 'sig source', 'key match', 'sig valid', 'first failure', 'verdict'].map((t) => h('th', {}, t)));
    const body = ids.map((id) => {
      const sc = scenarios[id];
      return h('tr', { class: id === currentId ? 'matrix-active' : '' },
        h('td', {}, h('button', { type: 'button', class: 'matrix-jump', onclick: () => { currentId = id; recompute(); renderAll(); } }, sc.title)),
        h('td', {}, sc.keyMatches ? "owner's" : id === 'wrong-key' ? "attacker's" : "owner's"),
        h('td', {}, sc.sigSource),
        h('td', { class: 'mono' }, sc.keyMatches ? '✓' : '✗'),
        h('td', { class: 'mono' }, sc.sigMatches ? '✓' : '✗'),
        h('td', { class: 'mono' }, sc.firstFailOp ?? '—'),
        h('td', {}, h('span', { class: 'verdict-pill ' + (sc.expectSuccess ? 'ok' : 'no') }, sc.expectSuccess ? 'ACCEPT' : 'REJECT')),
      );
    });
    matrixWrap.replaceChildren(h('div', { class: 'table-wrap' }, h('table', { class: 'math-table matrix-table' }, h('thead', {}, head), h('tbody', {}, ...body))));
  }

  // --- controls ---
  function syncControls(): void {
    backBtn.toggleAttribute('disabled', cursor <= 0);
    const atEnd = cursor >= steps.length;
    if (atEnd && document.activeElement === stepBtn) resetBtn.focus();
    stepBtn.toggleAttribute('disabled', atEnd);
    scrubber.max = String(steps.length);
    scrubber.value = String(cursor);
  }
  function renderAll(): void {
    renderKeyPanel();
    renderScenarioButtons();
    renderScenarioBlurb();
    renderTxPanel();
    renderScriptPanel();
    renderInspectors();
    renderTokenStrip();
    renderStack();
    renderStepDesc();
    renderStepDiff();
    renderVerdict();
    renderMatrix();
    syncControls();
  }
  function stepOnce(): void {
    if (cursor < steps.length) { cursor++; renderAll(); }
    if (cursor >= steps.length) stopAuto();
  }
  function stepBack(): void {
    if (cursor > 0) { cursor--; renderAll(); }
  }
  function stopAuto(): void {
    if (timer !== undefined) { clearInterval(timer); timer = undefined; autoBtn.textContent = 'Auto-run'; autoBtn.classList.add('secondary'); }
  }
  function startAuto(): void {
    autoBtn.textContent = '⏸ Pause';
    autoBtn.classList.remove('secondary');
    timer = window.setInterval(stepOnce, speed);
  }
  function toggleAuto(): void {
    if (timer !== undefined) { stopAuto(); return; }
    if (cursor >= steps.length) cursor = 0;
    startAuto();
  }
  backBtn.addEventListener('click', () => { stopAuto(); stepBack(); });
  stepBtn.addEventListener('click', () => { stopAuto(); stepOnce(); });
  autoBtn.addEventListener('click', toggleAuto);
  resetBtn.addEventListener('click', () => { stopAuto(); cursor = 0; renderAll(); });
  scrubber.addEventListener('input', () => { stopAuto(); cursor = Math.max(0, Math.min(steps.length, Number(scrubber.value))); renderAll(); });
  speedSel.addEventListener('change', () => { speed = Number(speedSel.value); if (timer !== undefined) { stopAuto(); startAuto(); } });

  // --- assemble ---
  const labSection = section('Core', 'Lock, sign, and verify');
  labSection.append(
    h('p', {}, 'A coin is locked to the owner’s pubKeyHash. Choose how the spend is attempted, open the inspectors to see the real bytes, then run the script. Most attempts fail — and each failure teaches something.'),
    keyPanel,
    h('div', { class: 'scenario-pick' }, h('span', { class: 'pick-label' }, 'Spend scenario'), scenarioBtns),
    scenarioBlurb,
    h('div', { class: 'playground-grid' }, txPanel, scriptPanel),
    inspectors,
  );
  const execSection = section('Execution', 'Run the script on the stack');
  execSection.append(
    h('p', {}, 'Bitcoin runs scriptSig then scriptPubKey on one shared stack (‖ marks the seam). Step forward and back, scrub the timeline, or click a token to jump — and watch each opcode consume and produce stack items.'),
    tokenStrip,
    h('div', { class: 'viz-grid' },
      h('div', { class: 'viz-left' }, stackView),
      h('div', { class: 'viz-right' }, stepDesc, stepDiff, verdict),
    ),
    h('div', { class: 'viz-controls' }, backBtn, stepBtn, autoBtn, resetBtn, h('label', { class: 'speed-label' }, 'speed', speedSel)),
    h('div', { class: 'scrubber-wrap' }, scrubber),
    h('h3', { class: 'matrix-heading' }, 'All scenarios at a glance'),
    matrixWrap,
  );

  const wrap = h('div', {});
  wrap.append(labSection, execSection);
  recompute();
  renderAll();
  return wrap;
}

// serialize sighash segments back to a flat byte string (for the preimage field)
function serializeSegments(segs: { bytes: Uint8Array }[]): Uint8Array {
  const total = segs.reduce((s, x) => s + x.bytes.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const s of segs) { out.set(s.bytes, o); o += s.bytes.length; }
  return out;
}

// ===========================================================================
// public mount
// ===========================================================================
export function mountApp(root: HTMLElement): void {
  liveSink = h('div', { class: 'visually-hidden', role: 'status', 'aria-live': 'polite' });
  root.replaceChildren(
    hero(),
    interactive(),
    whatIsSection(),
    patternsSection(),
    securitySection(),
    realWorldSection(),
    liveSink,
  );
}
