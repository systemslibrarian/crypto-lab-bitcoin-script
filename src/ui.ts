// ui.ts — all DOM construction and interaction for the demo. No crypto lives
// here; it calls engine/script/scenario. The centrepiece is a step-through
// stack visualizer: pick a scenario, then walk OP by OP and watch the stack
// grow and shrink until the script accepts or rejects the spend.

import { makeKeyPair, KeyPair, bytesToHex } from './engine';
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
import { buildScenarios, BuiltScenario, ScenarioId } from './scenario';

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
      if (v) node.setAttribute(k, '');
    } else node.setAttribute(k, String(v));
  }
  for (const c of children) node.append(c);
  return node;
}

function shortHex(hex: string, head = 10, tail = 8): string {
  if (hex.length <= head + tail + 1) return hex;
  return `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}
function satsToBtc(s: bigint): string {
  const btc = Number(s) / 1e8;
  return `${btc.toLocaleString('en-US', { maximumFractionDigits: 8 })} BTC`;
}

// ===========================================================================
// section builders
// ===========================================================================
function hero(): HTMLElement {
  const toggle = h('button', {
    class: 'theme-toggle',
    id: 'theme-toggle',
    type: 'button',
    'aria-label': 'Toggle color theme',
    title: 'Toggle theme',
  });
  toggle.textContent = '🌙';

  return h(
    'header',
    { class: 'hero-panel' },
    toggle,
    h('p', { class: 'hero-eyebrow' }, 'Bitcoin · Script · Digital signatures'),
    h('h1', {}, 'Bitcoin Script: locking and unlocking coins'),
    h(
      'p',
      { class: 'hero-lede' },
      'Every bitcoin is guarded by a tiny stack program. Build a real Pay-to-Public-Key-Hash lock, sign a transaction with secp256k1/ECDSA, then step through OP_DUP · OP_HASH160 · OP_EQUALVERIFY · OP_CHECKSIG and watch why the right key spends — and the wrong key, a forged signature, or a tampered transaction does not.',
    ),
    h('span', { class: 'hero-metric' }, 'Real secp256k1 · real HASH160 · real legacy sighash — no backend, no fake math'),
    (() => {
      const d = h('details', {});
      d.append(
        h('summary', {}, 'How to read this lab'),
        h(
          'p',
          {},
          'A locking script (scriptPubKey) sets the spending condition; an unlocking script (scriptSig) tries to satisfy it. To validate, Bitcoin runs scriptSig then scriptPubKey on one shared stack. If the script finishes without aborting and leaves a single TRUE on top, the spend is authorized. Use the scenario buttons below, then Step through the execution.',
        ),
      );
      return d;
    })(),
  );
}

function whatIsSection(): HTMLElement {
  const s = section('01 · Foundations', 'What is Bitcoin Script?');
  s.append(
    h(
      'p',
      {},
      'Bitcoin Script is a deliberately small, stack-based language. There are no loops and no unbounded recursion, so every script is guaranteed to terminate and its cost is predictable before it runs. That is a feature, not a limitation: the network must agree, forever, on whether a script succeeds.',
    ),
    h('div', { class: 'reuse-grid' },
      miniCard('Stack machine', 'Opcodes push and pop a single stack. Data goes on; operations like OP_HASH160 or OP_CHECKSIG consume it and push results.'),
      miniCard('No Turing-completeness', 'No loops, no jumps. Contrast with Ethereum’s EVM, which is general-purpose but must meter gas to stop infinite execution. Bitcoin avoids that whole class of risk by construction.'),
      miniCard('Secure by restraint', 'A smaller language is a smaller attack surface. Most coins are guarded by a handful of standard “template” scripts that wallets and nodes recognize and trust.'),
    ),
  );
  return s;
}

function patternsSection(owner: KeyPair): HTMLElement {
  const s = section('02 · Templates', 'Common script patterns');
  s.append(
    h('p', {}, 'A few standard templates account for almost all real spending conditions. This lab runs the two classic ones; modern Taproot is summarized for context.'),
    h('div', { class: 'playground-grid' },
      patternCard(
        'P2PK — Pay to Public Key',
        scriptToString(p2pkScriptPubKey(owner.pub)).replace(/<pubKey>/, `<pubKey ${shortHex(bytesToHex(owner.pub), 8, 6)}>`),
        '<sig>',
        'The earliest pattern: lock directly to a public key, unlock with one signature. Simple, but the full key sits in the output for everyone to see and is larger on-chain.',
      ),
      patternCard(
        'P2PKH — Pay to Public Key Hash',
        'OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG',
        '<sig> <pubKey>',
        'Historically the most common pattern, and the one this lab executes. The output commits only to a 20-byte hash of the key; the key is revealed only when spending. Smaller, and the key stays hidden until use.',
      ),
      patternCard(
        'P2TR — Pay to Taproot (modern)',
        'OP_1 <32-byte tweaked key>',
        '<schnorr sig>   (key path)',
        'Taproot uses Schnorr signatures and a tweaked key. A simple spend looks identical to any other Taproot spend, improving privacy; complex conditions hide in a Merkle tree, revealed only if used.',
      ),
    ),
    note('What this lab is not: it does not implement Taproot/Schnorr key tweaks, multisig (OP_CHECKMULTISIG), timelocks (OP_CHECKLOCKTIMEVERIFY), or a full node’s consensus rules. It focuses on the single-signature P2PKH path end to end.'),
  );
  return s;
}

function securitySection(): HTMLElement {
  const s = section('05 · Properties', 'Security properties & limitations');
  s.append(
    h('div', { class: 'reuse-grid' },
      miniCard('Predictable & bounded', 'No loops means validation always halts and its cost is known up front — no denial-of-service via runaway scripts.'),
      miniCard('Signatures commit to the tx', 'OP_CHECKSIG verifies a signature over the transaction’s sighash. Edit any signed field and the signature breaks — exactly the “tampered transaction” scenario.'),
      miniCard('Historical foot-guns', 'OP_CHECKMULTISIG pops one extra item (a permanent quirk now relied upon); an early integer-overflow bug once let someone create billions of BTC. Simplicity reduces, but never eliminates, bugs.'),
      miniCard('Taproot improvements', 'Schnorr enables key aggregation and makes a cooperative multisig look like a single ordinary spend, improving both privacy and on-chain efficiency for the common case.'),
    ),
  );
  return s;
}

function realWorldSection(): HTMLElement {
  const s = section('06 · In the wild', 'Where these scripts show up');
  s.append(
    h('p', {}, 'The same machinery scales to richer conditions you can explore elsewhere in the suite:'),
    h('div', { class: 'reuse-grid' },
      miniCard('Multisig (m-of-n)', 'OP_CHECKMULTISIG (or aggregated Schnorr under Taproot) requires several signatures — shared custody and exchange cold storage.'),
      miniCard('Timelocks', 'OP_CHECKLOCKTIMEVERIFY / OP_CHECKSEQUENCEVERIFY make a branch spendable only after a time or block height — vaults and refunds.'),
      miniCard('Lightning HTLCs', 'Hashed Time-Locked Contracts combine a hash preimage with a timelock to route payments trustlessly across channels.'),
    ),
    note('Pair this with the Bitcoin Wallet demo (keys → addresses) and ECDSA Forge (signatures up close) to connect the whole picture.'),
  );
  return s;
}

// ---- small reusable pieces ----
function section(kicker: string, title: string): HTMLElement {
  const sec = h('section', { class: 'lab-section' });
  sec.append(
    h('div', { class: 'section-heading-row' }, h('h2', {}, title), h('span', { class: 'section-kicker' }, kicker)),
  );
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

// ===========================================================================
// interactive core + visualizer (shared state controller)
// ===========================================================================
function interactive(): HTMLElement {
  let owner: KeyPair = makeKeyPair();
  let attacker: KeyPair = makeKeyPair();
  let scenarios = buildScenarios(owner, attacker);
  let currentId: ScenarioId = 'valid';
  let steps: TraceStep[] = [];
  let cursor = 0; // number of steps revealed
  let timer: number | undefined;

  // --- elements we update ---
  const keyPanel = h('div', { class: 'panel-card key-panel' });
  const scenarioBtns = h('div', { class: 'scenario-buttons', role: 'group', 'aria-label': 'Choose a spend scenario' });
  const scenarioBlurb = h('div', { class: 'scenario-blurb' });
  const txPanel = h('div', { class: 'panel-card tx-panel' });
  const scriptPanel = h('div', { class: 'panel-card script-panel' });
  const tokenStrip = h('div', { class: 'token-strip', 'aria-hidden': 'true' });
  const stackView = h('div', { class: 'stack-view', role: 'group', 'aria-label': 'Script execution stack' });
  const stepDesc = h('div', { class: 'step-desc', role: 'status', 'aria-live': 'polite' });
  const verdict = h('div', { class: 'verdict', role: 'status', 'aria-live': 'polite' });
  const stepBtn = h('button', { type: 'button' }, 'Step ▶');
  const autoBtn = h('button', { type: 'button', class: 'secondary' }, 'Auto-run');
  const resetBtn = h('button', { type: 'button', class: 'secondary' }, '↺ Reset');

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

  // --- renderers ---
  function renderKeyPanel(): void {
    keyPanel.replaceChildren(
      h('div', { class: 'panel-head' }, h('strong', {}, 'Owner key pair'), h('button', { type: 'button', class: 'secondary regen-btn', onclick: () => { owner = makeKeyPair(); attacker = makeKeyPair(); scenarios = buildScenarios(owner, attacker); recompute(); renderAll(); } }, '⟳ New keys')),
      kv('private key', shortHex(bytesToHex(owner.priv), 12, 10), 'secret — held by the owner only'),
      kv('public key', shortHex(bytesToHex(owner.pub), 12, 10), '33-byte compressed point on secp256k1'),
      kv('pubKeyHash', bytesToHex(owner.pubKeyHash), 'HASH160(pubKey) — this is what the lock commits to'),
      note('Keys are generated fresh in your browser and never leave it or get stored. Educational only.'),
    );
  }

  function renderScenarioButtons(): void {
    const order: ScenarioId[] = ['valid', 'wrong-key', 'forged-sig', 'tampered-tx'];
    scenarioBtns.replaceChildren(
      ...order.map((id) => {
        const sc = scenarios[id];
        const b = h('button', {
          type: 'button',
          class: 'scenario-btn' + (id === currentId ? ' is-active' : '') + (sc.expectSuccess ? ' good' : ' bad'),
          'aria-pressed': id === currentId,
          onclick: () => { currentId = id; recompute(); renderAll(); },
        }, sc.title);
        return b;
      }),
    );
  }

  function renderScenarioBlurb(): void {
    const sc = current();
    scenarioBlurb.replaceChildren(
      h('p', { class: 'twist' }, sc.twist),
      h('p', { class: 'expectation' },
        h('span', { class: 'scenario-status ' + (sc.expectSuccess ? 'scenario-status--valid' : 'scenario-status--invalid') },
          sc.expectSuccess ? '✓ should ACCEPT' : '✗ should REJECT'),
        h('span', { class: 'signed-over' }, ` signature commits to: ${sc.signedOver}`),
      ),
    );
  }

  function renderTxPanel(): void {
    const sc = current();
    const t = sc.tx;
    const valueRow = h('tr', {},
      h('td', {}, 'output value'),
      h('td', { class: 'mono' + (t.tamperedValue ? ' tampered' : '') }, `${t.outValueSats.toLocaleString('en-US')} sat  (${satsToBtc(t.outValueSats)})${t.tamperedValue ? '  ⚠ edited after signing' : ''}`),
    );
    txPanel.replaceChildren(
      h('strong', {}, 'Transaction being verified'),
      h('div', { class: 'table-wrap' },
        h('table', { class: 'math-table' },
          h('tbody', {},
            row('version', String(t.version)),
            row('input', `${shortHex(t.prevTxidHex, 10, 8)} : ${t.vout}`),
            valueRow,
            row('locktime', String(t.locktime)),
          ),
        ),
      ),
    );
  }

  function renderScriptPanel(): void {
    const sc = current();
    scriptPanel.replaceChildren(
      h('div', { class: 'script-line' },
        h('span', { class: 'script-tag unlock' }, 'scriptSig (unlock)'),
        h('code', {}, scriptToString(sc.scriptSig)),
      ),
      h('div', { class: 'script-line' },
        h('span', { class: 'script-tag lock' }, 'scriptPubKey (lock)'),
        h('code', {}, scriptToString(sc.scriptPubKey)),
      ),
      h('div', { class: 'script-bytes' },
        `scriptPubKey bytes: ${bytesToHex(serializeScript(sc.scriptPubKey))}`,
      ),
    );
  }

  function renderTokenStrip(): void {
    const els = combinedElements();
    const boundary = current().scriptSig.length;
    const activeElIndex = cursor - 1; // element that produced the most recent step
    const children: Node[] = [];
    els.forEach((el, i) => {
      if (i === boundary) children.push(h('span', { class: 'token-sep' }, '‖'));
      const executed = i < cursor;
      const active = i === activeElIndex;
      children.push(h('span', { class: 'token' + (executed ? ' executed' : '') + (active ? ' active' : '') }, tokenOf(el)));
    });
    tokenStrip.replaceChildren(...children);
  }

  function renderStack(): void {
    const shown: StackItem[] = cursor > 0 && steps[cursor - 1] ? steps[cursor - 1].stackAfter : [];
    const boxes = shown
      .map((item, idx) => {
        const isTop = idx === shown.length - 1;
        const label = item.label;
        const cls = 'stack-item' + (isTop ? ' top' : '') + statusTint(label);
        return h('div', { class: cls },
          h('span', { class: 'stack-item-label' }, label),
          h('code', { class: 'stack-item-hex' }, shortHex(item.hex, 12, 10)),
        );
      })
      .reverse(); // render top-of-stack at the top
    stackView.replaceChildren(
      h('div', { class: 'stack-caption' }, shown.length ? `stack (${shown.length} item${shown.length === 1 ? '' : 's'}, top first)` : 'stack is empty — press Step ▶'),
      ...(boxes.length ? boxes : [h('div', { class: 'stack-empty' }, '∅')]),
    );
  }

  function statusTint(label: string): string {
    if (/^TRUE/.test(label)) return ' is-true';
    if (/^FALSE/.test(label)) return ' is-false';
    return '';
  }

  function renderStepDesc(): void {
    if (cursor === 0) {
      stepDesc.replaceChildren(h('span', {}, 'Press Step ▶ to execute the first element of the script.'));
      stepDesc.className = 'step-desc';
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

  function renderVerdict(): void {
    const sc = current();
    const done = cursor >= steps.length && steps.length > 0;
    if (!done) {
      verdict.className = 'verdict';
      verdict.replaceChildren();
      return;
    }
    const r = execute(sc.scriptSig, sc.scriptPubKey, { sighash: sc.execSighash });
    if (r.success) {
      verdict.className = 'verdict verdict-accept';
      verdict.replaceChildren(
        h('div', { class: 'verdict-head' }, '✓ Script ACCEPTED — spend is authorized'),
        h('p', {}, sc.lesson),
      );
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

  function renderAll(): void {
    renderKeyPanel();
    renderScenarioButtons();
    renderScenarioBlurb();
    renderTxPanel();
    renderScriptPanel();
    renderTokenStrip();
    renderStack();
    renderStepDesc();
    renderVerdict();
    const atEnd = cursor >= steps.length;
    // Don't strand keyboard focus on the Step button when it disables at the end.
    if (atEnd && document.activeElement === stepBtn) resetBtn.focus();
    stepBtn.toggleAttribute('disabled', atEnd);
  }

  // --- controls ---
  function stepOnce(): void {
    if (cursor < steps.length) {
      cursor++;
      renderAll();
    }
    if (cursor >= steps.length) stopAuto();
  }
  function stopAuto(): void {
    if (timer !== undefined) {
      clearInterval(timer);
      timer = undefined;
      autoBtn.textContent = 'Auto-run';
      autoBtn.classList.add('secondary');
    }
  }
  function toggleAuto(): void {
    if (timer !== undefined) { stopAuto(); return; }
    if (cursor >= steps.length) cursor = 0;
    autoBtn.textContent = '⏸ Pause';
    autoBtn.classList.remove('secondary');
    timer = window.setInterval(stepOnce, 850);
  }
  stepBtn.addEventListener('click', () => { stopAuto(); stepOnce(); });
  autoBtn.addEventListener('click', toggleAuto);
  resetBtn.addEventListener('click', () => { stopAuto(); cursor = 0; renderAll(); });

  // --- assemble the two sections ---
  const interactiveSection = section('03 · Core', 'Lock, sign, and verify');
  interactiveSection.append(
    h('p', {}, 'A coin is locked to the owner’s pubKeyHash. Choose how the spend is attempted, then run the script. Three of the four attempts should fail — and each failure teaches something.'),
    keyPanel,
    h('div', { class: 'scenario-pick' }, h('span', { class: 'pick-label' }, 'Spend scenario:'), scenarioBtns),
    scenarioBlurb,
    h('div', { class: 'playground-grid' }, txPanel, scriptPanel),
  );

  const vizSection = section('04 · Execution', 'Run the script on the stack');
  vizSection.append(
    h('p', {}, 'Bitcoin runs scriptSig then scriptPubKey on one shared stack (‖ marks the seam). Step through and watch each opcode consume and produce stack items.'),
    tokenStrip,
    h('div', { class: 'viz-grid' },
      h('div', { class: 'viz-left' }, stackView),
      h('div', { class: 'viz-right' }, stepDesc, verdict),
    ),
    h('div', { class: 'viz-controls' }, stepBtn, autoBtn, resetBtn),
  );

  const wrap = h('div', {});
  wrap.append(interactiveSection, vizSection);
  recompute();
  renderAll();
  return wrap;
}

// ---- key/value + table row helpers ----
function kv(key: string, value: string, hint: string): HTMLElement {
  return h('div', { class: 'kv-row' },
    h('span', { class: 'kv-key' }, key),
    h('code', { class: 'kv-value' }, value),
    h('span', { class: 'kv-hint' }, hint),
  );
}
function row(k: string, v: string): HTMLElement {
  return h('tr', {}, h('td', {}, k), h('td', { class: 'mono' }, v));
}

// ===========================================================================
// public mount
// ===========================================================================
export function mountApp(root: HTMLElement): void {
  const owner = makeKeyPair(); // only for the static patterns section display
  root.replaceChildren(
    hero(),
    whatIsSection(),
    patternsSection(owner),
    interactive(),
    securitySection(),
    realWorldSection(),
  );
}
