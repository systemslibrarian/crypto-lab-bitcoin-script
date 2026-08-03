import { createHash } from 'node:crypto';
import { expect, test, type Locator, type Page } from '@playwright/test';

/**
 * Claims gate.
 *
 * The a11y spec proves the page is reachable; this one proves it is telling the
 * truth. Every headline verdict, counter and failure path is asserted against a
 * value the page itself produced, and wherever the page states the same fact
 * twice — the key panel's pubKeyHash vs. the HASH160 pipeline's output vs. the
 * 20 bytes inside the serialized scriptPubKey; the scenario's declared
 * expectation vs. what the interpreter actually decides; the comparison
 * matrix's "first failure" column vs. the step where execution really stops —
 * the two are compared to each other rather than to a literal in this file.
 *
 * A few facts are checked against an independent implementation living here in
 * the test (double-SHA256, Base58Check, DER parsing, the low-S bound). Those
 * are the assertions that would survive the page computing something wrong
 * consistently in both places.
 *
 * Keys are random per page load, so tests that need a fixed answer drive the
 * page's own "Advanced: custom inputs" drawer with privkey = 1.
 */

const CURVE_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/** privkey = 1 → the secp256k1 generator point, and its well-known identity. */
const PRIV_ONE = '0000000000000000000000000000000000000000000000000000000000000001';
const G_COMPRESSED = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179 8'.replace(/\s/g, '');
const G_HASH160 = '751e76e8199196d454941c45d1b3a323f1433bd6';
const G_ADDRESS = '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH';

const SCENARIOS = [
  'Valid spend',
  'Wrong public key',
  'Forged signature',
  'Tampered transaction',
  'High-S signature',
  'Malformed DER',
  'Swapped scriptSig order',
] as const;

// ---- independent reference implementations (deliberately not the page's) ----

function sha256dHex(hex: string): string {
  const once = createHash('sha256').update(Buffer.from(hex, 'hex')).digest();
  return createHash('sha256').update(once).digest('hex');
}

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58check(payloadHex: string): string {
  const payload = Buffer.from(payloadHex, 'hex');
  const checksum = Buffer.from(sha256dHex(payloadHex), 'hex').subarray(0, 4);
  const full = Buffer.concat([payload, checksum]);
  let n = BigInt('0x' + full.toString('hex'));
  let out = '';
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of full) {
    if (b !== 0) break;
    out = '1' + out;
  }
  return out;
}

/** Minimal DER(r,s) reader, so r/s can be checked without trusting engine.ts. */
function parseDER(derHex: string): { r: bigint; s: bigint } {
  const b = Buffer.from(derHex, 'hex');
  expect(b[0], 'DER must start with SEQUENCE (0x30)').toBe(0x30);
  expect(b[1], 'DER length byte must cover the rest of the structure').toBe(b.length - 2);
  let p = 2;
  expect(b[p++]).toBe(0x02);
  const rlen = b[p++];
  const r = BigInt('0x' + b.subarray(p, p + rlen).toString('hex'));
  p += rlen;
  expect(b[p++]).toBe(0x02);
  const slen = b[p++];
  const s = BigInt('0x' + b.subarray(p, p + slen).toString('hex'));
  expect(p + slen, 'DER must have no trailing bytes').toBe(b.length);
  return { r, s };
}

/** Read an N-byte little-endian hex field back into a number. */
function leHexToBigInt(hex: string): bigint {
  const b = Buffer.from(hex, 'hex').reverse();
  return b.length ? BigInt('0x' + b.toString('hex')) : 0n;
}

// ---- page readers -----------------------------------------------------------

async function boot(page: Page): Promise<void> {
  await page.goto('.');
  await expect(page.locator('.scenario-btn')).toHaveCount(SCENARIOS.length);
}

function scenarioBtn(page: Page, title: string): Locator {
  return page.locator('.scenario-btn', { hasText: title });
}

async function pick(page: Page, title: string): Promise<void> {
  await scenarioBtn(page, title).click();
  await expect(scenarioBtn(page, title)).toHaveAttribute('aria-pressed', 'true');
}

async function openInspectors(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const d of document.querySelectorAll('details.inspector')) {
      (d as HTMLDetailsElement).open = true;
    }
  });
}

async function openAdvanced(page: Page): Promise<void> {
  await page.evaluate(() => {
    const d = document.querySelector('details.advanced');
    if (d) (d as HTMLDetailsElement).open = true;
  });
}

/** label → value for the `.kv-row` pairs inside a panel. */
async function kvRows(scope: Locator): Promise<Record<string, string>> {
  return scope.evaluate((el) => {
    const out: Record<string, string> = {};
    for (const row of el.querySelectorAll('.kv-row')) {
      out[row.querySelector('.kv-key')?.textContent?.trim() ?? ''] =
        row.querySelector('.kv-value')?.textContent?.trim() ?? '';
    }
    return out;
  });
}

/** label → full hex for the copyable `.hex-field` blocks inside a panel. */
async function hexFields(scope: Locator): Promise<Record<string, string>> {
  return scope.evaluate((el) => {
    const out: Record<string, string> = {};
    for (const f of el.querySelectorAll('.hex-field')) {
      out[f.querySelector('.hex-label')?.textContent?.trim() ?? ''] =
        f.querySelector('code')?.textContent?.trim() ?? '';
    }
    return out;
  });
}

interface Segment {
  label: string;
  bytes: string;
  signedWas: string | null;
  note: string;
  changed: boolean;
}

async function sighashSegments(page: Page): Promise<Segment[]> {
  return page.evaluate(() =>
    Array.from(document.querySelectorAll('.seg-table tbody tr')).map((tr) => {
      const tds = tr.querySelectorAll('td');
      const wasEl = tds[1].querySelector('.seg-was');
      const was = wasEl?.textContent?.match(/\(signed: (\S+)\)/)?.[1] ?? null;
      const bytesCell = tds[1].cloneNode(true) as HTMLElement;
      bytesCell.querySelector('.seg-was')?.remove();
      return {
        label: tds[0].textContent?.trim() ?? '',
        bytes: bytesCell.textContent?.trim() ?? '',
        signedWas: was,
        note: tds[2].textContent?.trim() ?? '',
        changed: tr.classList.contains('seg-changed'),
      };
    }),
  );
}

interface MatrixRow {
  scenario: string;
  offeredKey: string;
  sigSource: string;
  keyMatch: string;
  sigValid: string;
  firstFailure: string;
  verdict: string;
}

async function matrix(page: Page): Promise<MatrixRow[]> {
  return page.evaluate(() =>
    Array.from(document.querySelectorAll('.matrix-table tbody tr')).map((tr) => {
      const t = Array.from(tr.querySelectorAll('td')).map((td) => td.textContent?.trim() ?? '');
      return {
        scenario: t[0],
        offeredKey: t[1],
        sigSource: t[2],
        keyMatch: t[3],
        sigValid: t[4],
        firstFailure: t[5],
        verdict: t[6],
      };
    }),
  );
}

interface StepView {
  n: number;
  token: string;
  action: string;
  note: string;
  stackLabels: string[];
  caption: string;
  popped: string[];
  pushed: string[];
  status: string;
}

async function stepView(page: Page): Promise<StepView> {
  return page.evaluate(() => {
    const desc = document.querySelector('.step-desc')!;
    const tokenText = desc.querySelector('.step-token')?.textContent ?? '';
    return {
      n: Number(tokenText.match(/^(\d+)\./)?.[1] ?? 0),
      token: tokenText.replace(/^\d+\.\s*/, ''),
      action: desc.querySelector('.step-action')?.textContent?.trim() ?? '',
      note: desc.querySelector('.step-note')?.textContent?.trim() ?? '',
      // The stack is drawn top-first; reverse it so the array reads
      // bottom-to-top, the order the interpreter actually pushes in.
      stackLabels: Array.from(document.querySelectorAll('.stack-view .stack-item-label'))
        .map((e) => e.textContent?.trim() ?? '')
        .reverse(),
      caption: document.querySelector('.stack-caption')?.textContent?.trim() ?? '',
      popped: Array.from(document.querySelectorAll('.diff-chip.pop')).map(
        (e) => e.textContent?.trim() ?? '',
      ),
      pushed: Array.from(document.querySelectorAll('.diff-chip.push')).map(
        (e) => e.textContent?.trim() ?? '',
      ),
      status: (desc.className.match(/step-([a-z-]+)$/) ?? ['', ''])[1],
    };
  });
}

async function stepCount(page: Page): Promise<number> {
  return Number(await page.locator('.scrubber').getAttribute('max'));
}

async function runToEnd(page: Page): Promise<void> {
  const total = await stepCount(page);
  await page.locator('.scrubber').fill(String(total));
  await expect(page.locator('.verdict-head')).toBeVisible();
}

function btn(page: Page, label: string): Locator {
  return page.locator('.viz-controls button', { hasText: label });
}

// ===========================================================================
// verdicts — the headline claim of every scenario
// ===========================================================================

test.describe('verdicts', () => {
  for (const title of SCENARIOS) {
    test(`"${title}" ends where it says it will`, async ({ page }) => {
      await boot(page);
      await pick(page, title);

      // What the page *declares* before you run it.
      const chip = await page.locator('.scenario-blurb .scenario-status').textContent();
      const declaredAccept = chip.includes('should ACCEPT');
      expect(chip).toMatch(/should (ACCEPT|REJECT)/);

      // What the interpreter actually decides, after really running it.
      await runToEnd(page);
      const head = await page.locator('.verdict-head').textContent();
      const actualAccept = head.includes('ACCEPTED');
      expect(head).toMatch(/Script (ACCEPTED — spend is authorized|REJECTED — spend refused)/);

      // The two must agree. This is the assertion the whole spec exists for.
      expect(actualAccept, `"${title}" declared ${chip} but the script said "${head}"`).toBe(
        declaredAccept,
      );
      expect(actualAccept).toBe(title === 'Valid spend');

      const verdict = page.locator('.verdict');
      if (actualAccept) {
        await expect(verdict).toHaveClass(/verdict-accept/);
        // The final stack is truthy — Bitcoin's actual success rule.
        const view = await stepView(page);
        expect(view.stackLabels).toEqual(['TRUE']);
      } else {
        await expect(verdict).toHaveClass(/verdict-reject/);
        // A rejection must say *why*, not just that it failed.
        await expect(verdict).toContainText('This rejection is the system working correctly');
        const reason = await page.locator('.verdict-reason').textContent();
        expect(reason).toMatch(
          /^reason: (OP_EQUALVERIFY: the public key does not match the committed pubKeyHash|top of stack is FALSE|script left an empty stack)$/,
        );
      }
      // Every scenario carries its lesson, and it is never empty boilerplate.
      expect((await verdict.locator('p').first().textContent()).length).toBeGreaterThan(80);
    });
  }

  test('no verdict is shown until execution actually finishes', async ({ page }) => {
    await boot(page);
    const total = await stepCount(page);
    await expect(page.locator('.verdict')).toBeEmpty();
    for (let i = 1; i < total; i++) {
      await btn(page, 'Step ▶').click();
      await expect(page.locator('.verdict'), `verdict leaked at step ${i}`).toBeEmpty();
    }
    await btn(page, 'Step ▶').click();
    await expect(page.locator('.verdict-head')).toContainText('ACCEPTED');

    // ...and stepping back retracts it again.
    await btn(page, '◀ Back').click();
    await expect(page.locator('.verdict')).toBeEmpty();
  });
});

// ===========================================================================
// the comparison matrix — a table of claims about all seven runs at once
// ===========================================================================

test.describe('comparison matrix', () => {
  test('every row agrees with the run it summarizes', async ({ page }) => {
    await boot(page);
    const rows = await matrix(page);
    expect(rows.map((r) => r.scenario)).toEqual([...SCENARIOS]);

    for (const row of rows) {
      await pick(page, row.scenario);
      await runToEnd(page);

      // verdict pill vs. the verdict the interpreter reached
      const accepted = (await page.locator('.verdict-head').textContent()).includes('ACCEPTED');
      expect(row.verdict, `${row.scenario}: matrix pill disagrees with the run`).toBe(
        accepted ? 'ACCEPT' : 'REJECT',
      );

      // "first failure" column vs. the step execution actually stops at
      const last = await stepView(page);
      if (row.firstFailure === '—') {
        expect(accepted).toBe(true);
        expect(last.status).toBe('verify-pass');
      } else {
        expect(accepted).toBe(false);
        expect(last.token, `${row.scenario}: failed at ${last.token}, matrix claims ${row.firstFailure}`)
          .toBe(row.firstFailure);
        expect(['abort', 'verify-fail']).toContain(last.status);
      }

      // "key match" column vs. what the HASH160 pipeline concluded
      await openInspectors(page);
      const pipeline = page.locator('.inspector').nth(2);
      const matched = (await pipeline.locator('.verify-line .scenario-status').textContent()).includes(
        'match → OP_EQUALVERIFY passes',
      );
      expect(matched, `${row.scenario}: matrix key-match column disagrees with the pipeline`).toBe(
        row.keyMatch === '✓',
      );

      // "sig valid" column: only the valid spend has a signature that verifies
      expect(row.sigValid).toBe(row.scenario === 'Valid spend' ? '✓' : '✗');
    }
  });

  test('only the wrong key is attributed to the attacker', async ({ page }) => {
    await boot(page);
    const rows = await matrix(page);
    for (const row of rows) {
      expect(row.offeredKey).toBe(row.scenario === 'Wrong public key' ? "attacker's" : "owner's");
      expect(row.sigSource.length).toBeGreaterThan(0);
    }
  });
});

// ===========================================================================
// the stack machine — structural claims only a browser can check
// ===========================================================================

test.describe('stack machine', () => {
  test('the popped/pushed diff accounts for every change in stack height', async ({ page }) => {
    await boot(page);
    for (const title of SCENARIOS) {
      await pick(page, title);
      const total = await stepCount(page);
      expect(total).toBeGreaterThan(0);

      let height = 0;
      for (let i = 1; i <= total; i++) {
        await btn(page, 'Step ▶').click();
        const view = await stepView(page);
        expect(view.n, `${title} step ${i}: numbering`).toBe(i);
        // The one invariant a stack machine cannot be allowed to break.
        expect(
          view.stackLabels.length,
          `${title} step ${i} (${view.token}): height ${height} − ${view.popped.length} + ${view.pushed.length} ≠ ${view.stackLabels.length}`,
        ).toBe(height - view.popped.length + view.pushed.length);
        // ...and the caption counts what is actually drawn.
        expect(view.caption).toBe(
          `stack (${view.stackLabels.length} item${view.stackLabels.length === 1 ? '' : 's'}, top first)`,
        );
        height = view.stackLabels.length;
      }
      await btn(page, '↺ Reset').click();
    }
  });

  test('P2PKH executes the opcodes in the documented order', async ({ page }) => {
    await boot(page);
    // README / hero: OP_DUP · OP_HASH160 · OP_EQUALVERIFY · OP_CHECKSIG.
    await expect(page.locator('.token')).toHaveText([
      '<sig>',
      '<pubKey>',
      'OP_DUP',
      'OP_HASH160',
      '<pubKeyHash>',
      'OP_EQUALVERIFY',
      'OP_CHECKSIG',
    ]);
    // The ‖ seam sits exactly where scriptSig ends and scriptPubKey begins.
    await expect(page.locator('.token-strip .token-sep')).toHaveCount(1);
    const sepIndex = await page.evaluate(() => {
      const kids = Array.from(document.querySelector('.token-strip')!.children);
      return kids.filter((k, i) => i < kids.findIndex((c) => c.classList.contains('token-sep'))).length;
    });
    expect(sepIndex).toBe(2); // <sig> <pubKey> ‖ …

    const expected = [
      { token: '<sig>', stack: ['signature'] },
      { token: '<pubKey>', stack: ['signature', 'public key'] },
      { token: 'OP_DUP', stack: ['signature', 'public key', 'public key'] },
      { token: 'OP_HASH160', stack: ['signature', 'public key', 'HASH160(public key)'] },
      { token: '<pubKeyHash>', stack: ['signature', 'public key', 'HASH160(public key)', 'pubKeyHash'] },
      { token: 'OP_EQUALVERIFY', stack: ['signature', 'public key'] },
      { token: 'OP_CHECKSIG', stack: ['TRUE'] },
    ];
    for (const step of expected) {
      await btn(page, 'Step ▶').click();
      const view = await stepView(page);
      expect(view.token).toBe(step.token);
      expect(view.stackLabels).toEqual(step.stack);
    }
  });

  test('the wrong key never reaches the signature check', async ({ page }) => {
    await boot(page);
    await pick(page, 'Wrong public key');
    // README: "the wrong key aborts at OP_EQUALVERIFY before the signature is
    // even checked". The script has 7 elements; execution must stop at 6.
    await expect(page.locator('.token')).toHaveCount(7);
    expect(await stepCount(page)).toBe(6);

    const seen: string[] = [];
    for (let i = 0; i < 6; i++) {
      await btn(page, 'Step ▶').click();
      seen.push((await stepView(page)).token);
    }
    expect(seen).not.toContain('OP_CHECKSIG');
    expect(seen[seen.length - 1]).toBe('OP_EQUALVERIFY');
    const last = await stepView(page);
    expect(last.status).toBe('abort');
    expect(last.action).toContain('Script aborts');
    await expect(btn(page, 'Step ▶')).toBeDisabled();
  });

  test('the token rail tracks the cursor and can drive it', async ({ page }) => {
    await boot(page);
    const total = await stepCount(page);
    await expect(page.locator('.token.executed')).toHaveCount(0);
    await expect(page.locator('.token.active')).toHaveCount(0);

    for (let i = 1; i <= total; i++) {
      await btn(page, 'Step ▶').click();
      await expect(page.locator('.token.executed')).toHaveCount(i);
      await expect(page.locator('.token.active')).toHaveCount(1);
      expect(await page.locator('.token.active').textContent()).toBe((await stepView(page)).token);
    }

    // Clicking a token jumps to that step, and the scrubber follows.
    await page.locator('.token').nth(3).click();
    expect(await page.locator('.scrubber').inputValue()).toBe('4');
    expect((await stepView(page)).token).toBe('OP_HASH160');
    await expect(page.locator('.token.executed')).toHaveCount(4);
  });

  test('the controls bound the cursor at both ends', async ({ page }) => {
    await boot(page);
    const total = await stepCount(page);
    await expect(btn(page, '◀ Back')).toBeDisabled();
    await expect(btn(page, 'Step ▶')).toBeEnabled();

    await page.locator('.scrubber').fill(String(total));
    await expect(btn(page, 'Step ▶')).toBeDisabled();
    await expect(btn(page, '◀ Back')).toBeEnabled();

    await btn(page, '◀ Back').click();
    expect(await page.locator('.scrubber').inputValue()).toBe(String(total - 1));
    await expect(btn(page, 'Step ▶')).toBeEnabled();

    await btn(page, '↺ Reset').click();
    expect(await page.locator('.scrubber').inputValue()).toBe('0');
    await expect(btn(page, '◀ Back')).toBeDisabled();
    await expect(page.locator('.stack-caption')).toHaveText('stack is empty — press Step ▶');
    await expect(page.locator('.verdict')).toBeEmpty();
  });

  test('auto-run walks to the verdict on its own and then stops', async ({ page }) => {
    await boot(page);
    await page.locator('.speed-sel').selectOption('400');
    const auto = page.locator('.viz-controls button', { hasText: 'Auto-run' });
    await auto.click();
    await expect(page.locator('.viz-controls button', { hasText: '⏸ Pause' })).toBeVisible();
    await expect(page.locator('.verdict-head')).toContainText('ACCEPTED', { timeout: 15_000 });
    // Once finished it must release the timer, not keep firing.
    await expect(page.locator('.viz-controls button', { hasText: 'Auto-run' })).toBeVisible();
    expect(await page.locator('.scrubber').inputValue()).toBe(String(await stepCount(page)));
  });
});

// ===========================================================================
// HASH160 pipeline — the commitment the lock is built on
// ===========================================================================

test.describe('HASH160 pipeline', () => {
  test('the pubKeyHash is the same 20 bytes everywhere the page prints it', async ({ page }) => {
    await boot(page);
    await openInspectors(page);

    const keys = await kvRows(page.locator('.key-panel'));
    const pubKeyHash = keys['pubKeyHash'];
    expect(pubKeyHash).toMatch(/^[0-9a-f]{40}$/);

    // (1) the HASH160 pipeline's own RIPEMD-160 output …
    const pipeline = page.locator('.inspector').nth(2);
    const pipeRows = await pipeline.locator('.pipe-row code').allTextContents();
    expect(pipeRows[1].trim()).toBe(pubKeyHash);
    // (2) … the "HASH160(public key)" / "committed pubKeyHash" comparison …
    const caps = await pipeline.locator('.pipe-compare code').allTextContents();
    expect(caps.map((c) => c.trim())).toEqual([pubKeyHash, pubKeyHash]);
    await expect(pipeline.locator('.verify-line .scenario-status')).toContainText(
      'match → OP_EQUALVERIFY passes',
    );

    // (3) … and the 20 bytes inside the serialized locking script. The whole
    // script must be the canonical P2PKH encoding, byte for byte.
    const script = await hexFields(page.locator('.script-panel'));
    expect(script['scriptPubKey bytes']).toBe(`76a914${pubKeyHash}88ac`);

    // (4) … and the subscript the signature commits to.
    const segs = await sighashSegments(page);
    expect(segs.find((s) => s.label === 'subscript')!.bytes).toBe(`76a914${pubKeyHash}88ac`);
  });

  test('the address is Base58Check(0x00 || pubKeyHash), verified independently', async ({ page }) => {
    await boot(page);
    const keys = await kvRows(page.locator('.key-panel'));
    expect(keys['P2PKH address']).toBe(base58check('00' + keys['pubKeyHash']));
    expect(keys['P2PKH address'].startsWith('1')).toBe(true);
  });

  test('privkey = 1 reproduces the textbook key, hash and address', async ({ page }) => {
    await boot(page);
    await openAdvanced(page);
    await page.locator('#adv-priv').fill(PRIV_ONE);
    await page.locator('.adv-actions button', { hasText: 'Apply' }).first().click();

    const keys = await kvRows(page.locator('.key-panel'));
    // README: validated at boot against the privkey = 1 key whose HASH160 is
    // 751e…3bd6 (address 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH).
    expect(keys['pubKeyHash']).toBe(G_HASH160);
    expect(keys['P2PKH address']).toBe(G_ADDRESS);
    expect(keys['P2PKH address']).toBe(base58check('00' + G_HASH160));
    // The public key for privkey = 1 is the generator point itself.
    expect(keys['public key'].startsWith(G_COMPRESSED.slice(0, 12))).toBe(true);
    expect(keys['public key'].endsWith(G_COMPRESSED.slice(-10))).toBe(true);

    // And the whole pipeline still runs on it.
    await runToEnd(page);
    await expect(page.locator('.verdict-head')).toContainText('ACCEPTED');
  });

  test('the swapped unlock hashes the signature, and says so', async ({ page }) => {
    await boot(page);
    await pick(page, 'Swapped scriptSig order');

    // A key mismatch opens the inspector that explains it, unprompted — checked
    // before anything in this test forces the <details> open.
    expect(
      await page.locator('.inspector').evaluateAll((els) =>
        els.map((e) => (e as HTMLDetailsElement).open),
      ),
      'the HASH160 inspector should self-open on a mismatch',
    ).toEqual([false, false, true]);
    await openInspectors(page);

    // The tokens themselves read in the reversed order.
    await expect(page.locator('.token').nth(0)).toHaveText('<pubKey>');
    await expect(page.locator('.token').nth(1)).toHaveText('<sig>');

    // OP_HASH160 hashes the top of the stack, which is now the signature.
    const pipeline = page.locator('.inspector').nth(2);
    const hexes = await hexFields(pipeline);
    const label = Object.keys(hexes).find((k) => k.includes('on top of stack'))!;
    expect(label).toMatch(/^signature on top of stack \(\d+ bytes\)$/);
    const bytes = Number(label.match(/\((\d+) bytes\)/)![1]);
    expect(hexes[label].length / 2).toBe(bytes);

    const compare = (await pipeline.locator('.pipe-compare code').allTextContents()).map((s) => s.trim());
    expect(compare[0], 'hashing the signature must not produce the committed hash').not.toBe(compare[1]);
    await expect(pipeline.locator('.verify-line .scenario-status')).toContainText(
      'mismatch → OP_EQUALVERIFY aborts',
    );
  });
});

// ===========================================================================
// sighash inspector — "sighash = SHA256(SHA256(preimage))"
// ===========================================================================

test.describe('sighash inspector', () => {
  test('the preimage is the fields concatenated and the sighash is its double SHA-256', async ({ page }) => {
    await boot(page);
    await openInspectors(page);

    const segs = await sighashSegments(page);
    expect(segs.map((s) => s.label)).toEqual([
      'version', 'input count', 'prev txid', 'prev vout', 'subscript len', 'subscript',
      'sequence', 'output count', 'output value', 'output script len', 'output script',
      'locktime', 'hash type',
    ]);

    const fields = await hexFields(page.locator('.inspector').nth(0));
    const preimage = fields['preimage (verifier)'];
    // Claim 1: the preimage really is those rows, in that order, concatenated.
    expect(preimage).toBe(segs.map((s) => s.bytes).join(''));
    // Claim 2, checked against node's SHA-256 rather than the page's:
    expect(fields['sighash = SHA256(SHA256(preimage))']).toBe(sha256dHex(preimage));

    // The legacy SIGHASH_ALL trailer, and the LE encodings, are what they say.
    expect(segs.find((s) => s.label === 'hash type')!.bytes).toBe('01000000');
    expect(leHexToBigInt(segs.find((s) => s.label === 'version')!.bytes)).toBe(1n);
    expect(leHexToBigInt(segs.find((s) => s.label === 'sequence')!.bytes)).toBe(0xffffffffn);
    expect(leHexToBigInt(segs.find((s) => s.label === 'locktime')!.bytes)).toBe(0n);

    // Length prefixes must match the things they prefix.
    // The length prefixes are rendered as varint *hex*, so parse them as hex.
    const len = (label: string) => parseInt(segs.find((s) => s.label === label)!.bytes, 16);
    expect(len('subscript len')).toBe(segs.find((s) => s.label === 'subscript')!.bytes.length / 2);
    expect(len('output script len')).toBe(
      segs.find((s) => s.label === 'output script')!.bytes.length / 2,
    );

    // The signed sighash matches the verified one, so no "different sighash" note.
    await expect(page.locator('.inspector').nth(0).locator('.lab-note')).toHaveCount(0);
  });

  test('the output value segment matches the amount the tx panel shows', async ({ page }) => {
    await boot(page);
    await openInspectors(page);
    const segs = await sighashSegments(page);
    const sats = leHexToBigInt(segs.find((s) => s.label === 'output value')!.bytes);

    const txText = await page.locator('.tx-panel').textContent();
    const shown = BigInt(txText.match(/([\d,]+) sat/)![1].replace(/,/g, ''));
    expect(shown).toBe(sats);
    // ...and the BTC figure beside it is that number of satoshis, converted.
    const btc = txText.match(/\(([\d.,]+) BTC\)/)![1];
    expect(btc).toBe((Number(sats) / 1e8).toLocaleString('en-US', { maximumFractionDigits: 8 }));
  });

  test('tampering changes exactly one field, and exactly one sighash', async ({ page }) => {
    await boot(page);
    await openInspectors(page);
    const original = await hexFields(page.locator('.inspector').nth(0));
    const originalSighash = original['sighash = SHA256(SHA256(preimage))'];

    await pick(page, 'Tampered transaction');
    // The sighash inspector opens itself for a tampered tx, before this test
    // forces anything open.
    expect(
      await page.locator('.inspector').evaluateAll((els) =>
        els.map((e) => (e as HTMLDetailsElement).open),
      ),
    ).toEqual([true, false, false]);
    await openInspectors(page);
    const segs = await sighashSegments(page);
    const changed = segs.filter((s) => s.changed);
    // The scenario claims the *output amount* was edited — only that.
    expect(changed).toHaveLength(1);
    expect(changed[0].label).toBe('output value');
    expect(changed[0].signedWas).not.toBeNull();
    expect(leHexToBigInt(changed[0].bytes)).toBe(100_000_000n);
    expect(leHexToBigInt(changed[0].signedWas!)).toBe(50_000n);

    const fields = await hexFields(page.locator('.inspector').nth(0));
    const tamperedSighash = fields['sighash = SHA256(SHA256(preimage))'];
    expect(fields['preimage (verifier)']).toBe(segs.map((s) => s.bytes).join(''));
    expect(tamperedSighash).toBe(sha256dHex(fields['preimage (verifier)']));
    // One byte-level edit, a completely different message to sign.
    expect(tamperedSighash).not.toBe(originalSighash);
    // The explanation quotes the sighash the owner actually signed.
    const note = await page.locator('.inspector').nth(0).locator('.lab-note').textContent();
    expect(note).toContain(originalSighash.slice(0, 10));
    expect(note).toContain(originalSighash.slice(-8));
    expect(note).toContain('That is exactly why OP_CHECKSIG fails');

    // The tx panel flags the edit in the row it happened in.
    await expect(page.locator('.tx-panel .tampered')).toContainText('⚠ edited after signing');
  });
});

// ===========================================================================
// signature decoder — DER, r/s, low-S
// ===========================================================================

test.describe('signature decoder', () => {
  test('the decoded r and s really are the DER it displays', async ({ page }) => {
    await boot(page);
    await openInspectors(page);
    const insp = page.locator('.inspector').nth(1);
    const der = (await hexFields(insp))['DER signature'];
    // Parsed here, not by the page: any disagreement is a real decoder bug.
    const { r, s } = parseDER(der);

    const rows = await kvRows(insp);
    const hex64 = (v: bigint) => v.toString(16).padStart(64, '0');
    // The panel abbreviates as head…tail; both ends must come from our parse.
    expect(rows['r'].startsWith(hex64(r).slice(0, 12))).toBe(true);
    expect(rows['r'].endsWith(hex64(r).slice(-10))).toBe(true);
    expect(rows['s'].startsWith(hex64(s).slice(0, 12))).toBe(true);
    expect(rows['s'].endsWith(hex64(s).slice(-10))).toBe(true);

    // low-S (BIP-146), checked against the curve order rather than the flag.
    expect(s <= CURVE_N / 2n).toBe(true);
    await expect(insp.locator('.insp-flags .scenario-status').first()).toHaveText('✓ low-S (BIP-146)');
    await expect(insp.locator('.insp-flags .scenario-status').nth(1)).toHaveText('✓ SIGHASH_ALL');
    await expect(insp.locator('.verify-line .scenario-status')).toHaveText('✓ verifies under policy');
    await expect(insp.locator('.verify-aside')).toHaveCount(0);
  });

  test('the high-S signature is the same signature with s replaced by n − s', async ({ page }) => {
    await boot(page);
    // Fix the key so RFC-6979 makes both scenarios deterministic and comparable.
    await openAdvanced(page);
    await page.locator('#adv-priv').fill(PRIV_ONE);
    await page.locator('.adv-actions button', { hasText: 'Apply' }).first().click();

    await openInspectors(page);
    const low = parseDER((await hexFields(page.locator('.inspector').nth(1)))['DER signature']);

    await pick(page, 'High-S signature');
    await openInspectors(page);
    const insp = page.locator('.inspector').nth(1);
    const high = parseDER((await hexFields(insp))['DER signature']);

    // Same nonce, same r; s flipped to the other root. This is the malleability.
    expect(high.r).toBe(low.r);
    expect(low.s + high.s).toBe(CURVE_N);
    expect(high.s > CURVE_N / 2n).toBe(true);

    await expect(insp.locator('.insp-flags .scenario-status').first()).toHaveText(
      '✗ high-S (non-standard)',
    );
    await expect(insp.locator('.verify-line .scenario-status')).toHaveText('✗ rejected by policy');
    // The distinguishing claim: policy rejects it, the raw math does not.
    await expect(insp.locator('.verify-aside')).toContainText(
      'the raw ECDSA math does check out; only the low-S policy rejects it',
    );
    await runToEnd(page);
    await expect(page.locator('.verdict-head')).toContainText('REJECTED');
  });

  test('malformed DER fails closed, with a parse error instead of an exception', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(e.message));
    await boot(page);
    await pick(page, 'Malformed DER');
    await openInspectors(page);

    const insp = page.locator('.inspector').nth(1);
    const rows = await kvRows(insp);
    expect(rows['parse error'].length).toBeGreaterThan(0);
    await expect(insp).toContainText('BIP-66 strict DER');
    await expect(insp.locator('.verify-line .scenario-status')).toHaveText('✗ OP_CHECKSIG → FALSE');
    // No r/s are offered for bytes that did not parse.
    expect(rows['r']).toBeUndefined();
    expect(rows['s']).toBeUndefined();

    await runToEnd(page);
    await expect(page.locator('.verdict-head')).toContainText('REJECTED');
    expect(errors, 'a malformed signature must not throw').toEqual([]);
  });

  test('the decoder agrees with OP_CHECKSIG on every scenario', async ({ page }) => {
    await boot(page);
    for (const title of SCENARIOS) {
      await pick(page, title);
      await openInspectors(page);
      const chip = await page.locator('.inspector').nth(1).locator('.verify-line .scenario-status').textContent();
      const decoderSaysValid = chip.includes('verifies under policy');

      await runToEnd(page);
      const reachedChecksig = (await stepView(page)).token === 'OP_CHECKSIG';
      const accepted = (await page.locator('.verdict-head').textContent()).includes('ACCEPTED');
      if (reachedChecksig) {
        // Two independent calls to checkSig, from the inspector and from the
        // interpreter, over the same sighash. They must not disagree.
        expect(decoderSaysValid, `${title}: decoder and OP_CHECKSIG disagree`).toBe(accepted);
      } else {
        expect(accepted).toBe(false);
      }
      await btn(page, '↺ Reset').click();
    }
  });
});

// ===========================================================================
// custom inputs and key regeneration
// ===========================================================================

test.describe('advanced inputs', () => {
  test('bad inputs are refused with a reason, and nothing changes', async ({ page }) => {
    await boot(page);
    const before = await kvRows(page.locator('.key-panel'));
    const err = page.locator('.adv-err');

    const cases: [string, string, string][] = [
      ['#adv-priv', '00', 'Private key: private key must be 32 bytes (64 hex)'],
      ['#adv-priv', '0'.repeat(64), 'Private key: private key must be in 1 … n−1'],
      ['#adv-priv', 'zz'.repeat(32), 'Private key: invalid hex'],
      ['#adv-val', 'abc', 'Output value must be a whole number of satoshis'],
      ['#adv-val', '2100000000000001', 'Output value exceeds the 21M BTC cap'],
    ];
    for (const [selector, value, message] of cases) {
      await openAdvanced(page);
      await page.locator('#adv-priv').fill('');
      await page.locator('#adv-val').fill('');
      await page.locator(selector).fill(value);
      await page.locator('.adv-actions button', { hasText: 'Apply' }).first().click();
      await expect(err).toHaveText(message);
      // A rejected input must not silently take effect.
      expect(await kvRows(page.locator('.key-panel'))).toEqual(before);
    }

    // n − 1 is the largest legal key and must be accepted.
    await openAdvanced(page);
    await page.locator('#adv-val').fill('');
    await page.locator('#adv-priv').fill((CURVE_N - 1n).toString(16).padStart(64, '0'));
    await page.locator('.adv-actions button', { hasText: 'Apply' }).first().click();
    await expect(err).toHaveText('');
    expect((await kvRows(page.locator('.key-panel')))['pubKeyHash']).not.toBe(before['pubKeyHash']);
  });

  test('a custom output value flows through the tx, the sighash and the verdict', async ({ page }) => {
    await boot(page);
    await openInspectors(page);
    const originalSighash = (await hexFields(page.locator('.inspector').nth(0)))[
      'sighash = SHA256(SHA256(preimage))'
    ];

    await openAdvanced(page);
    await page.locator('#adv-val').fill('123456');
    await page.locator('.adv-actions button', { hasText: 'Apply' }).first().click();

    await expect(page.locator('.tx-panel')).toContainText('123,456 sat (0.00123456 BTC)');
    await openInspectors(page);
    const segs = await sighashSegments(page);
    expect(leHexToBigInt(segs.find((s) => s.label === 'output value')!.bytes)).toBe(123_456n);

    const fields = await hexFields(page.locator('.inspector').nth(0));
    expect(fields['preimage (verifier)']).toBe(segs.map((s) => s.bytes).join(''));
    expect(fields['sighash = SHA256(SHA256(preimage))']).toBe(sha256dHex(fields['preimage (verifier)']));
    expect(fields['sighash = SHA256(SHA256(preimage))']).not.toBe(originalSighash);

    // A different amount is a different message — and it is signed correctly.
    await runToEnd(page);
    await expect(page.locator('.verdict-head')).toContainText('ACCEPTED');
  });

  test('new keys really are new, and the spend still verifies', async ({ page }) => {
    await boot(page);
    const before = await kvRows(page.locator('.key-panel'));
    await page.locator('.regen-btn').click();
    const after = await kvRows(page.locator('.key-panel'));

    expect(after['private key']).not.toBe(before['private key']);
    expect(after['public key']).not.toBe(before['public key']);
    expect(after['pubKeyHash']).not.toBe(before['pubKeyHash']);
    expect(after['P2PKH address']).toBe(base58check('00' + after['pubKeyHash']));

    await runToEnd(page);
    await expect(page.locator('.verdict-head')).toContainText('ACCEPTED');
    // The lock was rebuilt around the new key, not left pointing at the old one.
    const script = await hexFields(page.locator('.script-panel'));
    expect(script['scriptPubKey bytes']).toBe(`76a914${after['pubKeyHash']}88ac`);
  });
});

// ===========================================================================
// boot integrity
// ===========================================================================

test('the boot self-test runs and passes, with no page errors', async ({ page }) => {
  const logs: string[] = [];
  const errors: string[] = [];
  page.on('console', (m) => {
    logs.push(m.text());
    if (m.type() === 'error') errors.push(m.text());
  });
  page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));

  await boot(page);
  await runToEnd(page);

  const hashLine = logs.find((l) => l.includes('privkey=1 HASH160'));
  expect(hashLine, 'the boot self-test did not run').toBeDefined();
  // The line prints the computed hash and the expected one; they must match,
  // and the expected one must be the documented value.
  const found = hashLine!.match(/=== ([0-9a-f]{40}) — expect ([0-9a-f]{40})/)!;
  expect(found[1]).toBe(found[2]);
  expect(found[1]).toBe(G_HASH160);
  expect(logs).toContain('OP_CHECKSIG valid === true · tampered rejected === true');
  expect(errors).toEqual([]);
});
