// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from 'vitest';
import { mountApp } from '../src/ui';

function btn(text: RegExp): HTMLButtonElement | undefined {
  return Array.from(document.querySelectorAll('button')).find((b) =>
    text.test((b.textContent || '').trim()),
  ) as HTMLButtonElement | undefined;
}
function scenarioBtn(text: RegExp): HTMLButtonElement {
  return Array.from(document.querySelectorAll('.scenario-btn')).find((b) =>
    text.test((b.textContent || '').trim()),
  ) as HTMLButtonElement;
}
function runToEnd(): void {
  const step = btn(/^Step/)!;
  let g = 0;
  while (!step.hasAttribute('disabled') && g++ < 60) step.click();
}

beforeEach(() => {
  document.body.innerHTML = '<main id="app"></main>';
  mountApp(document.getElementById('app') as HTMLElement);
});

describe('reversible stepper', () => {
  it('Back walks execution backwards and clears the verdict', () => {
    runToEnd();
    expect(document.querySelector('.verdict')?.classList.contains('verdict-accept')).toBe(true);
    btn(/◀ Back/)!.click();
    expect(document.querySelector('.verdict')?.classList.contains('verdict-accept')).toBe(false);
  });

  it('the scrubber jumps to an arbitrary step', () => {
    const scrub = document.querySelector('.scrubber') as HTMLInputElement;
    expect(Number(scrub.max)).toBeGreaterThan(0);
    scrub.value = '0';
    scrub.dispatchEvent(new Event('input', { bubbles: true }));
    expect(document.querySelector('.step-desc')?.textContent).toMatch(/Press Step/);
  });

  it('clicking a token jumps straight to that opcode', () => {
    const checksig = Array.from(document.querySelectorAll('button.token')).find(
      (t) => (t.textContent || '').trim() === 'OP_CHECKSIG',
    ) as HTMLButtonElement;
    checksig.click();
    expect(document.querySelector('.step-desc')?.textContent).toMatch(/OP_CHECKSIG/);
  });

  it('shows a popped/pushed diff for the current step', () => {
    runToEnd();
    const diff = document.querySelector('.step-diff');
    expect(diff?.textContent).toMatch(/popped/);
    expect(diff?.textContent).toMatch(/pushed/);
  });
});

describe('scenario comparison matrix', () => {
  it('renders a row per scenario (4 canonical + 3 edge)', () => {
    expect(document.querySelectorAll('.matrix-table tbody tr').length).toBe(7);
  });
});

describe('edge-case scenarios', () => {
  it('high-S: rejected, and the signature decoder flags low-S = false', () => {
    scenarioBtn(/High-S/).click();
    runToEnd();
    expect(document.querySelector('.verdict')?.classList.contains('verdict-reject')).toBe(true);
    expect(document.querySelector('.inspectors')?.textContent).toMatch(/high-S/);
  });

  it('malformed DER: rejected and the decoder reports a parse error', () => {
    scenarioBtn(/Malformed DER/).click();
    runToEnd();
    expect(document.querySelector('.verdict')?.classList.contains('verdict-reject')).toBe(true);
    expect(document.querySelector('.inspectors')?.textContent).toMatch(/parse error/i);
  });

  it('swapped order: aborts at OP_EQUALVERIFY before OP_CHECKSIG', () => {
    scenarioBtn(/Swapped/).click();
    runToEnd();
    expect(document.querySelector('.verdict')?.classList.contains('verdict-reject')).toBe(true);
    const executed = Array.from(document.querySelectorAll('.token.executed')).map((t) => t.textContent);
    expect(executed).not.toContain('OP_CHECKSIG');
  });

  it('swapped order: HASH160 inspector hashes the signature (not the key) and shows a mismatch', () => {
    scenarioBtn(/Swapped/).click();
    const inspText = document.querySelector('.inspectors')?.textContent || '';
    // the hashed top-of-stack item is the signature here, and it must not match
    expect(inspText).toMatch(/signature on top of stack/);
    expect(inspText).toMatch(/mismatch → OP_EQUALVERIFY aborts/);
  });
});

describe('sighash inspector reflects the tampered transaction', () => {
  it('highlights the changed output-value segment', () => {
    scenarioBtn(/Tampered transaction/).click();
    expect(document.querySelector('.seg-changed')).toBeTruthy();
    expect(document.querySelector('.seg-changed')?.textContent).toMatch(/output value/);
  });
});

describe('advanced custom inputs', () => {
  it('applies a custom private key (privkey=1 → known pubKeyHash)', () => {
    const priv = document.querySelector('#adv-priv') as HTMLInputElement;
    priv.value = '00'.repeat(31) + '01';
    btn(/^Apply$/)!.click();
    expect(document.querySelector('.key-panel')?.textContent).toMatch(
      /751e76e8199196d454941c45d1b3a323f1433bd6/,
    );
  });

  it('rejects an invalid private key with an inline error', () => {
    const priv = document.querySelector('#adv-priv') as HTMLInputElement;
    priv.value = 'not-hex';
    btn(/^Apply$/)!.click();
    expect((document.querySelector('.adv-err')?.textContent || '').length).toBeGreaterThan(0);
  });

  it('rejects an out-of-range output value', () => {
    const val = document.querySelector('#adv-val') as HTMLInputElement;
    val.value = '999999999999999999';
    btn(/^Apply$/)!.click();
    expect(document.querySelector('.adv-err')?.textContent).toMatch(/21M|cap/i);
  });

  it('reset restores a fresh (non privkey=1) owner', () => {
    const priv = document.querySelector('#adv-priv') as HTMLInputElement;
    priv.value = '00'.repeat(31) + '01';
    btn(/^Apply$/)!.click();
    btn(/Reset to canonical/)!.click();
    expect(document.querySelector('.key-panel')?.textContent).not.toMatch(
      /751e76e8199196d454941c45d1b3a323f1433bd6/,
    );
  });
});
