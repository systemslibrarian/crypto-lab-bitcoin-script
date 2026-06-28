// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from 'vitest';
import { mountApp } from '../src/ui';

function byText(role: string, text: RegExp): HTMLButtonElement | undefined {
  return Array.from(document.querySelectorAll(role)).find((b) =>
    text.test((b.textContent || '').trim()),
  ) as HTMLButtonElement | undefined;
}

function runToEnd(): void {
  const step = byText('button', /^Step/)!;
  let guard = 0;
  while (!step.hasAttribute('disabled') && guard++ < 50) step.click();
}

describe('ui mounts and the stepper drives execution', () => {
  let root: HTMLDivElement;
  beforeEach(() => {
    document.body.innerHTML = '<div id="app"></div>';
    root = document.getElementById('app') as HTMLDivElement;
    mountApp(root);
  });

  it('renders the hero, all six sections, and seven scenario buttons', () => {
    expect(document.querySelector('h1')?.textContent).toMatch(/Bitcoin Script/i);
    expect(document.querySelectorAll('.lab-section').length).toBe(6);
    expect(document.querySelectorAll('.scenario-btn').length).toBe(7); // 4 canonical + 3 edge
  });

  it('exposes a valid aria-pressed state on the scenario toggle buttons', () => {
    const btns = Array.from(document.querySelectorAll('.scenario-btn'));
    // every button must carry a literal "true"/"false" (never "" or missing)
    for (const b of btns) {
      expect(['true', 'false']).toContain(b.getAttribute('aria-pressed'));
    }
    // exactly one is pressed (the active scenario)
    expect(btns.filter((b) => b.getAttribute('aria-pressed') === 'true')).toHaveLength(1);
  });

  it('valid scenario steps through to an ACCEPT verdict', () => {
    runToEnd();
    const verdict = document.querySelector('.verdict');
    expect(verdict?.classList.contains('verdict-accept')).toBe(true);
    expect(verdict?.textContent).toMatch(/ACCEPTED/);
  });

  it('tampered-transaction scenario ends in a REJECT verdict with a failing OP_CHECKSIG', () => {
    byText('button', /Tampered transaction/)!.click();
    runToEnd();
    const verdict = document.querySelector('.verdict');
    expect(verdict?.classList.contains('verdict-reject')).toBe(true);
    // the step description for the last revealed step should be the failed check
    expect(document.querySelector('.step-desc')?.textContent).toMatch(/INVALID/);
  });

  it('wrong-key scenario aborts (REJECT) and never reaches the signature check', () => {
    byText('button', /Wrong public key/)!.click();
    runToEnd();
    expect(document.querySelector('.verdict')?.classList.contains('verdict-reject')).toBe(true);
    // executed tokens in the strip should not include OP_CHECKSIG
    const executed = Array.from(document.querySelectorAll('.token.executed')).map(
      (t) => t.textContent,
    );
    expect(executed).not.toContain('OP_CHECKSIG');
    expect(executed).toContain('OP_EQUALVERIFY');
  });

  it('regenerating keys does not throw and keeps the demo runnable', () => {
    const regen = byText('button', /New keys/)!;
    expect(() => regen.click()).not.toThrow();
    expect(document.querySelectorAll('.scenario-btn').length).toBe(7);
    runToEnd();
    expect(document.querySelector('.verdict')?.classList.contains('verdict-accept')).toBe(true);
  });
});
