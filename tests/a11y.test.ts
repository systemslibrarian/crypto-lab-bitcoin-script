// @vitest-environment jsdom
//
// Structural accessibility gate. axe-core runs against the real mounted DOM in
// jsdom and flags ARIA/name/role/landmark/label problems. Colour-contrast is
// checked separately (verified by hand — see the contrast ratios in the build
// notes — because jsdom has no layout engine to measure it reliably), so that
// one rule is disabled here to avoid false "incomplete" noise.

import { describe, it, expect, beforeAll } from 'vitest';
import axe from 'axe-core';
import { mountApp } from '../src/ui';

function byText(text: RegExp): HTMLButtonElement | undefined {
  return Array.from(document.querySelectorAll('button')).find((b) =>
    text.test((b.textContent || '').trim()),
  ) as HTMLButtonElement | undefined;
}

describe('axe-core: no serious/critical WCAG violations', () => {
  beforeAll(() => {
    document.body.innerHTML = '<main id="app"></main>';
    mountApp(document.getElementById('app') as HTMLElement);
    // Drive some dynamic content onto the page (run a scenario to completion) so
    // axe sees the stack, step description, and verdict states too.
    byText(/Tampered transaction/)?.click();
    const step = byText(/^Step/);
    let guard = 0;
    while (step && !step.hasAttribute('disabled') && guard++ < 50) step.click();
  });

  it('passes axe on the fully-rendered demo', async () => {
    const results = await axe.run(document.body, {
      runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] },
      rules: { 'color-contrast': { enabled: false } },
    });
    const blocking = results.violations.filter(
      (v) => v.impact === 'serious' || v.impact === 'critical',
    );
    if (blocking.length) {
      for (const v of blocking) {
        // surface details when the gate fails
        console.error(`AXE ${v.impact}: ${v.id} — ${v.help}`);
        for (const n of v.nodes.slice(0, 3)) console.error('   ', n.html);
      }
    }
    expect(blocking.map((v) => v.id)).toEqual([]);
  });
});
