import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

import { auditContrast, formatContrastFailures } from './contrast';

/**
 * WCAG regression gate. Deploys are already gated on the self-test / smoke
 * vectors and on the claims spec; this gates them on accessibility the same way.
 *
 * Three things this file deliberately does NOT do, two of which it used to:
 *
 * 1. It does not inject `transition: none` / `transition-duration: 0s`. While
 *    that injection was present the suite was structurally unable to observe a
 *    transition or theme-swap defect, because it had deleted the very thing it
 *    was meant to check — and the `.token` rail's 150ms background/colour ramp
 *    on theme flip was exactly such a thing. Motion is settled honestly
 *    instead: `page.emulateMedia({ reducedMotion: 'reduce' })`, which exercises
 *    the stylesheet's real `prefers-reduced-motion` block, plus a poll until
 *    nothing is animating.
 *
 *    `test.use({ reducedMotion: 'reduce' })` is NOT equivalent — on Playwright
 *    1.61.1 it silently does nothing, both at file level and inside
 *    `test.describe`, and the page still reports `matches === false`. Hence
 *    `emulateMedia` plus `assertReducedMotion`, so a regression to the no-op
 *    form fails loudly rather than quietly disabling the premise.
 *
 * 2. It does not scan only the untouched page. `<main id="app">` ships empty and
 *    is filled by `mountApp`, and several rendered states — the ACCEPT and
 *    REJECT verdict panels, the populated stack, the popped/pushed diff chips,
 *    the malformed-DER parse-error branch of the signature decoder, the
 *    advanced drawer's validation alert — exist only after user input. A gate
 *    that scans first paint alone cannot see a violation in any of them, so the
 *    page is driven into each and scanned there.
 *
 * 3. It does not trust axe as the whole contrast oracle. Contrast is
 *    additionally measured arithmetically in `./contrast`, against the surface
 *    the text is really composited onto: axe refuses to compute contrast over a
 *    background gradient and files those nodes under "incomplete", which never
 *    reaches the violations array this gate asserts on.
 *
 * Every scan also asserts its content is actually on screen first, via
 * `expectRendered`, so an empty container can never be scanned and pass having
 * checked nothing.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** Fail loudly if reduced motion is not actually in effect. */
async function assertReducedMotion(page: Page): Promise<void> {
  const matches = await page.evaluate(
    () => window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
  expect(
    matches,
    'reduced motion is not in effect — page.emulateMedia is the only form that works here'
  ).toBe(true);
}

/** Let the browser get as far as the next two animation frames. */
async function frames(page: Page): Promise<void> {
  await page.evaluate(
    () => new Promise<void>((r) => requestAnimationFrame(() => requestAnimationFrame(() => r())))
  );
}

/**
 * Wait until motion has genuinely stopped, rather than deleting animations.
 *
 * Two failure modes had to be designed around, both observed on this page:
 *
 * 1. A CSS transition does not appear in `document.getAnimations()` until the
 *    style recalc that starts it has run. A poll issued straight after a
 *    mutation therefore sees an empty list, concludes "nothing is animating",
 *    and measures the frame *before* the transition. That is how the theme-swap
 *    check first came back reporting light-theme ink composited over
 *    dark-theme panels at 1.08:1. Hence the leading frame wait.
 *
 * 2. A theme flip does not produce one tidy batch. Instrumenting it showed
 *    ~594 transitions created at once and then further waves (3, then 17, then
 *    66, then 15) over the next several hundred milliseconds as the repaint
 *    propagates. Between waves the running count touches zero, so a poll for
 *    "nothing is running right now" can and does exit through a gap mid-drain.
 *    Hence quiescence is required to *hold* for a run of consecutive frames.
 *
 * The fix for both is to wait longer and look harder, never to re-add an
 * injected `transition: none` — that would delete the very behaviour this gate
 * exists to check.
 */
const QUIET_FRAMES = 10;

async function settle(page: Page): Promise<void> {
  await frames(page);
  await page.evaluate(() => {
    (window as unknown as { __quietFrames?: number }).__quietFrames = 0;
  });
  await page.waitForFunction(
    (need: number) => {
      const w = window as unknown as { __quietFrames?: number };
      const busy = document
        .getAnimations()
        .some((a) => a.playState === 'running' || a.playState === 'pending');
      if (busy) {
        w.__quietFrames = 0;
        return false;
      }
      w.__quietFrames = (w.__quietFrames ?? 0) + 1;
      return w.__quietFrames >= need;
    },
    QUIET_FRAMES,
    { timeout: 15_000 }
  );
  await frames(page);
}

/**
 * Guard against the empty-container scan. Every scan names the content it
 * expects to be looking at; if that content is missing the test fails here
 * rather than passing an axe run over nothing.
 */
async function expectRendered(page: Page, selectors: string[]): Promise<void> {
  for (const sel of selectors) {
    const locator = page.locator(sel).first();
    // 30s, not the 5s default. This waits for mountApp's first paint, which is
    // fast on an idle machine (the whole test runs in ~1.4s) but was measured
    // missing a 5s deadline on a loaded one. The assertion still requires the
    // content to appear — it just stops a busy machine producing a red run that
    // says nothing about the page.
    await expect(locator, `expected content at ${sel}`).toBeVisible({ timeout: 30_000 });
    const text = (await locator.innerText()).trim();
    expect(text.length, `expected non-empty content at ${sel}`).toBeGreaterThan(0);
  }
}

/**
 * WCAG 2.1.1: a container that scrolls must be operable from the keyboard.
 *
 * A box with `overflow-x: auto` whose content is wider than it is can only be
 * panned with a mouse or a touch drag unless it is focusable itself or holds
 * something focusable to tab to — so a keyboard user simply cannot read the
 * part that is off-screen. These containers only overflow once real content is
 * in them, which is why nothing scanning the untouched page ever reports one.
 * Elements are returned with their measured dimensions so a failure says which
 * box and by how much.
 */
async function unreachableScrollers(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex],summary,[contenteditable]';
    const describe = (el: Element): string => {
      let s = el.tagName.toLowerCase();
      if (el.id) s += `#${el.id}`;
      const cls = el.getAttribute('class');
      if (cls) s += `.${cls.trim().split(/\s+/).join('.')}`;
      return s;
    };
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      if (typeof el.checkVisibility === 'function' && !el.checkVisibility()) continue;
      const cs = getComputedStyle(el);
      const scrollsX = /auto|scroll/.test(cs.overflowX) && el.scrollWidth > el.clientWidth + 1;
      const scrollsY = /auto|scroll/.test(cs.overflowY) && el.scrollHeight > el.clientHeight + 1;
      if (!scrollsX && !scrollsY) continue;
      // Reachable either because the box itself takes focus, or because it
      // contains something focusable that scrolling will follow.
      if (el.matches(FOCUSABLE) && (el as HTMLElement).tabIndex >= 0) continue;
      if (el.querySelector(FOCUSABLE)) continue;
      out.push(
        `${describe(el)} scrolls ${scrollsX ? `x ${el.scrollWidth}>${el.clientWidth}` : ''}${
          scrollsY ? ` y ${el.scrollHeight}>${el.clientHeight}` : ''
        } but is not keyboard reachable`
      );
    }
    return out;
  });
}

/** Expand every disclosure widget so nothing hidden escapes the scan. */
async function expandAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const details of Array.from(document.querySelectorAll('details'))) {
      (details as HTMLDetailsElement).open = true;
    }
  });
}

async function open(page: Page, theme: 'dark' | 'light'): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');
  await assertReducedMotion(page);
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  // #app ships empty; wait for the real first paint before believing anything.
  await expectRendered(page, [
    '.key-panel',
    '.scenario-buttons',
    '.token-strip',
    '.stack-view',
    '.matrix-table',
  ]);
  await expandAll(page);
  await settle(page);
}

async function scan(page: Page, label: string): Promise<void> {
  await settle(page);

  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary, `axe violations in state: ${label}`).toEqual([]);

  const failures = await auditContrast(page);
  expect(
    formatContrastFailures(failures),
    `measured contrast failures in state: ${label}`
  ).toEqual([]);

  expect(await unreachableScrollers(page), `keyboard-unreachable scrollers in state: ${label}`)
    .toEqual([]);
}

/** Pick a spend scenario by its visible title and wait for the re-render. */
async function pickScenario(page: Page, title: string): Promise<void> {
  await page.locator('.scenario-btn', { hasText: title }).click();
  await expect(page.locator('.scenario-btn.is-active')).toHaveText(title);
  await expandAll(page);
}

/** Run the current scenario to completion by dragging the scrubber to the end. */
async function runToVerdict(page: Page): Promise<void> {
  const scrubber = page.locator('.scrubber');
  const max = await scrubber.getAttribute('max');
  await scrubber.fill(String(max));
  await scrubber.dispatchEvent('input');
  await expect(page.locator('.verdict-head')).toBeVisible();
  await expandAll(page);
}

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations on first paint (${theme})`, async ({ page }) => {
    await open(page, theme);
    await scan(page, `${theme} / initial`);
  });

  test(`no WCAG A/AA violations mid-execution (${theme})`, async ({ page }) => {
    await open(page, theme);

    // One step: the stack gains its first item and the popped/pushed diff chips
    // appear. Neither exists on first paint.
    await page.locator('button', { hasText: 'Step ▶' }).click();
    await expectRendered(page, ['.stack-item', '.diff-chip', '.step-desc']);
    await expect(page.locator('.token.executed').first()).toBeVisible();
    await scan(page, `${theme} / one step executed`);

    // Halfway: several stack items, an active token, a later opcode's note.
    const scrubber = page.locator('.scrubber');
    const max = Number(await scrubber.getAttribute('max'));
    await scrubber.fill(String(Math.max(1, Math.floor(max / 2))));
    await scrubber.dispatchEvent('input');
    await expectRendered(page, ['.stack-item.top', '.token.active']);
    await scan(page, `${theme} / mid-execution`);
  });

  test(`no WCAG A/AA violations on the ACCEPT verdict (${theme})`, async ({ page }) => {
    await open(page, theme);
    await pickScenario(page, 'Valid spend');
    await runToVerdict(page);
    await expect(page.locator('.verdict-accept')).toBeVisible();
    await expectRendered(page, ['.verdict-accept', '.stack-item.is-true']);
    await scan(page, `${theme} / verdict ACCEPT`);
  });

  // Every rejecting scenario paints a different failure surface: a mismatched
  // HASH160 (auto-opened inspector, `.mismatch`), a red step-desc, the
  // verdict-reject panel with its reason line, and for `bad-der` the signature
  // decoder's parse-error branch, which has no other way of being reached.
  for (const title of [
    'Wrong public key',
    'Forged signature',
    'Tampered transaction',
    'High-S signature',
    'Malformed DER',
    'Swapped scriptSig order',
  ]) {
    test(`no WCAG A/AA violations on the REJECT verdict — ${title} (${theme})`, async ({
      page,
    }) => {
      await open(page, theme);
      await pickScenario(page, title);
      await runToVerdict(page);
      await expect(page.locator('.verdict-reject')).toBeVisible();
      await expectRendered(page, ['.verdict-reject', '.verdict-security']);
      await scan(page, `${theme} / verdict REJECT — ${title}`);
    });
  }

  test(`no WCAG A/AA violations in the advanced-input error state (${theme})`, async ({ page }) => {
    await open(page, theme);

    // A validation alert only ever exists after a user submits a bad value —
    // exactly the kind of rendered state a load-time-only scan cannot see.
    await page.locator('#adv-priv').fill('not-hex');
    await page.locator('button', { hasText: 'Apply' }).click();
    await expectRendered(page, ['.adv-err']);
    await scan(page, `${theme} / advanced input rejected`);

    // ...and the accepted path, which re-derives every key-panel row.
    await page.locator('#adv-priv').fill('0'.repeat(63) + '1');
    await page.locator('#adv-val').fill('50000');
    await page.locator('button', { hasText: 'Apply' }).click();
    await expect(page.locator('.adv-err')).toBeEmpty();
    await expect(page.locator('.kv-value').nth(2)).toHaveText(
      '751e76e8199196d454941c45d1b3a323f1433bd6'
    );
    await expandAll(page);
    await scan(page, `${theme} / advanced input accepted`);
  });

  test(`no WCAG A/AA violations while auto-run is playing (${theme})`, async ({ page }) => {
    await open(page, theme);

    // The auto-run button swaps its own class and label mid-flight; that paused
    // "⏸ Pause" state is a distinct surface nothing else scans.
    await page.locator('.speed-sel').selectOption('1400');
    await page.locator('button', { hasText: 'Auto-run' }).click();
    await expect(page.locator('button', { hasText: '⏸ Pause' })).toBeVisible();
    await expectRendered(page, ['.stack-item']);
    await scan(page, `${theme} / auto-run playing`);
  });
}

/**
 * The horizontal-scroll containers are the point of a narrow viewport, and they
 * do not overflow at the default 1280px — `#app` caps at 1080px and everything
 * fits. Checking keyboard reachability only at desktop width would be a check
 * that can never fail. So this drives the same rich state at phone width, where
 * the wide byte tables genuinely scroll.
 */
for (const theme of ['dark'] as const) {
  test(`scroll containers stay operable at narrow widths (${theme})`, async ({ page }) => {
    // Headroom for CPU contention, not because this scan is slow: run alone it
    // finishes in about 1.5s. It timed out at the 30s default only while other
    // suites were competing for the machine. Raising the ceiling costs nothing
    // when the test passes and avoids a red run that says nothing about the page.
    test.setTimeout(150_000);
    await page.setViewportSize({ width: 380, height: 780 });
    await open(page, theme);
    await pickScenario(page, 'Tampered transaction');
    await runToVerdict(page);
    await expectRendered(page, ['.verdict-reject', '.seg-table']);
    await scan(page, `${theme} / 380px wide, tampered verdict`);
  });
}

