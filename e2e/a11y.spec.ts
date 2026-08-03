import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the self-test / smoke
 * vectors; this gates them on accessibility the same way. Scans the full page
 * with every collapsible expanded, in both themes.
 *
 * This lab has no <details>; its content is a step-through stack machine that
 * is always visible. We still expand any <details> defensively and reveal
 * class-toggled panels so nothing hidden escapes the scan.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function expandAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const details of document.querySelectorAll('details')) {
      (details as HTMLDetailsElement).open = true;
    }
    // Reveal any class-toggled collapsibles so their content is scanned.
    for (const el of document.querySelectorAll(
      '.accordion, .collapsible, .explainer, .step, .panel'
    )) {
      el.classList.add('open', 'active', 'is-open', 'expanded');
    }
  });
}

/**
 * Drive every in-flight animation and transition to its end state, then wait
 * for the compositor to agree, so axe samples final colours rather than tween
 * frames.
 *
 * `.token` carries `transition: background 0.15s ease, color 0.15s ease`, and
 * the theme toggle repaints `--panel` / `--ink-soft` underneath it, so flipping
 * the theme ramps the whole token rail over 150ms. axe reads *computed* colours
 * at the instant it runs; scanning without settling first measures half-faded
 * text and reports colour-contrast violations against pixels no user ever sits
 * and reads (the failure names `button[aria-label="Jump to step 1: <sig>"]` and
 * friends, and moves around between runs). Settled, both themes are clean, so
 * this is not masking a real violation — it removes the sampling race so the
 * gate measures the state the page actually rests in.
 */
async function settle(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{
      animation-duration:0s!important;animation-delay:0s!important;
      transition-duration:0s!important;transition-delay:0s!important;
      scroll-behavior:auto!important;
    }`,
  });
  await page.evaluate(async () => {
    await Promise.all(
      document.getAnimations().map((a) => a.finished.catch(() => undefined)),
    );
  });
}

async function scan(page: Page): Promise<void> {
  await settle(page);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await expandAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await expandAll(page);
  await scan(page);
});
