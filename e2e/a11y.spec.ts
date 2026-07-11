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

async function scan(page: Page): Promise<void> {
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
