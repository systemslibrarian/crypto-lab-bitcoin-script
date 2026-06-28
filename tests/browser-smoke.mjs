// tests/browser-smoke.mjs — real-browser verification using the system Edge
// (no Chromium download). Run with: npm run test:browser  (it builds first).
//
// Asserts, against the actual rendered page:
//   * loads with no console/page errors
//   * single banner landmark, main landmark present, theme defaults to dark
//   * axe-core with color-contrast ENABLED → 0 serious/critical violations
//     at desktop width (jsdom can't measure contrast; a real browser can)
//   * no horizontal overflow at 375px (mobile) across several scenarios,
//     with the inspectors and the comparison matrix expanded
//
// Exits non-zero on any failure.

import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import puppeteer from 'puppeteer-core';

const require = createRequire(import.meta.url);
const AXE_PATH = require.resolve('axe-core/axe.min.js');

const EDGE = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const PORT = 4401;
const BASE = `http://localhost:${PORT}/crypto-lab-bitcoin-script/`;

const results = [];
const consoleErrors = [];
function assert(label, cond, detail = '') {
  results.push({ label, pass: !!cond, detail });
  console.log(`${cond ? 'pass' : 'FAIL'}  ${label}${detail ? '  — ' + detail : ''}`);
}

function startPreview() {
  const child = spawn('npx', ['vite', 'preview', '--port', String(PORT), '--strictPort'], {
    stdio: ['ignore', 'pipe', 'pipe'],
    shell: process.platform === 'win32',
  });
  return new Promise((resolve) => {
    let buf = '';
    const on = (d) => { buf += d.toString(); if (buf.includes(String(PORT))) resolve(child); };
    child.stdout.on('data', on);
    child.stderr.on('data', on);
    setTimeout(() => resolve(child), 6000);
  });
}

async function overflow(page) {
  return page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
}

async function main() {
  const preview = await startPreview();
  let browser;
  try {
    browser = await puppeteer.launch({ executablePath: EDGE, headless: true, args: ['--no-sandbox', '--disable-gpu'] });
    const page = await browser.newPage();
    page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text()); });
    page.on('pageerror', (e) => consoleErrors.push('pageerror: ' + e.message));

    await page.setViewport({ width: 1280, height: 900 });
    await page.goto(BASE, { waitUntil: 'networkidle2', timeout: 30000 });

    assert('H1 renders', !!(await page.$('h1')));
    const theme = await page.evaluate(() => document.documentElement.getAttribute('data-theme'));
    assert('Theme defaults to dark', theme === 'dark', `theme=${theme}`);
    const banners = await page.$$eval('[role="banner"]', (n) => n.length);
    assert('Exactly one banner landmark', banners === 1, `count=${banners}`);
    assert('Main landmark present', !!(await page.$('main#app')));
    assert('No console errors on load', consoleErrors.length === 0, consoleErrors.join(' | '));

    // expand every inspector + drive a scenario so dynamic content is on the page
    await page.evaluate(() => {
      document.querySelectorAll('details.inspector, details.advanced').forEach((d) => d.setAttribute('open', ''));
    });

    // ---- axe with color-contrast ENABLED ----
    await page.addScriptTag({ path: AXE_PATH });
    const axe = await page.evaluate(async () => {
      // eslint-disable-next-line no-undef
      return await axe.run(document, {
        runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] },
      });
    });
    const blocking = axe.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical');
    for (const v of blocking) {
      console.error(`AXE ${v.impact}: ${v.id} — ${v.help}`);
      for (const n of v.nodes.slice(0, 4)) console.error('   ', n.target, '|', (n.html || '').slice(0, 120));
    }
    assert('axe: 0 serious/critical (contrast enabled)', blocking.length === 0, `found ${blocking.length}`);

    // ---- mobile overflow at 375px across scenarios ----
    await page.setViewport({ width: 375, height: 820 });
    await page.reload({ waitUntil: 'networkidle2' });
    await page.evaluate(() => {
      document.querySelectorAll('details.inspector, details.advanced').forEach((d) => d.setAttribute('open', ''));
    });
    let worst = await overflow(page);
    const titles = ['Wrong public key', 'Forged signature', 'Tampered transaction', 'High-S', 'Malformed DER', 'Swapped'];
    for (const t of titles) {
      await page.evaluate((tt) => {
        const b = Array.from(document.querySelectorAll('.scenario-btn')).find((x) => x.textContent.includes(tt));
        if (b) b.click();
      }, t);
      await new Promise((r) => setTimeout(r, 60));
      worst = Math.max(worst, await overflow(page));
    }
    assert(`No horizontal overflow @375px (worst delta=${worst}px)`, worst <= 1, `${worst}px`);

    assert('No console errors during run', consoleErrors.length === 0, consoleErrors.join(' | '));
  } finally {
    if (browser) await browser.close();
    preview.kill();
  }

  const failed = results.filter((r) => !r.pass);
  console.log('\n----------------------------------------------');
  console.log(`${results.length - failed.length}/${results.length} checks passed.`);
  // Force exit — the spawned preview server otherwise keeps the event loop alive.
  process.exit(failed.length ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
