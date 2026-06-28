import './style.css';
import './extra.css';
import { mountApp } from './ui';
import { makeKeyPair, signSighash, checkSig, bytesToHex } from './engine';

const THEME_KEY = 'theme';

function applyTheme(theme: 'dark' | 'light'): void {
  document.documentElement.setAttribute('data-theme', theme);
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {
    /* storage may be disabled — ignore */
  }
  const toggle = document.getElementById('theme-toggle');
  if (toggle) {
    toggle.textContent = theme === 'dark' ? '🌙' : '☀️';
    toggle.setAttribute('aria-label', theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
  }
}

function currentTheme(): 'dark' | 'light' {
  return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
}

function wireThemeToggle(): void {
  applyTheme(currentTheme());
  const toggle = document.getElementById('theme-toggle');
  if (!toggle) return;
  toggle.addEventListener('click', () => applyTheme(currentTheme() === 'dark' ? 'light' : 'dark'));
}

function selfTest(): void {
  // eslint-disable-next-line no-console
  console.group('crypto-lab-bitcoin-script · self-test');
  try {
    // Known-answer: privkey = 1 → canonical compressed pubkey + HASH160
    // (the well-known address 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH).
    const one = new Uint8Array(32);
    one[31] = 1;
    const kp = makeKeyPair(one);
    const expectHash = '751e76e8199196d454941c45d1b3a323f1433bd6';
    console.log('privkey=1 HASH160 ===', bytesToHex(kp.pubKeyHash), '— expect', expectHash);
    if (bytesToHex(kp.pubKeyHash) !== expectHash) console.error('SELF-TEST FAIL: HASH160 mismatch');

    // Sign/verify round trip over a fixed sighash.
    const sighash = new Uint8Array(32).fill(0x42);
    const sig = signSighash(sighash, kp.priv);
    const ok = checkSig(sig, kp.pub, sighash);
    const bad = checkSig(sig, kp.pub, new Uint8Array(32).fill(0x43));
    console.log('OP_CHECKSIG valid ===', ok, '· tampered rejected ===', !bad);
    if (!ok || bad) console.error('SELF-TEST FAIL: OP_CHECKSIG predicate');
  } catch (err) {
    console.error('Self-test threw:', err);
  } finally {
    console.groupEnd();
  }
}

function boot(): void {
  const root = document.getElementById('app');
  if (!(root instanceof HTMLDivElement)) throw new Error('#app root not found');
  mountApp(root);
  wireThemeToggle();
  selfTest();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot, { once: true });
} else {
  boot();
}
