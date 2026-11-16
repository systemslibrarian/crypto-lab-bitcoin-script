import './style.css';
import './extra.css';
import { mountApp } from './ui';
import { makeKeyPair, signSighash, checkSig, bytesToHex } from './engine';

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
  if (!(root instanceof HTMLElement)) throw new Error('#app root not found');
  mountApp(root);
  selfTest();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot, { once: true });
} else {
  boot();
}
