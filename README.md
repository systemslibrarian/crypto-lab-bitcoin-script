# crypto-lab-bitcoin-script

## What It Is

An interactive model of **Bitcoin Script** — the tiny, stack-based language that defines who is allowed to spend each bitcoin — using **real cryptography in the browser**. The page composes the audited [`@noble/secp256k1`](https://github.com/paulmillr/noble-secp256k1) and [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) libraries to build a genuine **Pay-to-Public-Key-Hash (P2PKH)** spend end to end: a secp256k1 key pair, a HASH160 (SHA-256 → RIPEMD-160) commitment in the locking script, a real **legacy SIGHASH_ALL** preimage over a concrete one-input/one-output transaction, an **ECDSA** signature (low-S, DER-encoded) in the unlocking script, and a hand-rolled stack interpreter that executes `OP_DUP · OP_HASH160 · OP_EQUALVERIFY · OP_CHECKSIG` one step at a time. Nothing is faked: the signature math, the hashes, and the sighash are all the real thing, validated at boot against the textbook privkey = 1 key whose HASH160 is `751e76e8199196d454941c45d1b3a323f1433bd6` (address `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH`). Keys are generated per session in memory and never persisted — this is **for education only**.

## When to Use It

- **Connecting digital signatures to how Bitcoin actually works** — students who have seen ECDSA in isolation can watch a signature get *checked by a script* to release funds, closing the gap between "I understand signatures" and "I understand spending conditions".
- **Teaching the stack machine concretely** — step through a real P2PKH script and see each opcode push and pop a shared stack, rather than reading the opcodes as abstract names.
- **Showing why bad spends are rejected** — flip between a valid spend, a wrong public key, a forged signature, and a tampered transaction, and see exactly *where* and *why* each invalid attempt fails.
- **Motivating the move to Taproot** — the page frames P2PK → P2PKH → P2TR so the trade-offs (key exposure, size, privacy) are visible.
- **Do NOT treat this as a wallet, a node, or a consensus implementation.** It models the single-signature P2PKH path for teaching; it does not validate full transactions, enforce every consensus rule, or handle multisig/timelocks/Taproot key tweaks.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-bitcoin-script](https://systemslibrarian.github.io/crypto-lab-bitcoin-script/)**

A coin is locked to an owner's `pubKeyHash`. Pick one of four spend scenarios — **Valid spend**, **Wrong public key**, **Forged signature**, or **Tampered transaction** — and the page assembles the matching `scriptSig` (unlock) and `scriptPubKey` (lock), signs (or mis-signs) a real transaction, and shows the resulting stack program. Then **Step ▶** (or **Auto-run**) walks the execution: the token strip highlights the current opcode while the stack grows and shrinks beside a plain-language description of each step, ending in an **ACCEPT** or **REJECT** verdict. Three of the four scenarios reject — and each rejection is the security model working: the wrong key aborts at `OP_EQUALVERIFY` before the signature is even checked, while the forged signature and the tampered transaction both fail at `OP_CHECKSIG`. **⟳ New keys** regenerates the key pair; the page is dark by default with a theme toggle that persists across visits.

## What Can Go Wrong

- **A browser is not a vault:** keys generated in a web tab can be exposed by malicious extensions, cross-site scripting, or clipboard sniffers — never put real funds behind a browser-generated key.
- **Script reveals the public key on spend:** P2PKH hides the key behind a hash until spending, but once spent the key is public; reusing addresses then erodes privacy and (theoretically) quantum resistance.
- **Signatures only commit to what the sighash covers:** the "tampered transaction" scenario shows that changing a signed field breaks the signature — but the flip side is that *un*signed fields (e.g. legacy malleability of the scriptSig) historically caused real bugs.
- **Historical foot-guns are real:** `OP_CHECKMULTISIG`'s off-by-one stack pop and an early value-overflow bug are reminders that even a deliberately small language is not bug-free.
- **This is not consensus-complete:** a real node enforces dozens of additional rules (script size limits, standardness, low-S/strict-DER policy, sequence/locktime semantics) that this teaching model does not.

## Real-World Usage

- P2PKH (`OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG`) secured the majority of historical Bitcoin transactions and is still widely seen on-chain.
- secp256k1 ECDSA with DER-encoded signatures and a SIGHASH byte is the exact signature format that appears inside real Bitcoin `scriptSig`/witness data.
- The same stack machine scales to richer conditions: multisig (`OP_CHECKMULTISIG`), timelocks (`OP_CHECKLOCKTIMEVERIFY` / `OP_CHECKSEQUENCEVERIFY`), and Lightning Network HTLCs.
- Taproot (P2TR) replaces this pattern for new outputs with Schnorr signatures and key aggregation, improving privacy and efficiency for the common cooperative case.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-bitcoin-script
cd crypto-lab-bitcoin-script
npm install
npm run dev
```

No environment variables, no API keys, no servers — everything runs client-side. The build bundles `@noble/secp256k1` and `@noble/hashes` into a single static JS file deployed straight to GitHub Pages, with no remote services and no telemetry. Additional scripts: `npm run build` (tsc + production build to `dist/`), `npm run preview` (serve the built `dist/` locally), and `npm test` (Vitest: engine known-answers, a jsdom run that drives the real stepper, and an axe-core WCAG 2 A/AA gate).

## Related Demos

- [crypto-lab-bitcoin-wallet](https://systemslibrarian.github.io/crypto-lab-bitcoin-wallet/) — keys → P2PKH/P2WPKH addresses, BIP-39 mnemonics, and BIP-32 HD derivation: where the keys this script checks come from.
- [crypto-lab-ecdsa-forge](https://systemslibrarian.github.io/crypto-lab-ecdsa-forge/) — secp256k1 ECDSA signing, RFC-6979 nonces, and nonce-reuse key recovery up close.
- [crypto-lab-ec-point-arithmetic](https://systemslibrarian.github.io/crypto-lab-ec-point-arithmetic/) — point addition and scalar multiplication, the group law under the curve.
- [crypto-lab-hash-zoo](https://systemslibrarian.github.io/crypto-lab-hash-zoo/) — the hash families (SHA-256, RIPEMD-160) behind HASH160 and the sighash.
- [crypto-lab-ed25519-forge](https://systemslibrarian.github.io/crypto-lab-ed25519-forge/) — a different signature scheme, for contrast with ECDSA.

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
