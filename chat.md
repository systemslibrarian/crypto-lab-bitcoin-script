# What Would Make This Demo a 10/10

## Short Answer

Current score: **8.5/10**.

This is already a strong demo because it uses real secp256k1 ECDSA, HASH160, DER signatures, a real legacy `SIGHASH_ALL` preimage, and a small visible stack interpreter. To make it a 10/10, the next work should not replace the crypto. It should make the hidden internals inspectable, make the learning path faster, and let students test controlled variations without turning the page into a wallet or full node.

## Evidence From The Current Repo

01. The realism foundation is solid. The README claims real P2PKH, real `legacy SIGHASH_ALL`, real ECDSA, and a hand-rolled interpreter (`README.md:5`), and the core code backs that up with `sighashPreimage` (`src/engine.ts:156`), `signSighash` (`src/engine.ts:183`), and `checkSig` (`src/engine.ts:192`).

02. The scenario model is well chosen. The four scenarios separate the important failure modes: valid spend, wrong public key, forged signature, and tampered transaction (`src/scenario.ts:115`, `src/scenario.ts:133`, `src/scenario.ts:153`, `src/scenario.ts:173`).

03. The UI already has the right core loop: choose a scenario, inspect the transaction/script, step through tokens, view stack state, and get an accept/reject verdict (`src/ui.ts:201`, `src/ui.ts:262`, `src/ui.ts:301`, `src/ui.ts:434`).

04. The tests are meaningful, not decorative. They cover known key/HASH160 answers, DER round trips, sighash changes, sign/verify behavior, P2PK, all four P2PKH scenarios, the real UI stepper, and an axe-core accessibility gate (`tests/engine.test.ts:31`, `tests/engine.test.ts:46`, `tests/engine.test.ts:60`, `tests/engine.test.ts:81`, `tests/engine.test.ts:111`, `tests/ui.test.ts:17`, `tests/a11y.test.ts:19`).

05. Current validation passes. `npm test` passed 3 files / 20 tests. `npm run build` completed `tsc && vite build` successfully.

06. The biggest gap is inspectability. The app says what the signature commits to (`src/ui.ts:262`) and shows `scriptPubKey` bytes (`src/ui.ts:301`), but it does not yet let the learner inspect the full sighash preimage, DER signature fields, HASH160 pipeline, or original-vs-tampered byte diff.

07. There is one small semantics/copy polish item. The interpreter comment says validity requires "a single truthy value" (`src/script.ts:130`), and the UI says "leaves a single TRUE on top" (`src/ui.ts:83`), but the implementation accepts any non-aborted script with at least one truthy top stack item (`src/script.ts:248`). That can be fine if the intended teaching model is Bitcoin-like top-stack truthiness, but the copy and comment should match the implementation.

## Highest-Impact Upgrades

01. **Add a Sighash Inspector.**

Show the exact legacy `SIGHASH_ALL` preimage as an annotated byte table: version, input count, previous txid, vout, subscript length, subscript, sequence, output count, output value, output script, locktime, and hash type. Then show `SHA256(SHA256(preimage))` and the final 32-byte message signed by ECDSA.

Why this matters: the tampered transaction scenario currently teaches the claim correctly, but a 10/10 demo lets the student see precisely which byte changed and why the signature stops verifying.

Acceptance criteria:

- Valid and tampered scenarios show original preimage, verifier preimage, and resulting sighash.
- Changed fields are highlighted in the tampered scenario.
- Hex can be copied without wrapping destroying the structure.
- Tests assert that the displayed preimage and displayed sighash match `legacySighash`.

02. **Add a Signature Decoder.**

Decode the `scriptSig` signature into DER sequence, `r`, `s`, and the trailing `SIGHASH_ALL` byte. Show low-S status, hash-type interpretation, and the result of verifying `(r, s)` against the current sighash and public key.

Why this matters: students often see "signature" as a magic blob. Showing DER + hash type turns that blob into a Bitcoin-specific object they can reason about.

Acceptance criteria:

- Valid signature shows parsed `r`, `s`, low-S, `SIGHASH_ALL`, and verify = true.
- Forged signature shows well-formed signature bytes but verify = false against the owner public key.
- Malformed signature examples, if added, fail closed instead of throwing.

03. **Show the HASH160 Pipeline and Address Bridge.**

For the public key, show compressed pubkey -> SHA-256 -> RIPEMD-160 -> `pubKeyHash`. Optionally add Base58Check P2PKH address derivation from version byte + hash + checksum.

Why this matters: the demo is about `OP_HASH160 <pubKeyHash> OP_EQUALVERIFY`; a 10/10 version should make that equality visually undeniable.

Acceptance criteria:

- Wrong-key scenario shows attacker `HASH160(pubkey)` beside committed owner `pubKeyHash`.
- Valid/forged/tampered scenarios show the owner pubkey hash matching before `OP_CHECKSIG`.
- If Base58Check is added, include a known-answer test for privkey = 1 / address `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH`.

04. **Upgrade the Stepper Into a Reversible Trace.**

Keep the current `Step` and `Auto-run`, but add back/forward controls, a timeline scrubber, token click-to-jump, and before/after stack diffs that explicitly label "popped" and "pushed" values for each opcode.

Why this matters: the current stack visualizer is clear, but learners often need to replay the exact moment where a failure happens. Reversibility makes the demo feel more like an instrument than a slideshow.

Acceptance criteria:

- Student can jump to `OP_EQUALVERIFY` or `OP_CHECKSIG` directly.
- Each step shows consumed stack items, produced stack items, and remaining stack.
- Wrong-key scenario visibly stops before `OP_CHECKSIG`.
- Auto-run has speed control and remains keyboard-operable.

05. **Move the Core Interaction Earlier.**

The current section order is educational, but the core interaction appears after foundations and templates. A 10/10 demo should put the live transaction/script/stack experience immediately after the hero, then let foundations and context support it below or beside it.

Why this matters: demos earn attention by giving the user something meaningful to do fast. The explanation is good; the interactive proof should arrive sooner.

Acceptance criteria:

- First viewport signals the actual Bitcoin Script activity, not only introductory text.
- The scenario picker and first stack action are reachable with minimal scrolling on desktop.
- Mobile keeps the scenario picker, transaction summary, and stepper in a coherent order.

06. **Add Safe User-Controlled Inputs.**

Add an "advanced" drawer where users can paste or generate a private key, public key, signature, output value, or destination hash. Validate everything strictly and provide reset buttons for the known-good scenarios.

Why this matters: the original prompt asks for generated or input key pairs, while the current UI only regenerates keys (`src/ui.ts:231`). Controlled input turns passive observation into experimentation.

Acceptance criteria:

- Invalid private keys, malformed public keys, malformed DER signatures, unsupported hash types, and oversized pushes produce clear local errors.
- No secret is persisted to localStorage.
- Reset returns to the four canonical scenarios.
- Tests cover valid input, invalid input, and reset behavior.

07. **Add a Scenario Comparison Matrix.**

After the user runs one scenario, show a compact matrix for all four scenarios: offered key, signature source, transaction signed, transaction verified, first failing opcode, and final verdict.

Why this matters: the demo already has excellent scenario selection; the matrix would make the contrast stick in one glance.

Acceptance criteria:

- Valid spend: key match yes, signature match yes, verdict accept.
- Wrong public key: key match no, first failure `OP_EQUALVERIFY`, `OP_CHECKSIG` not reached.
- Forged signature: key match yes, signature match no, first failure `OP_CHECKSIG`.
- Tampered transaction: key match yes, signature valid for original sighash only, first failure `OP_CHECKSIG`.

08. **Tighten Bitcoin Semantics and Edge-Case Coverage.**

Do not build a full consensus engine, but add a small "edge cases" mode for the rules this demo already touches: malformed DER, high-S signature, unsupported sighash byte, malformed compressed public key, empty stack, wrong push order, extra stack item semantics, and invalid push lengths.

Why this matters: 10/10 educational demos show not only the happy path and the obvious attacks, but also the boundary where simplified teaching ends.

Acceptance criteria:

- The UI labels these as educational edge cases, not full-node validation.
- The code either aligns copy with top-stack truthiness or enforces the stated "single TRUE" model.
- Tests cover each edge case with fail-closed behavior.

09. **Raise the Visual Design From Solid to Memorable.**

The current design is readable and consistent, but it is card-heavy and prose-heavy. A 10/10 version should give the stack machine a stronger visual identity: a transaction strip feeding a script rail, tokens flowing into a stack column, and verdict states that feel like the natural endpoint of the execution.

Why this matters: the learner should remember the mental model after leaving the page: unlocking script pushes data, locking script checks it, stack ends truthy or fails.

Acceptance criteria:

- The visual hierarchy centers the script execution, not repeated panels.
- Long hex values use copyable, horizontally-scrollable displays where structure matters.
- Color is always paired with text/icon state.
- Desktop and mobile avoid overlapping text, layout jumps, and tiny controls.

10. **Strengthen Trust-Building Tests.**

The existing tests are already good. The 10/10 version should add tests for displayed inspector values, a real-world legacy sighash known vector if practical, malformed DER/high-S cases, advanced-input validation, scenario matrix claims, and a browser screenshot smoke test for desktop/mobile layout.

Why this matters: the demo's selling point is "real cryptography in the browser." The tests should prove every visible claim that a skeptical learner might check.

Acceptance criteria:

- `npm test` verifies core crypto, interpreter behavior, UI claims, accessibility, and inspector displays.
- `npm run build` stays clean.
- No backend, network call, telemetry, or key persistence is introduced.

## What Not To Add

01. Do not turn it into a wallet. No persistence, balances, real UTXOs, seed phrases, or broadcast flow.

02. Do not implement a full Bitcoin node or consensus engine. The demo should name its simplifications and keep the P2PKH path precise.

03. Do not make Taproot the main implementation. Keep Taproot as context unless this becomes a separate demo; otherwise it will blur the P2PKH teaching objective.

04. Do not hide the crypto behind a larger Bitcoin library. The current hand-rolled inspectable transaction/script path is the right educational choice.

## Suggested Build Order

01. **Phase 1: Inspectability.** Add sighash inspector, signature decoder, HASH160 pipeline, copy buttons, and tests for displayed values. This is the biggest quality jump.

02. **Phase 2: Interaction Depth.** Add reversible stepping, scenario comparison, token jump controls, and speed control.

03. **Phase 3: Controlled Experimentation.** Add advanced inputs and edge-case presets with strict validation.

04. **Phase 4: Presentation Polish.** Move the core interaction earlier, reduce card/prose density, and strengthen responsive visual storytelling.

## Definition Of 10/10

A student should be able to leave the page able to answer these questions from direct observation, not just text:

01. What exact bytes did the signature commit to?
02. Which byte or field changed in the tampered transaction?
03. Why does a wrong public key fail before signature verification?
04. Why does a forged signature pass the hash check but fail `OP_CHECKSIG`?
05. How does `HASH160(pubkey)` become the committed `pubKeyHash`?
06. What is inside the DER signature and what does the `SIGHASH_ALL` byte mean?
07. Which parts are real Bitcoin behavior, and which parts are educational simplifications?

If those answers are visible, test-backed, and easy to explore in under two minutes, this demo is a 10/10.