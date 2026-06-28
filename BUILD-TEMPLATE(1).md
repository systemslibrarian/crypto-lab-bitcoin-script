# BUILD TEMPLATE: crypto-lab-[DEMO-NAME]
## Reusable build prompt for a new Crypto Lab demo

This template produces a NEW Vite + TypeScript browser demo from scratch — the
cryptographic logic, UI, and in-demo content. A SEPARATE standardization prompt
(Parts 0 + A–E) is run AFTERWARD and owns the shared header, theme toggle, README,
GitHub Pages config, and scripture footer. This build prompt deliberately stops where
that one begins.

> HOW TO USE THIS TEMPLATE
> Fill only the seven `[FILL: …]` sections below (SCOPE, SECURITY/CORRECTNESS
> INVARIANTS, ARCHITECTURE, UI, VISUAL SEMANTICS, EDGE CASES, EXTENSION SEAMS).
> Leave everything else byte-for-byte. Then paste the filled result to Opus / Claude Code
> as the build prompt. Run the standardization prompt on the result.

---

## REPO (fill before building)

- **Repo name:** `crypto-lab-[demo-name]`
- **About / one-liner:** `[FILL: one sentence naming the primitive(s), what it demonstrates, "Real WebCrypto/real primitives, no backend." No marketing language.]`
- **Catalog category label:** `[FILL: e.g. Block Cipher / Cryptanalysis / Authentication Protocol]` (cross-tags: `[FILL or none]`)
- **Catalog card title:** `[FILL: short human name, e.g. JWT Forge]`
- **Tags (3–4):** `[FILL: e.g. JWS · alg:none · HS/RS Confusion · WebCrypto]`
- **Accent (`--accent`):** `[FILL: hex, an unused color from the palette that visually groups it near related demos]`
- **Favicon emoji (for the standardization pass to use):** `[FILL: one emoji]`

---

## BUILD PROMPT (everything below this line is what you paste to the model)

```
# BUILD: crypto-lab-[demo-name]
## [FILL: one-line description of the demo]

Build a new Vite + TypeScript browser demo from scratch for the Crypto Lab suite.
It ships as a static site to GitHub Pages with NO backend.

This prompt produces the demo's cryptographic logic, UI, and content ONLY. A SEPARATE
standardization prompt (Parts 0 + A–E) will afterward apply the shared header, theme
contract, README, Pages config, and scripture footer. Therefore in THIS pass:
- Do NOT hand-build a header, top bar, nav, or theme-toggle button.
- Do NOT write the final README or the in-page scripture footer.
- DO mount the app content at `id="app"`.
- DO define `--accent` on `:root` (value: [FILL: hex]). If light/dark palettes exist,
  define `--accent` in both.
Those two demo-side prerequisites are the only things the standardization pass needs
from you; everything else header/footer/README-related is its job, not this one.

---

## ANTI-HALLUCINATION / DISCIPLINE RULES
- Real primitives only. Use WebCrypto (SubtleCrypto) or a named, justified library for
  the actual cryptographic operations. Do NOT simulate or fake math. If a primitive is
  not available in WebCrypto, use a specific well-known library and say which.
- For the primitive that IS the teaching subject, hand-roll the inspectable parts rather
  than hiding them inside a library — transparency of internals is the point of the demo.
- No backend, no network calls, no telemetry. Everything runs in the browser.
- Any key/secret material is generated per-session in memory and never persisted.
- Follow the relevant specification exactly; do not invent structure. Spec(s):
  [FILL: RFC / FIPS / paper references, or "n/a — classical cipher"].
- If a correctness or security invariant below conflicts with a feature, the invariant wins.
- Write runnable tests (see TESTING) and actually run them. Do not claim behavior you
  did not execute.
- Read before you write; re-read after each change to confirm it landed.

---

## SCOPE
[FILL:
 - What's IN scope: the exact algorithms/attacks/variants to build.
 - NON-GOALS, stated explicitly so they aren't flagged as gaps. For each non-goal,
   build at most a one-line "what this isn't" note in the UI. Common non-goals:
   adjacent-but-separate primitives, brute-force/wordlist cracking, persistence.
]

---

## SECURITY / CORRECTNESS INVARIANTS (bake in from the first commit; load-bearing)
[FILL: a numbered list of the non-negotiable invariants this demo must embody in its
 ARCHITECTURE, not merely describe. For attack demos, include the fail-closed rules and
 the "correct vs deliberately-vulnerable" isolation. For non-attack demos, include the
 correctness invariants (test vectors must pass, constant-time where claimed, etc.).
 Examples of the shape:
 1. [The default/correct path rejects the unsafe case; no code path silently accepts it.]
 2. [The component is told what to expect by the app; it never trusts attacker-controlled
    input to select its own validation routine.]
 3. [Distinct types make the unsafe substitution impossible in the correct path.]
 4. [Strict parsing/decoding; lenient parsing is its own vuln class.]
 5. [Independent validation steps are reported independently, never collapsed.]
 6. [Any deliberately-broken "vulnerable" mode is an isolated, clearly-labeled module that
    can never be the default and is visibly marked as broken in the UI.]
]

---

## ARCHITECTURE
[FILL: the file/module layout. Keep the inspectable crypto in small, separately-testable
 modules. Typical shape:
 - src/[domain]/[primitive].ts        — the core algorithm
 - src/[domain]/types.ts              — branded/strict types
 - src/[domain]/[verify|attack].ts    — verification and/or attack modules
 - src/ui/                            — panels and controls
 - index.html                        — content mounts at id="app"; :root defines --accent;
                                        NO header/footer (standardization pass owns those)
]

---

## UI
[FILL: the panels/controls and the single core interaction that produces the "aha."
 State explicitly what the central metaphor or toggle is, and what the user does step by
 step. If there are scripted launchers (attacks, presets), define each one's setup +
 expected outcome. Note the <640px stacking behavior.]

---

## VISUAL SEMANTICS
[FILL: what success and failure (or correct vs broken) look like, precisely. If the demo
 inverts an intuition (e.g. a forged-but-accepted result must read as ALARM, not as a
 green success), spell that out — the model will get it wrong by default. Governing rule:
 color should track [FILL: system integrity / correctness / whatever the real lesson is],
 not the raw return value. Never convey state by color alone: always pair icon + text +
 color (WCAG 1.4.1); verify it survives grayscale and deuteranopia.]

---

## EDGE CASES (each: defined behavior + a teaching tooltip)
[FILL: enumerate the malformed/boundary inputs and the exact fail-closed behavior for
 each. Include parsing/encoding edge cases, missing/oversized/duplicate fields, and any
 spec-mandated rejections. Each should teach, not just guard.]

---

## TESTING
Add runnable tests (Vitest preferred) and confirm they pass before finishing. Cover:
[FILL: the specific properties to assert — round-trips, known test vectors from the spec,
 correct-path accepts the good case and rejects every bad case, vulnerable-path (if any)
 demonstrably exhibits the flaw so the demo's claim is backed by a passing test, and any
 independent-validation guarantees.]

---

## ACCESSIBILITY / MOBILE
- All interactive controls (launchers, toggles, inputs) keyboard-operable with visible
  focus rings.
- State conveyed by icon + text + color, never color alone.
- Long monospace/technical strings in a horizontally-scrollable box with a copy button
  rather than wrapped, when wrapping would destroy meaningful structure.
- Text inputs are real <textarea>/<input> with <label>, not contenteditable divs.
- Layout stacks cleanly below 640px.

---

## EXTENSION SEAMS (leave seams, don't build yet)
[FILL: the most likely future extension (e.g. a post-quantum variant, an additional
 attack, a harder parameter set) and the 1–3 places in the architecture that should be
 shaped now so adding it later is additive, not a rewrite. Add a short
 `// [extension] point` comment at each seam. Do not implement the extension in this pass.
 If no obvious extension exists, write "none planned."]

---

## DEFINITION OF DONE
- `npm run dev` serves the working demo locally.
- The core interaction works and produces the intended "aha."
- Tests pass (state the count and what they cover).
- Content mounts at `id="app"`; `:root` defines `--accent` = [FILL: hex].
- NO header, top bar, theme toggle, README, or scripture footer added here — those are
  applied by the Parts 0 + A–E standardization prompt next.

Report a one-line summary when done:
`✓ crypto-lab-[demo-name] — demo logic + UI + tests complete, ready for Parts 0 + A–E`
```

---

## PIPELINE (for your own reference — not part of the pasted prompt)

1. Fill the seven `[FILL]` sections + the REPO block above.
2. Create the GitHub repo with the name, About one-liner.
3. Paste the filled BUILD PROMPT to Opus / Claude Code → working demo.
4. Run the existing **Parts 0 + A–E standardization prompt** on the result (header,
   theme, README, Pages config, footer, head/favicon).
5. Add the catalog card (title, tags, accent) to the `crypto-lab` index.
6. Deploy and verify the live URL.

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
