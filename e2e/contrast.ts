import type { Page } from '@playwright/test';

/**
 * Composite-aware WCAG 1.4.3 contrast measurement.
 *
 * This exists because axe is not a complete contrast oracle. When an element's
 * background is a gradient, axe reports the node as "incomplete" and it never
 * reaches the violations array the gate asserts on — so a control painted with
 * `linear-gradient(...)` is, as far as the gate is concerned, unchecked. axe
 * also under-reports plain cases: given two sibling elements both below AA it
 * has been observed to name exactly one.
 *
 * So: walk every element that owns text, composite the real painted background
 * (translucent layers included, gradient stops enumerated), and compute the
 * ratio against the surface the text is actually drawn on rather than against
 * white. A gradient is judged at its worst stop.
 */

export interface ContrastFailure {
  selector: string;
  text: string;
  foreground: string;
  background: string;
  fontSize: number;
  fontWeight: number;
  required: number;
  ratio: number;
}

export async function auditContrast(page: Page): Promise<ContrastFailure[]> {
  return page.evaluate(() => {
    interface RGBA {
      r: number;
      g: number;
      b: number;
      a: number;
    }

    const parse = (c: string): RGBA | null => {
      const m = c.match(/rgba?\(([^)]+)\)/);
      if (!m) return null;
      const p = m[1]
        .split(/[ ,/]+/)
        .filter(Boolean)
        .map(Number);
      if (p.length < 3 || p.some((n) => Number.isNaN(n))) return null;
      return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 };
    };

    const over = (fg: RGBA, bg: RGBA): RGBA => ({
      r: fg.r * fg.a + bg.r * (1 - fg.a),
      g: fg.g * fg.a + bg.g * (1 - fg.a),
      b: fg.b * fg.a + bg.b * (1 - fg.a),
      a: 1,
    });

    const luminance = (c: RGBA): number => {
      const f = (v: number): number => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
      };
      return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
    };

    const ratio = (a: RGBA, b: RGBA): number => {
      const l1 = luminance(a);
      const l2 = luminance(b);
      return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
    };

    const gradientStops = (cs: CSSStyleDeclaration): RGBA[] | null => {
      const bi = cs.backgroundImage;
      if (!bi || bi === 'none' || !/gradient/.test(bi)) return null;
      const cols = bi.match(/rgba?\([^)]+\)/g);
      if (!cols) return null;
      const stops = cols.map(parse).filter((c): c is RGBA => c !== null && c.a > 0);
      return stops.length ? stops : null;
    };

    /**
     * Every opaque background this element could actually be painted on. A
     * gradient host contributes one candidate per colour stop, so a gradient is
     * judged at its worst point rather than at an average that renders nowhere.
     */
    const effectiveBackgrounds = (el: Element): RGBA[] => {
      const layers: { color: RGBA | null; grad: RGBA[] | null }[] = [];
      let n: Element | null = el;
      while (n) {
        const cs = getComputedStyle(n);
        const grad = gradientStops(cs);
        const bg = parse(cs.backgroundColor);
        const opaqueColor = bg && bg.a > 0 ? bg : null;
        if (grad || opaqueColor) layers.push({ color: opaqueColor, grad });
        if (!grad && bg && bg.a >= 1) break;
        n = n.parentElement;
      }
      let bases: RGBA[] = [{ r: 255, g: 255, b: 255, a: 1 }];
      for (let i = layers.length - 1; i >= 0; i--) {
        const { color, grad } = layers[i];
        let next = bases;
        if (color) next = next.map((b) => over(color, b));
        if (grad) {
          const expanded: RGBA[] = [];
          for (const b of next) for (const g of grad) expanded.push(g.a >= 1 ? g : over(g, b));
          next = expanded;
        }
        bases = next;
      }
      return bases;
    };

    /**
     * Only measure text the browser is actually painting.
     *
     * The display/visibility/rect triple is not sufficient on its own. Content
     * inside a closed `<details>` reports `display: block`, `visibility:
     * visible` and a full-size bounding rect, yet is not rendered — Chromium
     * skips style updates for it, so `getComputedStyle` hands back whatever the
     * colours were the last time it *was* rendered. Auditing that measures a
     * frame nobody ever saw: it invented light-theme ink over dark-theme panels
     * at 1.08:1 after a theme swap, and it would just as happily pass a real
     * failure inside a collapsed panel by pairing it with a stale background.
     *
     * `checkVisibility()` accounts for this (it returns false for the closed
     * `<details>` case), so it is the authority and the rest is a backstop.
     */
    const isVisible = (el: Element): boolean => {
      if (typeof el.checkVisibility === 'function' && !el.checkVisibility()) return false;
      const cs = getComputedStyle(el);
      if (cs.display === 'none' || cs.visibility === 'hidden') return false;
      if (parseFloat(cs.opacity) === 0) return false;
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    };

    const ownText = (el: Element): string => {
      let t = '';
      for (const n of Array.from(el.childNodes)) {
        if (n.nodeType === Node.TEXT_NODE) t += n.textContent ?? '';
      }
      return t.trim();
    };

    const describe = (el: Element): string => {
      let s = el.tagName.toLowerCase();
      if (el.id) s += `#${el.id}`;
      const cls = el.getAttribute('class');
      if (cls) s += `.${cls.trim().split(/\s+/).join('.')}`;
      return s;
    };

    const failures: unknown[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const text = ownText(el);
      if (!text) continue;
      if (!isVisible(el)) continue;

      const cs = getComputedStyle(el);
      const fgRaw = parse(cs.color);
      if (!fgRaw) continue;

      const size = parseFloat(cs.fontSize);
      const weight = parseInt(cs.fontWeight, 10) || 400;
      const large = size >= 24 || (size >= 18.66 && weight >= 700);
      const required = large ? 3 : 4.5;

      let worst: { r: number; bg: RGBA } | null = null;
      for (const bg of effectiveBackgrounds(el)) {
        const fg = fgRaw.a < 1 ? over(fgRaw, bg) : fgRaw;
        const r = ratio(fg, bg);
        if (!worst || r < worst.r) worst = { r, bg };
      }
      if (!worst) continue;

      // Round to 2dp before comparing so a value that is exactly on the floor
      // (e.g. 4.50) is not failed by float noise, and one just under it is not
      // rounded up into a pass.
      const rounded = Math.round(worst.r * 100) / 100;
      if (rounded >= required) continue;

      failures.push({
        selector: describe(el),
        text: text.slice(0, 60),
        foreground: cs.color,
        background: `rgb(${[worst.bg.r, worst.bg.g, worst.bg.b]
          .map((v) => Math.round(v))
          .join(', ')})`,
        fontSize: size,
        fontWeight: weight,
        required,
        ratio: rounded,
      });
    }
    return failures as never;
  });
}

/** Render failures as short strings so an assertion diff is readable. */
export function formatContrastFailures(failures: ContrastFailure[]): string[] {
  return failures.map(
    (f) =>
      `${f.ratio}:1 (needs ${f.required}:1) ${f.selector} — fg ${f.foreground} on ${f.background} — "${f.text}"`
  );
}
