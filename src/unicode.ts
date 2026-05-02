/**
 * Unicode strip + normalization. Strip-set inventory + threat coverage: see
 * [[spec-api §1]] and CHANGELOG. This file documents only what the code
 * cannot show by itself.
 *
 * **Pipeline order is load-bearing:**
 *
 *   ANSI → orphan-surrogate → NFKC → strip-set → VS context → ZWJ context → mark cap → NFKC final
 *
 *   - First NFKC decomposes mathematical-bold and fullwidth forms before the
 *     strip-set check ⇒ catches homoglyph and fullwidth-delimiter forging.
 *   - VS-context runs BEFORE ZWJ-context so an orphan VS-16 cannot mislead
 *     the ZWJ check into preserving an otherwise-orphan ZWJ (M3.6 fix).
 *   - Final NFKC re-canonicalizes sequences exposed by intervening strips
 *     (e.g. `a + ZWSP + ́` → `a + ́` after ZWSP strip → `á` after final NFKC).
 *     Closes `pipeline(pipeline(x)) = pipeline(x)` idempotency that streaming
 *     relies on; prevents NFKC-composition bypass via stripped blockers.
 *
 * **Other invariants:**
 *
 *   - Codepoint iteration via `[...text]`, NOT `split('')` — surrogate-pair
 *     safety in ZWJ / VS / combining-mark passes.
 *   - Combining-mark counter resets on every non-mark codepoint, NOT on
 *     grapheme boundary — Zalgo defense.
 *   - NFKC is same-script-only ⇒ Cyrillic preservation is correct, not a
 *     leak. Cross-script homoglyphs are v0.2.
 *   - NFKC compatibility-decomposes NBSP (U+00A0) → regular space (U+0020).
 */

import type { Finding, Severity, UnicodeStripFinding } from './findings.js';
import {
  DEFAULT_POLICY,
  type Policy,
  type SanitizeOptions,
  type SanitizeResult,
  type UnicodeCategory
} from './policy.js';

/**
 * Char-class fragment per `UnicodeCategory`. `null` ⇒ sequence-shaped matcher
 * (handled by a dedicated function, not the union regex). `\u{...}` brace
 * escapes ⇒ file stays free of literal control bytes (transport-safe) and the
 * same source drives both strip (`g`) and membership test.
 *
 * v0.1 conflations: ZWJ U+200D gated by `zero-width`; BMP VS U+FE00-U+FE0F
 * folded into `supplementary-variation-selectors`. Cleaner split is v0.2.
 */
const CATEGORY_SOURCES: Record<UnicodeCategory, string | null> = {
  'tags-block': '\\u{E0001}-\\u{E007F}',
  'zero-width': '\\u200B-\\u200C\\u2060\\uFEFF',
  'bidi-override': '\\u202A-\\u202E\\u2066-\\u2069',
  'mongolian-fvs': '\\u180B-\\u180F',
  'interlinear-annotations': '\\uFFF9-\\uFFFB',
  'object-replacement': '\\uFFFC',
  'supplementary-pua': '\\u{F0000}-\\u{FFFFD}\\u{100000}-\\u{10FFFD}',
  'supplementary-variation-selectors': '\\u{E0100}-\\u{E01EF}',
  'soft-hyphen-fillers': '\\u00AD\\u034F\\u115F\\u1160',
  'math-invisibles': '\\u2061-\\u2064',
  'c0-c1-controls': '\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F-\\u009F',
  'orphaned-surrogates': null,
  'ansi-escapes': null
};

/** Default policy hits the same key every call; custom policies pay one compile per unique category set. */
const CATEGORY_REGEX_CACHE = new Map<string, { test: RegExp; strip: RegExp }>();

function buildStripRegexes(
  categories: ReadonlySet<UnicodeCategory>
): { test: RegExp; strip: RegExp } | null {
  const sorted = [...categories].filter((c) => CATEGORY_SOURCES[c] !== null).sort();
  if (sorted.length === 0) return null;

  const key = sorted.join('|');
  const cached = CATEGORY_REGEX_CACHE.get(key);
  if (cached !== undefined) return cached;

  const klass = `[${sorted.map((c) => CATEGORY_SOURCES[c]).join('')}]`;
  const compiled = {
    test: new RegExp(klass, 'u'),
    strip: new RegExp(klass, 'gu')
  };
  CATEGORY_REGEX_CACHE.set(key, compiled);
  return compiled;
}

/** Pure ASCII is by definition already NFKC. */
// biome-ignore lint/suspicious/noControlCharactersInRegex: NUL-DEL is the deliberate ASCII range
const ASCII_ONLY = /^[\x00-\x7F]*$/;

const EMOJI_RE = /\p{Extended_Pictographic}/u;

const VS_RE = /[︀-️]/u;

/**
 * CSI: `ESC [ <param 0x30-0x3F>* <intermediate 0x20-0x2F>* <final 0x40-0x7E>`.
 * Covers SGR, cursor, mode-set/reset. Stray ESC outside CSI is
 * caught by the C0 strip in stripUnconditional ( is in U+0000-U+001F).
 */
// biome-ignore lint/suspicious/noControlCharactersInRegex: ESC byte is intentional
const ANSI_ESCAPE = /\[[0-?]*[ -/]*[@-~]/g;

const DEFAULT_COMBINING_MARK_CAP = 4;

/**
 * @example
 *   stripAnsiEscapes('[31mhello[0m') // 'hello'
 */
export function stripAnsiEscapes(text: string): string {
  // No ESC ⇒ no CSI match possible; skip regex pass.
  if (text.indexOf('') === -1) return text;
  return text.replace(ANSI_ESCAPE, '');
}

/**
 * Walks code units (NOT codepoints) — codepoint iteration silently drops orphans.
 * Orphan surrogates can bypass codepoint-iteration sanitizers and recombine into
 * Tags-block characters in UTF-16-internal runtimes (Node, browsers).
 */
export function stripOrphanedSurrogates(text: string): string {
  if (!/[\uD800-\uDFFF]/.test(text)) return text;

  let result = '';
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (i + 1 < text.length) {
        const next = text.charCodeAt(i + 1);
        if (next >= 0xdc00 && next <= 0xdfff) {
          result += text.slice(i, i + 2);
          i++;
        }
        // else: orphan high — strip (do not append)
      }
      // else: orphan high at end — strip
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      // orphan low (no preceding high) — strip
    } else {
      result += text[i];
    }
  }
  return result;
}

/**
 * Identity preserved by ASCII fast-path + post-normalize `===` fallback for
 * cross-engine correctness (V8 optimizes the no-op case; the spec doesn't).
 */
export function normalizeNFKC(text: string): string {
  if (ASCII_ONLY.test(text)) return text;
  const out = text.normalize('NFKC');
  return out === text ? text : out;
}

/** Single union regex per category set; non-global membership pre-test preserves identity by reference. */
function stripUnconditional(text: string, categories: ReadonlySet<UnicodeCategory>): string {
  const regexes = buildStripRegexes(categories);
  if (regexes === null) return text;
  if (!regexes.test.test(text)) return text;
  return text.replace(regexes.strip, '');
}

/** Strip ZWJ (U+200D) unless between emoji codepoints. */
function stripNonEmojiZwj(text: string): string {
  if (text.indexOf('‍') === -1) return text;

  const chars = [...text];
  const result: string[] = [];

  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i] as string;
    if (ch === '‍') {
      const before = chars[i - 1];
      const after = chars[i + 1];
      const beforeIsEmoji = before !== undefined && (EMOJI_RE.test(before) || VS_RE.test(before));
      const afterIsEmoji = after !== undefined && EMOJI_RE.test(after);
      if (beforeIsEmoji && afterIsEmoji) {
        result.push(ch);
      }
      // else: strip
    } else {
      result.push(ch);
    }
  }

  return result.join('');
}

/** Strip variation selectors (U+FE00-U+FE0F) unless they follow an emoji codepoint. */
function stripNonEmojiVariationSelectors(text: string): string {
  if (!VS_RE.test(text)) return text;

  const chars = [...text];
  const result: string[] = [];

  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i] as string;
    if (VS_RE.test(ch)) {
      const before = chars[i - 1];
      if (before !== undefined && EMOJI_RE.test(before)) {
        result.push(ch);
      }
      // else: strip
    } else {
      result.push(ch);
    }
  }

  return result.join('');
}

/** Counter resets on every non-mark codepoint, NOT on grapheme boundary — load-bearing for Zalgo defense. */
export function capCombiningMarks(text: string, cap: number = DEFAULT_COMBINING_MARK_CAP): string {
  if (!/\p{Mark}/u.test(text)) return text;

  const chars = [...text];
  const result: string[] = [];
  let markCount = 0;

  for (const char of chars) {
    if (/\p{Mark}/u.test(char)) {
      markCount++;
      if (markCount <= cap) {
        result.push(char);
      }
    } else {
      markCount = 0;
      result.push(char);
    }
  }

  return result.join('');
}

/** `Finding.charClass` label per category. */
const CATEGORY_CHAR_CLASS: Record<UnicodeCategory, string> = {
  'tags-block': 'U+E0001-U+E007F',
  'zero-width': 'U+200B,U+200C,U+200D,U+2060,U+FEFF',
  'bidi-override': 'U+202A-U+202E,U+2066-U+2069',
  'mongolian-fvs': 'U+180B-U+180F',
  'interlinear-annotations': 'U+FFF9-U+FFFB',
  'object-replacement': 'U+FFFC',
  'supplementary-pua': 'U+F0000-U+FFFFD,U+100000-U+10FFFD',
  'supplementary-variation-selectors': 'U+FE00-U+FE0F,U+E0100-U+E01EF',
  'soft-hyphen-fillers': 'U+00AD,U+034F,U+115F,U+1160',
  'math-invisibles': 'U+2061-U+2064',
  'c0-c1-controls': 'U+0000-U+0008,U+000B,U+000C,U+000E-U+001F,U+007F-U+009F',
  'orphaned-surrogates': 'U+D800-U+DFFF',
  'ansi-escapes': 'CSI'
};

const CATEGORY_DEFAULT_SEVERITY: Record<UnicodeCategory, Severity> = {
  'tags-block': 'high',
  'bidi-override': 'high',
  'orphaned-surrogates': 'high',
  'ansi-escapes': 'high',
  'c0-c1-controls': 'high',
  'zero-width': 'medium',
  'mongolian-fvs': 'medium',
  'interlinear-annotations': 'medium',
  'object-replacement': 'medium',
  'supplementary-pua': 'medium',
  'supplementary-variation-selectors': 'medium',
  'soft-hyphen-fillers': 'medium',
  'math-invisibles': 'medium'
};

const ZALGO_CAP_RULE_ID = 'zalgo-cap';
const ZALGO_CAP_DEFAULT_SEVERITY: Severity = 'medium';
const ZALGO_CAP_CHAR_CLASS = '\\p{Mark}';
const FINDING_RULE_VERSION = 1;

/** `findings === null` ⇒ non-Detailed mode (no array allocated). `shouldEmit` gate keeps the silent path a single `replace()`. */
type EmitContext = Readonly<{
  findings: Finding[] | null;
  onFinding: ((f: Finding) => void) | undefined;
  policy: Policy;
}>;

function shouldEmit(ctx: EmitContext): boolean {
  return ctx.findings !== null || ctx.onFinding !== undefined;
}

function emit(ctx: EmitContext, finding: Finding): void {
  if (ctx.findings !== null) ctx.findings.push(finding);
  ctx.onFinding?.(finding);
}

function effectiveSeverity(ruleId: string, fallback: Severity, policy: Policy): Severity {
  return policy.severityOverrides[ruleId] ?? fallback;
}

function makeUnicodeStrip(
  ruleId: string,
  offset: number,
  length: number,
  charClass: string,
  count: number,
  severity: Severity
): UnicodeStripFinding {
  return Object.freeze({
    kind: 'unicode-strip' as const,
    ruleId,
    ruleVersion: FINDING_RULE_VERSION,
    action: 'stripped' as const,
    offset,
    length,
    charClass,
    count,
    severity
  });
}

/** Batches contiguous matches into single findings. Caller does the membership pre-check. */
function applyRegexStripWithFindings(
  text: string,
  regex: RegExp,
  ruleId: string,
  charClass: string,
  severity: Severity,
  ctx: EmitContext
): string {
  let out = '';
  let lastEnd = 0;
  let runStart = -1;
  let runEnd = -1;
  let runCount = 0;

  for (const m of text.matchAll(regex)) {
    const start = m.index ?? 0;
    const end = start + m[0].length;

    out += text.slice(lastEnd, start);
    lastEnd = end;

    if (start === runEnd) {
      runEnd = end;
      runCount++;
    } else {
      if (runCount > 0) {
        emit(
          ctx,
          makeUnicodeStrip(ruleId, runStart, runEnd - runStart, charClass, runCount, severity)
        );
      }
      runStart = start;
      runEnd = end;
      runCount = 1;
    }
  }

  if (runCount > 0) {
    emit(ctx, makeUnicodeStrip(ruleId, runStart, runEnd - runStart, charClass, runCount, severity));
  }

  out += text.slice(lastEnd);
  return out;
}

/** Per-category strip with finding emission. Compiles + caches under `:single:<cat>` key. */
function stripOneCategoryWithFindings(
  text: string,
  cat: UnicodeCategory,
  ctx: EmitContext
): string {
  const src = CATEGORY_SOURCES[cat];
  if (src === null) return text;

  const cacheK = `:single:${cat}`;
  let pair = CATEGORY_REGEX_CACHE.get(cacheK);
  if (pair === undefined) {
    const klass = `[${src}]`;
    pair = { test: new RegExp(klass, 'u'), strip: new RegExp(klass, 'gu') };
    CATEGORY_REGEX_CACHE.set(cacheK, pair);
  }

  if (!pair.test.test(text)) return text;

  const charClass = CATEGORY_CHAR_CLASS[cat];
  const severity = effectiveSeverity(cat, CATEGORY_DEFAULT_SEVERITY[cat], ctx.policy);
  return applyRegexStripWithFindings(text, pair.strip, cat, charClass, severity, ctx);
}

/** Per-category passes so findings carry precise category-level ruleId. Silent mode still uses the union regex. */
function stripStripSetCategoriesWithFindings(text: string, ctx: EmitContext): string {
  let result = text;
  for (const cat of ctx.policy.unicode.categories) {
    if (CATEGORY_SOURCES[cat] === null) continue;
    result = stripOneCategoryWithFindings(result, cat, ctx);
  }
  return result;
}

function stripAnsiEscapesWithFindings(text: string, ctx: EmitContext): string {
  if (text.indexOf('') === -1) return text;
  const ruleId: UnicodeCategory = 'ansi-escapes';
  const severity = effectiveSeverity(ruleId, CATEGORY_DEFAULT_SEVERITY[ruleId], ctx.policy);
  return applyRegexStripWithFindings(
    text,
    ANSI_ESCAPE,
    ruleId,
    CATEGORY_CHAR_CLASS[ruleId],
    severity,
    ctx
  );
}

/** v0.1: aggregate finding (`count = N`, `length = 0`, `offset = firstStripIndex`) — distributed strips don't form a contiguous span. */
function stripOrphanedSurrogatesWithFindings(text: string, ctx: EmitContext): string {
  if (!/[\uD800-\uDFFF]/.test(text)) return text;

  let result = '';
  let stripped = 0;
  let firstOffset = -1;

  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (i + 1 < text.length) {
        const next = text.charCodeAt(i + 1);
        if (next >= 0xdc00 && next <= 0xdfff) {
          result += text.slice(i, i + 2);
          i++;
          continue;
        }
      }
      if (firstOffset === -1) firstOffset = i;
      stripped++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      if (firstOffset === -1) firstOffset = i;
      stripped++;
    } else {
      result += text[i];
    }
  }

  if (stripped > 0 && shouldEmit(ctx)) {
    const ruleId: UnicodeCategory = 'orphaned-surrogates';
    emit(
      ctx,
      makeUnicodeStrip(
        ruleId,
        firstOffset === -1 ? 0 : firstOffset,
        0,
        CATEGORY_CHAR_CLASS[ruleId],
        stripped,
        effectiveSeverity(ruleId, CATEGORY_DEFAULT_SEVERITY[ruleId], ctx.policy)
      )
    );
  }

  return result;
}

/** Findings reported under `ruleId: 'zero-width'` (v0.1 conflation; ZWJ has no carved category). Aggregated count=N. */
function stripNonEmojiZwjWithFindings(text: string, ctx: EmitContext): string {
  if (text.indexOf('‍') === -1) return text;

  const chars = [...text];
  const result: string[] = [];
  let stripped = 0;
  let firstOffset = -1;
  let codepointStart = 0;

  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i] as string;
    if (ch === '‍') {
      const before = chars[i - 1];
      const after = chars[i + 1];
      const beforeIsEmoji = before !== undefined && (EMOJI_RE.test(before) || VS_RE.test(before));
      const afterIsEmoji = after !== undefined && EMOJI_RE.test(after);
      if (beforeIsEmoji && afterIsEmoji) {
        result.push(ch);
      } else {
        if (firstOffset === -1) firstOffset = codepointStart;
        stripped++;
      }
    } else {
      result.push(ch);
    }
    codepointStart += ch.length;
  }

  if (stripped > 0 && shouldEmit(ctx)) {
    const ruleId: UnicodeCategory = 'zero-width';
    emit(
      ctx,
      makeUnicodeStrip(
        ruleId,
        firstOffset === -1 ? 0 : firstOffset,
        0,
        CATEGORY_CHAR_CLASS[ruleId],
        stripped,
        effectiveSeverity(ruleId, CATEGORY_DEFAULT_SEVERITY[ruleId], ctx.policy)
      )
    );
  }

  return result.join('');
}

function stripNonEmojiVariationSelectorsWithFindings(text: string, ctx: EmitContext): string {
  if (!VS_RE.test(text)) return text;

  const chars = [...text];
  const result: string[] = [];
  let stripped = 0;
  let firstOffset = -1;
  let codepointStart = 0;

  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i] as string;
    if (VS_RE.test(ch)) {
      const before = chars[i - 1];
      if (before !== undefined && EMOJI_RE.test(before)) {
        result.push(ch);
      } else {
        if (firstOffset === -1) firstOffset = codepointStart;
        stripped++;
      }
    } else {
      result.push(ch);
    }
    codepointStart += ch.length;
  }

  if (stripped > 0 && shouldEmit(ctx)) {
    const ruleId: UnicodeCategory = 'supplementary-variation-selectors';
    emit(
      ctx,
      makeUnicodeStrip(
        ruleId,
        firstOffset === -1 ? 0 : firstOffset,
        0,
        CATEGORY_CHAR_CLASS[ruleId],
        stripped,
        effectiveSeverity(ruleId, CATEGORY_DEFAULT_SEVERITY[ruleId], ctx.policy)
      )
    );
  }

  return result.join('');
}

/** `ruleId: 'zalgo-cap'` is synthetic (no UnicodeCategory entry); always runs (cap is policy-controlled, not category-gated). */
function capCombiningMarksWithFindings(text: string, ctx: EmitContext): string {
  if (!/\p{Mark}/u.test(text)) return text;

  const cap = ctx.policy.unicode.combiningMarkCap;
  const chars = [...text];
  const result: string[] = [];
  let dropped = 0;
  let firstOffset = -1;
  let markCount = 0;
  let codepointStart = 0;

  for (const char of chars) {
    if (/\p{Mark}/u.test(char)) {
      markCount++;
      if (markCount <= cap) {
        result.push(char);
      } else {
        if (firstOffset === -1) firstOffset = codepointStart;
        dropped++;
      }
    } else {
      markCount = 0;
      result.push(char);
    }
    codepointStart += char.length;
  }

  if (dropped > 0 && shouldEmit(ctx)) {
    emit(
      ctx,
      makeUnicodeStrip(
        ZALGO_CAP_RULE_ID,
        firstOffset === -1 ? 0 : firstOffset,
        0,
        ZALGO_CAP_CHAR_CLASS,
        dropped,
        effectiveSeverity(ZALGO_CAP_RULE_ID, ZALGO_CAP_DEFAULT_SEVERITY, ctx.policy)
      )
    );
  }

  return result.join('');
}

/** Composed Unicode pipeline. Returns input by reference if unchanged. See file header for pipeline order. */
export function stripUnicode(text: string, options?: SanitizeOptions): string {
  return runStripUnicode(text, makeContext(options, /*detailed*/ false));
}

/** Frozen `SanitizeResult`; `result.text === text` (same ref) when `changed === false`. */
export function stripUnicodeDetailed(text: string, options?: SanitizeOptions): SanitizeResult {
  const ctx = makeContext(options, /*detailed*/ true);
  const out = runStripUnicode(text, ctx);
  const changed = out !== text;
  return Object.freeze({
    text: changed ? out : text,
    changed,
    findings: Object.freeze([...(ctx.findings ?? [])])
  });
}

function makeContext(options: SanitizeOptions | undefined, detailed: boolean): EmitContext {
  return {
    findings: detailed ? [] : null,
    onFinding: options?.onFinding,
    policy: options?.policy ?? DEFAULT_POLICY
  };
}

function runStripUnicode(text: string, ctx: EmitContext): string {
  const cats = ctx.policy.unicode.categories;
  const telemetry = shouldEmit(ctx);

  let result = text;
  if (cats.has('ansi-escapes')) {
    result = telemetry ? stripAnsiEscapesWithFindings(result, ctx) : stripAnsiEscapes(result);
  }
  if (cats.has('orphaned-surrogates')) {
    result = telemetry
      ? stripOrphanedSurrogatesWithFindings(result, ctx)
      : stripOrphanedSurrogates(result);
  }
  if (ctx.policy.unicode.nfkcEnabled) {
    result = normalizeNFKC(result);
  }
  result = telemetry
    ? stripStripSetCategoriesWithFindings(result, ctx)
    : stripUnconditional(result, cats);
  // VS BEFORE ZWJ: ZWJ-context accepts VS-16 as "emoji-ish" before-context
  // (`VS_RE.test(before)` branch). If ZWJ ran first against an orphan VS-16,
  // it would preserve the ZWJ; then VS strip would orphan it. Streaming
  // re-runs the pipeline across pushes ⇒ that's `f(f(x)) ≠ f(x)`. Running
  // VS first eliminates orphan VS-16 before ZWJ-context evaluation.
  if (cats.has('supplementary-variation-selectors')) {
    result = telemetry
      ? stripNonEmojiVariationSelectorsWithFindings(result, ctx)
      : stripNonEmojiVariationSelectors(result);
  }
  if (cats.has('zero-width')) {
    result = telemetry ? stripNonEmojiZwjWithFindings(result, ctx) : stripNonEmojiZwj(result);
  }
  result = telemetry
    ? capCombiningMarksWithFindings(result, ctx)
    : capCombiningMarks(result, ctx.policy.unicode.combiningMarkCap);
  // Final NFKC: re-canonicalizes sequences exposed by intervening strips.
  // Closes `f(f(x)) = f(x)` idempotency that streaming relies on; prevents
  // adversary bypass via stripped blockers between codepoints, e.g.:
  // `a​́` becomes `á` after ZWSP strip — still un-NFKC; final NFKC yields `á`).
  if (ctx.policy.unicode.nfkcEnabled) {
    result = normalizeNFKC(result);
  }
  return result;
}
