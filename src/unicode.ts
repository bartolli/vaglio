/**
 * Unicode strip + normalization layer for Vaglio v0.1.
 *
 * Lifted from `~/Projects/sotto/src/message-io.ts` per the extraction inventory,
 * extended with three research-driven additions (orphaned UTF-16 surrogates,
 * ANSI terminal escape sequences, legacy C0/C1 control characters) per
 * spec-requirements §F1.
 *
 * Unconditional strip set:
 *   - C0 controls except \t \n \r  U+0000-U+0008, U+000B, U+000C, U+000E-U+001F
 *   - C1 controls (incl. NEL)      U+007F-U+009F   (U+00A0 NBSP is printable; not stripped)
 *   - Soft hyphen                  U+00AD
 *   - Combining grapheme joiner    U+034F
 *   - Hangul fillers               U+115F, U+1160
 *   - Mongolian FVS                U+180B-U+180F
 *   - Zero-width space / NJ        U+200B, U+200C
 *   - Bidi overrides               U+202A-U+202E
 *   - Word joiner                  U+2060
 *   - Invisible math operators     U+2061-U+2064
 *   - Bidi isolates                U+2066-U+2069
 *   - BOM                          U+FEFF
 *   - Interlinear annotations      U+FFF9-U+FFFB
 *   - Object replacement           U+FFFC
 *   - Unicode Tags block           U+E0001-U+E007F
 *   - Supp. Variation Selectors    U+E0100-U+E01EF
 *   - Supp. Private Use Area-A/B   U+F0000-U+FFFFD, U+100000-U+10FFFD
 *
 * Context-aware:
 *   - ZWJ U+200D preserved between emoji codepoints
 *   - Variation selectors U+FE00-U+FE0F preserved after emoji codepoints
 *   - Combining marks capped per base character (Zalgo defense)
 *
 * Sequence-shaped:
 *   - ANSI Control Sequence Introducer (CSI: ESC [ ... <final>)
 *   - Orphaned UTF-16 surrogates (lone high U+D800-U+DBFF or low U+DC00-U+DFFF)
 *
 * Pipeline plumbing (Slice A.1, vertical 2026-04-29):
 *   - `stripUnicode(text, options?)` accepts `SanitizeOptions` (spec-api §1).
 *   - `policy.unicode.nfkcEnabled === false` skips the NFKC stage.
 *   - `policy.unicode.combiningMarkCap` overrides the default cap of 4.
 *   - Per-category gating (`policy.unicode.categories`) and findings emission land
 *     in Slices A.2 / A.3.
 *
 * Load-bearing details:
 *   1. Pipeline order — ANSI strip → orphan-surrogate cleanup → NFKC → unconditional
 *      strip-set → VS context → ZWJ context → mark cap → NFKC (final). The first NFKC
 *      decomposes mathematical-bold and fullwidth forms before the strip set is checked
 *      (this catches homoglyph and fullwidth-delimiter forging). VS-context runs before
 *      ZWJ-context so an orphan VS-16 cannot mislead the ZWJ check into preserving an
 *      otherwise-orphan ZWJ (M3.6 fix). The final NFKC re-canonicalizes sequences
 *      exposed by stripping intervening blockers (e.g. `a + ZWSP + ́` → `a + ́` after
 *      ZWSP strip → `á` after final NFKC) — this closes the
 *      `pipeline(pipeline(x)) = pipeline(x)` idempotency gap that streaming relies on
 *      and prevents an attacker from bypassing NFKC composition by inserting a stripped
 *      blocker between codepoints.
 *   2. Codepoint iteration via [...text] (NOT text.split('')) — surrogate-pair safety in
 *      the ZWJ / VS / combining-mark passes.
 *   3. Combining-mark counter resets on every non-mark codepoint, NOT on grapheme
 *      boundary — the Zalgo test exercises this specifically.
 *   4. NFKC is same-script-only by Unicode spec — Cyrillic preservation is correct, not
 *      a leak. Cross-script homoglyphs (Greek↔Latin, Cyrillic↔Latin) are out of scope
 *      for v0.1.
 *   5. NFKC compatibility-decomposes NBSP (U+00A0) to regular space (U+0020). Tests
 *      reflect this — NBSP is "preserved" in the sense that it survives the strip set,
 *      but it is normalized to ASCII space by NFKC.
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
 * Per-category strip-set sources (Slice A.2). Each entry is the regex character-class
 * fragment for one `UnicodeCategory`. `stripUnconditional` builds an active union regex
 * from the categories enabled in `policy.unicode.categories`.
 *
 * `null` entries are categories handled by their own dedicated function (sequence-shaped
 * matchers that don't fit a character-class range): `orphaned-surrogates` (`stripOrphanedSurrogates`)
 * and `ansi-escapes` (`stripAnsiEscapes`).
 *
 * Sources use `\u{...}` brace escapes inside string literals so the file stays free of
 * literal control bytes (transport-safe) and so the same source string drives both the
 * strip (`g`) and the membership test (no `g`) without re-typing ranges.
 *
 * v0.1 conflations (documented for v0.2 spec amendment):
 *   - ZWJ U+200D context-aware stripping is gated by `zero-width` (its codepoint is in
 *     the zero-width class even though the strip is sequence-aware, not range-only).
 *   - BMP variation selectors U+FE00-U+FE0F (no dedicated category in spec) are gated by
 *     `supplementary-variation-selectors`, conflating BMP and supplementary VS into one
 *     toggle. Cleaner split is a v0.2 concern.
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

/**
 * Cache of compiled `(test, strip)` regex pairs keyed by a sorted-category cache key.
 * The default policy hits the same key on every call; custom policies pay one
 * compilation per unique category set.
 */
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

/** ASCII-only fast-path predicate for normalizeNFKC. Pure ASCII is always already NFKC. */
// biome-ignore lint/suspicious/noControlCharactersInRegex: NUL-DEL is the deliberate ASCII range
const ASCII_ONLY = /^[\x00-\x7F]*$/;

/** Emoji codepoint test — Extended_Pictographic covers emoji base characters. */
const EMOJI_RE = /\p{Extended_Pictographic}/u;

/** Variation selector range U+FE00-U+FE0F. */
const VS_RE = /[︀-️]/u;

/**
 * ANSI Control Sequence Introducer:
 *   ESC [ <param-bytes 0x30-0x3F>* <intermediate-bytes 0x20-0x2F>* <final-byte 0x40-0x7E>
 * Covers SGR (colors), cursor positioning, mode-set/reset — the dominant attack surface
 * in MCP tool output and CLI integrations. Stray ESC bytes outside CSI sequences are
 * caught by the C0 strip in stripUnconditional ( is in U+0000-U+001F).
 */
// biome-ignore lint/suspicious/noControlCharactersInRegex: ESC byte is intentional
const ANSI_ESCAPE = /\[[0-?]*[ -/]*[@-~]/g;

/** Default cap for combining marks per base character. Overridable via the `cap` argument. */
const DEFAULT_COMBINING_MARK_CAP = 4;

/**
 * Strip ANSI escape sequences (CSI).
 *
 * @example
 *   stripAnsiEscapes('[31mhello[0m') // 'hello'
 */
export function stripAnsiEscapes(text: string): string {
  // Fast-path: a CSI sequence requires ESC (U+001B); without it, no ANSI match
  // can occur. Returning by reference here means clean inputs skip the regex
  // pass and the (potentially allocating) replace call.
  if (text.indexOf('') === -1) return text;
  return text.replace(ANSI_ESCAPE, '');
}

/**
 * Strip orphaned UTF-16 surrogates — lone high (U+D800-U+DBFF) or low (U+DC00-U+DFFF)
 * surrogates with no valid pair partner. Walks code units (NOT codepoints) to detect
 * orphans precisely; codepoint iteration would silently drop them.
 *
 * Why: orphan surrogates can bypass codepoint-iteration sanitizers and recombine into
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
 * NFKC normalize. Same-script-only by Unicode spec — Cyrillic, CJK, and emoji sequences
 * are preserved. Compatibility-decomposes mathematical alphanumerics, fullwidth forms,
 * and NBSP (U+00A0 → U+0020).
 *
 * Identity preserved by an ASCII fast-path: pure ASCII (no codepoint > 0x7F) is by
 * definition already in NFKC, so the normalization call can be skipped entirely.
 * Non-ASCII inputs fall back to a post-normalize `===` check that returns the input
 * by reference when the normalization was a no-op (cross-engine correctness — V8
 * happens to optimize this, but the spec doesn't require it).
 */
export function normalizeNFKC(text: string): string {
  if (ASCII_ONLY.test(text)) return text;
  const out = text.normalize('NFKC');
  return out === text ? text : out;
}

/**
 * Strip codepoints belonging to the enabled UnicodeCategory members. Builds a single
 * union regex from the policy's category set (cached per unique set) and runs it once.
 *
 * Identity preserved by a non-global membership test against the same union: if no
 * codepoint in the active strip set is present, return the input by reference.
 */
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

/**
 * Cap combining marks per base character. Counter resets on every non-mark codepoint,
 * NOT on grapheme boundary — load-bearing.
 */
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

// ─────────────────────────────────────────────────────────────────────────────
// Findings infrastructure (Slice A.3)
// ─────────────────────────────────────────────────────────────────────────────

/** Charclass label per category (free-form string for `Finding.charClass`). */
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

/** Per spec-api §6 severity defaults table. */
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

/** Schema version for forensic stability of v0.1 findings (spec-api §6). */
const FINDING_RULE_VERSION = 1;

/**
 * Pipeline-internal context. `findings === null` indicates non-Detailed mode (the
 * array isn't allocated and findings are not retained). `onFinding`, when set, fires
 * synchronously regardless of mode. `shouldEmit(ctx)` is `true` whenever any sink
 * exists — it is checked before doing the matchAll/batching work, so the silent
 * path stays a single `replace()` call.
 */
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

/**
 * Run a global regex against `text`, batch contiguous matches into single findings,
 * and emit them through `ctx`. Returns the stripped string. The non-global membership
 * pre-check is the caller's responsibility (e.g. a category-specific test regex or
 * an `indexOf` fast-path).
 */
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

/**
 * Per-category strip with finding emission (telemetry path). Compiles a single-category
 * test+strip regex pair on first use and caches it under a `:single:<cat>` key in the
 * shared cache so repeat callers don't re-compile.
 */
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

/**
 * Telemetry-mode replacement for `stripUnconditional` — runs each enabled strip-set
 * category as its own pass so findings can carry the precise category-level ruleId.
 * Silent mode still uses the union regex via `stripUnconditional` for one-pass speed.
 */
function stripStripSetCategoriesWithFindings(text: string, ctx: EmitContext): string {
  let result = text;
  for (const cat of ctx.policy.unicode.categories) {
    if (CATEGORY_SOURCES[cat] === null) continue;
    result = stripOneCategoryWithFindings(result, cat, ctx);
  }
  return result;
}

/** ANSI strip with finding emission. Silent path stays in `stripAnsiEscapes`. */
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

/**
 * Orphan-surrogate strip with finding emission. v0.1 simplification: emits one
 * aggregate finding with `count = N` (number of stripped surrogates) and
 * `offset = firstStripIndex`, `length = 0` — distributed strips don't form a single
 * contiguous span. Documented as a v0.1 limitation in spec-api §6.
 */
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

/**
 * ZWJ context-aware strip with finding emission. Findings are reported under
 * `ruleId: 'zero-width'` per the v0.1 conflation (ZWJ is a zero-width codepoint;
 * spec doesn't carve it into its own category). Aggregated: one finding with
 * count=N when distributed strips occur.
 */
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

/** VS context-aware strip with finding emission (under `supplementary-variation-selectors`). */
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

/**
 * Combining-mark cap with finding emission. Findings carry `ruleId: 'zalgo-cap'`
 * (synthetic — there is no UnicodeCategory entry) and aggregate dropped marks across
 * the input. Always runs (cap is controlled by `policy.unicode.combiningMarkCap`,
 * not gated by a category).
 */
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

/**
 * Composed Unicode pipeline. See file header for load-bearing pipeline order.
 *
 * Returns the input string by reference if no transformation occurred (identity
 * preservation per spec-api §2). Hot-path consumers can short-circuit via
 * `result === input`.
 *
 * Slice A.3: dispatches between a silent fast path (no findings; uses the cached
 * union regex in `stripUnconditional`) and a telemetry path (per-category passes
 * that emit `UnicodeStripFinding`s through `onFinding` and/or the findings array
 * in Detailed mode).
 */
export function stripUnicode(text: string, options?: SanitizeOptions): string {
  return runStripUnicode(text, makeContext(options, /*detailed*/ false));
}

/**
 * Detailed variant per spec-api §1, §2. Always constructs a `findings` array;
 * `result.text === text` (same reference) when `result.changed === false`.
 */
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
  // VS context strip runs BEFORE ZWJ context strip. Reason: the ZWJ-context
  // check accepts a preceding variation selector (U+FE0F) as "emoji-ish"
  // before-context (per `stripNonEmojiZwj`'s `VS_RE.test(before)` branch),
  // but the VS-context strip later removes orphan VS-16 whose own before
  // wasn't emoji. If ZWJ ran first against an orphan VS-16, it would
  // preserve the ZWJ (treating VS-16 as emoji-ish); then VS strip would
  // remove the VS-16, leaving a now-orphan ZWJ that the next pipeline pass
  // would strip. That's a pipeline-idempotency violation: `f(f(x)) ≠ f(x)`,
  // which streaming exposes by re-running the pipeline across pushes.
  // Running VS first eliminates orphan VS-16 before ZWJ-context evaluation,
  // so the ZWJ check sees consistent before-context.
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
  // Final NFKC pass to close the pipeline-idempotency gap. The first NFKC
  // (above) decomposes mathematical-bold and fullwidth forms before the
  // strip-set checks; the strip steps may then remove intervening characters
  // (zero-width, bidi, control) that were blocking NFKC composition (e.g.
  // `a​́` becomes `á` after ZWSP strip — still un-NFKC). A
  // second NFKC re-canonicalizes those exposed sequences. Without this,
  // pipeline(pipeline(x)) ≠ pipeline(x), which breaks stream/batch
  // equivalence and lets an attacker bypass NFKC composition by inserting
  // a stripped blocker between codepoints. Idempotency was already claimed
  // by spec §F1; this restores the implementation to match.
  if (ctx.policy.unicode.nfkcEnabled) {
    result = normalizeNFKC(result);
  }
  return result;
}
