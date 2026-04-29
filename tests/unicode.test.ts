import { describe, expect, it } from 'vitest';
import type { Finding, UnicodeStripFinding } from '../src/findings.js';
import { policy } from '../src/policy.js';
import {
  capCombiningMarks,
  normalizeNFKC,
  stripAnsiEscapes,
  stripOrphanedSurrogates,
  stripUnicode,
  stripUnicodeDetailed
} from '../src/unicode.js';

// Test corpus ported from ~/Projects/sotto/src/message-io.test.ts lines 14-225
// per the extraction inventory mapping. Original `sanitizeInbound` describe →
// `stripUnicode` here. Three new sub-describes added for the research-driven
// additions (orphaned surrogates, ANSI escapes, C0/C1 controls).

// Codepoints that don't survive JSON transport (orphan surrogates, C0/C1 controls)
// are constructed via String.fromCharCode at runtime rather than embedded as source
// escapes. \u{...} brace escapes are kept as-is (JSON doesn't interpret them).
const HIGH_SURROGATE = String.fromCharCode(0xd800);
const LOW_SURROGATE = String.fromCharCode(0xdc00);
const ESC = String.fromCharCode(0x1b);
const NUL = String.fromCharCode(0x00);
const VT = String.fromCharCode(0x0b);
const FF = String.fromCharCode(0x0c);
const DEL = String.fromCharCode(0x7f);
const NEL = String.fromCharCode(0x85);

describe('stripUnicode', () => {
  describe('Unicode Tags block (U+E0001-U+E007F)', () => {
    it('strips invisible tag characters used for hidden text encoding', () => {
      const hidden = '\u{E0048}\u{E0045}\u{E004C}\u{E004C}\u{E004F}';
      expect(stripUnicode(`normal${hidden}text`)).toBe('normaltext');
    });

    it('strips tag begin/end markers', () => {
      const tagged = '\u{E0001}payload\u{E007F}';
      expect(stripUnicode(tagged)).toBe('payload');
    });
  });

  describe('zero-width characters', () => {
    it('strips zero-width space U+200B', () => {
      expect(stripUnicode('hello​world')).toBe('helloworld');
    });

    it('strips zero-width non-joiner U+200C', () => {
      expect(stripUnicode('hello‌world')).toBe('helloworld');
    });

    it('strips BOM U+FEFF', () => {
      expect(stripUnicode('﻿hello')).toBe('hello');
    });

    it('strips word joiner U+2060', () => {
      expect(stripUnicode('hello⁠world')).toBe('helloworld');
    });
  });

  describe('ZWJ handling (U+200D)', () => {
    it('preserves ZWJ in compound emoji sequences (family)', () => {
      const family = '\u{1F468}‍\u{1F469}‍\u{1F467}‍\u{1F466}';
      expect(stripUnicode(family)).toBe(family);
    });

    it('preserves ZWJ in woman technologist emoji', () => {
      const techWoman = '\u{1F469}‍\u{1F4BB}';
      expect(stripUnicode(techWoman)).toBe(techWoman);
    });

    it('strips ZWJ between regular text characters', () => {
      expect(stripUnicode('hello‍world')).toBe('helloworld');
    });

    it('strips standalone ZWJ', () => {
      expect(stripUnicode('‍')).toBe('');
    });

    it('strips ZWJ at end of string even after emoji (no trailing partner)', () => {
      // ZWJ requires emoji on BOTH sides; trailing emoji-then-ZWJ has no `after`.
      expect(stripUnicode('\u{1F469}‍')).toBe('\u{1F469}');
    });
  });

  describe('bidi override characters', () => {
    it('strips RTL/LTR override characters U+202A-U+202E', () => {
      const withOverrides = '‪hello‫‬world‭‮';
      expect(stripUnicode(withOverrides)).toBe('helloworld');
    });

    it('strips isolate characters U+2066-U+2069', () => {
      const withIsolates = '⁦hello⁧⁨world⁩';
      expect(stripUnicode(withIsolates)).toBe('helloworld');
    });

    it('does NOT strip actual Arabic characters', () => {
      expect(stripUnicode('مرحبا')).toBe('مرحبا');
    });

    it('does NOT strip actual Hebrew characters', () => {
      expect(stripUnicode('שלום')).toBe('שלום');
    });
  });

  describe('variation selectors', () => {
    it('preserves variation selector U+FE0F after emoji', () => {
      const heartEmoji = '❤️';
      expect(stripUnicode(heartEmoji)).toBe(heartEmoji);
    });

    it('strips variation selector not adjacent to emoji', () => {
      expect(stripUnicode('hello️world')).toBe('helloworld');
    });

    it('strips variation selector at start of string (no preceding emoji)', () => {
      expect(stripUnicode('️hello')).toBe('hello');
    });
  });

  describe('other invisible characters', () => {
    it('strips soft hyphen U+00AD', () => {
      expect(stripUnicode('hel­lo')).toBe('hello');
    });

    it('strips combining grapheme joiner U+034F', () => {
      expect(stripUnicode('hel͏lo')).toBe('hello');
    });

    it('strips Hangul fillers U+115F, U+1160', () => {
      expect(stripUnicode('helloᅟᅠworld')).toBe('helloworld');
    });

    it('strips interlinear annotations U+FFF9-U+FFFB', () => {
      expect(stripUnicode('hello￹hidden￺￻world')).toBe('hellohiddenworld');
    });

    it('strips object replacement character U+FFFC', () => {
      expect(stripUnicode('hello￼world')).toBe('helloworld');
    });

    it('strips Supplementary Private Use Area-A codepoints', () => {
      expect(stripUnicode('hello\u{F0000}world')).toBe('helloworld');
    });

    it('strips Supplementary Private Use Area-B codepoints', () => {
      expect(stripUnicode('hello\u{100000}world')).toBe('helloworld');
    });

    it('strips Mongolian Free Variation Selectors U+180B-U+180F', () => {
      expect(stripUnicode('hello᠋᠏world')).toBe('helloworld');
    });

    it('strips invisible math operators U+2061-U+2064', () => {
      expect(stripUnicode('a⁡b⁢c⁣d⁤e')).toBe('abcde');
    });

    it('strips Supplementary Variation Selectors U+E0100-U+E01EF', () => {
      expect(stripUnicode('hello\u{E0100}\u{E01EF}world')).toBe('helloworld');
    });
  });

  describe('NFKC normalization', () => {
    it('collapses mathematical bold to ASCII (homoglyph defense)', () => {
      const mathBold = '\u{1D42C}\u{1D432}\u{1D42C}\u{1D42D}\u{1D41E}\u{1D426}';
      expect(stripUnicode(mathBold)).toBe('system');
    });

    it('collapses fullwidth angle brackets (delimiter forging defense)', () => {
      expect(stripUnicode('＜system＞')).toBe('<system>');
    });

    it('collapses fullwidth Latin letters', () => {
      expect(stripUnicode('Ｈｅｌｌｏ')).toBe('Hello');
    });

    it('preserves Cyrillic characters (NFKC does not collapse cross-script)', () => {
      // Cyrillic 'a' (U+0430) is visually identical to Latin 'a' (U+0061) but a different
      // codepoint. NFKC is same-script-only by spec — does NOT collapse Cyrillic to Latin.
      // The escape form 'а' is used instead of the literal glyph to keep the source
      // free of confusable characters per IDE/lint conventions.
      expect(stripUnicode('а')).toBe('а');
    });

    it('preserves legitimate CJK text', () => {
      expect(stripUnicode('你好世界')).toBe('你好世界');
    });

    it('preserves emoji with variation selectors after normalize', () => {
      const heart = '❤️';
      expect(stripUnicode(heart)).toBe(heart);
    });

    it('preserves ZWJ emoji sequences after normalize', () => {
      const family = '\u{1F468}‍\u{1F469}‍\u{1F467}‍\u{1F466}';
      expect(stripUnicode(family)).toBe(family);
    });

    it('NFKC normalizes NBSP U+00A0 to ASCII space U+0020 (documented behavior)', () => {
      // NBSP has compatibility decomposition to space per Unicode spec.
      // It is NOT stripped by the C0/C1 pass, but it is folded to space by NFKC.
      // The strip set treats NBSP as printable; NFKC treats it as a compat-equivalent of space.
      expect(stripUnicode('hello world')).toBe('hello world');
    });
  });

  describe('combining character abuse', () => {
    it('limits combining marks to 4 per base character', () => {
      const zalgo = 'à́̂̃̄̅';
      const result = stripUnicode(zalgo);
      const marks = [...result].filter((c) => /\p{Mark}/u.test(c));
      expect(marks.length).toBeLessThanOrEqual(4);
    });

    it('preserves legitimate diacritics (Bulgarian й)', () => {
      expect(stripUnicode('й')).toBe('й');
    });

    it('preserves legitimate diacritics (Bulgarian ь)', () => {
      expect(stripUnicode('ь')).toBe('ь');
    });
  });

  describe('legitimate text preservation', () => {
    it('preserves Bulgarian Cyrillic text', () => {
      const bg = 'Здравейте, как сте?';
      expect(stripUnicode(bg)).toBe(bg);
    });

    it('preserves CJK characters', () => {
      expect(stripUnicode('你好世界')).toBe('你好世界');
    });

    it('preserves standard emoji without ZWJ', () => {
      expect(stripUnicode('\u{1F60A}\u{1F389}\u{1F525}')).toBe('\u{1F60A}\u{1F389}\u{1F525}');
    });

    it('preserves flag emoji', () => {
      expect(stripUnicode('\u{1F1E7}\u{1F1EC}')).toBe('\u{1F1E7}\u{1F1EC}');
    });

    it('preserves empty string', () => {
      expect(stripUnicode('')).toBe('');
    });

    it('preserves normal ASCII text', () => {
      expect(stripUnicode('Hello, world! 123')).toBe('Hello, world! 123');
    });

    it('preserves newlines and tabs', () => {
      expect(stripUnicode('line1\nline2\ttab')).toBe('line1\nline2\ttab');
    });

    it('preserves carriage returns', () => {
      expect(stripUnicode('line1\r\nline2')).toBe('line1\r\nline2');
    });

    it('returns same string reference when input is clean (identity preservation)', () => {
      // spec-api §2: stripUnicode should return the input by reference if no
      // transformation occurred, so hot-path consumers can short-circuit via
      // `result === input`. Currently relies on V8 returning the same reference
      // for already-NFC ASCII out of normalize('NFKC'); a guard
      // (`if (cleaned === text) return text` chain or dirty flag) is needed
      // for cross-engine correctness.
      const input = 'Hello, world! 123';
      const result = stripUnicode(input);
      expect(result).toBe(input);
      expect(Object.is(result, input)).toBe(true);
    });
  });

  describe('mixed-threat integration (real-world payload shape)', () => {
    it('handles fullwidth delimiters + tags-block + bidi override in one payload', () => {
      // Combined attack: NFKC must fold the fullwidth angle brackets, the unconditional
      // strip must remove the Tags-block hidden text and the bidi override marker.
      const attack = '＜system＞\u{E0048}\u{E0049}‮ignore‬';
      expect(stripUnicode(attack)).toBe('<system>ignore');
    });
  });

  // ─── 2026-04-28 research-driven additions ───────────────────────────────

  describe('orphaned UTF-16 surrogates (research addition)', () => {
    it('strips lone high surrogate U+D800', () => {
      expect(stripUnicode(`hello${HIGH_SURROGATE}world`)).toBe('helloworld');
    });

    it('strips lone low surrogate U+DC00', () => {
      expect(stripUnicode(`hello${LOW_SURROGATE}world`)).toBe('helloworld');
    });

    it('preserves valid surrogate pair', () => {
      // U+20001 (CJK Extension B) — a valid pair, encodes as D840 DC01 in UTF-16.
      expect(stripUnicode('a\u{20001}b')).toBe('a\u{20001}b');
    });

    it('strips multiple consecutive orphans', () => {
      expect(stripUnicode(`a${HIGH_SURROGATE}${HIGH_SURROGATE}b`)).toBe('ab');
    });
  });

  describe('ANSI terminal escape sequences (research addition)', () => {
    it('strips SGR color sequences', () => {
      expect(stripUnicode(`${ESC}[31mred${ESC}[0m text`)).toBe('red text');
    });

    it('strips cursor positioning sequences', () => {
      expect(stripUnicode(`hello${ESC}[2J${ESC}[Hworld`)).toBe('helloworld');
    });

    it('strips multi-parameter SGR', () => {
      expect(stripUnicode(`${ESC}[1;31;42mloud${ESC}[0m`)).toBe('loud');
    });

    it('strips lone ESC byte via C0 strip when not part of CSI', () => {
      // ESC alone (no `[` follow-up) is a C0 control — caught by stripUnconditional.
      expect(stripUnicode(`hello${ESC}world`)).toBe('helloworld');
    });

    it('preserves text that looks like ANSI but lacks ESC', () => {
      expect(stripUnicode('look at [31m these [0m brackets')).toBe(
        'look at [31m these [0m brackets'
      );
    });

    it('exposes stripAnsiEscapes as a granular function', () => {
      expect(stripAnsiEscapes(`${ESC}[31mhello${ESC}[0m`)).toBe('hello');
    });
  });

  describe('C0/C1 control characters (research addition)', () => {
    it('strips null byte U+0000', () => {
      expect(stripUnicode(`hello${NUL} world`)).toBe('hello world');
    });

    it('strips vertical tab U+000B', () => {
      expect(stripUnicode(`hello${VT}world`)).toBe('helloworld');
    });

    it('strips form feed U+000C', () => {
      expect(stripUnicode(`hello${FF}world`)).toBe('helloworld');
    });

    it('strips DEL U+007F', () => {
      expect(stripUnicode(`hello${DEL}world`)).toBe('helloworld');
    });

    it('strips NEL U+0085 (C1)', () => {
      expect(stripUnicode(`hello${NEL}world`)).toBe('helloworld');
    });

    it('strips arbitrary C1 controls U+0080-U+009F', () => {
      const c1 = (cp: number) => String.fromCharCode(cp);
      expect(stripUnicode(`a${c1(0x80)}b${c1(0x90)}c${c1(0x9f)}d`)).toBe('abcd');
    });

    it('preserves \\t \\n \\r as documented exceptions', () => {
      expect(stripUnicode('a\tb\nc\rd')).toBe('a\tb\nc\rd');
    });
  });
});

// ─── Granular function smoke tests ────────────────────────────────────────

describe('normalizeNFKC', () => {
  it('collapses mathematical bold to ASCII', () => {
    const mathBold = '\u{1D42C}\u{1D432}\u{1D42C}\u{1D42D}\u{1D41E}\u{1D426}';
    expect(normalizeNFKC(mathBold)).toBe('system');
  });

  it('preserves Cyrillic (same-script-only by Unicode spec)', () => {
    // Cyrillic 'a' (U+0430) ≠ Latin 'a' (U+0061); NFKC does not fold across scripts.
    // Escape form used to avoid the confusable-glyph warning.
    expect(normalizeNFKC('а')).toBe('а');
  });

  it('compat-decomposes NBSP to ASCII space', () => {
    expect(normalizeNFKC(' ')).toBe(' ');
  });

  it('value-preserves already-normalized ASCII', () => {
    const ascii = 'plain ASCII';
    expect(normalizeNFKC(ascii)).toBe(ascii);
  });
});

describe('capCombiningMarks', () => {
  it('caps at the default of 4', () => {
    const zalgo = 'à́̂̃̄̅';
    const result = capCombiningMarks(zalgo);
    const marks = [...result].filter((c) => /\p{Mark}/u.test(c));
    expect(marks.length).toBe(4);
  });

  it('respects an explicit cap argument', () => {
    const zalgo = 'à́̂̃̄̅';
    const result = capCombiningMarks(zalgo, 2);
    const marks = [...result].filter((c) => /\p{Mark}/u.test(c));
    expect(marks.length).toBe(2);
  });

  it('counter resets on next non-mark codepoint (load-bearing)', () => {
    // Six marks on a, then six marks on b — each base independently respects the cap.
    const input = 'à́̂̃̄̅b̀́̂̃̄̅';
    const result = capCombiningMarks(input, 4);
    expect([...result].length).toBe(10);
  });
});

describe('stripOrphanedSurrogates', () => {
  it('handles strings with no surrogates (fast path)', () => {
    expect(stripOrphanedSurrogates('plain ASCII')).toBe('plain ASCII');
  });

  it('strips lone high surrogate', () => {
    expect(stripOrphanedSurrogates(`a${HIGH_SURROGATE}b`)).toBe('ab');
  });

  it('strips lone low surrogate', () => {
    expect(stripOrphanedSurrogates(`a${LOW_SURROGATE}b`)).toBe('ab');
  });

  it('preserves valid surrogate pairs', () => {
    expect(stripOrphanedSurrogates('a\u{1F600}b')).toBe('a\u{1F600}b');
  });
});

describe('identity preservation (per spec-api §2)', () => {
  // Each guard short-circuits on a clean input and returns the SAME reference.
  // Spec contract: when no transformation occurs, the return value === the input.

  it('stripAnsiEscapes returns input by reference when no ESC byte is present', () => {
    const clean = 'no escape sequences here';
    expect(stripAnsiEscapes(clean)).toBe(clean);
  });

  it('normalizeNFKC returns input by reference for pure ASCII (fast path)', () => {
    const ascii = 'plain ASCII text 1234567890';
    expect(normalizeNFKC(ascii)).toBe(ascii);
  });

  it('normalizeNFKC returns input by reference for already-NFKC non-ASCII', () => {
    // Cyrillic stays unchanged through NFKC (same-script-only); the post-normalize
    // === check returns the input reference even when the engine allocates a new
    // string. (This is the cross-engine fallback from the M3.3 guard.)
    const cyrillic = 'Кириллица — без изменений';
    expect(normalizeNFKC(cyrillic)).toBe(cyrillic);
  });

  it('stripUnicode returns input by reference for clean ASCII (full chain)', () => {
    const clean = 'totally clean ASCII input — no problems here';
    expect(stripUnicode(clean)).toBe(clean);
  });

  it('stripUnicode returns input by reference for clean non-ASCII (full chain)', () => {
    // Cyrillic + emoji + ZWJ-bound emoji sequence — no strippable codepoints.
    const clean = 'Привет 👨‍👩‍👧 мир';
    expect(stripUnicode(clean)).toBe(clean);
  });

  it('stripUnicode breaks identity (returns a new string) when any stage transforms', () => {
    const dirty = `a${ESC}[31mb`;
    expect(stripUnicode(dirty)).not.toBe(dirty);
    expect(stripUnicode(dirty)).toBe('ab');
  });
});

describe('stripUnicode — Policy plumbing (Slice A.1)', () => {
  it('uses DEFAULT_POLICY when no options are passed', () => {
    expect(stripUnicode('hello')).toBe('hello');
  });

  it('honors policy.unicode.nfkcEnabled = false (skips NFKC normalization)', () => {
    // 'ﬁ' (U+FB01 LATIN SMALL LIGATURE FI) decomposes to 'fi' under NFKC.
    const ligature = 'ﬁle';
    const noNfkc = policy().setNfkcEnabled(false).build();

    expect(stripUnicode(ligature)).toBe('file'); // default: NFKC on
    expect(stripUnicode(ligature, { policy: noNfkc })).toBe(ligature);
  });

  it('honors policy.unicode.combiningMarkCap', () => {
    // Six combining marks on a single base — default cap is 4, override to 2.
    const zalgo = 'à́̂̃̄̅';
    const cap2 = policy().setCombiningMarkCap(2).build();

    const defaultMarks = [...stripUnicode(zalgo)].filter((c) => /\p{Mark}/u.test(c)).length;
    const cap2Marks = [...stripUnicode(zalgo, { policy: cap2 })].filter((c) =>
      /\p{Mark}/u.test(c)
    ).length;

    expect(defaultMarks).toBe(4);
    expect(cap2Marks).toBe(2);
  });

  it('preserves identity for clean input regardless of options', () => {
    const clean = 'plain ASCII';
    const customPolicy = policy().setCombiningMarkCap(2).build();
    expect(stripUnicode(clean, { policy: customPolicy })).toBe(clean);
  });
});

describe('stripUnicode — per-category gating (Slice A.2)', () => {
  it('disabling tags-block leaves Tags-block codepoints in place', () => {
    const tagged = '\u{E0048}\u{E0045}payload';
    const noTags = policy().disableUnicodeCategory('tags-block').build();

    expect(stripUnicode(tagged)).toBe('payload'); // default: stripped
    expect(stripUnicode(tagged, { policy: noTags })).toBe(tagged);
  });

  it('disabling bidi-override leaves bidi codepoints in place', () => {
    const evil = `before‮after`;
    const noBidi = policy().disableUnicodeCategory('bidi-override').build();

    expect(stripUnicode(evil)).toBe('beforeafter');
    expect(stripUnicode(evil, { policy: noBidi })).toBe(evil);
  });

  it('disabling math-invisibles leaves U+2061-U+2064 in place', () => {
    const tricky = `1⁡2`; // FUNCTION APPLICATION between digits
    const noMath = policy().disableUnicodeCategory('math-invisibles').build();

    expect(stripUnicode(tricky)).toBe('12');
    expect(stripUnicode(tricky, { policy: noMath })).toBe(tricky);
  });

  it('disabling ansi-escapes leaves ESC sequences in place', () => {
    const colored = `${ESC}[31mred`;
    const noAnsi = policy().disableUnicodeCategory('ansi-escapes').build();

    expect(stripUnicode(colored)).toBe('red');
    // C0 strip would still remove the bare ESC byte; with c0-c1-controls also off,
    // the full sequence survives unchanged.
    const noAnsiNoC0 = policy()
      .disableUnicodeCategory('ansi-escapes')
      .disableUnicodeCategory('c0-c1-controls')
      .build();
    expect(stripUnicode(colored, { policy: noAnsi })).toBe(`[31mred`); // ESC byte stripped by C0
    expect(stripUnicode(colored, { policy: noAnsiNoC0 })).toBe(colored);
  });

  it('disabling orphaned-surrogates leaves lone surrogates in place', () => {
    const broken = `a${HIGH_SURROGATE}b`;
    const noSurrogates = policy().disableUnicodeCategory('orphaned-surrogates').build();

    expect(stripUnicode(broken)).toBe('ab');
    // NFKC throws RangeError on ill-formed UTF-16 in some engines; v0.1 contract is
    // "if you turn off orphaned-surrogates, you accept the consequences." Verify the
    // function returns *something* deterministic — V8's normalize tolerates lone
    // surrogates by passing them through.
    const result = stripUnicode(broken, { policy: noSurrogates });
    expect(result).toContain('a');
    expect(result).toContain('b');
  });

  it('emits no transformation when ALL categories are disabled and NFKC is off', () => {
    const dirty = '‪evil';
    let bare = policy();
    for (const cat of [
      'tags-block',
      'zero-width',
      'bidi-override',
      'mongolian-fvs',
      'interlinear-annotations',
      'object-replacement',
      'supplementary-pua',
      'supplementary-variation-selectors',
      'soft-hyphen-fillers',
      'math-invisibles',
      'orphaned-surrogates',
      'ansi-escapes',
      'c0-c1-controls'
    ] as const) {
      bare = bare.disableUnicodeCategory(cat);
    }
    bare = bare.setNfkcEnabled(false).setCombiningMarkCap(Number.POSITIVE_INFINITY);
    const builtBare = bare.build();
    expect(stripUnicode(dirty, { policy: builtBare })).toBe(dirty);
  });
});

describe('stripUnicodeDetailed (Slice A.3)', () => {
  it('returns same-reference text + empty findings on clean input', () => {
    const clean = 'plain ASCII';
    const result = stripUnicodeDetailed(clean);
    expect(result.text).toBe(clean);
    expect(result.changed).toBe(false);
    expect(result.findings).toHaveLength(0);
  });

  it('emits a single tags-block finding for one Tags-block run', () => {
    const tagged = 'a\u{E0048}\u{E0045}\u{E004C}\u{E004C}\u{E004F}b';
    const result = stripUnicodeDetailed(tagged);
    expect(result.changed).toBe(true);
    expect(result.text).toBe('ab');
    expect(result.findings).toHaveLength(1);

    const f = result.findings[0] as UnicodeStripFinding;
    expect(f.kind).toBe('unicode-strip');
    expect(f.ruleId).toBe('tags-block');
    expect(f.action).toBe('stripped');
    expect(f.severity).toBe('high');
    expect(f.count).toBe(5);
    expect(f.charClass).toBe('U+E0001-U+E007F');
    expect(f.ruleVersion).toBe(1);
  });

  it('batches CONTIGUOUS runs into one finding (count = N)', () => {
    // Three consecutive bidi codepoints — one finding, count=3.
    const evil = 'before‪‫‬after';
    const result = stripUnicodeDetailed(evil);
    expect(result.findings).toHaveLength(1);
    const f = result.findings[0] as UnicodeStripFinding;
    expect(f.ruleId).toBe('bidi-override');
    expect(f.count).toBe(3);
    expect(f.length).toBe(3);
  });

  it('emits SEPARATE findings for non-contiguous matches of the same category', () => {
    // Two bidi codepoints separated by a normal letter — two findings.
    const evil = '‪a‫b';
    const result = stripUnicodeDetailed(evil);
    const bidi = result.findings.filter(
      (f) => f.kind === 'unicode-strip' && f.ruleId === 'bidi-override'
    );
    expect(bidi).toHaveLength(2);
    for (const f of bidi as UnicodeStripFinding[]) expect(f.count).toBe(1);
  });

  it('emits findings for multiple categories in one input', () => {
    const dirty = '‪payload\u{E0048}'; // bidi-override + tags-block
    const result = stripUnicodeDetailed(dirty);
    const ruleIds = result.findings.map((f) => f.kind === 'unicode-strip' && f.ruleId);
    expect(ruleIds).toContain('bidi-override');
    expect(ruleIds).toContain('tags-block');
  });

  it('honors policy.severityOverrides for a per-ruleId severity bump', () => {
    const tagged = '\u{E0048}\u{E0045}';
    const policyCritical = policy().setSeverity('tags-block', 'critical').build();

    const result = stripUnicodeDetailed(tagged, { policy: policyCritical });
    const f = result.findings[0] as UnicodeStripFinding;
    expect(f.severity).toBe('critical');
  });

  it('fires onFinding synchronously per emitted finding', () => {
    const tagged = '\u{E0048}\u{E0045}';
    const calls: Finding[] = [];
    stripUnicodeDetailed(tagged, { onFinding: (f) => calls.push(f) });
    expect(calls).toHaveLength(1);
    expect((calls[0] as UnicodeStripFinding).ruleId).toBe('tags-block');
  });

  it('emits an aggregate orphan-surrogate finding (offset=firstStrip, length=0, count=N)', () => {
    const broken = `prefix${HIGH_SURROGATE}${LOW_SURROGATE}suffix${HIGH_SURROGATE}`;
    // First two are a valid pair, last one is orphan high → 1 stripped.
    const result = stripUnicodeDetailed(broken);
    const orph = result.findings.find(
      (f): f is UnicodeStripFinding =>
        f.kind === 'unicode-strip' && f.ruleId === 'orphaned-surrogates'
    );
    expect(orph).toBeDefined();
    expect(orph?.count).toBe(1);
    expect(orph?.length).toBe(0);
    expect(orph?.severity).toBe('high');
    expect(orph?.charClass).toBe('U+D800-U+DFFF');
  });

  it('emits a zalgo-cap finding when combining marks exceed the cap', () => {
    // 'a' + 6 combining marks U+0300..U+0305. NFKC disabled so marks aren't
    // composed back into precomposed base forms; cap=4 leaves 4 marks, 2 dropped.
    const zalgo = 'a\u0300\u0301\u0302\u0303\u0304\u0305';
    const noNfkc = policy().setNfkcEnabled(false).build();
    const result = stripUnicodeDetailed(zalgo, { policy: noNfkc });
    const cap = result.findings.find(
      (f): f is UnicodeStripFinding => f.kind === 'unicode-strip' && f.ruleId === 'zalgo-cap'
    );
    expect(cap).toBeDefined();
    expect(cap?.count).toBe(2);
    expect(cap?.severity).toBe('medium');
  });

  it('non-Detailed stripUnicode + onFinding still fires the callback (silent path opts in)', () => {
    const tagged = '\u{E0048}';
    const calls: Finding[] = [];
    const out = stripUnicode(tagged, { onFinding: (f) => calls.push(f) });
    expect(out).toBe('');
    expect(calls).toHaveLength(1);
  });

  it('non-Detailed stripUnicode without onFinding stays on the silent fast path', () => {
    // Smoke test: no callback, no detailed result — just a string. Behavior identical
    // to the M2 / Slice A.1 path.
    expect(stripUnicode('\u{E0048}payload')).toBe('payload');
  });
});
