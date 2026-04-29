import { describe, expect, it } from 'vitest';
import {
  capCombiningMarks,
  normalizeNFKC,
  stripAnsiEscapes,
  stripOrphanedSurrogates,
  stripUnicode
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
