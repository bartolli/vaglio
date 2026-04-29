import { describe, expect, it } from 'vitest';
import { sanitize } from '../src/sanitize.js';

// Codepoints that don't survive JSON transport (per ops-test-protocol).
const ZWSP = String.fromCharCode(0x200b);
const RLO = String.fromCharCode(0x202e);
const PDF = String.fromCharCode(0x202c);
const ESC = String.fromCharCode(0x1b);

// Pipeline order (spec-api §2): stripUnicode → stripTags → redact. Locked because:
//   - unicode first: invisibles / fullwidth / ANSI / bidi must be normalized before
//     the downstream stages can see what they're matching against. A credential
//     hidden by ZWSP must be revealed before redact runs; a tag boundary obscured
//     by ZWSP must be revealed before stripTags runs.
//   - tags second: removes whole reasoning blocks. Credentials embedded inside a
//     reasoning block disappear with the block — no need to redact what isn't there.
//   - redact last: catches whatever credentials remain in visible text.
// Slice-D-specific assertions (onFinding ordering, sanitizeDetailed identity, etc.)
// live in sanitize.test.ts; this file pins the agentic-loop threat shapes against
// the public root export.

describe('composed pipeline (stripUnicode → stripTags → redact)', () => {
  it('passes clean ASCII unchanged', () => {
    expect(sanitize('Hello, world! 123')).toBe('Hello, world! 123');
  });

  it('preserves legitimate Cyrillic / CJK / emoji while redacting an adjacent credential', () => {
    expect(sanitize('Здравейте 你好 🌍 — token=AKIAIOSFODNN7EXAMPLE')).toBe(
      'Здравейте 你好 🌍 — token=<credential>'
    );
  });

  describe('threat: credential hidden behind invisibles', () => {
    it('zero-width space between credential characters does not shield from redaction', () => {
      // Tool output / RAG chunk contains a credential laced with ZWSP. A naive
      // regex pass would miss it; stripUnicode reveals the canonical form first.
      const hidden = `AKI${ZWSP}AIOSFODNN7${ZWSP}EXAMPLE`;
      expect(sanitize(hidden)).toBe('<credential>');
    });

    it('bidi override around a credential is stripped before redact runs', () => {
      // U+202E RLO + credential + U+202C PDF — bidi controls flagged for unconditional strip.
      expect(sanitize(`${RLO}AKIAIOSFODNN7EXAMPLE${PDF}`)).toBe('<credential>');
    });

    it('ANSI escape wrapping does not shield credentials in MCP/CLI tool output', () => {
      // MCP tools and CLI integrations frequently emit ANSI color codes. The terminal
      // hides them; the LLM tokenizes the raw bytes and the credential remains visible.
      expect(sanitize(`${ESC}[31mAKIAIOSFODNN7EXAMPLE${ESC}[0m`)).toBe('<credential>');
    });
  });

  describe('threat: reasoning-tag credential leak', () => {
    it('credential embedded inside <internal>...</internal> is removed with the block', () => {
      // Agent's reasoning trace contains a credential it saw earlier. Without
      // sanitization, downstream tools / users see it.
      const input = '<internal>my key is AKIAIOSFODNN7EXAMPLE, plan: ...</internal>response';
      expect(sanitize(input)).toBe('response');
    });

    it('reasoning block + adjacent visible credential: tag removed AND credential redacted', () => {
      const input = '<internal>thinking step</internal> output: token=AKIAIOSFODNN7EXAMPLE';
      expect(sanitize(input)).toBe(' output: token=<credential>');
    });
  });

  describe('threat: NFKC homoglyph / fullwidth-delimiter forging', () => {
    it('fullwidth angle brackets fold to ASCII, credential still redacted', () => {
      // Attacker uses ＜system＞ to forge a system tag past a naive `<`/`>` filter.
      // NFKC folds the brackets to canonical `<>`; the credential pattern still matches.
      // Note: Vaglio's job is to canonicalize; downstream filtering of `<system>` itself
      // is the consumer's concern (out of scope per spec).
      const input = '＜system＞ AKIAIOSFODNN7EXAMPLE ＜/system＞';
      expect(sanitize(input)).toBe('<system> <credential> </system>');
    });
  });

  describe('threat: composite agentic-loop attack', () => {
    it('Tags-block hidden payload + reasoning-tag credential leak + visible credential', () => {
      // Multi-vector tool output crossing into the next agentic step:
      //   - Tags-block (U+E0048 ... U+E004F) carries hidden "HELLO" — would smuggle
      //     instructions in a real attack.
      //   - <internal>...</internal> leaks a credential the agent saw earlier.
      //   - A separate visible credential sits in the response text.
      // Sanitized output: hidden Tags-block stripped, reasoning block excised,
      // visible credential redacted. Nothing survives that the next model can act on.
      const TAGS_HELLO = '\u{E0048}\u{E0045}\u{E004C}\u{E004C}\u{E004F}';
      const input =
        `output:${TAGS_HELLO} ` +
        `<internal>cached secret AKIAIOSFODNN7EXAMPLE</internal> ` +
        `next: AKIAIOSFODNN7EXAMPLE`;
      expect(sanitize(input)).toBe('output:  next: <credential>');
    });
  });

  describe('identity: clean input round-trips by reference', () => {
    it('a clean string passes through all three stages unchanged by reference', () => {
      // Clean input avoids: any unicode-strip codepoint, any `<` (tag fast-path),
      // any credential pattern.
      const input = 'plain prose with no threats';
      expect(sanitize(input)).toBe(input);
      expect(Object.is(sanitize(input), input)).toBe(true);
    });
  });
});
