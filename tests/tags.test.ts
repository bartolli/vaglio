import { describe, expect, it } from 'vitest';
import { DEFAULT_REASONING_TAGS, stripTags } from '../src/tags.js';

describe('stripTags', () => {
  describe('default tag (internal)', () => {
    it('removes internal tag block', () => {
      expect(stripTags('before<internal>secret</internal>after')).toBe('beforeafter');
    });

    it('removes multiple internal blocks', () => {
      expect(stripTags('a<internal>1</internal>b<internal>2</internal>c')).toBe('abc');
    });

    it('handles multi-line block content (load-bearing: \\s\\S lazy)', () => {
      const input = 'pre<internal>line1\nline2\nline3</internal>post';
      expect(stripTags(input)).toBe('prepost');
    });

    it('lazy match does not over-match across multiple blocks', () => {
      // Greedy regex would consume everything between the FIRST `<internal>` and LAST `</internal>`,
      // wiping out the `keep` segment. Lazy (`*?`) stops at the first `</internal>`.
      const input = '<internal>a</internal>keep<internal>b</internal>';
      expect(stripTags(input)).toBe('keep');
    });

    it('preserves text with no internal tags', () => {
      expect(stripTags('plain text, no tags')).toBe('plain text, no tags');
    });

    it('DEFAULT_REASONING_TAGS contains internal', () => {
      expect(DEFAULT_REASONING_TAGS).toContain('internal');
    });

    it('DEFAULT_REASONING_TAGS is the implicit default for stripTags', () => {
      const input = 'a<internal>x</internal>b';
      expect(stripTags(input)).toBe(stripTags(input, DEFAULT_REASONING_TAGS));
    });

    it('handles nested same-name tags (lazy matches first open to first close)', () => {
      // Adversarial pattern: attacker nests tags hoping the outer block leaks.
      // Lazy regex pairs the first `<internal>` with the first `</internal>`,
      // leaving the inner `d</internal>e` as residue. The orphaned `</internal>`
      // is intentional — preservation of unbalanced closers is tested below.
      const input = 'a<internal>b<internal>c</internal>d</internal>e';
      expect(stripTags(input)).toBe('ad</internal>e');
    });
  });

  describe('configurable tag names', () => {
    it('accepts a single tag name as string', () => {
      expect(stripTags('a<thinking>plan</thinking>b', 'thinking')).toBe('ab');
    });

    it('accepts a list of tag names', () => {
      const input = 'a<x>1</x>b<y>2</y>c<z>3</z>d';
      expect(stripTags(input, ['x', 'y', 'z'])).toBe('abcd');
    });

    it('does not strip tags whose name is not in the list', () => {
      // 'internal' is the default but is overridden here by an explicit list.
      expect(stripTags('keep<internal>x</internal>this', ['thinking'])).toBe(
        'keep<internal>x</internal>this'
      );
    });

    it('returns input unchanged when names list is empty', () => {
      const input = 'a<internal>x</internal>b';
      expect(stripTags(input, [])).toBe(input);
    });

    it('escapes regex metacharacters in tag names (defensive)', () => {
      // The `.` in `re.gex` must match literally, not "any character".
      // Without escaping it would also match `<reXgex>...</reXgex>`.
      const input = 'a<re.gex>x</re.gex>b<reXgex>y</reXgex>c';
      expect(stripTags(input, ['re.gex'])).toBe('ab<reXgex>y</reXgex>c');
    });

    it('case-sensitive by default (consumers pass casing variants explicitly)', () => {
      expect(stripTags('a<INTERNAL>x</INTERNAL>b')).toBe('a<INTERNAL>x</INTERNAL>b');
      expect(stripTags('a<INTERNAL>x</INTERNAL>b', ['INTERNAL', 'internal'])).toBe('ab');
    });
  });

  describe('preservation invariants', () => {
    it('preserves empty string', () => {
      expect(stripTags('')).toBe('');
    });

    it('returns same string reference when input is clean (identity preservation)', () => {
      // spec-api §2: stripTags returns input by reference if no transformation occurred.
      // M3 task: add explicit guard so this holds across engines, not by V8 coincidence.
      const input = 'plain text without any tags';
      const result = stripTags(input);
      expect(result).toBe(input);
      expect(Object.is(result, input)).toBe(true);
    });

    it('does not strip an unbalanced opening tag with no closer', () => {
      // Lazy regex requires both open AND close. Bare `<internal>...` stays.
      expect(stripTags('a<internal>orphan')).toBe('a<internal>orphan');
    });

    it('does not strip an unbalanced closing tag with no opener', () => {
      expect(stripTags('orphan</internal>b')).toBe('orphan</internal>b');
    });

    it('preserves tag-like text inside an unrelated context', () => {
      const code = 'function f<T>(x: T): T { return x; }';
      expect(stripTags(code)).toBe(code);
    });

    it('preserves Unicode content in surrounding text', () => {
      // Tag-stripping is byte-domain; legitimate Unicode (Cyrillic, CJK, emoji) round-trips.
      const input = 'Здравейте<internal>x</internal>你好🌍';
      expect(stripTags(input)).toBe('Здравейте你好🌍');
    });

    it('preserves Unicode content INSIDE a tag block being stripped', () => {
      // Lazy match terminates at the first `</internal>` regardless of internal codepoints.
      expect(stripTags('a<internal>тест 你好 🌍</internal>b')).toBe('ab');
    });
  });
});
