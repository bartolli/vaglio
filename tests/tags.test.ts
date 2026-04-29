import { describe, expect, it } from 'vitest';
import type { Finding, UnicodeStripFinding } from '../src/findings.js';
import { DEFAULT_POLICY, policy } from '../src/policy.js';
import { DEFAULT_REASONING_TAGS, stripTags, stripTagsDetailed } from '../src/tags.js';

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

    it('DEFAULT_REASONING_TAGS matches DEFAULT_POLICY.reasoningTags.names', () => {
      // DEFAULT_REASONING_TAGS is informational (spec-api §1 vaglio/tags subpath);
      // the runtime reads from DEFAULT_POLICY.reasoningTags.names. Both should agree.
      expect([...DEFAULT_POLICY.reasoningTags.names].sort()).toEqual(
        [...DEFAULT_REASONING_TAGS].sort()
      );
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

  describe('configurable tag names (via policy())', () => {
    it('accepts a single added tag name', () => {
      const customPolicy = policy().addReasoningTag('thinking').build();
      expect(stripTags('a<thinking>plan</thinking>b', { policy: customPolicy })).toBe('ab');
    });

    it('accepts multiple added tag names', () => {
      const customPolicy = policy()
        .addReasoningTag('x')
        .addReasoningTag('y')
        .addReasoningTag('z')
        .build();
      const input = 'a<x>1</x>b<y>2</y>c<z>3</z>d';
      expect(stripTags(input, { policy: customPolicy })).toBe('abcd');
    });

    it('does not strip tags whose name is not in the policy set', () => {
      // Default 'internal' removed; only 'thinking' active.
      const customPolicy = policy()
        .removeReasoningTag('internal')
        .addReasoningTag('thinking')
        .build();
      expect(stripTags('keep<internal>x</internal>this', { policy: customPolicy })).toBe(
        'keep<internal>x</internal>this'
      );
    });

    it('returns input unchanged when reasoning-tag set is empty', () => {
      const input = 'a<internal>x</internal>b';
      const customPolicy = policy().removeReasoningTag('internal').build();
      const result = stripTags(input, { policy: customPolicy });
      expect(result).toBe(input);
      expect(Object.is(result, input)).toBe(true);
    });

    it('escapes regex metacharacters in tag names (defensive)', () => {
      // The `.` in `re.gex` must match literally, not "any character".
      // Without escaping it would also match `<reXgex>...</reXgex>`.
      const customPolicy = policy().addReasoningTag('re.gex').build();
      const input = 'a<re.gex>x</re.gex>b<reXgex>y</reXgex>c';
      expect(stripTags(input, { policy: customPolicy })).toBe('ab<reXgex>y</reXgex>c');
    });

    it('case-sensitive by default (consumers add casing variants explicitly)', () => {
      // Default policy strips only `internal`, not `INTERNAL`.
      expect(stripTags('a<INTERNAL>x</INTERNAL>b')).toBe('a<INTERNAL>x</INTERNAL>b');
      const customPolicy = policy().addReasoningTag('INTERNAL').build();
      expect(stripTags('a<INTERNAL>x</INTERNAL>b', { policy: customPolicy })).toBe('ab');
    });
  });

  describe('preservation invariants', () => {
    it('preserves empty string', () => {
      expect(stripTags('')).toBe('');
    });

    it('returns same string reference when input is clean (identity preservation)', () => {
      // spec-api §2: stripTags returns input by reference if no transformation occurred.
      // The `!text.includes('<')` fast-path guarantees this without running the regex.
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

describe('stripTags — Policy plumbing (Slice C)', () => {
  it('uses DEFAULT_POLICY when no options are passed', () => {
    expect(stripTags('a<internal>x</internal>b')).toBe('ab');
  });

  it('uses DEFAULT_POLICY when options object has no policy', () => {
    expect(stripTags('a<internal>x</internal>b', {})).toBe('ab');
  });

  it('reads policy.reasoningTags.names (custom policy overrides default)', () => {
    const customPolicy = policy()
      .removeReasoningTag('internal')
      .addReasoningTag('reasoning')
      .build();
    expect(stripTags('a<reasoning>x</reasoning>b', { policy: customPolicy })).toBe('ab');
    expect(stripTags('a<internal>x</internal>b', { policy: customPolicy })).toBe(
      'a<internal>x</internal>b'
    );
  });

  it('default and added names cooperate (both stripped)', () => {
    const customPolicy = policy().addReasoningTag('thinking').build();
    expect(
      stripTags('a<internal>x</internal>b<thinking>y</thinking>c', { policy: customPolicy })
    ).toBe('abc');
  });
});

describe('stripTagsDetailed (Slice C)', () => {
  it('returns identity reference (Object.is) when input has no tags', () => {
    // Identity-preservation invariant per spec-api §2 — required test per ops-test-protocol.
    const input = 'clean text without tag delimiters';
    const result = stripTagsDetailed(input);
    expect(result.changed).toBe(false);
    expect(Object.is(result.text, input)).toBe(true);
    expect(result.findings).toEqual([]);
  });

  it('returns identity reference when names set is empty', () => {
    const input = 'a<internal>x</internal>b';
    const customPolicy = policy().removeReasoningTag('internal').build();
    const result = stripTagsDetailed(input, { policy: customPolicy });
    expect(result.changed).toBe(false);
    expect(Object.is(result.text, input)).toBe(true);
    expect(result.findings).toEqual([]);
  });

  it('returns identity reference when `<` is present but no tag match (telemetry path)', () => {
    // Exercises the telemetry branch where the includes('<') fast-path doesn't fire,
    // matchAll runs, finds nothing, `any` stays false, and the original ref is returned.
    // Without this case, the only stripTagsDetailed identity test goes through the
    // `!text.includes('<')` early return.
    const input = 'function f<T>(x: T): T { return x; }';
    const result = stripTagsDetailed(input);
    expect(result.changed).toBe(false);
    expect(Object.is(result.text, input)).toBe(true);
    expect(result.findings).toEqual([]);
  });

  it('emits one UnicodeStripFinding per stripped block (full shape)', () => {
    const input = 'before<internal>secret</internal>after';
    const result = stripTagsDetailed(input);
    expect(result.changed).toBe(true);
    expect(result.text).toBe('beforeafter');
    expect(result.findings).toHaveLength(1);
    const f = result.findings[0] as UnicodeStripFinding;
    expect(f.kind).toBe('unicode-strip');
    expect(f.ruleId).toBe('reasoning-tag');
    expect(f.ruleVersion).toBe(1);
    expect(f.action).toBe('stripped');
    expect(f.charClass).toBe('internal');
    expect(f.count).toBe('<internal>secret</internal>'.length);
    expect(f.severity).toBe('medium');
    // offset = position of `<internal>` in the input.
    expect(f.offset).toBe(input.indexOf('<internal>'));
    // length = `<internal>secret</internal>`.length.
    expect(f.length).toBe('<internal>secret</internal>'.length);
  });

  it('emits separate findings for separate blocks (lazy match)', () => {
    // Two distinct blocks → two findings; offsets monotonically increasing.
    const input = '<internal>a</internal>keep<internal>b</internal>';
    const result = stripTagsDetailed(input);
    expect(result.text).toBe('keep');
    expect(result.findings).toHaveLength(2);
    const offsets = result.findings.map((f) => (f.kind === 'unicode-strip' ? f.offset : -1));
    expect(offsets[0]).toBe(0);
    expect(offsets[1]).toBe(input.indexOf('<internal>b'));
  });

  it('multi-line block: finding length spans the full <name>...</name>', () => {
    const block = '<internal>line1\nline2\nline3</internal>';
    const input = `pre${block}post`;
    const result = stripTagsDetailed(input);
    expect(result.text).toBe('prepost');
    expect(result.findings).toHaveLength(1);
    const f = result.findings[0] as UnicodeStripFinding;
    expect(f.offset).toBe('pre'.length);
    expect(f.length).toBe(block.length);
  });

  it('returns frozen findings array', () => {
    const result = stripTagsDetailed('a<internal>x</internal>b');
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.findings)).toBe(true);
    expect(Object.isFrozen(result.findings[0])).toBe(true);
  });

  it('changed === false when policy has empty names set even with tag-like input', () => {
    const customPolicy = policy().removeReasoningTag('internal').build();
    const result = stripTagsDetailed('a<internal>x</internal>b', { policy: customPolicy });
    expect(result.changed).toBe(false);
  });
});

describe('stripTags — onFinding + severity (Slice C)', () => {
  it('onFinding fires synchronously from non-Detailed stripTags', () => {
    // Findings array is NOT retained when stripTags is the entry point (only the callback fires).
    const observed: Finding[] = [];
    const out = stripTags('a<internal>x</internal>b<internal>y</internal>c', {
      onFinding: (f) => observed.push(f)
    });
    expect(out).toBe('abc');
    expect(observed).toHaveLength(2);
    expect(observed[0]?.kind).toBe('unicode-strip');
    if (observed[0]?.kind === 'unicode-strip') {
      expect(observed[0].charClass).toBe('internal');
    }
  });

  it('onFinding fires from stripTagsDetailed; both callback and findings array see the same events in order', () => {
    const observed: Finding[] = [];
    const result = stripTagsDetailed('a<internal>x</internal>b<internal>y</internal>c', {
      onFinding: (f) => observed.push(f)
    });
    expect(result.findings).toHaveLength(2);
    expect(observed).toHaveLength(2);
    expect(observed[0]).toBe(result.findings[0]);
    expect(observed[1]).toBe(result.findings[1]);
  });

  it('severity defaults to medium for reasoning-tag findings', () => {
    const result = stripTagsDetailed('a<internal>x</internal>b');
    const f = result.findings[0] as UnicodeStripFinding;
    expect(f.severity).toBe('medium');
  });

  it('policy.severityOverrides for reasoning-tag beats the default medium', () => {
    const customPolicy = policy().setSeverity('reasoning-tag', 'high').build();
    const result = stripTagsDetailed('a<internal>x</internal>b', { policy: customPolicy });
    const f = result.findings[0] as UnicodeStripFinding;
    expect(f.severity).toBe('high');
  });

  it('multiple configured names each emit findings carrying their own charClass', () => {
    const customPolicy = policy().addReasoningTag('thinking').build();
    const input = 'a<internal>x</internal>b<thinking>y</thinking>c';
    const result = stripTagsDetailed(input, { policy: customPolicy });
    expect(result.text).toBe('abc');
    expect(result.findings).toHaveLength(2);
    const charClasses = result.findings
      .map((f) => (f.kind === 'unicode-strip' ? f.charClass : null))
      .filter((c): c is string => c !== null)
      .sort();
    expect(charClasses).toEqual(['internal', 'thinking']);
  });

  it('cross-name offset frame: later names see post-prior-pass text', () => {
    // v0.1 contract documented in src/tags.ts header. After 'internal' iterates and
    // strips its block, 'thinking' runs against the post-internal text — so the
    // 'thinking' finding's offset is in the rewritten text, NOT the original input.
    const customPolicy = policy().addReasoningTag('thinking').build();
    const internalBlock = '<internal>aaaa</internal>';
    const thinkingBlock = '<thinking>bb</thinking>';
    const input = `${internalBlock}${thinkingBlock}`;
    const result = stripTagsDetailed(input, { policy: customPolicy });
    expect(result.text).toBe('');

    const findingsByClass = new Map<string, UnicodeStripFinding>();
    for (const f of result.findings) {
      if (f.kind === 'unicode-strip') findingsByClass.set(f.charClass, f);
    }
    const internalFinding = findingsByClass.get('internal');
    const thinkingFinding = findingsByClass.get('thinking');
    if (!internalFinding || !thinkingFinding) throw new Error('expected both findings');
    // 'internal' iterates first (Set insertion order: default 'internal', then added 'thinking').
    // Its offset is at position 0 in the original input.
    expect(internalFinding.offset).toBe(0);
    expect(internalFinding.length).toBe(internalBlock.length);
    // 'thinking' runs against the text WITH the internal block already removed.
    // The original-input offset was internalBlock.length (24); the post-prior-pass offset is 0.
    expect(thinkingFinding.offset).toBe(0);
    expect(thinkingFinding.length).toBe(thinkingBlock.length);
  });
});
