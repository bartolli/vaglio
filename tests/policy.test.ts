/**
 * Tests for src/policy.ts.
 *
 * Covers DEFAULT_POLICY shape, builder immutability, every customization
 * method, build() validation paths (duplicate ruleId, buffer-limit floor),
 * and the frozen output contract.
 */

import { describe, expect, it } from 'vitest';
import { type CredentialPattern, DEFAULT_CREDENTIAL_PATTERNS } from '../src/credentials.js';
import { VaglioPolicyValidationError, VaglioStreamCanceledError } from '../src/errors.js';
import { DEFAULT_POLICY, type Policy, policy } from '../src/policy.js';

describe('DEFAULT_POLICY', () => {
  it('is frozen at the top level', () => {
    expect(Object.isFrozen(DEFAULT_POLICY)).toBe(true);
  });

  it('freezes nested unicode/credentials/strip/reasoningTags slots', () => {
    expect(Object.isFrozen(DEFAULT_POLICY.unicode)).toBe(true);
    expect(Object.isFrozen(DEFAULT_POLICY.credentials)).toBe(true);
    expect(Object.isFrozen(DEFAULT_POLICY.strip)).toBe(true);
    expect(Object.isFrozen(DEFAULT_POLICY.reasoningTags)).toBe(true);
  });

  it('enables all 13 Unicode categories', () => {
    expect(DEFAULT_POLICY.unicode.categories.size).toBe(13);
    expect(DEFAULT_POLICY.unicode.categories.has('tags-block')).toBe(true);
    expect(DEFAULT_POLICY.unicode.categories.has('orphaned-surrogates')).toBe(true);
    expect(DEFAULT_POLICY.unicode.categories.has('ansi-escapes')).toBe(true);
    expect(DEFAULT_POLICY.unicode.categories.has('c0-c1-controls')).toBe(true);
  });

  it('seeds default credential patterns', () => {
    expect(DEFAULT_POLICY.credentials.patterns).toHaveLength(DEFAULT_CREDENTIAL_PATTERNS.length);
    expect(DEFAULT_POLICY.credentials.patterns.map((p) => p.ruleId)).toContain('pem-private-key');
  });

  it('starts with no user strip patterns', () => {
    expect(DEFAULT_POLICY.strip.patterns).toHaveLength(0);
  });

  it('seeds the default reasoning-tag set with "internal"', () => {
    expect(DEFAULT_POLICY.reasoningTags.names.has('internal')).toBe(true);
    expect(DEFAULT_POLICY.reasoningTags.names.size).toBe(1);
  });

  it('uses "<credential>" as the default placeholder', () => {
    expect(DEFAULT_POLICY.placeholderDefault).toBe('<credential>');
  });

  it('caps combining marks at 4 by default', () => {
    expect(DEFAULT_POLICY.unicode.combiningMarkCap).toBe(4);
  });

  it('has nfkcEnabled default true', () => {
    expect(DEFAULT_POLICY.unicode.nfkcEnabled).toBe(true);
  });

  it('auto-derives bufferLimit from PEM (4096) + slack (64) = 4160', () => {
    expect(DEFAULT_POLICY.bufferLimit).toBe(4160);
  });

  it('starts with no severity overrides', () => {
    expect(Object.keys(DEFAULT_POLICY.severityOverrides)).toHaveLength(0);
  });
});

describe('PolicyBuilder — immutability', () => {
  it('returns a new builder from every customization method', () => {
    const a = policy();
    const b = a.addReasoningTag('plan');
    expect(a).not.toBe(b);
  });

  it('leaves the original builder unchanged after customization', () => {
    const base = policy().addReasoningTag('plan');
    const stricter = base.disableUnicodeCategory('soft-hyphen-fillers');

    // base.build() still has soft-hyphen-fillers enabled.
    const baseBuilt = base.build();
    expect(baseBuilt.unicode.categories.has('soft-hyphen-fillers')).toBe(true);

    const stricterBuilt = stricter.build();
    expect(stricterBuilt.unicode.categories.has('soft-hyphen-fillers')).toBe(false);
  });

  it('produces independent Policies from a shared base', () => {
    const base = policy().addReasoningTag('plan');
    const a: Policy = base.disableUnicodeCategory('math-invisibles').build();
    const b: Policy = base.disableUnicodeCategory('soft-hyphen-fillers').build();

    expect(a.unicode.categories.has('math-invisibles')).toBe(false);
    expect(a.unicode.categories.has('soft-hyphen-fillers')).toBe(true);

    expect(b.unicode.categories.has('math-invisibles')).toBe(true);
    expect(b.unicode.categories.has('soft-hyphen-fillers')).toBe(false);
  });

  it('returns the same builder when adding a tag that is already present (no-op short-circuit)', () => {
    const a = policy();
    const b = a.addReasoningTag('internal'); // 'internal' is already in defaults.
    expect(a).toBe(b);
  });

  it('returns the same builder when removing an absent reasoning tag', () => {
    const a = policy();
    const b = a.removeReasoningTag('not-present');
    expect(a).toBe(b);
  });

  it('returns the same builder when enabling an already-enabled Unicode category', () => {
    const a = policy();
    const b = a.enableUnicodeCategory('tags-block');
    expect(a).toBe(b);
  });
});

describe('PolicyBuilder — addCredentialPattern overloads', () => {
  it('accepts (RegExp, options) form', () => {
    const built = policy()
      .addCredentialPattern(/sk-myorg-[a-z0-9]{32}/g, {
        ruleId: 'myorg-key',
        placeholder: '<myorg>'
      })
      .build();

    const myorg = built.credentials.patterns.find((p) => p.ruleId === 'myorg-key');
    expect(myorg).toBeDefined();
    expect(myorg?.placeholder).toBe('<myorg>');
    expect(myorg?.pattern.source).toBe('sk-myorg-[a-z0-9]{32}');
  });

  it('accepts a fully-formed CredentialPattern object', () => {
    const entry: CredentialPattern = Object.freeze({
      ruleId: 'gitlab-pat',
      pattern: /glpat-[A-Za-z0-9_-]{20}/g,
      placeholder: '<gitlab>',
      severity: 'high' as const
    });

    const built = policy().addCredentialPattern(entry).build();
    const gitlab = built.credentials.patterns.find((p) => p.ruleId === 'gitlab-pat');
    expect(gitlab).toBeDefined();
    expect(gitlab?.severity).toBe('high');
  });

  it('removeCredentialPattern drops the matching ruleId', () => {
    const built = policy().removeCredentialPattern('long-hex').build();
    expect(built.credentials.patterns.find((p) => p.ruleId === 'long-hex')).toBeUndefined();
    expect(built.credentials.patterns.length).toBe(DEFAULT_CREDENTIAL_PATTERNS.length - 1);
  });

  it('removeCredentialPattern is a no-op for an absent ruleId', () => {
    const built = policy().removeCredentialPattern('not-a-real-rule').build();
    expect(built.credentials.patterns.length).toBe(DEFAULT_CREDENTIAL_PATTERNS.length);
  });
});

describe('PolicyBuilder — strip patterns', () => {
  it('addStripPattern registers a regex with a user-supplied ruleId', () => {
    const built = policy()
      .addStripPattern(/\bclassified\b/g, { ruleId: 'classified-marker', severity: 'high' })
      .build();

    expect(built.strip.patterns).toHaveLength(1);
    const entry = built.strip.patterns[0];
    expect(entry?.ruleId).toBe('classified-marker');
    expect(entry?.severity).toBe('high');
    expect(entry?.pattern.source).toBe('\\bclassified\\b');
  });

  it('removeStripPattern drops the matching ruleId', () => {
    const built = policy()
      .addStripPattern(/foo/g, { ruleId: 'foo' })
      .addStripPattern(/bar/g, { ruleId: 'bar' })
      .removeStripPattern('foo')
      .build();

    expect(built.strip.patterns).toHaveLength(1);
    expect(built.strip.patterns[0]?.ruleId).toBe('bar');
  });
});

describe('PolicyBuilder — reasoning tags', () => {
  it('addReasoningTag adds a name to the set', () => {
    const built = policy().addReasoningTag('scratchpad').build();
    expect(built.reasoningTags.names.has('scratchpad')).toBe(true);
    expect(built.reasoningTags.names.has('internal')).toBe(true);
  });

  it('removeReasoningTag removes a name from the set', () => {
    const built = policy().removeReasoningTag('internal').build();
    expect(built.reasoningTags.names.has('internal')).toBe(false);
    expect(built.reasoningTags.names.size).toBe(0);
  });
});

describe('PolicyBuilder — knobs', () => {
  it('setCombiningMarkCap overrides the default cap', () => {
    const built = policy().setCombiningMarkCap(2).build();
    expect(built.unicode.combiningMarkCap).toBe(2);
  });

  it('setNfkcEnabled toggles NFKC', () => {
    const built = policy().setNfkcEnabled(false).build();
    expect(built.unicode.nfkcEnabled).toBe(false);
  });

  it('setPlaceholderDefault overrides the default redaction placeholder', () => {
    const built = policy().setPlaceholderDefault('<REDACTED>').build();
    expect(built.placeholderDefault).toBe('<REDACTED>');
  });

  it('setSeverity registers a per-ruleId severity override', () => {
    const built = policy().setSeverity('jwt', 'critical').build();
    expect(built.severityOverrides.jwt).toBe('critical');
  });

  it('setSeverity overrides accumulate across multiple calls', () => {
    const built = policy().setSeverity('jwt', 'critical').setSeverity('long-hex', 'low').build();
    expect(built.severityOverrides.jwt).toBe('critical');
    expect(built.severityOverrides['long-hex']).toBe('low');
  });
});

describe('build() — bufferLimit auto-derivation and override', () => {
  it('grows when a longer maxMatchLength is added', () => {
    const built = policy()
      .addCredentialPattern(/AAA[\s\S]*?ZZZ/g, { ruleId: 'big', maxMatchLength: 10000 })
      .build();
    expect(built.bufferLimit).toBe(10000 + 64);
  });

  it('respects setBufferLimit when ≥ auto-derived minimum', () => {
    const built = policy().setBufferLimit(8000).build();
    // Default auto-min is 4160 (PEM 4096 + slack 64); 8000 is above the floor.
    expect(built.bufferLimit).toBe(8000);
  });

  it('throws VaglioPolicyValidationError when setBufferLimit is below the auto-min', () => {
    expect(() => policy().setBufferLimit(100).build()).toThrow(VaglioPolicyValidationError);
  });

  it('error.causes carries a "buffer-limit-too-low" cause with the auto-min in detail', () => {
    try {
      policy().setBufferLimit(100).build();
      expect.fail('expected build() to throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VaglioPolicyValidationError);
      const err = e as VaglioPolicyValidationError;
      expect(err.causes).toHaveLength(1);
      expect(err.causes[0]?.rule).toBe('buffer-limit-too-low');
      expect(err.causes[0]?.detail).toContain('4160');
    }
  });
});

describe('build() — duplicate ruleId validation', () => {
  it('throws when two credential patterns share a ruleId', () => {
    expect(() =>
      policy()
        .addCredentialPattern(/foo/g, { ruleId: 'shared' })
        .addCredentialPattern(/bar/g, { ruleId: 'shared' })
        .build()
    ).toThrow(VaglioPolicyValidationError);
  });

  it('throws when a credential pattern collides with a strip pattern by ruleId', () => {
    try {
      policy()
        .addCredentialPattern(/foo/g, { ruleId: 'shared' })
        .addStripPattern(/bar/g, { ruleId: 'shared' })
        .build();
      expect.fail('expected build() to throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VaglioPolicyValidationError);
      const err = e as VaglioPolicyValidationError;
      expect(err.causes).toHaveLength(1);
      expect(err.causes[0]?.rule).toBe('duplicate-rule-id');
    }
  });

  it('reports multiple validation failures in a single throw', () => {
    try {
      policy()
        .addCredentialPattern(/foo/g, { ruleId: 'shared' })
        .addCredentialPattern(/bar/g, { ruleId: 'shared' })
        .setBufferLimit(50)
        .build();
      expect.fail('expected build() to throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VaglioPolicyValidationError);
      const err = e as VaglioPolicyValidationError;
      expect(err.causes.length).toBeGreaterThanOrEqual(2);
      const rules = err.causes.map((c) => c.rule);
      expect(rules).toContain('duplicate-rule-id');
      expect(rules).toContain('buffer-limit-too-low');
    }
  });

  it('does NOT flag a ruleId reused after removeCredentialPattern', () => {
    const built = policy()
      .removeCredentialPattern('long-hex')
      .addCredentialPattern(/[A-F0-9]{40}/g, { ruleId: 'long-hex' })
      .build();
    expect(built.credentials.patterns.filter((p) => p.ruleId === 'long-hex')).toHaveLength(1);
  });
});

describe('VaglioPolicyValidationError', () => {
  it('exposes a frozen causes array', () => {
    const err = new VaglioPolicyValidationError([
      { pattern: '', rule: 'duplicate-rule-id', detail: 'x' }
    ]);
    expect(Object.isFrozen(err.causes)).toBe(true);
  });

  it('carries name and message, and is instanceof Error', () => {
    const err = new VaglioPolicyValidationError([
      { pattern: '', rule: 'duplicate-rule-id', detail: 'x' }
    ]);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('VaglioPolicyValidationError');
    expect(err.message).toContain('duplicate-rule-id');
  });
});

describe('VaglioStreamCanceledError', () => {
  it('carries name, reason, and is instanceof Error', () => {
    const reason = { code: 'user-aborted' };
    const err = new VaglioStreamCanceledError(reason);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('VaglioStreamCanceledError');
    expect(err.reason).toBe(reason);
  });
});

describe('policy() factory + built Policy independence', () => {
  it('returns a fresh builder per call', () => {
    expect(policy()).not.toBe(policy());
  });

  it('built Policy.unicode.categories is independent across builds (mutating one does not affect the other)', () => {
    const a: Policy = policy().build();
    const b: Policy = policy().build();
    // Sanity: TS prevents mutation; we cast through `Set<string>` to exercise the runtime
    // independence guarantee — even if a consumer reaches around the type system, the two
    // Policies must not share their underlying Set.
    (a.unicode.categories as Set<string>).delete('tags-block');
    expect(b.unicode.categories.has('tags-block')).toBe(true);
  });

  it('built Policy.reasoningTags.names is independent across builds', () => {
    const a: Policy = policy().build();
    const b: Policy = policy().build();
    (a.reasoningTags.names as Set<string>).delete('internal');
    expect(b.reasoningTags.names.has('internal')).toBe(true);
  });

  it('build() can be called multiple times off the same builder, producing structurally-equal Policies', () => {
    const base = policy().addReasoningTag('plan');
    const a = base.build();
    const b = base.build();
    expect(a).not.toBe(b); // distinct object identities
    expect(a.reasoningTags.names.has('plan')).toBe(true);
    expect(b.reasoningTags.names.has('plan')).toBe(true);
  });
});
