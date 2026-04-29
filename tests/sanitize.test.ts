import { describe, expect, it } from 'vitest';
import type { CredentialFinding, Finding, UnicodeStripFinding } from '../src/findings.js';
import { policy } from '../src/policy.js';
import { sanitize, sanitizeDetailed } from '../src/sanitize.js';

// Codepoints that don't survive JSON transport (per ops-test-protocol).
const ZWSP = String.fromCharCode(0x200b);
const RLO = String.fromCharCode(0x202e);
const PDF = String.fromCharCode(0x202c);
const ESC = String.fromCharCode(0x1b);

describe('sanitize (silent composed pipeline)', () => {
  it('passes clean ASCII unchanged by reference', () => {
    const input = 'plain prose with no threats';
    const out = sanitize(input);
    expect(out).toBe(input);
    expect(Object.is(out, input)).toBe(true);
  });

  it('zero-width-laced credential is revealed by stripUnicode then redacted', () => {
    // ZWSP between credential characters; naive regex misses it. The composed
    // pipeline normalizes first, redacts second.
    const hidden = `AKI${ZWSP}AIOSFODNN7${ZWSP}EXAMPLE`;
    expect(sanitize(hidden)).toBe('<credential>');
  });

  it('bidi-override-wrapped credential is unwrapped then redacted', () => {
    expect(sanitize(`${RLO}AKIAIOSFODNN7EXAMPLE${PDF}`)).toBe('<credential>');
  });

  it('ANSI-wrapped credential is unwrapped then redacted', () => {
    expect(sanitize(`${ESC}[31mAKIAIOSFODNN7EXAMPLE${ESC}[0m`)).toBe('<credential>');
  });

  it('reasoning-tag block carrying a credential is removed wholesale', () => {
    const input = '<internal>cached AKIAIOSFODNN7EXAMPLE</internal>response';
    expect(sanitize(input)).toBe('response');
  });

  it('NFKC folds fullwidth delimiters before downstream stages run', () => {
    // ＜system＞ folds to <system>; the credential between still redacts.
    const input = '＜system＞ AKIAIOSFODNN7EXAMPLE ＜/system＞';
    expect(sanitize(input)).toBe('<system> <credential> </system>');
  });

  it('Tags-block invisibles + reasoning-leak + visible credential — full agentic-loop cleanse', () => {
    const TAGS_HELLO = '\u{E0048}\u{E0045}\u{E004C}\u{E004C}\u{E004F}';
    const input =
      `output:${TAGS_HELLO} ` +
      `<internal>cached secret AKIAIOSFODNN7EXAMPLE</internal> ` +
      `next: AKIAIOSFODNN7EXAMPLE`;
    expect(sanitize(input)).toBe('output:  next: <credential>');
  });
});

describe('sanitize — onFinding callback (telemetry on silent surface)', () => {
  it('fires synchronously per stage, in pipeline order: unicode-strip → reasoning-tag → credential', () => {
    // ZWSP forces a unicode-strip emit; <internal> forces a reasoning-tag emit;
    // AKIA... forces a credential emit. Order asserts the composed pipeline runs
    // unicode → tags → redact regardless of where threats appear in the input.
    const input = `${ZWSP}<internal>x</internal>AKIAIOSFODNN7EXAMPLE`;
    const seen: Array<{ kind: Finding['kind']; ruleId: string }> = [];
    sanitize(input, { onFinding: (f) => seen.push({ kind: f.kind, ruleId: f.ruleId }) });

    expect(seen).toEqual([
      { kind: 'unicode-strip', ruleId: 'zero-width' },
      { kind: 'unicode-strip', ruleId: 'reasoning-tag' },
      { kind: 'credential', ruleId: 'aws-access-key' }
    ]);
  });

  it('does not fire for clean input', () => {
    const seen: Finding[] = [];
    const out = sanitize('clean ASCII', { onFinding: (f) => seen.push(f) });
    expect(seen).toEqual([]);
    expect(Object.is(out, 'clean ASCII')).toBe(true);
  });
});

describe('sanitizeDetailed', () => {
  it('returns a frozen result with findings array also frozen', () => {
    const r = sanitizeDetailed('<internal>x</internal>');
    expect(Object.isFrozen(r)).toBe(true);
    expect(Object.isFrozen(r.findings)).toBe(true);
  });

  it('preserves identity by reference when no stage transforms', () => {
    const input = 'clean ASCII';
    const r = sanitizeDetailed(input);
    expect(r.changed).toBe(false);
    expect(Object.is(r.text, input)).toBe(true);
    expect(r.findings).toEqual([]);
  });

  it('merges findings from every stage in pipeline order', () => {
    const input = `${ZWSP}<internal>x</internal>AKIAIOSFODNN7EXAMPLE`;
    const r = sanitizeDetailed(input);

    expect(r.changed).toBe(true);
    expect(r.findings.map((f) => ({ kind: f.kind, ruleId: f.ruleId }))).toEqual([
      { kind: 'unicode-strip', ruleId: 'zero-width' },
      { kind: 'unicode-strip', ruleId: 'reasoning-tag' },
      { kind: 'credential', ruleId: 'aws-access-key' }
    ]);
  });

  it('still fires user onFinding while populating findings', () => {
    const seen: Finding[] = [];
    const r = sanitizeDetailed('<internal>x</internal>AKIAIOSFODNN7EXAMPLE', {
      onFinding: (f) => seen.push(f)
    });
    expect(seen.length).toBe(r.findings.length);
    expect(seen).toEqual([...r.findings]);
  });

  it('cross-stage offset frame: each stage`s findings reference its own input text', () => {
    // Input  : ZWSP + 'A<internal>x</internal>B'
    // After U: 'A<internal>x</internal>B'   (ZWSP at offset 0 stripped)
    // After T: 'AB'                          (tag at offset 1 in post-U text)
    //
    // Reasoning-tag finding offset MUST be 1 (post-stripUnicode position),
    // not 2 (original input position). v0.1 contract — primer + spec-api §6.
    const input = `${ZWSP}A<internal>x</internal>B`;
    const r = sanitizeDetailed(input);

    const u = r.findings.find((f) => f.ruleId === 'zero-width') as UnicodeStripFinding;
    const t = r.findings.find((f) => f.ruleId === 'reasoning-tag') as UnicodeStripFinding;

    expect(u.offset).toBe(0);
    expect(t.offset).toBe(1);
    expect(r.text).toBe('AB');
  });
});

describe('sanitize — policy plumbing', () => {
  it('custom credential pattern from policy flows through to redact stage', () => {
    const customPolicy = policy()
      .addCredentialPattern(/SECRET-[A-Z0-9]{8}/g, { ruleId: 'custom-marker' })
      .build();
    const input = 'token=SECRET-ABCD1234 and AKIAIOSFODNN7EXAMPLE';
    expect(sanitize(input, { policy: customPolicy })).toBe('token=<credential> and <credential>');
  });

  it('severityOverride on a stage rule reaches the merged findings', () => {
    const customPolicy = policy().setSeverity('aws-access-key', 'critical').build();
    const r = sanitizeDetailed('AKIAIOSFODNN7EXAMPLE', { policy: customPolicy });
    const credFinding = r.findings.find((f) => f.kind === 'credential') as CredentialFinding;
    expect(credFinding.severity).toBe('critical');
  });

  it('disabling a unicode category in policy disables it in the composed pipeline', () => {
    // Disable zero-width: ZWSP is no longer stripped, so the credential remains
    // hidden and AWS pattern doesn't match.
    const customPolicy = policy().disableUnicodeCategory('zero-width').build();
    const hidden = `AKI${ZWSP}AIOSFODNN7${ZWSP}EXAMPLE`;
    const out = sanitize(hidden, { policy: customPolicy });
    expect(out).toBe(hidden);
    expect(Object.is(out, hidden)).toBe(true);
  });

  it('custom reasoning-tag name flows through to stripTags stage', () => {
    const customPolicy = policy().addReasoningTag('thinking').build();
    expect(sanitize('keep<thinking>plan</thinking>this', { policy: customPolicy })).toBe(
      'keepthis'
    );
  });
});
