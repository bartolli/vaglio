import { describe, expect, it } from 'vitest';
import { DEFAULT_CREDENTIAL_PATTERNS, redact, redactDetailed } from '../src/credentials.js';
import type { CredentialFinding, Finding } from '../src/findings.js';
import { policy } from '../src/policy.js';

describe('redact', () => {
  describe('Anthropic API keys', () => {
    it('redacts a bare anthropic key', () => {
      expect(redact('sk-ant-api03-abcdefghijklmnopqrstuvwx')).toBe('<credential>');
    });

    it('redacts an anthropic key in whitespace-bounded context', () => {
      expect(redact('key=sk-ant-api03-abcdefghijklmnopqrstuvwx rest')).toBe(
        'key=<credential> rest'
      );
    });

    it('does not redact short non-key strings starting with sk-ant-', () => {
      // Pattern requires 20+ non-whitespace chars after `sk-ant-`.
      expect(redact('sk-ant-too-short')).toBe('sk-ant-too-short');
    });
  });

  describe('AWS access keys', () => {
    it('redacts an AKIA-prefixed access key', () => {
      expect(redact('AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE')).toBe('AWS_ACCESS_KEY=<credential>');
    });

    it('redacts an ASIA-prefixed access key (per spec; new in v0.1)', () => {
      expect(redact('temp creds: ASIAIOSFODNN7EXAMPLE here')).toBe('temp creds: <credential> here');
    });
  });

  describe('JWT Bearer tokens', () => {
    it('redacts a Bearer JWT', () => {
      const jwt = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkw';
      expect(redact(`Authorization: ${jwt}`)).toBe('Authorization: <credential>');
    });

    it('does not redact bare "Bearer" without an eyJ payload', () => {
      expect(redact('Bearer 12345')).toBe('Bearer 12345');
    });
  });

  describe('Slack tokens (new in v0.1)', () => {
    it('redacts a Slack bot token (xoxb)', () => {
      expect(redact('SLACK=xoxb-1234567890-abcdefghijkl')).toBe('SLACK=<credential>');
    });

    it('redacts a Slack user token (xoxp)', () => {
      expect(redact('xoxp-1234567890-1234567890-abcdef')).toBe('<credential>');
    });
  });

  describe('GitHub PATs (new in v0.1)', () => {
    it('redacts a classic GitHub personal access token (ghp_)', () => {
      // Classic PAT: `ghp_` + 36 alphanumeric chars (40 total).
      expect(redact('GH_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789')).toBe(
        'GH_TOKEN=<credential>'
      );
    });

    it('does not redact ghp_ prefixes shorter than 36 chars', () => {
      expect(redact('ghp_tooshort')).toBe('ghp_tooshort');
    });
  });

  describe('Stripe restricted keys (new in v0.1)', () => {
    it('redacts a Stripe rk_live_ key', () => {
      expect(redact('STRIPE_KEY=rk_live_abcdefghijklmnopqrstuvwxyz')).toBe(
        'STRIPE_KEY=<credential>'
      );
    });
  });

  describe('PEM private-key blocks (new in v0.1)', () => {
    it('redacts an RSA private-key block (lazy multi-line match)', () => {
      const pem = [
        '-----BEGIN RSA PRIVATE KEY-----',
        'MIIEowIBAAKCAQEAvLxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        'BODY-LINE-PLACEHOLDER',
        '-----END RSA PRIVATE KEY-----'
      ].join('\n');
      expect(redact(`config:\n${pem}\nrest`)).toBe('config:\n<credential>\nrest');
    });

    it('redacts an EC private-key block', () => {
      const pem = '-----BEGIN EC PRIVATE KEY-----\nMHcC...\n-----END EC PRIVATE KEY-----';
      expect(redact(pem)).toBe('<credential>');
    });

    it('redacts a generic PRIVATE KEY block (no algorithm prefix)', () => {
      const pem = '-----BEGIN PRIVATE KEY-----\nMIIBpAYJKoZIhvcN...\n-----END PRIVATE KEY-----';
      expect(redact(pem)).toBe('<credential>');
    });

    it('lazy match does not span across two PEM blocks', () => {
      // Greedy `[\s\S]*` would consume through the second BEGIN/END pair.
      // Lazy `[\s\S]*?` stops at the first `-----END ... PRIVATE KEY-----`.
      const two =
        '-----BEGIN RSA PRIVATE KEY-----\nA\n-----END RSA PRIVATE KEY-----\n' +
        'middle\n' +
        '-----BEGIN EC PRIVATE KEY-----\nB\n-----END EC PRIVATE KEY-----';
      expect(redact(two)).toBe('<credential>\nmiddle\n<credential>');
    });
  });

  describe('long hex strings', () => {
    it('redacts a 64-char hex string at word boundaries', () => {
      const hex = 'a'.repeat(64);
      expect(redact(`hash=${hex} done`)).toBe('hash=<credential> done');
    });

    it('does not redact a 40-char git SHA (below the 64 threshold)', () => {
      const sha = 'a'.repeat(40);
      expect(redact(`commit ${sha}`)).toBe(`commit ${sha}`);
    });
  });

  describe('default patterns and customization', () => {
    it('DEFAULT_CREDENTIAL_PATTERNS includes the 8 spec-required ruleIds', () => {
      const ids = DEFAULT_CREDENTIAL_PATTERNS.map((p) => p.ruleId);
      expect(ids).toEqual(
        expect.arrayContaining([
          'anthropic-token',
          'aws-access-key',
          'jwt',
          'slack-token',
          'github-pat',
          'stripe-restricted-key',
          'pem-private-key',
          'long-hex'
        ])
      );
    });

    it('does NOT include sot-session-* (consumer-specific; dropped from defaults)', () => {
      const ids = DEFAULT_CREDENTIAL_PATTERNS.map((p) => p.ruleId);
      expect(ids).not.toContain('sot-session');
    });

    it('PEM pattern declares maxMatchLength = 4096 (covers real RSA-4096 PKCS#8 with margin)', () => {
      // Real RSA-4096 PKCS#8 PEM measured at 3272 bytes (see tests/fixtures/real-pem-rsa-4096.txt).
      // 4096 gives ~25% margin and mnemonically aligns with the key bit length.
      const pem = DEFAULT_CREDENTIAL_PATTERNS.find((p) => p.ruleId === 'pem-private-key');
      expect(pem?.maxMatchLength).toBe(4096);
    });

    it('redacts multiple distinct credential types in one input', () => {
      const input = [
        'aws=AKIAIOSFODNN7EXAMPLE',
        'anth=sk-ant-api03-abcdefghijklmnopqrstuvwx',
        'gh=ghp_abcdefghijklmnopqrstuvwxyz0123456789'
      ].join(' ');
      expect(redact(input)).toBe('aws=<credential> anth=<credential> gh=<credential>');
    });

    it('accepts a custom pattern via policy().addCredentialPattern', () => {
      const customPolicy = policy()
        .addCredentialPattern(/sess-[a-z0-9]{16,}/g, { ruleId: 'session' })
        .build();
      expect(redact('Cookie: sess-abcdef0123456789xyz here', { policy: customPolicy })).toBe(
        'Cookie: <credential> here'
      );
    });

    it('honors per-pattern placeholder override via policy()', () => {
      const customPolicy = policy()
        .addCredentialPattern(/sess-[a-z0-9]{16,}/g, {
          ruleId: 'cookie',
          placeholder: '[SESSION]'
        })
        .build();
      expect(redact('id=sess-abcdef0123456789', { policy: customPolicy })).toBe('id=[SESSION]');
    });

    it('default placeholder is `<credential>` (not `[REDACTED]`)', () => {
      // Spec-requirements §F1: semantic placeholder beats `***`-style masks.
      // LLMs hallucinate around brackety masks; a typed placeholder reads as
      // an intentional removal and preserves prompt structure.
      expect(redact('AKIAIOSFODNN7EXAMPLE')).toBe('<credential>');
      expect(redact('AKIAIOSFODNN7EXAMPLE')).not.toContain('[REDACTED]');
    });
  });

  describe('string-boundary cases', () => {
    it('redacts an AWS key at end of string with no trailing whitespace', () => {
      // `\b` boundary on long-hex behaves differently than `\S{20,}` on anthropic;
      // an AWS key uses neither — the literal `[0-9A-Z]{16}` repetition handles
      // end-of-string fine. Documented separately for confidence.
      expect(redact('key=AKIAIOSFODNN7EXAMPLE')).toBe('key=<credential>');
    });

    it('redacts a long-hex string at end of input where the trailing \\b is at EOF', () => {
      const hex = 'a'.repeat(64);
      expect(redact(`hash=${hex}`)).toBe('hash=<credential>');
    });

    it('redacts a JWT at end of string with no trailing whitespace', () => {
      const jwt = `Bearer eyJ${'a'.repeat(50)}`;
      expect(redact(`Authorization: ${jwt}`)).toBe('Authorization: <credential>');
    });

    it('redacts a credential as the entire input', () => {
      // Whole-string match — no surrounding context.
      const pem = '-----BEGIN PRIVATE KEY-----\nMIIBpA...\n-----END PRIVATE KEY-----';
      expect(redact(pem)).toBe('<credential>');
    });
  });

  describe('idempotence across calls', () => {
    it('produces the same result on repeated invocations with the same input', () => {
      // `String.prototype.replace` with a global regex resets `lastIndex` per
      // spec; this test asserts call-level idempotence (which the contract
      // requires) rather than the lower-level reset behavior.
      const input = 'AKIAIOSFODNN7EXAMPLE';
      expect(redact(input)).toBe('<credential>');
      expect(redact(input)).toBe('<credential>');
      expect(redact(input)).toBe('<credential>');
    });
  });

  describe('preservation invariants', () => {
    it('preserves empty string', () => {
      expect(redact('')).toBe('');
    });

    it('preserves plain text with no credential-shaped substrings', () => {
      const input = 'Hello world. Nothing to redact here. 12345.';
      expect(redact(input)).toBe(input);
    });

    it('returns same string reference when input is clean (identity preservation)', () => {
      // spec-api §2: redact returns input by reference if no transformation occurred.
      // M3 task: explicit per-stage guard for cross-engine correctness; today this
      // rides on V8 reference-stability of `.replace()` with no match.
      const input = 'plain prose, no secrets';
      const result = redact(input);
      expect(result).toBe(input);
      expect(Object.is(result, input)).toBe(true);
    });

    it('preserves Unicode content surrounding a redacted credential', () => {
      // Credential redaction is byte-domain; legitimate Cyrillic / CJK / emoji round-trip.
      const input = 'Здравейте AKIAIOSFODNN7EXAMPLE 你好 🌍';
      expect(redact(input)).toBe('Здравейте <credential> 你好 🌍');
    });
  });
});

describe('redact — Policy plumbing (Slice B)', () => {
  it('uses DEFAULT_POLICY when no options are passed', () => {
    expect(redact('AKIAIOSFODNN7EXAMPLE')).toBe('<credential>');
  });

  it('honors policy.placeholderDefault for patterns without an explicit placeholder', () => {
    const customPolicy = policy().setPlaceholderDefault('[SECRET]').build();
    expect(redact('AKIAIOSFODNN7EXAMPLE', { policy: customPolicy })).toBe('[SECRET]');
  });

  it('per-pattern placeholder beats policy.placeholderDefault', () => {
    // Policy default is `[SECRET]`, but the user-added pattern has its own.
    const customPolicy = policy()
      .setPlaceholderDefault('[SECRET]')
      .addCredentialPattern(/sess-[a-z0-9]{16,}/g, {
        ruleId: 'cookie',
        placeholder: '[COOKIE]'
      })
      .build();
    expect(redact('id=sess-abcdef0123456789', { policy: customPolicy })).toBe('id=[COOKIE]');
  });

  it('removeCredentialPattern excludes a default pattern from redaction', () => {
    const noAws = policy().removeCredentialPattern('aws-access-key').build();
    expect(redact('AKIAIOSFODNN7EXAMPLE', { policy: noAws })).toBe('AKIAIOSFODNN7EXAMPLE');
  });

  it('addCredentialPattern coerces a non-global RegExp to global', () => {
    // A non-global regex would replace only the first match via `.replace()` and
    // throw under `matchAll`. The builder coerces at registration so the runtime
    // path stays uniform.
    const customPolicy = policy().addCredentialPattern(/X{4}/, { ruleId: 'four-x' }).build();
    expect(redact('XXXX-XXXX', { policy: customPolicy })).toBe('<credential>-<credential>');
  });

  it('non-global user pattern does NOT throw on the telemetry path (matchAll)', () => {
    // Defense-in-depth: matchAll throws TypeError on non-global RegExps. Coercion at
    // registration is the only correct place to fix this; this test pins down the
    // telemetry path explicitly.
    const customPolicy = policy().addCredentialPattern(/X{4}/, { ruleId: 'four-x' }).build();
    const result = redactDetailed('XXXX-XXXX', { policy: customPolicy });
    expect(result.changed).toBe(true);
    expect(result.findings).toHaveLength(2);
  });
});

describe('redactDetailed (Slice B)', () => {
  it('returns same-reference text + empty findings on clean input', () => {
    const clean = 'plain prose, no secrets';
    const result = redactDetailed(clean);
    expect(result.text).toBe(clean);
    expect(Object.is(result.text, clean)).toBe(true);
    expect(result.changed).toBe(false);
    expect(result.findings).toHaveLength(0);
  });

  it('emits a single CredentialFinding for one match (full shape)', () => {
    const input = 'token=AKIAIOSFODNN7EXAMPLE rest';
    const result = redactDetailed(input);
    expect(result.changed).toBe(true);
    expect(result.text).toBe('token=<credential> rest');
    expect(result.findings).toHaveLength(1);

    const f = result.findings[0] as CredentialFinding;
    expect(f.kind).toBe('credential');
    expect(f.ruleId).toBe('aws-access-key');
    expect(f.action).toBe('redacted');
    expect(f.severity).toBe('high');
    expect(f.placeholder).toBe('<credential>');
    expect(f.ruleVersion).toBe(1);
    expect(f.offset).toBe(6); // 'token='.length
    expect(f.length).toBe(20); // 'AKIAIOSFODNN7EXAMPLE'.length
  });

  it('emits one finding per non-contiguous match of the same pattern', () => {
    // Two AWS-shaped 20-char keys (AWS pattern: prefix + 16 [0-9A-Z]).
    const input = 'AKIAIOSFODNN7EXAMPLE and AKIAIOSFODNN7EXAMPLE';
    const result = redactDetailed(input);
    const aws = result.findings.filter(
      (f): f is CredentialFinding => f.kind === 'credential' && f.ruleId === 'aws-access-key'
    );
    expect(aws).toHaveLength(2);
    expect(aws[0]?.offset).toBe(0);
    expect(aws[1]?.offset).toBe(25); // 20 ('AKIA…EXAMPLE') + 5 (' and ')
  });

  it('emits findings for multiple distinct pattern matches in one input', () => {
    const input = 'aws=AKIAIOSFODNN7EXAMPLE gh=ghp_abcdefghijklmnopqrstuvwxyz0123456789';
    const result = redactDetailed(input);
    const ids = result.findings.map((f) => (f.kind === 'credential' ? f.ruleId : null));
    expect(ids).toContain('aws-access-key');
    expect(ids).toContain('github-pat');
    expect(result.text).toBe('aws=<credential> gh=<credential>');
  });

  it('built-in severity defaults follow spec-api §6 (high tier)', () => {
    // anthropic-token, aws-access-key, pem-private-key, stripe-restricted-key → high.
    const cases = [
      { input: 'sk-ant-api03-abcdefghijklmnopqrstuvwx', ruleId: 'anthropic-token' },
      { input: 'AKIAIOSFODNN7EXAMPLE', ruleId: 'aws-access-key' },
      { input: 'rk_live_abcdefghijklmnopqrstuvwxyz', ruleId: 'stripe-restricted-key' }
    ];
    for (const { input, ruleId } of cases) {
      const f = redactDetailed(input).findings[0] as CredentialFinding;
      expect(f.ruleId).toBe(ruleId);
      expect(f.severity).toBe('high');
    }
  });

  it('built-in severity defaults follow spec-api §6 (medium tier)', () => {
    // jwt, github-pat, slack-token, long-hex → medium.
    const cases = [
      { input: `Bearer eyJ${'a'.repeat(50)}`, ruleId: 'jwt' },
      { input: 'ghp_abcdefghijklmnopqrstuvwxyz0123456789', ruleId: 'github-pat' },
      { input: 'xoxb-1234567890-abcdefghijkl', ruleId: 'slack-token' },
      { input: `${'a'.repeat(64)}`, ruleId: 'long-hex' }
    ];
    for (const { input, ruleId } of cases) {
      const f = redactDetailed(input).findings[0] as CredentialFinding;
      expect(f.ruleId).toBe(ruleId);
      expect(f.severity).toBe('medium');
    }
  });

  it('policy.severityOverrides[ruleId] wins over the per-pattern default', () => {
    const upgrade = policy().setSeverity('aws-access-key', 'critical').build();
    const f = redactDetailed('AKIAIOSFODNN7EXAMPLE', { policy: upgrade })
      .findings[0] as CredentialFinding;
    expect(f.severity).toBe('critical');
  });

  it('user-added pattern without explicit severity falls back to medium', () => {
    const customPolicy = policy()
      .addCredentialPattern(/sess-[a-z0-9]{16,}/g, { ruleId: 'session' })
      .build();
    const f = redactDetailed('id=sess-abcdef0123456789', { policy: customPolicy })
      .findings[0] as CredentialFinding;
    expect(f.ruleId).toBe('session');
    expect(f.severity).toBe('medium');
  });

  it('finding.placeholder reflects the resolved placeholder (per-pattern wins over policy default)', () => {
    const customPolicy = policy()
      .setPlaceholderDefault('[SECRET]')
      .addCredentialPattern(/sess-[a-z0-9]{16,}/g, {
        ruleId: 'cookie',
        placeholder: '[COOKIE]'
      })
      .build();
    const result = redactDetailed('a=AKIAIOSFODNN7EXAMPLE b=sess-abcdef0123456789', {
      policy: customPolicy
    });
    const ids = new Map(
      result.findings
        .filter((f): f is CredentialFinding => f.kind === 'credential')
        .map((f) => [f.ruleId, f.placeholder])
    );
    expect(ids.get('aws-access-key')).toBe('[SECRET]');
    expect(ids.get('cookie')).toBe('[COOKIE]');
  });

  it('non-Detailed redact + onFinding fires the callback (silent path opts in)', () => {
    const calls: Finding[] = [];
    const out = redact('AKIAIOSFODNN7EXAMPLE', { onFinding: (f) => calls.push(f) });
    expect(out).toBe('<credential>');
    expect(calls).toHaveLength(1);
    expect(calls[0]?.kind).toBe('credential');
  });

  it('onFinding fires synchronously per match in pattern order', () => {
    const calls: string[] = [];
    redactDetailed('aws=AKIAIOSFODNN7EXAMPLE gh=ghp_abcdefghijklmnopqrstuvwxyz0123456789', {
      onFinding: (f) => {
        if (f.kind === 'credential') calls.push(f.ruleId);
      }
    });
    // Pattern array order in DEFAULT_CREDENTIAL_PATTERNS: anthropic, aws, jwt, slack,
    // github, stripe, pem, long-hex. So aws fires before github.
    expect(calls).toEqual(['aws-access-key', 'github-pat']);
  });

  it('uses DEFAULT_CREDENTIAL_PATTERNS membership when policy is default', () => {
    // Smoke test that policy.credentials.patterns is wired to the default array.
    const ruleIds = DEFAULT_CREDENTIAL_PATTERNS.map((p) => p.ruleId);
    expect(ruleIds).toContain('aws-access-key');
  });
});
