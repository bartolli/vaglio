import { describe, expect, it } from 'vitest';
import { type CredentialPattern, DEFAULT_CREDENTIAL_PATTERNS, redact } from '../src/credentials.js';

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

    it('accepts a custom pattern array', () => {
      const custom: ReadonlyArray<CredentialPattern> = [
        { ruleId: 'session', pattern: /sess-[a-z0-9]{16,}/g }
      ];
      expect(redact('Cookie: sess-abcdef0123456789xyz here', custom)).toBe(
        'Cookie: <credential> here'
      );
    });

    it('returns input unchanged when pattern array is empty', () => {
      const input = 'sk-ant-api03-abcdefghijklmnopqrstuvwx';
      expect(redact(input, [])).toBe(input);
    });

    it('honors per-pattern placeholder override', () => {
      const custom: ReadonlyArray<CredentialPattern> = [
        { ruleId: 'cookie', pattern: /sess-[a-z0-9]{16,}/g, placeholder: '[SESSION]' }
      ];
      expect(redact('id=sess-abcdef0123456789', custom)).toBe('id=[SESSION]');
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
