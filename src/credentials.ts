/**
 * Credential redaction for Vaglio v0.1.
 *
 * Lifted from `~/Projects/sotto/src/message-io.ts` lines 155-170 per the
 * extraction inventory.
 *
 * Refactored from a bare `RegExp[]` to `CredentialPattern` objects per
 * spec-api §4. Default set extended with Slack, GitHub, Stripe, and PEM
 * patterns per spec-requirements §F1 (2026-04-28 review). The consumer-
 * specific `sot-session-*` pattern is dropped from defaults.
 *
 * Default placeholder is `<credential>` per spec-requirements §F1 — semantic
 * placeholders preserve prompt structure (LLMs hallucinate around `***` masks).
 *
 * `pattern.lastIndex = 0` reset before each `.replace()`. Per ECMAScript spec,
 * `String.prototype.replace` with a global regex already resets `lastIndex` to
 * 0 internally; the explicit reset is defensive insurance against a future
 * refactor to `.exec()` / `.test()` / `.matchAll()`, where lastIndex drift IS
 * load-bearing. The extraction inventory's "load-bearing" framing was carried
 * forward from sotto verbatim; for the current `.replace()`-only path it's a
 * no-op kept for forward compatibility.
 *
 * `severity`, `ruleVersion`, and detail-variant findings are deferred to M3
 * (require the Findings + Policy surface).
 */

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type CredentialPattern = Readonly<{
  /** Stable identifier for telemetry; appears in Finding.ruleId. */
  ruleId: string;

  /** The match expression. Must compile cleanly; ReDoS-validated at Policy.build() (M3). */
  pattern: RegExp;

  /** Per-pattern placeholder. Falls back to the default (`<credential>`) when omitted. */
  placeholder?: string;

  /** Per-pattern severity. M3 wires this through Findings. */
  severity?: Severity;

  /** Schema version for forensic stability. Default 1. */
  ruleVersion?: number;

  /**
   * Maximum match length. Required for unbounded patterns; enforced at
   * Policy.build() in M3. Builtin: PEM declares 4096 (covers RSA-4096
   * PKCS#8 PEM at ~3272 bytes with ~25% margin; mnemonically aligned with
   * the key bit length). Bumped from 3072 after empirical measurement of
   * a freshly-generated RSA-4096 fixture surfaced 3072 as insufficient.
   */
  maxMatchLength?: number;
}>;

const DEFAULT_PLACEHOLDER = '<credential>';

export const DEFAULT_CREDENTIAL_PATTERNS: ReadonlyArray<CredentialPattern> = Object.freeze([
  Object.freeze({
    ruleId: 'anthropic-token',
    pattern: /sk-ant-\S{20,}/g
  }),
  Object.freeze({
    ruleId: 'aws-access-key',
    pattern: /(?:AKIA|ASIA)[0-9A-Z]{16}/g
  }),
  Object.freeze({
    ruleId: 'jwt',
    pattern: /Bearer\s+eyJ[a-zA-Z0-9._-]{50,}/g
  }),
  Object.freeze({
    ruleId: 'slack-token',
    pattern: /xox[bp]-[A-Za-z0-9-]{20,}/g
  }),
  Object.freeze({
    ruleId: 'github-pat',
    pattern: /ghp_[A-Za-z0-9]{36}/g
  }),
  Object.freeze({
    ruleId: 'stripe-restricted-key',
    pattern: /rk_live_[A-Za-z0-9]{20,}/g
  }),
  Object.freeze({
    ruleId: 'pem-private-key',
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    maxMatchLength: 4096
  }),
  Object.freeze({
    ruleId: 'long-hex',
    pattern: /\b[0-9a-f]{64,}\b/g
  })
]);

/**
 * Redact credentials by replacing matched substrings with a placeholder.
 *
 * @param text     Input string.
 * @param patterns Credential patterns. Defaults to {@link DEFAULT_CREDENTIAL_PATTERNS}.
 *
 * @example
 *   redact('key=sk-ant-api03-abcdefghijklmnopqrst')
 *   // → 'key=<credential>'
 */
export function redact(
  text: string,
  patterns: ReadonlyArray<CredentialPattern> = DEFAULT_CREDENTIAL_PATTERNS
): string {
  if (patterns.length === 0) return text;

  let result = text;
  for (const p of patterns) {
    p.pattern.lastIndex = 0;
    const replacement = p.placeholder ?? DEFAULT_PLACEHOLDER;
    result = result.replace(p.pattern, replacement);
  }
  return result;
}
