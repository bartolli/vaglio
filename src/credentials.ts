/**
 * Credential redaction for Vaglio v0.1.
 *
 * Lifted from `~/Projects/sotto/src/message-io.ts` lines 155-170 per the
 * extraction inventory; reshaped in M3.4 Slice B to the spec-api §1 surface
 * (`redact(text, options?)` + `redactDetailed`).
 *
 * Default placeholder is `<credential>` per spec-requirements §F1 — semantic
 * placeholders preserve prompt structure (LLMs hallucinate around `***` masks).
 *
 * Per-pattern `severity` baked into the 8 built-ins per spec-api §6 table.
 * `policy.severityOverrides[ruleId]` wins; per-pattern `severity` is the
 * default; user-added patterns without an explicit severity fall back to
 * `'medium'`.
 *
 * v0.1 simplification (Slice B): when multiple patterns run against the same
 * input, each pattern's `CredentialFinding.offset` is in the text AS PROCESSED
 * BY PRIOR PATTERNS in this stage. Same shape as Slice A's "post-NFKC
 * canonical text" offset frame. Documented for primer resync.
 *
 * `pattern.lastIndex = 0` reset before `.replace()` on the silent path.
 * `String.prototype.replace` with a global regex resets `lastIndex` internally
 * per ECMAScript spec; the explicit reset is forward-compatibility insurance.
 * The telemetry path uses `matchAll`, which clones the regex internally and
 * does not require the reset.
 */

import type { CredentialFinding, Finding, PolicyAction, Severity } from './findings.js';
import {
  DEFAULT_CREDENTIAL_PATTERNS,
  DEFAULT_POLICY,
  type Policy,
  type SanitizeOptions,
  type SanitizeResult
} from './policy.js';

export type { Severity };
/**
 * Re-export of the built-in credential pattern set. The array literal lives
 * in `policy.ts` to break a load-time cycle (see the `DEFAULT_CREDENTIAL_PATTERNS`
 * comment there); this re-export is the spec-api §1 public surface.
 */
export { DEFAULT_CREDENTIAL_PATTERNS };

export type CredentialPattern = Readonly<{
  /** Stable identifier for telemetry; appears in Finding.ruleId. */
  ruleId: string;

  /**
   * The match expression. Must be global; the builder coerces user-supplied
   * non-global RegExps to global at registration (see `PolicyBuilder.
   * addCredentialPattern`). `matchAll` requires `g` and would throw otherwise.
   */
  pattern: RegExp;

  /** Per-pattern placeholder. Falls back to `policy.placeholderDefault` (default `<credential>`). */
  placeholder?: string;

  /** Per-pattern default severity. Wins over the v0.1 `'medium'` fallback; loses to `policy.severityOverrides`. */
  severity?: Severity;

  /** Schema version for forensic stability. Default 1. */
  ruleVersion?: number;

  /**
   * Maximum match length. Required for unbounded patterns. v0.2 will enforce
   * at `Policy.build()` (deferred per primer); v0.1 is advisory. Builtin: PEM
   * declares 4096 (covers RSA-4096 PKCS#8 PEM at ~3272 bytes with ~25% margin;
   * mnemonically aligned with the key bit length).
   */
  maxMatchLength?: number;
}>;

/** Default rule-version for v0.1 findings (spec-api §6). */
const FINDING_RULE_VERSION = 1;

/** v0.1 fallback severity for user-added patterns without an explicit `severity`. */
const USER_PATTERN_DEFAULT_SEVERITY: Severity = 'medium';

// ─────────────────────────────────────────────────────────────────────────────
// Internal emission machinery (mirrors src/unicode.ts EmitContext shape)
// ─────────────────────────────────────────────────────────────────────────────

type EmitContext = Readonly<{
  findings: Finding[] | null;
  onFinding: ((f: Finding) => void) | undefined;
  policy: Policy;
}>;

function shouldEmit(ctx: EmitContext): boolean {
  return ctx.findings !== null || ctx.onFinding !== undefined;
}

function emit(ctx: EmitContext, finding: Finding): void {
  if (ctx.findings !== null) ctx.findings.push(finding);
  ctx.onFinding?.(finding);
}

function effectiveSeverity(pattern: CredentialPattern, policy: Policy): Severity {
  return (
    policy.severityOverrides[pattern.ruleId] ?? pattern.severity ?? USER_PATTERN_DEFAULT_SEVERITY
  );
}

function makeCredentialFinding(
  ruleId: string,
  ruleVersion: number,
  action: PolicyAction,
  offset: number,
  length: number,
  placeholder: string,
  severity: Severity
): CredentialFinding {
  return Object.freeze({
    kind: 'credential' as const,
    ruleId,
    ruleVersion,
    action,
    offset,
    length,
    placeholder,
    severity
  });
}

function makeContext(options: SanitizeOptions | undefined, detailed: boolean): EmitContext {
  return {
    findings: detailed ? [] : null,
    onFinding: options?.onFinding,
    policy: options?.policy ?? DEFAULT_POLICY
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Pipeline
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Silent fast path: per-pattern global `.replace()`. Identity preserved
 * naturally — no-match `replace` returns the input string.
 */
function redactSilent(text: string, policy: Policy): string {
  const patterns = policy.credentials.patterns;
  if (patterns.length === 0) return text;

  let result = text;
  for (const p of patterns) {
    p.pattern.lastIndex = 0;
    const placeholder = p.placeholder ?? policy.placeholderDefault;
    result = result.replace(p.pattern, placeholder);
  }
  return result;
}

/**
 * Telemetry path: per-pattern `matchAll`, build the output with placeholder
 * substitution, emit one `CredentialFinding` per match. Each finding's
 * `offset` is in the text AS PROCESSED BY PRIOR PATTERNS in this stage —
 * v0.1 simplification documented in the file header.
 */
function redactWithFindings(text: string, ctx: EmitContext): string {
  const patterns = ctx.policy.credentials.patterns;
  if (patterns.length === 0) return text;

  let result = text;
  for (const p of patterns) {
    const placeholder = p.placeholder ?? ctx.policy.placeholderDefault;
    const severity = effectiveSeverity(p, ctx.policy);
    const ruleVersion = p.ruleVersion ?? FINDING_RULE_VERSION;

    let out = '';
    let lastEnd = 0;
    let any = false;

    for (const m of result.matchAll(p.pattern)) {
      any = true;
      const start = m.index ?? 0;
      const end = start + m[0].length;
      out += result.slice(lastEnd, start);
      out += placeholder;
      lastEnd = end;
      emit(
        ctx,
        makeCredentialFinding(
          p.ruleId,
          ruleVersion,
          'redacted',
          start,
          end - start,
          placeholder,
          severity
        )
      );
    }

    if (any) {
      out += result.slice(lastEnd);
      result = out;
    }
  }
  return result;
}

function runRedact(text: string, ctx: EmitContext): string {
  return shouldEmit(ctx) ? redactWithFindings(text, ctx) : redactSilent(text, ctx.policy);
}

/**
 * Redact credential matches from `text` using `policy.credentials.patterns`.
 * Returns the input string by reference if no pattern matched (spec-api §2).
 *
 * @example
 *   redact('key=sk-ant-api03-abcdefghijklmnopqrst')
 *   // → 'key=<credential>'
 */
export function redact(text: string, options?: SanitizeOptions): string {
  return runRedact(text, makeContext(options, /*detailed*/ false));
}

/**
 * Detailed variant per spec-api §1, §2. Returns a frozen `SanitizeResult`;
 * `result.text === text` (same reference) when `result.changed === false`.
 *
 * @example
 *   const r = redactDetailed('Authorization: Bearer eyJ' + 'a'.repeat(50));
 *   // r.changed === true, r.findings[0].kind === 'credential', r.findings[0].ruleId === 'jwt'
 */
export function redactDetailed(text: string, options?: SanitizeOptions): SanitizeResult {
  const ctx = makeContext(options, /*detailed*/ true);
  const out = runRedact(text, ctx);
  const changed = out !== text;
  return Object.freeze({
    text: changed ? out : text,
    changed,
    findings: Object.freeze([...(ctx.findings ?? [])])
  });
}
