/**
 * Credential redaction. Default placeholder `<credential>` (semantic, not `***`)
 * preserves prompt structure ⇒ LLMs hallucinate around opaque masks.
 *
 * Severity precedence: `policy.severityOverrides[ruleId]` ⇒ per-pattern
 * `severity` ⇒ `'medium'` fallback for user patterns.
 *
 * Cross-pattern offset frame: each pattern's `CredentialFinding.offset` is in
 * the text post-prior-patterns within this stage.
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
/** Array literal lives in `policy.ts` to break the credentials.ts → policy.ts → credentials.ts load-time cycle. */
export { DEFAULT_CREDENTIAL_PATTERNS };

export type CredentialPattern = Readonly<{
  ruleId: string;
  /** Coerced to global by `PolicyBuilder.addCredentialPattern` at registration — `matchAll` throws on non-global. */
  pattern: RegExp;
  /** Falls back to `policy.placeholderDefault` (default `<credential>`). */
  placeholder?: string;
  severity?: Severity;
  ruleVersion?: number;
  /** Required for unbounded patterns (v0.1 advisory; v0.2 enforced). PEM ships 4096 — covers RSA-4096 PKCS#8 (~3272 bytes). */
  maxMatchLength?: number;
}>;

const FINDING_RULE_VERSION = 1;
const USER_PATTERN_DEFAULT_SEVERITY: Severity = 'medium';

/** Exported so the streaming engine drives `redactCore` with the same per-pattern semantics as batch. */
export type EmitContext = Readonly<{
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

/**
 * Returns `cutoff` such that `text.slice(0, cutoff)` can be committed safely
 * (no greedy-extension or partial-prefix concerns); the tail must be held for
 * the next push. `anyMatch` reports whether any pattern matched anywhere ⇒
 * engines use it to suppress no-progress overflow when a credential is held
 * in the tail.
 *
 * Algorithm: cutoff = `text.length - holdback`. Any match crossing the cutoff
 * (`start < cutoff <= end`) shrinks cutoff to the match's start so the whole
 * match lands in the held tail.
 *
 * Multi-pattern caveat: cutoff is computed on the ORIGINAL `text`. After p1
 * substitutes, p2's match may not exist ⇒ cutoff is conservative. Harmless
 * for built-ins (placeholders are non-credential-shaped); user patterns
 * matching `<credential>`-shaped strings are a v0.2 edge case.
 */
export function findHoldbackCutoff(
  text: string,
  patterns: ReadonlyArray<CredentialPattern>,
  holdback: number
): { cutoff: number; anyMatch: boolean } {
  let cutoff = text.length - holdback;
  if (cutoff <= 0) return { cutoff: 0, anyMatch: false };
  let anyMatch = false;
  for (const p of patterns) {
    for (const m of text.matchAll(p.pattern)) {
      anyMatch = true;
      const start = m.index ?? 0;
      const end = start + m[0].length;
      if (end <= cutoff) continue;
      if (start >= cutoff) break;
      cutoff = start;
      break;
    }
  }
  return { cutoff, anyMatch };
}

/** Identity preserved naturally — no-match `replace` returns the input string. Exported for streaming. */
export function redactSilent(text: string, policy: Policy): string {
  const patterns = policy.credentials.patterns;
  if (patterns.length === 0) return text;

  let result = text;
  for (const p of patterns) {
    // `String.prototype.replace` with /g resets lastIndex per spec; explicit reset is forward-compat insurance.
    p.pattern.lastIndex = 0;
    const placeholder = p.placeholder ?? policy.placeholderDefault;
    result = result.replace(p.pattern, placeholder);
  }
  return result;
}

/**
 * `baseOffset` shifts emitted offsets: batch passes 0, streaming passes
 * `consumedBytes` so findings carry absolute position in the engine's emit
 * history. Exported for streaming.
 */
export function redactCore(text: string, ctx: EmitContext, baseOffset: number): string {
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
          baseOffset + start,
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
  return shouldEmit(ctx) ? redactCore(text, ctx, 0) : redactSilent(text, ctx.policy);
}

/**
 * Returns the input by reference if no pattern matched.
 * @example
 *   redact('key=sk-ant-api03-abcdefghijklmnopqrst')   // → 'key=<credential>'
 */
export function redact(text: string, options?: SanitizeOptions): string {
  return runRedact(text, makeContext(options, /*detailed*/ false));
}

/**
 * Frozen `SanitizeResult`; `result.text === text` (same ref) when `changed === false`.
 * @example
 *   const r = redactDetailed('Authorization: Bearer eyJ' + 'a'.repeat(50));
 *   // r.findings[0].ruleId === 'jwt'
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
