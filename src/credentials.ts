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

/**
 * Internal emission context. Exported because the streaming engine
 * (`src/stream-redact.ts`) needs to drive `redactCore` against the same
 * per-pattern sequential semantics as the batch surface.
 */
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
 * Determine the effective leading-region cutoff for streaming redact.
 * Returns the position in `text` such that `text.slice(0, cutoff)` can be
 * safely committed (no greedy-extension or partial-prefix concerns); the
 * tail `text.slice(cutoff)` must be retained for the next push. Also
 * reports `anyMatch` — true if any pattern matched anywhere in `text`,
 * regardless of whether the match crossed the cutoff. Engines use
 * `anyMatch` to suppress the "no-progress" overflow signal when a
 * credential is pending in the held tail (the buffer is doing useful
 * work; the next push will commit the match).
 *
 * Algorithm: cutoff starts at `text.length - holdback`. For each pattern,
 * scan matches; if any match crosses the cutoff (`start < cutoff <= end`),
 * shrink cutoff to the match's start so the entire match lands in the
 * held tail. Matches entirely in the leading region (`end <= cutoff`)
 * don't move cutoff. Matches entirely in the held region
 * (`start >= cutoff`) don't move cutoff and can't grow into the leading
 * region from a later push (chunks append at the end).
 *
 * Multi-pattern caveat: phase-1 examines patterns on the ORIGINAL `text`.
 * Pattern p2's match may not exist after p1 substitutes in phase-2's
 * redactCore pass; the cutoff is therefore conservative (might shrink
 * more than necessary). Built-in patterns don't introduce new matches via
 * substitution (placeholders are non-credential-shaped), so this is
 * harmless for v0.1 default policy. User-defined patterns that match
 * `<credential>`-shaped strings are an edge case documented for v0.2.
 *
 * Exported for the streaming engines (`stream-redact`, `stream-sanitize`).
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

// ─────────────────────────────────────────────────────────────────────────────
// Pipeline
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Silent fast path: per-pattern global `.replace()`. Identity preserved
 * naturally — no-match `replace` returns the input string.
 *
 * Exported for the streaming engine (`src/stream-redact.ts`); the public
 * surface remains `redact` / `redactDetailed`.
 */
export function redactSilent(text: string, policy: Policy): string {
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
 *
 * `baseOffset` shifts every emitted finding's offset by a fixed amount.
 * Batch (`redactDetailed`) passes `0` (offsets are batch-relative). The
 * streaming engine passes `consumedBytes` so findings carry an absolute
 * position in the engine's emit history.
 *
 * Exported for the streaming engine; public surface unchanged.
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
