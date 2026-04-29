/**
 * Composed sanitize pipeline for Vaglio v0.1 — M3.4 Slice D.
 *
 * `sanitize(text, options?)` runs the three stages in spec-api §2 order:
 *
 *   stripUnicode  →  stripTags  →  redact
 *
 * Each stage receives the same `SanitizeOptions` (`policy`, `onFinding`).
 * Stages are composed by string-passing; per-stage telemetry is delivered
 * by reusing the existing component telemetry paths via `onFinding`. The
 * silent path is a literal `redact(stripTags(stripUnicode(text)))` — no
 * findings allocation when neither `onFinding` nor the Detailed variant
 * is in play.
 *
 * `sanitizeDetailed` builds one merged findings array. Stage findings
 * appear in pipeline order (all unicode-strip findings first, then
 * reasoning-tag findings, then credential findings). Within a stage,
 * order is the stage's own (per-category for unicode, per-name for
 * tags, per-pattern for credentials).
 *
 * v0.1 simplifications captured for the M3 wiki resync:
 *
 *   - **Cross-stage offset frame.** Each stage's `Finding.offset` is in
 *     the input *to that stage* — i.e. the text after all prior stages
 *     completed. Mirrors Slice A's post-NFKC frame, Slice B's
 *     post-prior-pattern frame, and Slice C's post-prior-name frame.
 *     Stable cross-pipeline offsets are a v0.2 refinement.
 *
 *   - **`onFinding` ordering.** User `onFinding` fires synchronously
 *     during each stage's emit, so the callback observes stage order
 *     by construction. Within a stage, the order is the stage's natural
 *     iteration order (unchanged from Slices A/B/C).
 *
 * Identity preservation (spec-api §2): when the composed result equals
 * the input by reference, both `sanitize` and `sanitizeDetailed` return
 * the input ref (the latter inside a frozen `SanitizeResult` with
 * `changed: false`, `findings: []`).
 */

import { redact } from './credentials.js';
import type { Finding } from './findings.js';
import type { SanitizeOptions, SanitizeResult } from './policy.js';
import { stripTags } from './tags.js';
import { stripUnicode } from './unicode.js';

/**
 * Run the composed sanitize pipeline over `text`. Returns the input
 * string by reference if no stage produced a change (spec-api §2).
 *
 * Passing `options.onFinding` opts into telemetry without allocating a
 * findings array; each stage's emit fires the callback synchronously.
 *
 * @example
 *   sanitize('<internal>secret</internal> token=AKIAIOSFODNN7EXAMPLE')
 *   // → ' token=<credential>'
 */
export function sanitize(text: string, options?: SanitizeOptions): string {
  const afterUnicode = stripUnicode(text, options);
  const afterTags = stripTags(afterUnicode, options);
  return redact(afterTags, options);
}

/**
 * Detailed variant per spec-api §1, §2. Returns a frozen `SanitizeResult`
 * with merged findings from every stage; `result.text === text` (same
 * reference) when `result.changed === false`.
 *
 * @example
 *   const r = sanitizeDetailed('<internal>x</internal> AKIAIOSFODNN7EXAMPLE');
 *   // r.changed === true
 *   // r.findings[0].kind === 'unicode-strip' ? false  (no unicode strip here)
 *   // r.findings.some(f => f.kind === 'credential' && f.ruleId === 'aws-access-key') === true
 */
export function sanitizeDetailed(text: string, options?: SanitizeOptions): SanitizeResult {
  const findings: Finding[] = [];
  const userOnFinding = options?.onFinding;
  const merge: (f: Finding) => void = userOnFinding
    ? (f) => {
        findings.push(f);
        userOnFinding(f);
      }
    : (f) => {
        findings.push(f);
      };

  const stageOptions: SanitizeOptions =
    options?.policy !== undefined
      ? { policy: options.policy, onFinding: merge }
      : { onFinding: merge };

  const out = sanitize(text, stageOptions);
  const changed = out !== text;

  return Object.freeze({
    text: changed ? out : text,
    changed,
    findings: Object.freeze([...findings])
  });
}
