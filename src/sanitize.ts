/**
 * Composed pipeline: `stripUnicode → stripTags → redact`. Each stage's
 * `Finding.offset` is in *its own input* (post-prior-stages within this call);
 * stable cross-pipeline offsets are a v0.2 refinement.
 */

import { redact } from './credentials.js';
import type { Finding } from './findings.js';
import type { SanitizeOptions, SanitizeResult } from './policy.js';
import { stripTags } from './tags.js';
import { stripUnicode } from './unicode.js';

/**
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
 * Frozen `SanitizeResult` with merged findings; `result.text === text` (same ref) when `changed === false`.
 *
 * @example
 *   const r = sanitizeDetailed('<internal>x</internal> AKIAIOSFODNN7EXAMPLE');
 *   // r.findings: one 'reasoning-tag' unicode-strip + one 'aws-access-key' credential
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
