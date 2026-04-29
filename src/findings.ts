/**
 * Finding shape for Vaglio v0.1.
 *
 * Per spec-api §6: a closed discriminated union over three kinds —
 * `unicode-strip` (Unicode strip-set hits, ANSI escapes, orphan surrogates,
 * combining-mark caps, tag-block strips, user-supplied strip patterns),
 * `credential` (placeholder substitutions for credential patterns), and
 * `stream-diagnostic` (overflow warnings, cancel notifications).
 *
 * Severity lives here (single source of truth) — both Policy and the
 * Finding shape consume it; credentials.ts re-exports for ergonomics.
 *
 * Contract: Findings carry NO raw snippets (spec-api §6 "No raw snippets").
 * Forensic source context is a v0.2 opt-in surface; v0.1 telemetry is
 * structurally incapable of leaking partial credentials or PII.
 */

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type FindingKind = 'unicode-strip' | 'credential' | 'stream-diagnostic';

export type PolicyAction = 'stripped' | 'redacted' | 'replaced';

export type UnicodeStripFinding = Readonly<{
  kind: 'unicode-strip';
  /**
   * Stable rule identifier (e.g. `"tags-block"`, `"bidi-override"`,
   * `"orphaned-surrogate"`, `"ansi-escape"`, `"c0-control"`, `"zalgo-cap"`,
   * or a user-supplied id from `addStripPattern`).
   */
  ruleId: string;
  ruleVersion: number;
  action: PolicyAction;
  /** Absolute character offset in the stream/batch. */
  offset: number;
  /** Total character span affected. */
  length: number;
  /** Unicode block name or hex codepoint range that drove the match. */
  charClass: string;
  /** Consecutive characters removed (≥ 1; > 1 when contiguous run is batched). */
  count: number;
  severity: Severity;
}>;

export type CredentialFinding = Readonly<{
  kind: 'credential';
  /** Matches `CredentialPattern.ruleId`. */
  ruleId: string;
  ruleVersion: number;
  action: PolicyAction;
  offset: number;
  length: number;
  /** Exact placeholder substituted at the match site. */
  placeholder: string;
  severity: Severity;
}>;

export type StreamDiagnosticFinding = Readonly<{
  kind: 'stream-diagnostic';
  /** `"buffer-overflow-warning"` | `"stream-canceled"`. */
  ruleId: string;
  ruleVersion: number;
  severity: Severity;
  message: string;
}>;

export type Finding = UnicodeStripFinding | CredentialFinding | StreamDiagnosticFinding;
