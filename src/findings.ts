export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type FindingKind = 'unicode-strip' | 'credential' | 'stream-diagnostic';

export type PolicyAction = 'stripped' | 'redacted' | 'replaced';

export type UnicodeStripFinding = Readonly<{
  kind: 'unicode-strip';
  /** Built-in: a `UnicodeCategory` literal, `"reasoning-tag"`, or `"zalgo-cap"`. User-supplied via `addStripPattern`. */
  ruleId: string;
  ruleVersion: number;
  action: PolicyAction;
  offset: number;
  length: number;
  /** Unicode block name or hex codepoint range that drove the match. */
  charClass: string;
  /** Consecutive characters removed; > 1 when a contiguous run is batched into one finding. */
  count: number;
  severity: Severity;
}>;

export type CredentialFinding = Readonly<{
  kind: 'credential';
  ruleId: string;
  ruleVersion: number;
  action: PolicyAction;
  offset: number;
  length: number;
  /** Placeholder substituted at the match site (per-pattern override or `policy.placeholderDefault`). */
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
