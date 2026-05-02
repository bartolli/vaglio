/**
 * `vaglio/credentials` subpath — selective re-export per spec-api §1.
 *
 * Treeshaking entry point for consumers who want only credential redaction.
 * Internal helpers (redactCore, redactSilent, findHoldbackCutoff, EmitContext)
 * are NOT re-exported — they are cross-module plumbing whose contracts are not
 * frozen at v0.1.
 */

export {
  type CredentialPattern,
  DEFAULT_CREDENTIAL_PATTERNS,
  redact,
  redactDetailed
} from './credentials.js';
export type {
  CredentialFinding,
  Finding,
  Severity
} from './findings.js';
export type {
  Policy,
  SanitizeOptions,
  SanitizeResult
} from './policy.js';
