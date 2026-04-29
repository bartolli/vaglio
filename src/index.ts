/**
 * Vaglio v0.1 — root export per spec-api §1.
 *
 * Slices A + B + C wired:
 *   - `stripUnicode`, `stripUnicodeDetailed` — composed Unicode strip pipeline.
 *   - `redact`, `redactDetailed` — credential redaction.
 *   - `stripTags`, `stripTagsDetailed` — reasoning-tag block stripping.
 *   - Granular Unicode helpers (`stripAnsiEscapes`, `normalizeNFKC`, etc.).
 *   - `DEFAULT_REASONING_TAGS` — informational default tag-name list.
 *   - `Policy`, `PolicyBuilder`, `DEFAULT_POLICY`, `policy()` factory.
 *   - `Finding` discriminated union, `Severity`, `PolicyAction`, `UnicodeCategory`.
 *   - `SanitizeOptions`, `SanitizeResult`.
 *   - `VaglioPolicyValidationError`, `VaglioStreamCanceledError`.
 *
 * `sanitize`/`sanitizeDetailed` (Slice D) and the streaming surface (M3.5)
 * land incrementally; this file is updated per slice.
 */

export {
  type CredentialPattern,
  DEFAULT_CREDENTIAL_PATTERNS,
  redact,
  redactDetailed
} from './credentials.js';
export {
  VaglioPolicyValidationError,
  VaglioStreamCanceledError
} from './errors.js';
export type {
  CredentialFinding,
  Finding,
  FindingKind,
  PolicyAction,
  Severity,
  StreamDiagnosticFinding,
  UnicodeStripFinding
} from './findings.js';
export {
  DEFAULT_POLICY,
  type Policy,
  type PolicyBuilder,
  policy,
  type SanitizeOptions,
  type SanitizeResult,
  type StripPattern,
  type UnicodeCategory
} from './policy.js';
export {
  DEFAULT_REASONING_TAGS,
  stripTags,
  stripTagsDetailed
} from './tags.js';
export {
  capCombiningMarks,
  normalizeNFKC,
  stripAnsiEscapes,
  stripOrphanedSurrogates,
  stripUnicode,
  stripUnicodeDetailed
} from './unicode.js';
