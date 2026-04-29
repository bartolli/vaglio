/**
 * Vaglio v0.1 — root export per spec-api §1.
 *
 * Slice A wired so far:
 *   - `stripUnicode`, `stripUnicodeDetailed` — composed Unicode strip pipeline.
 *   - Granular Unicode helpers (`stripAnsiEscapes`, `normalizeNFKC`, etc.).
 *   - `Policy`, `PolicyBuilder`, `DEFAULT_POLICY`, `policy()` factory.
 *   - `Finding` discriminated union, `Severity`, `PolicyAction`, `UnicodeCategory`.
 *   - `SanitizeOptions`, `SanitizeResult`.
 *   - `VaglioPolicyValidationError`, `VaglioStreamCanceledError`.
 *
 * `redact`/`redactDetailed` (Slice B), `stripTags`/`stripTagsDetailed` (Slice C),
 * `sanitize`/`sanitizeDetailed` (Slice D), and the streaming surface (M3.5) land
 * incrementally; this file is updated per slice.
 */

export {
  type CredentialPattern,
  DEFAULT_CREDENTIAL_PATTERNS
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
  capCombiningMarks,
  normalizeNFKC,
  stripAnsiEscapes,
  stripOrphanedSurrogates,
  stripUnicode,
  stripUnicodeDetailed
} from './unicode.js';
