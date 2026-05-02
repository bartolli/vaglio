/**
 * `vaglio/unicode` subpath — selective re-export per spec-api §1.
 *
 * Treeshaking entry point for consumers who want only the Unicode pipeline.
 * Internal helpers (stripAnsiEscapes, stripOrphanedSurrogates) are NOT re-exported:
 * they are subsumed by the composed stripUnicode pipeline whose load-bearing
 * order (ANSI → orphan-surrogate → NFKC → strip-set → VS context → ZWJ context
 * → mark cap → NFKC) defenders must not bypass.
 *
 * Granular per-category strip variants (stripBidi, stripZeroWidth, etc.) are
 * deferred to v0.2 pending consumer demand.
 */

export type {
  Finding,
  UnicodeStripFinding
} from './findings.js';
export type {
  Policy,
  SanitizeOptions,
  SanitizeResult,
  UnicodeCategory
} from './policy.js';
export {
  capCombiningMarks,
  normalizeNFKC,
  stripUnicode,
  stripUnicodeDetailed
} from './unicode.js';
