/**
 * Error types for Vaglio v0.1.
 *
 * Two classes per spec-api §8: `VaglioPolicyValidationError` (thrown by
 * `Policy.build()` when the assembled policy fails validation) and
 * `VaglioStreamCanceledError` (thrown by streaming surfaces after cancel).
 *
 * Both extend `Error` — `instanceof` works, stack traces are preserved, and
 * standard JS error-handling patterns apply. v0.1 surfaces both at the root
 * `vaglio` export; no separate `vaglio/errors` subpath (spec §8 — surface is
 * small enough that a dedicated subpath would be overhead).
 */

export type PolicyValidationCause = Readonly<{
  /** The regex source for the offending pattern, or `''` when not pattern-scoped. */
  pattern: string;
  /**
   * Validation rule that fired. v0.1 set:
   *   - `"missing-max-match"` — currently emitted only via the v0.2 ReDoS/static analyzer; reserved.
   *   - `"redos"`             — reserved for v0.2 static analyzer.
   *   - `"duplicate-rule-id"` — same `ruleId` declared on multiple patterns (credential or strip).
   *   - `"buffer-limit-too-low"` — explicit `setBufferLimit` below auto-derived minimum.
   *
   * `"invalid-regex"` from the original spec is unreachable in v0.1 because the
   * `pattern: RegExp` shape means JS throws at construction, not at `build()`.
   * Reserved here for forward-compat with v0.2's static analyzer (which may parse
   * regex source strings).
   */
  rule:
    | 'redos'
    | 'missing-max-match'
    | 'invalid-regex'
    | 'duplicate-rule-id'
    | 'buffer-limit-too-low';
  detail: string;
}>;

/**
 * Thrown by `Policy.build()` when validation fails.
 *
 * `causes` reports every validation failure at once — consumers fix all issues
 * in one pass rather than playing whack-a-mole.
 */
export class VaglioPolicyValidationError extends Error {
  readonly causes: ReadonlyArray<PolicyValidationCause>;

  constructor(causes: ReadonlyArray<PolicyValidationCause>) {
    const summary =
      causes.length === 1 ? '1 validation error' : `${causes.length} validation errors`;
    super(
      `Policy validation failed (${summary}): ${causes.map((c) => `${c.rule}: ${c.detail}`).join('; ')}`
    );
    this.name = 'VaglioPolicyValidationError';
    this.causes = Object.freeze([...causes]);
  }
}

/**
 * Thrown by streaming surfaces (`createSanitizeStream`, `sanitizeIterable`, and
 * the `redact` siblings) when called after cancel. Carries the cancel reason.
 */
export class VaglioStreamCanceledError extends Error {
  readonly reason: unknown;

  constructor(reason: unknown) {
    super('Vaglio stream was canceled');
    this.name = 'VaglioStreamCanceledError';
    this.reason = reason;
  }
}
