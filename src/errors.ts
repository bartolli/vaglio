export type PolicyValidationCause = Readonly<{
  /** Regex source, or `''` when the cause is not pattern-scoped. */
  pattern: string;
  /**
   * `"redos"` and `"missing-max-match"` are reserved for the v0.2 static analyzer
   * (unreachable in v0.1). `"invalid-regex"` is unreachable because the
   * `pattern: RegExp` shape means JS throws at construction, not at `build()`.
   */
  rule:
    | 'redos'
    | 'missing-max-match'
    | 'invalid-regex'
    | 'duplicate-rule-id'
    | 'buffer-limit-too-low';
  detail: string;
}>;

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

export class VaglioStreamCanceledError extends Error {
  readonly reason: unknown;

  constructor(reason: unknown) {
    super('Vaglio stream was canceled');
    this.name = 'VaglioStreamCanceledError';
    this.reason = reason;
  }
}
