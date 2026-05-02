# Changelog

All notable changes to `@bartolli/vaglio` are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer 2.0.0](https://semver.org/spec/v2.0.0.html).

## [0.1.0-rc.1] — 2026-05-02

### Changed

- Package scoped as `@bartolli/vaglio`; install: `pnpm add @bartolli/vaglio`.

## [0.1.0] — 2026-05-02

First public release. Defense-side library for sanitizing text crossing the LLM trust boundary in context-loading pipelines.

### Threat coverage (Unicode prompt-injection defenses, all default-on)

- **Tags block** — U+E0000–U+E007F. Strips invisible-tag-encoded prompt overlays.
- **Bidi overrides** — U+202A–U+202E, U+2066–U+2069. Defeats RTL/LRO reordering attacks.
- **Zero-width** — U+200B–U+200D, U+FEFF, U+2060. Strips ZWSP/ZWNJ/ZWJ/BOM/word-joiner; **ZWJ context-aware** (preserves emoji ligatures).
- **Mongolian Free Variation Selectors** — U+180B–U+180F. Strips FVS-encoded payloads.
- **Interlinear annotations** — U+FFF9–U+FFFB. Strips IAA/IAS/IAT.
- **Object replacement** — U+FFFC.
- **Supplementary PUA** — U+F0000–U+10FFFD. Strips private-use codepoints adversaries co-opt for hidden channels.
- **Supplementary variation selectors** — U+E0100–U+E01EF + BMP U+FE00–U+FE0F. **Context-aware** (preserves VS after emoji base characters).
- **Soft-hyphen / CGJ / Hangul fillers** — U+00AD, U+034F, U+115F, U+1160, U+3164, U+FFA0.
- **Math invisibles** — U+2061–U+2064. Invisible function-application/separator/plus/times.
- **Orphaned UTF-16 surrogates** — strips lone high/low surrogates that bypass NFKC. Per AWS Security Blog (Sep 2025).
- **ANSI escape sequences** — `ESC [`, `ESC ]`, et al. Defeats terminal-control payloads.
- **C0 / C1 controls** — U+0000–U+001F (less `\t \n \r`), U+007F–U+009F including U+0085 NEL. NBSP U+00A0 preserved.
- **NFKC normalization** — folds fullwidth/Mathematical-Alphanumeric/Letterlike-Symbols homoglyphs to ASCII (97.3% / 70% empirical fold rates per Node 22). Cross-script homoglyphs (Greek↔Latin, Cyrillic↔Latin) intentionally preserved per Unicode same-script invariant.
- **Combining-mark cap (Zalgo)** — caps consecutive combining marks per base character (default 4).

**Pipeline order is load-bearing**: ANSI → orphan-surrogate → NFKC → strip-set → VS context → ZWJ context → mark cap → NFKC final. Final NFKC re-canonicalizes sequences exposed by intervening strips.

### Credential redaction

- **8 builtin patterns**: `anthropic-key` (`sk-ant-api03-…`), `aws-access-key` (AKIA + ASIA), `jwt`, `slack-token` (`xoxb`/`xoxp`), `github-pat` (`ghp_`), `stripe-key` (`sk_live_`/`sk_test_`), `pem-private-key` (PKCS#8 / PKCS#1, `maxMatchLength: 4096` ⇒ covers RSA-4096), `long-hex` (≥ 64 hex chars).
- **Default placeholder** `<credential>`. Per-pattern override via `placeholder` field.
- **Severity defaults** per pattern; consumer override via `Policy.severityOverrides[ruleId]`.
- **`maxMatchLength` contract** — required for unbounded patterns; consumed for `bufferLimit` auto-derivation; `Policy.build()` throws `VaglioPolicyValidationError` if omitted.

### Reasoning-tag stripping

- **Default tag**: `<internal>…</internal>`. Configurable via `policy().addReasoningTag(name)`.
- **Lazy multi-line** match (`[\s\S]*?`) ⇒ stops at first close, no nested-tag bleed.
- **Identity preservation** via `text.includes('<')` fast path.

### Public surface

- **Pure batch functions**: `sanitize`, `redact`, `stripUnicode`, `stripTags` (+ `*Detailed` variants returning `{ text, changed, findings }`).
- **Streaming factories**: `createSanitizeStream`, `createRedactStream` ⇒ `TransformStream<string, string>`. Per-call internal state.
- **Async-iter adapters**: `sanitizeIterable`, `redactIterable` ⇒ accept `AsyncIterable<string> | Iterable<string>`.
- **Builder**: `policy()` ⇒ immutable — every method returns a new builder; `build()` produces a frozen `Policy`.
- **Subpaths** (treeshaking): `@bartolli/vaglio/unicode`, `@bartolli/vaglio/credentials`, `@bartolli/vaglio/tags` ⇒ composed-pipeline entry points only. Granular per-category strip exports deferred to v0.2 — composing strip stages out of order loses the load-bearing pipeline order, so v0.2 will ship them with explicit ordering guidance.
- **Defaults**: `DEFAULT_POLICY`, `DEFAULT_CREDENTIAL_PATTERNS`, `DEFAULT_REASONING_TAGS`.
- **Errors**: `VaglioPolicyValidationError` (multi-cause), `VaglioStreamCanceledError`.

### Streaming contract

- **Sliding-window buffer** sized by `Policy.bufferLimit` (auto-derived = `max(maxMatchLength) + 64`; default 4160 from PEM 4096 + slack 64). User override permitted; `build()` rejects below auto-min.
- **Cross-chunk credential redaction** via `matchAll`-aware `redactCore`. Verified against real RSA-4096 PEM split mid-body.
- **Cumulative offset frame** — `Finding.offset = consumedBytes + matchOffsetInBuffer` (post-redaction absolute origin per emit history).
- **Per-stage finding offset** in batch — each stage's findings carry offsets in *that stage's input* (post-prior-stage). Cross-stage stable offsets deferred to v0.2.
- **Single-buffer architecture** for sanitize streaming — one buffer per call, all stages run against it per push, in pipeline order.
- **Trailing-edge ZWJ holdback** ⇒ stream/batch equivalence under adversary-controlled chunking. Without it, a chunk boundary right after U+200D would strip the ZWJ as orphan, diverging from batch output.
- **Cancel** ⇒ buffer released; partial-credential matches discarded; subsequent ops throw `VaglioStreamCanceledError`; optional `stream-canceled` finding via `onFinding`.
- **Overflow** ⇒ slide-emit oldest bytes; `buffer-overflow-warning` finding fires only when slide-emit happens AND zero substantive findings (`credential` ∪ `unicode-strip`) emit in that push (avoids steady-state noise).
- **Source-thrown errors** propagate as-is. `VaglioStreamCanceledError` is reserved for user-initiated cancel.
- **Idempotent flush**; **empty `push('')`** is a no-op; `push()` after `flush()` throws generic `Error` (usage bug, not cancellation).

### Telemetry

- **Discriminated `Finding` union** with three kinds: `unicode-strip`, `credential`, `stream-diagnostic`.
- **`ruleId` + `ruleVersion`** on every finding; SIEM aggregation default view is trend-by-`ruleId`.
- **No raw snippets** — count-based aggregation only. Defense-side telemetry contract.
- **Silent operation** — non-detailed variants skip findings construction unless `onFinding` is provided.
- **Identity preservation** — `*Detailed` variants return `text === input` (same reference) when `changed === false`. Hot-path consumers short-circuit downstream work via identity check.

### Build / runtime

- **Node ≥ 22 LTS**, ESM-only, `sideEffects: false` ⇒ treeshakeable.
- **Zero runtime dependencies.**
- **OIDC + npm provenance** via Sigstore (GitHub Actions Trusted Publisher).
- **Pinned action SHAs** (`actions/checkout@v6.0.2`, `actions/setup-node@v6.4.0`); Corepack-activated pnpm.
- **`dependency-review-action`** PR gate at `fail-on-severity: high`.
- **Static contract gates**: `publint` + `@arethetypeswrong/cli --profile esm-only` in CI.

### Out of scope (permanent boundaries)

Vaglio does not parse HTML (DOMPurify), extract content (Defuddle / Markdownify / pdf-parse / mammoth), format channel-specific output (app policy), handle binary or EXIF (different domain), or apply non-deterministic detection (§F7 determinism contract).

### Roadmap (v0.2 candidates)

Cross-script homoglyph folding, ReDoS analyzer + runtime kill-switches, granular per-category Unicode strip exports, detail-variant streams, pluggable Unicode rules (`addUnicodeRule`), control-token forging detection, external-content tagging, stable cross-stage offset frame.

[0.1.0]: https://github.com/bartolli/vaglio/releases/tag/v0.1.0
