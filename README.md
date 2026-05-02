# vaglio

Sanitize text crossing the LLM trust boundary.

Text-domain filter between extracted content, tool output, RAG chunks,
peer-model output, and the model. Zero runtime dependencies, ESM-only,
stream-aware, deterministic.

> Pre-1.0. The v0.1 surface is spec-locked. Breaking changes possible at
> minor-version boundaries until 1.0.

## Install

```sh
pnpm add vaglio
```

Requires Node ≥ 22 LTS. ESM-only.

## Quick start

```ts
import { sanitize } from 'vaglio';

const safe = sanitize(untrustedText);
await llm.send(safe);
```

Pipeline order: NFKC → strip Unicode invisibles → strip reasoning-tag
blocks → redact credentials. All four stages run against
[`DEFAULT_POLICY`](#default-policy).

## Threat coverage

Deterministic. No ML, no entropy heuristics.

- **Unicode invisibles.** Tags block (U+E0001–U+E007F), zero-width
  (ZWSP, ZWNJ, BOM, word joiner), bidi overrides (U+202A–U+202E,
  U+2066–U+2069), Mongolian Free Variation Selectors, interlinear
  annotations, supplementary PUA, supplementary variation selectors,
  soft hyphen / CGJ / Hangul fillers, invisible math operators, orphaned
  UTF-16 surrogates.
- **Homoglyph forging via NFKC.** Mathematical-alphanumeric
  (𝐬𝐲𝐬𝐭𝐞𝐦 → system) and fullwidth (＜system＞ → \<system\>) collapse to
  ASCII. Cross-script (Greek↔Latin, Cyrillic↔Latin) preserved by spec.
- **Zalgo.** Combining-mark cap per base character (default 4).
- **ANSI escapes.** `ESC[…]` sequences — invisible in terminals,
  tokenized verbatim by LLMs.
- **C0/C1 controls.** U+0000–U+001F and U+007F–U+009F stripped except
  `\t`, `\n`, `\r`. NBSP (U+00A0) preserved (printable, not control).
- **Reasoning-tag leakage.** `<internal>…</internal>` blocks; tag-name
  set is configurable.
- **Credentials.** Anthropic, AWS (AKIA/ASIA), Bearer JWT, Slack, GitHub
  PAT, Stripe restricted, PEM private key (RSA / EC / Ed25519 /
  generic), long hex (≥ 64 chars). Default placeholder `<credential>`.

## Where it plugs in

```
URL  → fetch → HTML→markdown extractor          → markdown ┐
File → document extractor (PDF, DOCX, …)        → text     │
HTML → HTML→text converter                      → text     │
RAG  → retrieve → chunk                         → text     ├→ vaglio.sanitize() → LLM
Tool → API call → serialize                     → string   │
LLM  → output (router / planner / loop step)    → text     ┘
```

The last row is the inter-model trust boundary. The receiving model
treats peer-model output as untrusted — same threat surface as user
input.

## Recipes

### Sanitize a string

```ts
import { sanitize } from 'vaglio';
const safe = sanitize(text);
```

### Telemetry via callback

Non-`Detailed` variants build no findings array unless `onFinding` is
provided. Silent operation is the default cost.

```ts
import { sanitize } from 'vaglio';

sanitize(text, {
  onFinding: (f) => metrics.emit(f.kind, f.ruleId, f.severity),
});
```

### Detail variant

```ts
import { sanitizeDetailed } from 'vaglio';

const result = sanitizeDetailed(input);
if (result.text === input) return input; // identity-check fast path (contract)
audit.write(result.findings);
return result.text;
```

### Web Streams

Cross-chunk credentials redact via an internal sliding-window buffer
(`Policy.bufferLimit`, auto-derived from the longest active pattern + 64).

```ts
import { createSanitizeStream } from 'vaglio';

await response.body!
  .pipeThrough(new TextDecoderStream())
  .pipeThrough(createSanitizeStream({ onFinding: emitMetric }))
  .pipeTo(modelInputSink);
```

### Async iterable

```ts
import { sanitizeIterable } from 'vaglio';

async function* turns() {
  for await (const turn of agentLoop) yield turn.content;
}

for await (const safe of sanitizeIterable(turns(), { onFinding: emitMetric })) {
  yield safe;
}
```

### Custom credential pattern

```ts
import { policy, sanitize } from 'vaglio';

const myPolicy = policy()
  .addCredentialPattern(/sot-session-[a-z0-9]{32}/i, {
    ruleId: 'sot-session',
    placeholder: '<session>',
    severity: 'high',
  })
  .build();

const safe = sanitize(text, { policy: myPolicy });
```

The builder is immutable: each method returns a new instance; `build()`
returns a frozen `Policy`. Reuse a base to derive variants:

```ts
const base     = policy().addReasoningTag('plan');
const stricter = base.disableUnicodeCategory('soft-hyphen-fillers').build();
const lenient  = base.build();
```

### Per-hop policy in a model-to-model chain

```ts
import { policy, sanitize } from 'vaglio';

const planner = policy().addReasoningTag('scratchpad').addReasoningTag('plan').build();
const router  = policy().build();

const safeRouterOut = sanitize(routerOutput, { policy: router });
await mainModel.generate({ context: safeRouterOut });

const safePlannerOut = sanitize(plannerOutput, { policy: planner });
await worker.run(safePlannerOut);
```

### Low-latency streaming

The default `bufferLimit` is **4160** characters — driven by the PEM
private-key pattern (`maxMatchLength: 4096` + 64). At ~4 chars/token,
downstream sees ~1k tokens of holdback. Drop the PEM pattern for
token-stream agents that don't ingest PEM blocks:

```ts
import { policy, createSanitizeStream } from 'vaglio';

const lowLatency = policy().removeCredentialPattern('pem-private-key').build();
// bufferLimit = 320 (~80 tokens)

const stream = createSanitizeStream({ policy: lowLatency });
```

### Tool result and RAG

```ts
import { sanitize } from 'vaglio';

const apiResponse    = await externalTool(args);
const safeToolResult = sanitize(JSON.stringify(apiResponse));

const chunks  = await retriever.search(query);
const context = chunks.map((c) => sanitize(c.text)).join('\n\n');
```

## Findings

```ts
type Finding =
  | { kind: 'unicode-strip';     ruleId: string; ruleVersion: number; action: PolicyAction; offset: number; length: number; charClass: string; count: number; severity: Severity; }
  | { kind: 'credential';        ruleId: string; ruleVersion: number; action: PolicyAction; offset: number; length: number; placeholder: string; severity: Severity; }
  | { kind: 'stream-diagnostic'; ruleId: string; ruleVersion: number; severity: Severity; message: string; };

type PolicyAction = 'stripped' | 'redacted' | 'replaced';
type Severity     = 'low' | 'medium' | 'high' | 'critical';
```

In v0.1, `unicode-strip` and reasoning-tag findings emit
`action: 'stripped'`; credential findings emit `action: 'redacted'`.
`'replaced'` is reserved.

Findings carry no raw snippets — emitting partial credentials or PII
into telemetry is a secondary leakage anti-pattern.

`ruleVersion` increments per CHANGELOG when a builtin's pattern,
severity, or `charClass` changes. Forensic logs survive pattern updates.

Continuous identical infractions (Zalgo run, repeated Tags-block
codepoints) aggregate into a single finding via `count` and `length`.

## Default policy

`DEFAULT_POLICY`:

| Slot                 | Default                                 |
| -------------------- | --------------------------------------- |
| Unicode categories   | all 13 enabled (see below)              |
| Combining-mark cap   | 4 per base character                    |
| NFKC                 | enabled                                 |
| Reasoning tags       | `internal`                              |
| Credential patterns  | 8 builtins                              |
| Placeholder          | `<credential>`                          |
| `bufferLimit`        | 4160 (PEM-driven)                       |

Categories: `tags-block`, `zero-width`, `bidi-override`, `mongolian-fvs`,
`interlinear-annotations`, `object-replacement`, `supplementary-pua`,
`supplementary-variation-selectors`, `soft-hyphen-fillers`,
`math-invisibles`, `orphaned-surrogates`, `ansi-escapes`,
`c0-c1-controls`.

Every slot is tunable via the builder.

## Streaming contract

- Identical semantics across batch (`sanitize`, `redact`), Web Streams
  (`createSanitizeStream`, `createRedactStream`), and async iterables
  (`sanitizeIterable`, `redactIterable`).
- Sliding-window buffer holds back the trailing `bufferLimit` characters
  per push so a chunk-straddling credential lands in the next leading
  region.
- Overflow: when the held tail can't shrink without losing a match,
  oldest bytes commit and a `stream-diagnostic` finding fires
  (`ruleId: 'buffer-overflow-warning'`). Redaction trumps fidelity.
- Cancel: `TransformStream.cancel(reason)` or async-iter `return()`
  releases the buffer and discards partial-credential state. Subsequent
  operations throw `VaglioStreamCanceledError`. A final
  `stream-diagnostic` finding (`ruleId: 'stream-canceled'`) emits via
  `onFinding` if subscribed.
- `flush()` is idempotent. Double-flush is a no-op. `push()` after
  `flush()` throws.
- Errors are fail-fast: catastrophic regex backtracking or corrupted
  state tears down the stream. Consumers must not retry.
- Identity preservation does not extend to streaming — use the batch
  surface for reference-equality fast paths.

## Roadmap

Planned for v0.2 and beyond:

- **Cross-script homoglyph folding** (Greek↔Latin, Cyrillic↔Latin) as an
  opt-in `Policy` flag. Off by default — folding across scripts would
  destroy legitimate non-Latin text.
- **ReDoS static analysis** on user-supplied patterns at `Policy.build()`
  time. v0.1 builtins are pre-validated at library-build time; user
  patterns are accepted unchecked.
- **Detail-variant streams.** Streaming exposes `onFinding` only in v0.1;
  a `createSanitizeStreamDetailed` shape is under consideration.
- **Pluggable Unicode rules** — `addUnicodeRule({ ruleId, range, action })`
  for codepoint-range stripping outside the closed `UnicodeCategory` set.
  Workaround in v0.1: `addStripPattern` with a regex.
- **Control-token forging detection** — model-specific message-role
  markers (`<|im_start|>`, `Human:` / `Assistant:`, etc.). Requires
  per-model presets.
- **External-content tagging** — auto-wrap RAG output in
  `<untrusted-data>…</untrusted-data>`.

## Out of scope

These belong in other layers, not in vaglio:

- **HTML parsing.** Vaglio operates on text and markdown only. Run an
  HTML sanitizer upstream.
- **Content extraction.** Vaglio sanitizes already-extracted text, not
  raw documents. Run an extractor upstream.
- **Binary / EXIF stripping.** Different domain (image / file).
- **Channel-specific output formatting.** App policy — chat-platform
  rendering, emoji allowlists, length caps, casing normalization.
- **Non-deterministic detection.** Repetition / entropy heuristics,
  ML-based detection, indirect prompt-injection (IPIA) defenses,
  token-boundary disruption mitigation. Vaglio is deterministic by
  contract — these belong in a separate detection layer.

## Compatibility

| Runtime                                            | v0.1                              |
| -------------------------------------------------- | --------------------------------- |
| Node ≥ 22 LTS                                      | CI matrix on 22 + 24              |
| Browsers                                           | supported via standard Web APIs (not in CI) |
| Edge runtimes                                      | supported via standard surfaces (not in CI) |
| Alternative JS runtimes                            | deferred from CI                  |

## License

[MIT](./LICENSE)
