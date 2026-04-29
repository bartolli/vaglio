## First read

Wiki primer at `projects/vaglio/primer.md`, loaded via
`mcp__wiki__prime(scope="vaglio")` per the global session protocol
(`~/.claude/CLAUDE.md` §7). The wiki primer is the authoritative
orientation surface — Current Focus, Frame for a fresh session, Next
Steps, Open Questions, Blocked On. Updated as work progresses.

## Wiki integration

WIKI_SCOPE: vaglio

This project is indexed in the personal llm-wiki at
`$WIKI_VAULT/projects/vaglio/`. The session protocol (call
`mcp__wiki__prime(scope="vaglio")` at session start, etc.) lives in
the global `~/.claude/CLAUDE.md` §7. The wiki primer now carries both
the durable cross-session state (active ADRs, hub pages) and the
active-phase orientation (Current Focus, Next Steps, Open Questions).

## Wiki resync protocol

The wiki is canonical for cross-session orientation. Resync whenever
project state crosses a durable threshold so that future sessions
(local or via `mcp__wiki__prime`) read accurate state.

Triggers:

- An open question in `primer.md` is resolved → strip it; reflect the
  resolution in the relevant ADR or spec.
- A milestone checkbox in `plan/plan-v0.md` flips → tick it; add a
  Status Log entry with the date.
- A new architectural decision lands → write or update an ADR; add a
  bullet to `index.md`'s Pages list and a wikilink from the primer.
- Phase or status changes → update `index.md` frontmatter (`phase`,
  `status`, `updated`).
- A new scope enters the wiki → flag for explicit user approval, then
  add to `~/llm-wiki/vault/CLAUDE.md` §"Frozen vocabulary".

Steps:

1. Re-read `~/llm-wiki/vault/CLAUDE.md` for current authoring rules.
   Load-bearing rules: `primer.md` is human-authored (edit only on
   explicit ask); folder name = slug prefix in `projects/`; ADR
   supersession is bidirectional (`superseded_by` + `supersedes`);
   bump `updated:` on every edit; reuse existing tags from `prime`'s
   `top_tags`.
2. Edit the relevant pages under
   `~/llm-wiki/vault/projects/vaglio/`. Use the matching template
   from `wiki://template/{domain}/{kind}` for new pages.
3. Push to the Postgres index:

   ```bash
   pnpm --filter @llm-wiki/sync start
   ```

   Run from `~/llm-wiki/vault-infra/`. Requires `WIKI_DB` env var and
   a running `llm_wiki` Postgres database. The walker is one-way
   (vault → PG) and idempotent — content-hash skip means re-running
   on an unchanged vault is a no-op.

Frozen-vocabulary edits to `~/llm-wiki/vault/CLAUDE.md` (kinds,
scopes, statuses, methodologies) need explicit user approval — flag
before editing, don't autonomously add.