## First read

Wiki primer at `projects/vaglio/primer.md`, loaded via
`mcp__wiki__prime(scope="vaglio")` per the global wiki session
protocol in `~/.claude/CLAUDE.md`.

## Wiki integration

WIKI_SCOPE: vaglio

Authoring rules and resync protocol: `$WIKI_VAULT/CLAUDE.md`.

## Sub-agent spawning

When spawning a sub-agent for vaglio work, the prompt must include:

- the WIKI_SCOPE (so it can prime),
- the specific spec / ADR section relevant to the task,
- the slicing methodology pointer
  (`projects/vaglio/ops/ops-slicing-protocol`).

Don't assume the sub-agent will discover these via search.
