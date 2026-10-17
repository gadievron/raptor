# Codex adapters for RAPTOR procedures

`.agents/skills` remains a symlink to `.claude/skills`. Existing methodology
skills remain shared. The generated `source-command-*` skills add discoverable
entry points to `.claude/commands/*.md`; they do not copy workflow bodies.
For example, invoke `$source-command-scan`, `$source-command-project`, or
`$source-command-commands`. These names are Codex skills, not native `/scan`
slash-command registrations. Natural-language requests can also select skills.

Read the linked source procedure before acting. Its stages, gates, lifecycle,
artifacts, error handling, and approval requirements remain authoritative.
Resolve references from the source file's directory. Follow aliases to their
canonical command document. Source `dispatch` frontmatter describes routing;
it is not an instruction to start a pipeline without reading the body (some
commands only print help). Supply the user's actual arguments where the source
uses `$ARGUMENTS`; never execute unresolved placeholders or shell-evaluate user
arguments. Preserve literal commands and use argv-based argument handling.

Adapt host interaction names to available Codex tools: file reading, user
questions, and delegating to registered native agents where authorized. Narrative
references to the main Claude agent mean the current host agent. Literal
`claude` subprocesses, backend identifiers, credentials, permissions, hooks, and
sandbox configurations remain actual dependencies; do not replace them by name
or assume equivalent controls exist. Respect read-only and fetch-only roles.
If a required tool, model, delegation feature, or isolation control is unavailable,
report the limitation and stop that step. Never claim unexecuted stages succeeded.
An unavailable optional component may be skipped only when the source permits it.

Use the source lifecycle rules. Commands implemented by `raptor.py` already
manage their lifecycle; do not create a second run around them. Shared methodology
skills and progressive-loading references remain the source of detailed guidance.

Native `.codex/agents/*.toml` files retain Codex metadata and load the matching
Claude role procedure by its frontmatter name. Claude frontmatter does not
install Codex hooks or enforce Codex tool permissions. This patch shares
instructions; it does not establish runtime/backend parity or certify every
workflow end to end.

## Maintenance

Edit command and role procedures once, in `.claude/commands` and `.claude/agents`.
Body edits are visible immediately through the adapters. After adding, renaming,
or changing command descriptions, run:

```bash
python3 scripts/sync_codex_commands.py --write
python3 scripts/sync_codex_commands.py --check
```

The generator preserves native agent settings, updates only their instruction
blocks, and reports obsolete adapters for manual review rather than deleting
them. New role names require an explicit native Codex agent definition. The check
mode detects missing/stale adapters and unmapped roles without writing files.
