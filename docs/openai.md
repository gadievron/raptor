# OpenAI Codex support

RAPTOR provides initial Codex support through the same Python and `libexec/`
commands used by Claude Code. Start with the
[quickstart and troubleshooting guide](codex-quickstart.md).

The shared `bin/raptor` launcher prefers Claude when both CLIs are installed.
It falls back to Codex when Claude is absent; `bin/raptor --codex` selects Codex
explicitly. Direct `codex` from a trusted RAPTOR checkout also loads the project
configuration. Review and trust the checkout and its hooks normally.

## Shared procedures

| Path | Purpose |
| --- | --- |
| `AGENTS.md` | Repository instructions |
| `.agents/skills/` | Symlink to `../.claude/skills/` |
| `.claude/commands/` | Maintained command procedures |
| `.claude/skills/source-command-*/SKILL.md` | Thin discoverable command entry points |
| `.claude/agents/` | Maintained specialist role procedures |
| `.codex/agents/` | Native Codex metadata and loaders for shared role procedures |
| `.codex/config.toml` | Project-local environment, sandbox directory grants and inline hooks |

Use natural language or explicitly name a skill such as `$source-command-scan`,
`$source-command-project`, `$source-command-commands`, `$code-understanding`, or
`$exploitability-validation`. Command skills load the maintained source document;
they do not copy its workflow body or register native Claude-style slash commands.

See [command compatibility](codex-command-compatibility.md) for argument handling,
role adaptation and maintenance. Body edits need no synchronization; after adding
or renaming commands or changing descriptions, regenerate the thin entry points:

```bash
python3 scripts/sync_codex_commands.py --write
python3 scripts/sync_codex_commands.py --check
```

## Startup and environment

SessionStart runs `libexec/raptor-session-init` with explicit internal Codex/hook
markers. It produces the startup banner, seeds the existing session registry,
and publishes private context for RAPTOR's shared process startup. The host
broker validates session identity across Codex's tool PID sandbox.

Codex neither writes nor consumes `.codex/raptor.env`. Restoration happens inside
RAPTOR commands; arbitrary shell commands retain native environment inheritance.
Claude continues using its native `CLAUDE_ENV_FILE` mechanism. Existing
`BASH_ENV` stripping remains unchanged. See [runtime details](codex-runtime.md)
for storage, ownership, directory grants and validation boundaries.

## Initial support boundary

Real subprocess validation covers startup, project creation and switching,
projectless binding, and a local mechanical scan. Generated skills and role
loaders make procedures discoverable; they do not certify every advanced
workflow or install missing backends, tool permissions or isolation controls.

Generic Codex PreToolUse/PostToolUse command rewriting is disabled: making its
input rewrite effective required an allow decision that bypassed native command
rules in testing. Explicit Python lifecycle transitions remain authoritative;
RAPTOR-owned exit receipts now supply failure bookkeeping without changing
commands or approvals; see [command outcomes](codex-tool-outcomes.md). Arbitrary
external tool interception and automatic read-coverage parity are not provided. Stop/SessionEnd hooks use validated session context. Claude's native
failure hooks remain unchanged.

Inspect scan metrics and warnings. A completed local scan may still have reduced
coverage from unavailable remote packs or warnings about optional isolation
layers. Do not infer full coverage or complete cross-platform support from the
Linux smoke tests.
