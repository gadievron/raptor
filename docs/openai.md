# OpenAI Codex Support

RAPTOR can now run its operator-facing workflow from OpenAI Codex as well as Claude Code. The Python and `libexec/` tools stay the source of truth; the Codex files are the agent-facing layer that teaches Codex how to call them.

## What Lives Where

| Path | Purpose |
|------|---------|
| `AGENTS.md` | Repository instructions Codex reads before working in RAPTOR |
| `.agents/skills/` | Symlink to `../.claude/skills/` — shared skill definitions for both Claude Code and Codex |
| `.codex/agents/` | Codex sub-agent definitions converted from the existing RAPTOR specialist agents |
| `.codex/config.toml` | Codex shell environment settings for RAPTOR sessions |
| `.codex/hooks.json` | Session-start hook that runs `libexec/raptor-session-init` |
| `docs/openai.md` | This file — OpenAI Codex setup and agent-surface layout |

The `.claude/` surface remains in place. This is not a fork of the workflow; it is the same RAPTOR machinery exposed to another agent shell.

## Running It

Install Codex, then open the repo:

```bash
npm install -g @openai/codex
cd /path/to/raptor
codex
```

Codex loads `AGENTS.md` and discovers repo skills from `.agents/skills`. You can ask for normal RAPTOR commands in plain language, or name a skill explicitly with `$source-command-agentic`, `$source-command-understand`, `$exploitability-validation`, and so on.

## Startup Hook

Codex runs:

```bash
_RAPTOR_TRUSTED=1 libexec/raptor-session-init
```

That generates `.startup-output` and `.codex/raptor.env`. The env file is ignored by git and is only session state.

`libexec/raptor-session-init` also keeps the old `CLAUDE_ENV_FILE` fallback so existing Claude Code sessions are not broken by this change.

## Skill Shape

`.agents/skills` is a symlink to `../.claude/skills`, so both Claude Code and Codex read the same skill definitions. Each skill is a directory containing a `SKILL.md` with `name` and `description` frontmatter. Extra notes, scripts and reference files stay inside that skill directory and are loaded progressively by the agent when needed.

The copied skills intentionally keep RAPTOR's existing command boundaries:

- `source-command-*` skills mirror slash-command workflows such as `/scan`, `/agentic`, `/validate`, `/understand`, `/diagram`, `/project`, `/fuzz`, `/web` and `/tune`.
- `code-understanding` and `exploitability-validation` hold the deeper methodology files.
- `crash-analysis/*` and `oss-forensics/*` expose the specialist workflows without making the base prompt huge.

## Developer Notes

When adding a new RAPTOR command, add or update the Python/libexec implementation first, then expose it through:

1. `.claude/commands/` if Claude needs it.
2. Skills are shared via the `.agents/skills` → `.claude/skills` symlink, so updating `.claude/skills/` covers both platforms.
3. `AGENTS.md` if it changes global operating rules.
4. `README.md` or command docs if it is user-facing.

Keep the agent files thin. They should describe how to call RAPTOR, not reimplement RAPTOR in prose.


## Codex shell lifecycle hooks

Codex uses `PreToolUse` and `PostToolUse` adapters for simple POSIX-shell
`libexec/raptor-*` invocations. The pre-hook adds a subshell-local EXIT
recorder. The post-hook reads its private per-invocation result and shares
Claude's existing failure-marker and run-attribution logic. Command stdout
is never treated as exit-status evidence. Re-review changed hooks in `/hooks`.

Successful commands retain their stdout and exit status. Explicit Python
lifecycle transitions remain authoritative. Codex Stop only finalizes a
recorded failure; an unknown result stays unresolved for its owner or later
reconciliation. Claude's failure-only and Stop hooks are unchanged.

Pipelines, shell compounds, redirections, exec wrappers, non-POSIX shells,
and direct `python3 raptor.py` invocations are not instrumented by this
initial adapter. These still use the runner's normal lifecycle handling.
A killed shell, sandbox-denied recorder, or missing completion event can
leave no result; that is unknown, never inferred success or failure.

Private result files use mode 0600 inside a user-owned 0700 system-temp
directory named `raptor-codex-hook-results-<uid>`. Normal completion consumes
the record. Interrupted invocations can leave pending files; they contain
command text, not captured command output or added session credentials.
This is status bookkeeping, not a security boundary against an agent or
process that already runs as the same user. System-temp access must be
available to both hook and command execution environments.

The adapter does not implement the separate startup/env-file bridge or
claim full Codex/Claude feature parity. Validate real hook rewriting and
completion delivery on the installed Codex version before rollout.
