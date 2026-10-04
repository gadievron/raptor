# OpenAI Codex Support

RAPTOR can now run its operator-facing workflow from OpenAI Codex as well as Claude Code. The Python and `libexec/` tools stay the source of truth; the Codex files are the agent-facing layer that teaches Codex how to call them.

## What Lives Where

| Path | Purpose |
|------|---------|
| `AGENTS.md` | Repository instructions Codex reads before working in RAPTOR |
| `.agents/skills/` | Codex skills for commands, validation, understanding, crash work, coverage and OSS forensics |
| `.codex/agents/` | Codex sub-agent definitions converted from the existing RAPTOR specialist agents |
| `.codex/config.toml` | Codex shell environment settings for RAPTOR sessions |
| `.codex/hooks.json` | Session-start hook that runs `libexec/raptor-session-init` |

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

Each skill is a directory containing a `SKILL.md` with `name` and `description` frontmatter. Extra notes, scripts and reference files stay inside that skill directory and are loaded progressively by the agent when needed.

The copied skills intentionally keep RAPTOR's existing command boundaries:

- `source-command-*` skills mirror slash-command workflows such as `/scan`, `/agentic`, `/validate`, `/understand`, `/diagram`, `/project`, `/fuzz`, `/web` and `/tune`.
- `code-understanding` and `exploitability-validation` hold the deeper methodology files.
- `crash-analysis/*` and `oss-forensics/*` expose the specialist workflows without making the base prompt huge.

## Developer Notes

When adding a new RAPTOR command, add or update the Python/libexec implementation first, then expose it through:

1. `.claude/commands/` if Claude needs it.
2. `.agents/skills/source-command-*/SKILL.md` if Codex needs it.
3. `AGENTS.md` if it changes global operating rules.
4. `README.md` or command docs if it is user-facing.

Keep the agent files thin. They should describe how to call RAPTOR, not reimplement RAPTOR in prose.
