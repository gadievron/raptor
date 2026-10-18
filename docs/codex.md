# Codex support

Use the shared launcher with `--codex`, or run `codex` directly from a trusted
RAPTOR checkout. Review and trust the checkout and its hooks through Codex's
normal trust flow.

```bash
bin/raptor --codex
```

The workspace-write sandbox is required for analyses. Use natural language or
name a skill explicitly (`$scan`, `$project`).

RAPTOR's Claude-style `/scan`, `/fuzz`, `/web` and `/agentic` shortcuts are not
registered Codex slash commands. In the Codex chat composer, use:

```text
$scan /absolute/path/to/repo
```

Likewise use `$agentic`, `$fuzz` or
`$web` with the target and options for that workflow. Type
`/skills` to browse installed skills, or `$commands` to list
RAPTOR workflows. Ordinary requests such as `scan /absolute/path/to/repo`
also select the matching RAPTOR skill. These are chat inputs, not shell commands.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Missing or invalid startup context | Review `/hooks` and any SessionStart error. Confirm the checkout is trusted and restart. |
| Writes denied during startup | Use workspace-write. Custom paths need explicit directory grants. |
| Project differs after resume | Inspect current session status. Use `-p` to pin the intended project. |
