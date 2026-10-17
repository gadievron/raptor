# Codex support

Use the shared launcher with `--codex`, or run `codex` directly from a trusted
RAPTOR checkout. Review and trust the checkout and its hooks through Codex's
normal trust flow.

```bash
bin/raptor --codex
```

The workspace-write sandbox is required for analyses. Use natural language or
name a skill explicitly (`$source-command-scan`, `$source-command-project`).

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Missing or invalid startup context | Review `/hooks` and any SessionStart error. Confirm the checkout is trusted and restart. |
| Writes denied during startup | Use workspace-write. Custom paths need explicit directory grants. |
| Project differs after resume | Inspect current session status. Use `-p` to pin the intended project. |
