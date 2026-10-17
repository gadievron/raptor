# Run RAPTOR with Codex

Install RAPTOR's normal dependencies and authenticate the Codex CLI using its
normal login flow. This integration was tested with Codex CLI 0.163.0 on Linux.
Keep the checkout's `.agents/skills` symlink pointing to `../.claude/skills`.

Start from your target directory:

```bash
/path/to/raptor/bin/raptor --codex
```

The shared launcher starts Claude by default when both CLIs are on PATH, and
falls back to Codex when Claude is missing. `--codex` explicitly requires Codex.
For native Codex options, use the launcher argument separator:

```bash
/path/to/raptor/bin/raptor --codex -- --sandbox workspace-write
```

Review and trust the RAPTOR checkout and its hooks through Codex's normal trust
flow. Trusting a target repository is a separate decision: `--trust-repo` is a
RAPTOR target preflight override, not Codex project/hook trust. Do not disable
native command approval or sandboxing to solve startup errors.

Use natural language to request a project or scan. When the command-adapter
patch is installed, explicit skill names include `$source-command-project`,
`$source-command-scan` and `$source-command-commands`. Existing methodology
skills remain shared. These names are skills; Claude's `/scan` and `/project`
are not automatically registered as native Codex slash commands.

A useful acceptance sequence is to create a project with an explicit target,
inspect its status in another tool call, run a local scan, select another
project, clear the binding with project none, and inspect status again.
RAPTOR commands restore session context internally; do not source
`.codex/raptor.env` or expect arbitrary `echo "$RAPTOR_*"` calls to show it.
See [runtime details](codex-runtime.md).

Resume the most recent interactive conversation with the shared launcher:

```bash
/path/to/raptor/bin/raptor --codex --continue
```

Projects are bound to launcher sessions, not permanently stored in Codex chat
history. A new launcher process seeds its binding from an explicit `-p` choice,
auto-detection, or the last-activated bookmark. An old chat's project selection
should not be inferred from the conversation alone; inspect current project
status after resume. To pin a named project when resuming:

```bash
/path/to/raptor/bin/raptor --codex -p myproject --continue
```

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Missing or invalid startup context | Review `/hooks` in Codex and any SessionStart error. Confirm the checkout is trusted and restart after correcting the failure. Do not source an old env file. |
| Writes denied during startup/analysis | Use workspace-write. The project grants only RAPTOR-owned state directories; custom registry/output paths need explicit native directory grants. |
| Local rules run but remote packs are dropped | The sandbox cannot download uncached rules. Inspect dropped-pack metrics and use locally available rules; report reduced coverage. |
| Project differs after resume | Inspect current session status. Launcher seeding may choose the current bookmark or caller-directory match; use `-p` to pin the intended project. |
| Shell does not show RAPTOR variables | Restoration happens inside RAPTOR Python commands; ordinary shell environment inheritance remains native. |
| Optional workflow cannot supply required controls | Stop that step and report the unsupported requirement. Shared instructions do not install missing tool permissions, hooks or backends. |

Never set `BASH_ENV` or change shell profiles for this integration. Existing
RAPTOR stripping stays in force. A scan's successful exit does not mean all rule
packs or every optional isolation layer were available; inspect its warnings
and metrics. Generic tool-failure interception and automatic read-coverage hook
parity are not yet provided.
