# Codex support

Use the shared launcher with `--codex`. Review and trust the checkout and its
hooks through Codex's normal trust flow.

```bash
bin/raptor --codex
```

The launcher pins `RAPTOR_CODEX_HOOK_ROOT` to its own resolved installation.
Hooks use that host-side anchor even when their working directory is a nested
repository or scan target. They never discover executable code using the hook
cwd, git root, payload, or `RAPTOR_DIR`. Plain `codex` launches without the
launcher anchor refuse RAPTOR hooks; use the launcher rather than setting the
anchor from a target repository. Restart through the launcher after updating
these hook definitions, then review them through `/hooks`.

The workspace-write sandbox is required for analyses. Use natural language or
name a skill explicitly (`$scan`, `$project`).

RAPTOR commands recover operator configuration, output settings, provider
credentials and routing from the private session broker. Ordinary shell
commands retain Codex's core environment filter. Credentials are not placed in
launcher arguments or persistent startup context; target subprocesses retain
RAPTOR's existing credential stripping. Restart Codex after upgrading the
broker so it captures the operator's current environment. Custom output and
credential-file locations still need the appropriate native sandbox grants.

For standalone Python files required by a shared RAPTOR procedure, use:

```bash
python3 -I libexec/raptor-session-init --codex-python <script-path> [args...]
```

The runner restores the current session before executing the file, preserves
its arguments and exit status, and uses the native sandbox and approval policy.
It does not initialize a new session or modify future shell environments.

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

Codex project bindings and run ownership are scoped to the root session, even
when multiple conversations share an app-server process. Subagents share their
root's binding. See [session ownership](codex-sessions.md) for compatibility,
locking, upgrade behavior, and validation limits. Review the changed hooks and
restart after upgrading from PID-only Codex session state.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Missing or invalid startup context | Review `/hooks` and any SessionStart error. Confirm the checkout is trusted and restart. |
| Writes denied during startup | Use workspace-write. Custom paths need explicit directory grants. |
| Project differs after resume | Inspect current session status. Use `-p` to pin the intended project. |

## Integration scope

Codex is an interactive RAPTOR frontend. Some analysis stages still dispatch
to Claude through the shared backend and require its configured authentication;
interactive `--codex` selection does not change that backend. The separate
Codex execution backend effort must integrate below the Python dispatcher,
with the same lifecycle, artifact validation, budgets, and sandbox controls.

Native hook trust and checkout trust are separate prerequisites. Review hooks
through `/hooks` after their definitions change, then start or resume a session.
Automated tests with synthetic owner processes do not replace native client
acceptance; see [the acceptance checklist](codex-sessions.md#native-acceptance-still-required).
