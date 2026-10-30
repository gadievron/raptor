# Codex support

## Setup

Use Python 3.12 or newer and install RAPTOR's locked dependencies from the
checkout you intend to launch:

```bash
uv sync --locked
source .venv/bin/activate
uv tool install semgrep
```

Install and sign in to Codex using the [official CLI instructions](https://learn.chatgpt.com/docs/cli).
For an existing standalone installation, update and record the version:

```bash
codex update
codex --version
codex login
```

Use a Linux environment. Native Windows is not supported; use WSL for Windows.
macOS and WSL support have not been verified end to end.

Use the shared launcher with `--codex`. Review and trust the checkout and its
hooks through Codex's normal trust flow.

```bash
bin/raptor --codex -- --sandbox workspace-write --ask-for-approval on-request
```

After an update, add `--no-daemon` after `--` if Codex reconnects to an older
server, so the new client/server receives the launcher's environment.

The launcher pins `RAPTOR_CODEX_HOOK_ROOT` to its own resolved installation.
Hooks use that host-side anchor even when their working directory is a nested
repository or scan target. They never discover executable code using the hook
cwd, git root, payload, or `RAPTOR_DIR`. Plain `codex` launches without the
launcher anchor refuse RAPTOR hooks; use the launcher rather than setting the
anchor from a target repository. Restart through the launcher after updating
these hook definitions, then review them through `/hooks`.

The workspace-write sandbox is required for analyses. Use natural language or
name a skill explicitly (`$scan`, `$project`).

There are separate trust decisions: trust the RAPTOR checkout so Codex loads
its project configuration, then review its five hooks through `/hooks`.
Changed hook definitions need review again. A listed but untrusted hook is
different from a missing hook. RAPTOR's target `config`/`build`/`dynamic` trust
markers are separate; `--trust-repo` does not make Codex discover or trust
RAPTOR hooks. See the [native hook trust contract](https://learn.chatgpt.com/docs/hooks).

Use a normal Git checkout for the first full journey. On Codex 0.166.0,
linked-worktree hook discovery still fails the owner-specific configuration
check. Other project settings and skills may load while the hooks are absent
or come from the primary checkout. Verify all five hook sources in `/hooks`
before running analysis in a worktree. The bootstrap fallback initializes
state; it cannot provide missing `PostToolUse`, `SubagentStart`, or `SessionEnd`
events.
This concerns the RAPTOR/Codex workspace being a linked worktree; a separate
analysis target that happens to be a worktree is a different case.

RAPTOR commands recover operator configuration, output settings, provider
credentials and routing from the private session broker. Ordinary shell
commands retain Codex's core environment filter. Credentials are not placed in
launcher arguments or persistent startup context; target subprocesses retain
RAPTOR's existing credential stripping. Restart Codex after upgrading the
broker so it captures the operator's current environment. Custom output and
credential-file locations still need the appropriate native sandbox grants.

Codex sign-in authenticates the interactive frontend. Configure the shared
analysis backend separately in `~/.config/raptor/models.json` or through
`RAPTOR_CONFIG`; see [LLM configuration](llm.md). Selecting `--codex` or `-m`
does not replace Claude-dispatched backend stages or their authentication.
Choose output and registry locations before launch; use narrow `--add-dir`
grants when the native policy requires them for custom locations.

Workspace-write does not imply network access. Registry packs, cloning and
provider calls need the native policy's permitted network route or normal
command approval. A scan with unavailable packs is reduced-coverage evidence,
even if the process exits successfully. Keep those limitations in the report.

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
root's binding. See [session ownership](codex-sessions.md) for project switching,
subagents and upgrades. Review the changed hooks and
restart after upgrading from PID-only Codex session state.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Missing or invalid startup context | Review `/hooks` and any SessionStart error. Confirm the checkout is trusted and restart. |
| Writes denied during startup | Use workspace-write. Custom paths need explicit directory grants. |
| Project differs after resume | Inspect current session status. Use `-p` to pin the intended project. |
| No RAPTOR hooks in a worktree | Check actual source paths in `/hooks`; use a normal checkout for the first full journey. Bootstrap cannot replace later events. |
| Hook says the launcher anchor is missing | Restart through `bin/raptor --codex`; for an isolated check add `--no-daemon` after `--`. Do not derive an anchor from a target directory. |
| Codex reports bubblewrap needs user namespaces | Run Codex from a regular host terminal; an outer sandbox may prevent creation of its inner sandbox. |
| Frontend signs in but an analysis stage cannot authenticate | Check the shared backend provider configuration and credential/file grants separately from Codex sign-in. |

