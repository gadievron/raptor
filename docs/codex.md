# Codex support

## Setup

Use Python 3.12 or newer and install RAPTOR's locked dependencies from the
checkout you intend to launch:

```bash
uv sync --locked --link-mode copy --extra codex --extra grammars
source .venv/bin/activate
uv tool install semgrep
```

Copy mode prepares independent dependency files for installation protection.
If an existing environment uses cache hard links, add `--reinstall` to the
same sync command before launching with installation protection. Keep the
extras you already use. An existing Semgrep installation can keep its current
version; the tool-install command above is for a new setup.

Install and sign in to Codex using the [official CLI instructions](https://learn.chatgpt.com/docs/cli).
For an existing standalone installation:

```bash
codex update
codex --version
codex login
```

Use a Linux environment. Native Windows is not supported; use WSL for Windows.
macOS and WSL support have not been verified end to end.

## Install the hooks plugin

From the trusted RAPTOR checkout, install the local Codex hooks plugin:

```bash
codex plugin marketplace add . --json
codex plugin add raptor-codex-hooks@raptor-local --json
```

The plugin requires the RAPTOR checkout and its dependencies. It installs into
Codex's user-level cache and remains inactive outside RAPTOR launcher sessions.

Start RAPTOR through the shared launcher:

```bash
bin/raptor --codex -- --sandbox workspace-write --ask-for-approval on-request
```

Trust the RAPTOR checkout through Codex's normal project trust flow, then
review the five plugin hooks through `/hooks`: SessionStart, SubagentStart,
PostToolUse, Stop and SessionEnd. Restart through the launcher after review.
The same installed plugin serves normal checkouts and linked worktrees.

Checkout trust and hook trust are separate. RAPTOR's target
`config`/`build`/`dynamic` trust markers are also separate; `--trust-repo` does
not install or trust Codex hooks. See [Codex hook review](https://learn.chatgpt.com/docs/hooks).

### Update the plugin

The plugin cache is not a live view of the checkout. After a RAPTOR update
changes the packaged hooks, reinstall the plugin, review changed hooks through
`/hooks`, and restart through the launcher:

```bash
codex plugin remove raptor-codex-hooks@raptor-local
codex plugin add raptor-codex-hooks@raptor-local --json
```

If Codex reconnects to a server started before the update, add `--no-daemon`
after `--` to start a fresh client/server with the launcher's environment.

The `codex` extra supplies the optional WebSocket transport for session
naming. It does not install a provider SDK or change your Semgrep version.

## Run workflows

In the Codex chat composer, invoke a skill with its target:

```text
$scan /absolute/path/to/repo
```

Use `$agentic`, `$fuzz` or `$web` for the corresponding workflows. Type
`/skills` to browse skills or `$commands` to list RAPTOR workflows. Ordinary
requests such as `scan /absolute/path/to/repo` also select the matching skill.
These are chat inputs. Claude-style `/scan`, `/fuzz`, `/web` and `/agentic`
shortcuts are not registered Codex slash commands.

Codex sign-in authenticates the interactive frontend. Configure the shared
analysis backend separately in `~/.config/raptor/models.json` or through
`RAPTOR_CONFIG`; see [LLM configuration](llm.md). Some analysis stages still
use the Claude backend and require its configured authentication. Selecting
`--codex` or `-m` does not replace that backend.

Choose output and registry locations before launch. Restart Codex after
changing operator configuration or credentials. Custom output and
credential-file locations may need narrow `--add-dir` grants through Codex's
normal sandbox policy.

Workspace-write does not imply network access. Registry packs, cloning and
provider calls need the permitted network route or normal command approval.
A scan with unavailable packs has reduced coverage even if it exits successfully.

## Projects and conversations

Each Codex conversation keeps its own active project, even when conversations
share a Codex server. Use `$project create`, `$project use` and `$project status`
to manage it; `$project none` clears the current conversation's binding.
Subagents share their root conversation's project. Switching projects does not
move an existing run or its output, and ending one conversation does not end
another's runs. After resuming, check `$project status` before continuing work.

Without an explicit workflow path, resolve the active project's target first,
then the validated launcher target, then the original caller directory. Read
launcher data with `libexec/raptor-session-init --codex-context`; resolve a
relative launch target against its stored caller directory. After `$project none`, a bare `$scan` still uses the launch target, including after resume.

### Conversation names

When a verified local Codex control connection is available, RAPTOR requests
names such as `raptor · my-project · target`. SessionStart and Stop use the
current conversation's project and target, so project changes appear after
a turn completes. Once RAPTOR observes a manually chosen name, it leaves
that conversation's name alone.

Naming is optional. Missing transport, unsupported client versions, a busy
lock or a slow server leave the existing name in place. RAPTOR does not start
another server, resume a thread or change command approval to obtain a title.
`--no-daemon` remains supported; versions without an accessible control
listener simply keep their existing names. Remote-server naming is unsupported.

Concurrent conversations have separate naming state, including conversations
sharing one Codex server. The connection must belong to the authenticated
session owner; RAPTOR never chooses the latest conversation from a list.
Multiple instances can share a protected installation. Naming state lives in
the private session registry outside the checkout, and each instance retains
its own launcher scratch lifetime. Naming does not make the installation writable.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Missing or invalid startup context | Confirm the plugin is installed and enabled, review `/hooks` and any SessionStart error, trust the checkout and restart through `bin/raptor --codex`. |
| No RAPTOR hooks in a worktree | Check `/hooks` for the five installed plugin sources under Codex's plugin cache. Startup fallback cannot replace missing later events. |
| Plugin is listed but RAPTOR startup is absent | Launch through `bin/raptor --codex`; add `--no-daemon` after `--` if reconnecting to an older server. Do not set a hook root from a scan target. |
| Writes denied during startup | Use workspace-write. Custom paths need explicit directory grants. |
| Project differs after resume | Check `$project status`; use `-p` at launch to pin the intended project. |
| Conversation keeps its existing name | Check that the `codex` extra is installed. Naming needs a verified local control listener; unsupported transports and slow servers are skipped. A manual name is preserved. |
| Codex reports bubblewrap needs user namespaces | Run Codex from a regular host terminal. An outer sandbox or container may prevent creation of Codex's inner sandbox; if it also fails on the host, check the host/container namespace policy. |
| Frontend signs in but an analysis stage cannot authenticate | Check backend provider configuration and credential/file grants separately from Codex sign-in. |
