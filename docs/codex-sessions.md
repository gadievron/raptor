# Codex sessions

Each Codex conversation keeps its own active project, even when several
conversations share a Codex server. Changing projects in one conversation does
not switch the project in another conversation that is already running.

Use `$project create`, `$project use` and `$project status` to manage the
current conversation's binding. `$project none` explicitly clears it for that
conversation. The shared active-project bookmark can seed a new conversation;
it does not replace an existing conversation's choice.

Subagents share their root conversation's project binding. They do not select
an independent project. Keep the native Codex parent/child relationship when
using an external client; missing session context causes RAPTOR commands to fail
rather than borrow another conversation's state.

A run retains the project and output location recorded when it started.
Switching projects later does not transfer ownership of that run. Ending one
conversation does not end another conversation's runs.

After resuming a conversation, check `$project status` before continuing work.
Use `-p` with the launcher when you want to pin a particular project. When
upgrading from the older PID-only Codex session implementation, restart or
resume through `bin/raptor --codex` and review changed hooks. Existing in-flight
records are not automatically migrated to the new session identity.

See [Codex setup](codex.md) for installation, hook review and troubleshooting.
