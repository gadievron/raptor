# Initial Codex runtime support

Use the shared `bin/raptor` launcher: Claude is preferred when installed;
Codex is the fallback, or selected explicitly with `--codex`. Direct `codex`
from the trusted RAPTOR checkout also uses the project-local configuration.
Review and trust the project configuration and hooks through Codex's normal
trust flow. The normal workspace-write sandbox is required for analyses.

Codex has no equivalent of Claude's `CLAUDE_ENV_FILE`. SessionStart seeds the
shared session registry and publishes private per-installation, per-Codex-session
metadata under `~/.local/share/raptor/codex-contexts`. The registry remains the
source of credentials and project binding. A small host broker validates the
owning Codex process, process identity stamps, and credential generation.
RAPTOR's shared Python startup restores a fixed allowlist of environment values
before dispatch. Separate tool calls therefore keep their session project.

Codex's PID sandbox can hide the host owner. In that case RAPTOR uses private,
capability-authenticated file IPC under `/tmp/raptor-codex-env-<uid>/`; the host
validates the owner before answering. The broker has no command-execution API
and exits when its owner is gone. Context and message files require private
permissions and reject symlinks. This is not isolation against arbitrary code
already running as the same OS user. Target environments strip session markers
and credentials through the existing target-environment sanitization.

This mechanism affects RAPTOR entry points, not arbitrary shell commands. It
does not set `BASH_ENV`, install shell startup shims, modify shell profiles, or
change global Codex configuration. Existing launcher and subprocess stripping
of `BASH_ENV` stays unchanged. Claude continues using its native env-file hook.
The old `.codex/raptor.env` is neither consumed nor written by Codex startup.

The project-local workspace-write grants cover only RAPTOR-owned `~/.raptor`
and `~/.local/share/raptor`, in addition to Codex's normal workspace and temp
roots. SessionStart creates these directories before tool sandbox setup.
Custom registry or output paths outside those roots need explicit native
Codex directory grants. Read-only analyses are unsupported; simple version/help
paths do not require environment restoration. Current runtime validation targets
Linux; macOS and Windows parity has not been established.

Generic PreToolUse command rewriting is disabled. Making its `updatedInput`
effective requires an `allow` decision which, in real CLI tests, bypassed both
forbidden and approval-required execution rules. Native command approval must
remain authoritative. RAPTOR's explicit Python run lifecycle works; automatic
Claude-style interception of arbitrary tool failures is not claimed.

Validation included a real Codex workspace-write subprocess, project creation,
project continuity across separate tool calls, and a completed local Semgrep
scan. Uncached remote rule packs could not download in the network-restricted
sandbox and were skipped: a successful local scan is not full rule coverage.
Existing sandbox/credential-isolation fallback warnings remain relevant and
must not be interpreted as evidence that every optional isolation layer ran.
