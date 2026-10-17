# Codex RAPTOR command outcomes

Codex PostToolUse provides model-facing shell output, which cannot safely prove
exit status. RAPTOR records its own Python dispatch outcome instead. The native
tool command is never rewritten; no hook returns an approval decision.

The shared `cli_outcome()` context surrounds RAPTOR Python CLI dispatch. It
preserves SystemExit values, uncaught exceptions, KeyboardInterrupt and normal
returns, and records only when this is an opted-in RAPTOR Codex shell tool call.
Claude, hooks and ordinary invocations don't write receipts. Original argv is
captured before dispatch can change argv or cwd. Credential generation and native
Codex tool-call ID bind a receipt to its installation/session/invocation; argv
is hashed, not stored. Receipt files are private and reject symlinks.

The notification-only PostToolUse hook matches a simple literal invocation to
one receipt. It restores validated session context, and routes a proven nonzero
outcome through the shared failure-marker path. Attribution requires the run
registered in-process or an exact run-directory argument; there is no newest-run
fallback. Existing running status, session ownership, worker liveness and
explicit finalizer checks still apply. In-process registration takes precedence
over argument hints. Explicit completion/failure remains authoritative.

This supplies failure bookkeeping for direct Python RAPTOR CLI commands and
Python libexec entry points, plus the known agentic/openant Bash dispatchers
which exec the Python CLI. It doesn't observe arbitrary external executables
or every Bash helper. Pipelines, shell compounds, expansions, wrappers and
multiple ambiguous receipts remain unknown. A runless failed query does not
poison an unrelated run. SIGKILL, os._exit, import failures before the dispatch
guard and interpreter shutdown failures can prevent a trustworthy receipt;
these stay unknown until normal lifecycle reconciliation. No success/failure
is inferred from stdout. Multi-turn runs retain their existing lifecycle
ownership rather than being prematurely finalized by Stop.

Linux real-Codex tests verified exit 7 produces Failed, exit 0 preserves
Completed despite spoofed output, and forbidden/approval-required commands stay
blocked. The native sandbox remains enabled. This is bookkeeping, not isolation
against arbitrary code running as the same user; an OS user can already alter
the run files. It does not change BASH_ENV, shell profiles, global configuration,
normal command approval or sandbox permissions.
