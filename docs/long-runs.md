# Long Runs Under External Supervisors

Long `/audit` runs routinely outlive the environment that launched
them. This page covers the one supervisor RAPTOR detects and defends
against automatically — the Claude Code subagent background-shell cap
— plus the launch conventions, the self-bounding behavior, SIGTERM
semantics, and the resume command that recovers a killed run.

## The cap

The Claude Code harness caps every **subagent** background shell at
`CLAUDE_SUBAGENT_BG_SHELL_MAX_MS` (default 3,600,000 ms = 1 hour). The
timer is armed when the shell is backgrounded and kills the process
group at the cap regardless of what it is doing — observed kills land
within ~10 ms of spawn+3600s, with a `[killed]` marker in the task
output. **Main-thread background shells are uncapped**; only shells
spawned inside a subagent (Task tool) are affected.

An audit killed this way is not corrupted: journal rows are appended
per verdict, the ledger is reconciled at checkpoints, and the run
metadata simply never reaches a terminal status. Everything on disk
stays coherent up to the kill — which is exactly what
`raptor-audit resume` consumes.

## Launch conventions

In order of preference when a run may exceed an hour:

1. **Launch from the main thread**, not from a subagent — main-thread
   background shells have no cap.
2. **Raise the cap**: export a larger
   `CLAUDE_SUBAGENT_BG_SHELL_MAX_MS` before launching the harness.
3. **Detach** the run from the shell's process group (`setsid`), so
   the group kill misses it.
4. **Let self-bounding handle it** (the default): the audit concludes
   gracefully inside the cap and tells you how to continue.

## Self-bounding

At `raptor-audit run` / `resume` start, when no explicit `--max-time`
is set and the environment says the process is under a Claude
**subagent** shell (`core.run.supervisor`: `CLAUDECODE` or a `claude`
process ancestor, plus the subagent stamps — `AI_AGENT` ending
`_agent` or `CLAUDE_CODE_CHILD_SESSION`), the run defaults its wall
budget to the cap minus a 300s drain margin — **3300s** under the
harness default — and prints one loud line naming the cap, the resume
command, and the opt-out.

The bound reuses the existing wall-budget machinery (`--max-time` /
the deepen-reserve budget rails; there is no second clock), so the
conclusion is **graceful**: in-flight reviews are harvested, ledgers
and journal flushed, the report written, and the lifecycle records
`completed` with a remainder note stating how many gaps are left.
Continue in a new run — cross-run verdict reuse imports the completed
verdicts at $0 and reviews only the remainder.

* `--no-supervisor-bound` opts a run (or a resumed segment) out.
* Main-thread and interactive contexts are unaffected — detection
  returns nothing and no bound is applied.
* Misdetection is safe in both directions: a false positive
  self-bounds gracefully; a false negative dies at the cap as before
  and `resume` recovers it.

## SIGTERM semantics

When a supervisor stops the run with SIGTERM instead of SIGKILL, the
orchestrator's TERM handler (installed on the main thread, once)
concludes the run in bounded time:

* **First TERM** — stop dispatching, harvest in-flight completions,
  flush ledgers/journal/telemetry, write the salvage exports and the
  (completeness-aware) report, mark the lifecycle **`interrupted`**
  with a resume hint, exit 130. Total grace is bounded (~30s watchdog:
  on expiry, a best-effort flush then a forced exit 130).
* **Second TERM** — immediate exit 130 after the best-effort flush.

## Resuming a killed run

```
libexec/raptor-audit resume <out-dir> [--allow-drift] [--max-time N] [--no-supervisor-bound]
```

Re-enters a failed/interrupted/killed run **as the same run**:

* prior-segment journal verdicts are re-imported at $0
  (hash-verified, the landed verdict-reuse machinery);
* the remaining gaps are recomputed against the **original**
  checklist/scope/pins from the persisted `audit-run-config.json`;
* the remaining budget is the original `--max-cost` minus booked
  spend — the reconciled `cost-breakdown.json` ledger is
  authoritative, with the journal's per-entry costs as the floor when
  the run died before its first reconciliation;
* ledgers and telemetry **append**, with a resume-marker row at the
  segment boundary;
* the lifecycle transitions `interrupted → running → completed`, and
  **one** final report covers all segments (segment provenance noted
  in `audit-report.json` and the run metadata).

Guards:

* a **completed** run is refused — start a new run instead (verdict
  reuse continues it at $0);
* a run whose recorded worker is still alive is refused (it is
  actually in flight);
* the **staleness gate**: every hashed journal verdict is re-verified
  against the target tree; any drift refuses the resume with the
  drifted functions named. `--allow-drift` proceeds instead, printing
  one loud re-verification line per drifted function and re-reviewing
  those functions rather than reusing them.

## Environment knobs

See [environment.md](environment.md) ("Other" table) for
`CLAUDE_SUBAGENT_BG_SHELL_MAX_MS`, `AI_AGENT`, and
`CLAUDE_CODE_CHILD_SESSION` — all read-only harness contract
variables; RAPTOR never sets them.
