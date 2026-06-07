"""Sandbox error types.

Kept in a tiny dependency-free module so every layer — probes.py,
context.py, _spawn.py — and every consumer can import the exception
without pulling in the sandbox machinery or risking a circular import.
"""

from __future__ import annotations

# Process exit code a RAPTOR CLI uses to signal "sandbox isolation could
# not engage" across a process boundary. BaseException propagation only
# works in-process; when a parent (e.g. /agentic, /scan) spawns scanner.py
# or codeql as a SUBPROCESS, the child catches SandboxSetupError at its top
# level, prints the actionable message, and exits with THIS code. The
# parent detects it and re-raises SandboxSetupError so the same fail-loud
# invariant crosses the boundary instead of degrading to a per-stage
# "0 findings". Chosen distinct from 0 (success), 1 (findings/generic
# error), 2 (argparse), 130 (SIGINT).
#
# Convention boundary: this code is only MEANINGFUL coming from a RAPTOR
# child explicitly wired to emit it on SandboxSetupError (scanner,
# codeql/agent, llm_analysis/agent). A parent must only translate exit-3 ←
# SandboxSetupError for children it KNOWS follow the convention — never for
# an arbitrary subprocess. (packages/sca/cli.py's main() pre-dates this and
# returns 3 for its own unrecoverable errors; nothing translates sca's exit
# code as a sandbox signal, and "sandbox couldn't engage" is a failure
# anyway, so it reads correctly either way.)
SANDBOX_ENGAGE_EXIT_CODE = 3


class SandboxSetupError(BaseException):
    """Raised when sandbox isolation could not ENGAGE for a run.

    The distinction this type encodes is the whole point: it means the
    isolation the caller requested (namespace unshare, mount-ns, etc.)
    failed to set up, so the target command **never executed**. That is
    categorically different from "the command ran and exited non-zero"
    or "the command ran and produced no output".

    Without this signal those two cases are indistinguishable downstream:
    a sandbox wrapper that dies before `exec` returns empty stdout, and a
    consumer (e.g. the semgrep scanner) reads empty stdout as "tool ran,
    found nothing" → silent "0 findings".

    **Subclasses BaseException, NOT Exception — deliberately, like
    KeyboardInterrupt and SystemExit.** Consumers swallow sandbox-call
    failures with broad ``except Exception`` at MANY altitudes — leaf
    runner, ThreadPoolExecutor ``future.result()`` collectors, whole-
    workflow wrappers. Guarding each one is whack-a-mole that a future
    ``except Exception`` silently re-breaks. Inheriting from BaseException
    means a failed engagement propagates past every ``except Exception``
    automatically and can only be caught by code that names it (the
    top-level CLI handlers, which print the actionable message and exit
    non-zero). This is the structural guarantee that "isolation could not
    engage" can never masquerade as a clean "0 findings".

    Caveat this imposes on consumers: cleanup that MUST run on this error
    belongs in ``finally``, not in an ``except Exception`` block (which
    will not catch it) — the same contract code already honours for
    KeyboardInterrupt.

    Policy: RAPTOR does NOT auto-degrade to weaker isolation when the
    requested profile can't engage — that would silently pick an
    isolation posture the operator never chose. The operator resolves it
    explicitly (e.g. `--sandbox network-only`). `instructions` carries the
    actionable next step; `reason` carries the kernel/wrapper's own
    diagnostic.
    """

    def __init__(self, reason: str, instructions: str = "") -> None:
        self.reason = reason
        self.instructions = instructions
        msg = reason
        if instructions:
            msg = f"{reason}\n  → {instructions}"
        super().__init__(msg)
