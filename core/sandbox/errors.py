"""Sandbox error types.

Kept in a tiny dependency-free module so every layer — probes.py,
context.py, _spawn.py — and every consumer can import the exception
without pulling in the sandbox machinery or risking a circular import.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # annotation-only; no runtime import (tiers imports us)
    from .tiers import ContainmentTier

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

    ``setup_category`` carries the exec-status-pipe category letter
    (M/L/S/U/X/P/F/C, or the synthetic '!' for a spawn child that died
    mid-setup without reaching any reporting site — see
    ``core/sandbox/_spawn._write_setup_status``) when the raise site
    holds one, else ``None``. The distinction a consumer can act on:
    ``"X"`` means every isolation layer engaged and the failure was
    the target's own exec inside the sandbox — a per-invocation
    condition (binary transiently unexecutable, e.g. ETXTBSY from a
    lingering writer; a path outside the bind set) that a caller with
    retry semantics may legitimately re-attempt at FULL isolation.
    ``"!"`` is also per-invocation (external SIGKILL / OOM landed on
    the setup child) but says nothing about isolation. Every other
    category (and ``None``) means isolation itself could not engage,
    where a retry cannot help and the fail-loud contract stands.
    """

    def __init__(self, reason: str, instructions: str = "",
                 setup_category: str | None = None) -> None:
        self.reason = reason
        self.instructions = instructions
        self.setup_category = setup_category
        msg = reason
        if instructions:
            msg = f"{reason}\n  → {instructions}"
        super().__init__(msg)


class SandboxDisableRefusedError(SandboxSetupError):
    """A CLI sandbox disable (``--no-sandbox`` / ``--sandbox none``)
    was requested without a matching-authority consent — refused.

    The disable is a request for tier NONE, honoured only when
    ``core.sandbox.disable_consent.resolve_disable_consent`` finds a
    consent source (interactive TTY on stdin+stderr, or a validated
    launcher/CI-minted nonce). Refusal means the run STOPS — the
    request is never silently downgraded to "run sandboxed anyway"
    (which would quietly invert the operator's stated intent) and
    never granted with a warning.

    BaseException semantics are inherited deliberately: a broad
    ``except Exception`` between the argparse boundary and the run
    proper must not be able to swallow the refusal and proceed —
    in either direction (bare OR sandboxed) proceeding would decide
    a posture question the gate just refused to decide. CLI entry
    points route this through ``parser.error`` (clean exit-2 UX);
    library callers see the exception itself.
    """


class SandboxFloorError(SandboxSetupError):
    """Containment floor could not be met — the target never executed.

    Raised by the floor contract (``core/sandbox/tiers.py``) when the
    tier a call requires (its *floor*) exceeds the tier the selected
    lane delivers: at the entry-time check for statically-knowable
    shapes, and at the hard pre-exec dispatch assertion for every
    demotion route. Chained (``raise ... from``) to the original
    backend failure when a demotion carried one, so the environmental
    cause stays diagnosable.

    Subclass, not fields-on-parent: existing ``except``/``isinstance``
    sites and the ``SANDBOX_ENGAGE_EXIT_CODE`` cross-process convention
    keep working unchanged; only code that NAMES the subtype gets the
    structured fields. BaseException semantics are inherited — the
    "never masquerade as 0 findings" guarantee is untouched.

    ``achievable`` carries the tier the refused lane would have
    delivered; ``floor`` carries the required tier. Both are
    :class:`~core.sandbox.tiers.ContainmentTier` values (annotation
    only — this module stays dependency-free; ``tiers.py`` imports us,
    never the reverse at runtime).
    """

    def __init__(self, reason: str, instructions: str = "", *,
                 achievable: "ContainmentTier",
                 floor: "ContainmentTier",
                 setup_category: str | None = None) -> None:
        super().__init__(reason, instructions,
                         setup_category=setup_category)
        self.achievable = achievable
        self.floor = floor
