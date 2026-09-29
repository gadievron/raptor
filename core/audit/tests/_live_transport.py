"""Transport/product partition for the live adjudication legs.

The live legs in this directory run real engines (semgrep, the
compiler analyzers, interpreters) and adjudicate ground truth from
their results. Under battery load the RUNTIME sometimes fails to
carry an engine at all — the child cannot be spawned (fork OSError),
hits the deadline, or is signal-killed by the resource ceiling — and
the sweep honestly reports an error result. That error is a statement
about the test environment, not about the classification logic under
test, so the affected leg must SKIP with the transport's reason, in
both directions and observed under battery load at identical trees.

Every error shape that describes what the engine DID — a wrong
verdict, an unparseable rule, a positive exit code, a parse failure
on the fixture — stays a hard failure. The partition below is keyed
on the FULL result identity (tool + outcome + rule_id keying + the
exact minted reason, anchored), exactly the idiom of
``test_sanwit_live._skip_if_runtime_degraded``: a product regression
that mints ``error`` for a reason the transport never produces still
fails the assertions that follow.

Guard-shape notes (all minted strings verified against the product
code that mints them; the anti-drift pins live in
``test_live_transport_guards.py``):

* semgrep — ``packages.semgrep.runner.run_rule`` mints the transport
  errors with ``returncode=-1``; ``core.audit.sweep.run_semgrep_sweep``
  surfaces them with ``rule_id=rule_config`` (truthy). The sweep's own
  ``rule_id=None`` arms are product/config territory (missing file,
  the closing broad except) EXCEPT the exact pre-spawn
  ``"semgrep not installed"`` arm.
* anchoring — ``\\Z``, not ``$`` (``$`` also matches before a trailing
  newline, widening the deadline arm to suffixed spellings).
* ``SandboxSetupError`` derives from ``BaseException`` and escapes the
  sweep's ``except Exception``; the guarded runners convert it to a
  skip (same treatment as test_dynamic_sweep_forgery).
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from core.audit.expanded_semgrep import ExpandedRuleResult
from core.audit.sweep import SweepResult

# ---------------------------------------------------------------------------
# semgrep channel
# ---------------------------------------------------------------------------

# The reasons packages.semgrep.runner.run_rule mints when the runtime
# failed to carry the scan (all with returncode=-1, surfaced by
# run_semgrep_sweep with rule_id=rule_config):
#   * the process deadline (subprocess.TimeoutExpired);
#   * a child that could not be spawned (OSError -> str(e), the
#     "[Errno N] ..." form; errno-less OSErrors stay hard);
#   * the PATH probe (binary gone between collection and the run);
#   * the sandbox refusal (core.sandbox import failed at spawn time);
#   * a signal-killed engine ("semgrep exited with code -N" — semgrep
#     itself exits 0/1 on a carried scan and >=2 on its own failures,
#     so a NEGATIVE code is always the runtime's kill, never the
#     engine's verdict; positive codes stay hard).
SEMGREP_TRANSPORT_RE = re.compile(
    r"Timeout after \d+s\Z"
    r"|\[Errno \d+\] "
    r"|semgrep is not installed \(semgrep binary not found on PATH\)\Z"
    r"|core\.sandbox unavailable — refusing to run semgrep "
    r"|semgrep exited with code -\d+(?::|\Z)",
)

# run_semgrep_sweep's own pre-spawn availability arm (rule_id=None —
# distinct from the runner-minted arm above, which rides with
# rule_id=rule_config). Exact match only: the sweep's closing broad
# except also lands with rule_id=None and str(exc) can be anything,
# including "[Errno N] ..." from product-code OSErrors — those must
# stay hard failures.
_SEMGREP_NOT_INSTALLED = "semgrep not installed"


def skip_if_semgrep_transport_degraded(result: SweepResult) -> None:
    """Skip (with the transport's reason) when the live semgrep run
    degraded instead of carrying the scan. Full-identity keying: tool,
    outcome, single-error shape, and the rule_id arm each minted
    reason actually rides with."""
    if result.tool != "semgrep" or result.outcome != "error":
        return
    errors = list(result.errors or [])
    if len(errors) != 1:
        return
    if result.rule_id and SEMGREP_TRANSPORT_RE.match(errors[0]):
        pytest.skip(f"semgrep transport degraded: {errors[0]}")
    if result.rule_id is None and errors[0] == _SEMGREP_NOT_INSTALLED:
        pytest.skip(f"semgrep transport degraded: {errors[0]}")


def _sandbox_setup_error() -> type[BaseException]:
    """The sandbox's setup-failure type, or a never-raised stand-in
    when core.sandbox itself cannot import (then nothing can raise
    it either)."""
    try:
        from core.sandbox.errors import SandboxSetupError
    except ImportError:
        class _NeverRaised(BaseException):
            pass

        return _NeverRaised
    return SandboxSetupError


def run_semgrep_sweep_guarded(**kwargs: Any) -> SweepResult:
    """``run_semgrep_sweep`` with the transport guard applied — the
    drop-in for live call sites. Product classifications (including
    every non-error outcome and every product-shaped error) pass
    through untouched for the caller's own hard assertions."""
    from core.audit.sweep import run_semgrep_sweep

    try:
        result = run_semgrep_sweep(**kwargs)
    except _sandbox_setup_error() as exc:
        pytest.skip(f"sandbox setup degraded: {exc}")
    skip_if_semgrep_transport_degraded(result)
    return result


def guard_refinement_semgrep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Interpose the transport guard at the ``core.audit.sweep`` seam
    for tests driving ``core.audit.refinement._dispatch_semgrep``,
    which collapses the sweep result to ``"{outcome}: N match(es)"``
    (identity gone by the time the test sees it). refinement resolves
    ``run_semgrep_sweep`` at call time (function-local import), so the
    module attribute is the real seam; ``pytest.skip.Exception``
    derives from ``BaseException`` and escapes refinement's
    ``except Exception`` cleanly."""
    import core.audit.sweep as sweep_mod

    real = sweep_mod.run_semgrep_sweep
    sandbox_err = _sandbox_setup_error()

    def _guarded(**kwargs: Any) -> SweepResult:
        try:
            result = real(**kwargs)
        except sandbox_err as exc:
            pytest.skip(f"sandbox setup degraded: {exc}")
        skip_if_semgrep_transport_degraded(result)
        return result

    monkeypatch.setattr(sweep_mod, "run_semgrep_sweep", _guarded)


# A trivially matching probe for call sites whose product surface
# collapses transport identity entirely (negative controls return
# bare None on ANY control failure; a drain row's "still dark" reason
# is identical for a refused rule and a dead engine). The probe runs
# the same executed path (run_semgrep_sweep -> runner) so a dead or
# overloaded engine is caught by the transport guard, and a healthy
# engine that cannot carry even this rule skips with the probe's
# identity instead of letting the caller adjudicate on a vacuous
# result.
_PROBE_RULE = (
    "rules:\n"
    "  - id: live-transport-probe\n"
    "    languages: [python]\n"
    "    severity: ERROR\n"
    "    message: probe\n"
    "    pattern: os.system(...)\n"
)
_PROBE_TARGET = "import os\nos.system('x')\n"


def skip_unless_semgrep_carries_probe(tmp_path: Path, *, context: str) -> None:
    """Skip unless the semgrep engine carries a trivial known-matching
    rule RIGHT NOW. Returns silently on a healthy engine so the
    caller's hard assertions stand; use only where the product surface
    has already collapsed the failure identity."""
    probe_dir = tmp_path / "live-transport-probe"
    probe_dir.mkdir(exist_ok=True)
    (probe_dir / "probe.py").write_text(_PROBE_TARGET, encoding="utf-8")
    rule = probe_dir / "probe.yaml"
    rule.write_text(_PROBE_RULE, encoding="utf-8")
    result = run_semgrep_sweep_guarded(
        target_path=probe_dir,
        file_path="probe.py",
        function_name="probe",
        rule_config=str(rule),
    )
    if result.outcome != "confirmed":
        pytest.skip(
            f"semgrep engine cannot carry a trivial known-matching probe "
            f"({context}): {result.outcome} {result.errors}",
        )


# ---------------------------------------------------------------------------
# expanded-view channel (core.audit.expanded_semgrep)
# ---------------------------------------------------------------------------

# run_expanded_semgrep_rule collapses everything into ok=False +
# reason. Transport arms, verified against the minting code:
#   * the preprocessor view's transport degradations, joined behind
#     "no fidelity-3 view: " (deadline, spawn OSError, the probe
#     losing the preprocessor under load, the sandbox refusal, and a
#     signal-killed cpp — which surfaces as the empty-stderr
#     "exit code -N" spelling of the preprocess-failed arm; a
#     positive exit code or stderr text is the preprocessor's own
#     verdict on the source and stays hard);
#   * the runner availability arms ("semgrep not installed",
#     "semgrep runner unavailable: ...").
# "semgrep errors on expanded view: <inner>" is transport only when
# the inner text is a SINGLE runner-minted transport error (handled
# in the guard below); "semgrep on expanded view failed: ..." wraps
# product code and stays hard.
EXPANDED_VIEW_TRANSPORT_RE = re.compile(
    r"no fidelity-3 view: preprocessor timed out \(\d+s\)\Z"
    r"|no fidelity-3 view: preprocessor invocation failed: \[Errno \d+\] "
    r"|no fidelity-3 view: no C preprocessor available"
    r" \(need gcc, g\+\+ or cpp\)\Z"
    r"|no fidelity-3 view: core\.sandbox unavailable — refusing to run the "
    r"preprocessor "
    r"|no fidelity-3 view: preprocess failed — no fidelity-3 view: "
    r"exit code -\d+\Z"
    r"|semgrep not installed\Z"
    r"|semgrep runner unavailable: ",
)

_EXPANDED_SEMGREP_PREFIX = "semgrep errors on expanded view: "


def skip_if_expanded_view_transport_degraded(
    result: ExpandedRuleResult,
) -> None:
    """Skip when the expanded-view leg degraded for a transport
    reason. Product degradations (non-C file, path escape, budget
    exhausted, a preprocessor that REJECTED the source, semgrep's own
    positive-exit failures) pass through for the caller's asserts."""
    if result.ok:
        return
    reason = result.reason or ""
    if EXPANDED_VIEW_TRANSPORT_RE.match(reason):
        pytest.skip(f"expanded-view transport degraded: {reason}")
    if reason.startswith(_EXPANDED_SEMGREP_PREFIX):
        inner = reason[len(_EXPANDED_SEMGREP_PREFIX):]
        # A single runner-minted transport error only: the join uses
        # "; " for multi-error payloads, and a mixed list must stay a
        # hard failure.
        if "; " not in inner and SEMGREP_TRANSPORT_RE.match(inner):
            pytest.skip(f"expanded-view transport degraded: {reason}")


# ---------------------------------------------------------------------------
# raw engine pins (direct subprocess.run call sites)
# ---------------------------------------------------------------------------


def run_pinned_subprocess(
    argv: Sequence[str],
    *,
    timeout: int,
    context: str,
    env: dict[str, str] | None = None,
    skip_signals: tuple[int, ...] | None = None,
) -> subprocess.CompletedProcess[str]:
    """``subprocess.run`` for live engine pins with the transport
    partition applied: a deadline hit, a spawn OSError, or a
    runtime-killed child (negative returncode) skips; every exit code
    >= 0 — the engine's own verdict — returns for the caller's hard
    assertions.

    ``skip_signals`` narrows the signal arm (e.g. ``(9,)`` where a
    non-KILL signal such as a segfault is itself product-relevant);
    ``None`` treats every signal kill as transport.
    """
    try:
        proc = subprocess.run(  # noqa: PLW1510 — returncode is the caller's verdict
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired:
        pytest.skip(f"{context}: engine pin timed out after {timeout}s")
    except OSError as exc:
        pytest.skip(f"{context}: engine pin could not spawn: {exc}")
    if proc.returncode < 0:
        sig = -proc.returncode
        if skip_signals is None or sig in skip_signals:
            pytest.skip(f"{context}: engine pin killed by signal {sig}")
    return proc
