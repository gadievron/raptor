"""Map a sandbox execution's ``sandbox_info`` dict to a ``WitnessOutcome``.

The sandbox layer (``core/sandbox/observe.py::_interpret_result``) already
classifies post-execution state:

  * crash signals (SIGSEGV / SIGABRT / SIGBUS / SIGFPE / SIGILL)
  * resource-limit kills (SIGXCPU / SIGXFSZ)
  * seccomp kills (SIGSYS)
  * sanitizer reports (ASAN / UBSAN / MSAN / TSAN)
  * sandbox-enforcement events (network / write / seccomp blocks)

This module is the thin adapter that turns that dict into the
``WitnessOutcome`` enum plus a structured ``outcome_detail`` payload, so
consumers (LLM-exploit executors, future PoC runners) can write
post-execution Witnesses with consistent provenance.

``core.witness`` does not import ``core.sandbox`` — the function takes a
plain dict so the dependency arrow stays clean. Producers grab the dict
off the ``CompletedProcess`` (``result.sandbox_info``) and pass it in.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from core.witness.types import WitnessOutcome


def outcome_from_sandbox_info(
    sandbox_info: Optional[Dict[str, Any]],
    returncode: Optional[int] = None,
) -> Tuple[WitnessOutcome, Dict[str, Any]]:
    """Classify a sandboxed execution as a ``(WitnessOutcome, detail)`` pair.

    Precedence (most-informative wins):

    1. **Sanitizer report** → ``SANITIZER_REPORT``. ASAN with
       ``halt_on_error=0`` can fire without abnormal exit; we still
       call that a sanitizer outcome because the bug was observed.
    2. **Crash signal** (``crashed=True``, or signal in
       SIGSEGV/SIGABRT/SIGBUS/SIGFPE/SIGILL) → ``EXIT_SIGNAL``.
    3. **Resource-exceeded** (SIGXCPU / SIGXFSZ) → ``EXIT_SIGNAL``
       with ``resource_exceeded=True`` in detail. Caller can disambiguate
       a fuzz-hang from a sanitizer-triggered crash by reading detail.
    4. **Seccomp kill** (SIGSYS) → ``EXIT_SIGNAL`` with
       ``seccomp_killed=True``. Operationally a different class than
       a target crash, but still "the process died by signal."
    5. **Sandbox enforcement** (``blocked`` non-empty, no other class
       fired) → ``NO_OBVIOUS_EFFECT`` with ``blocked`` in detail. The
       process didn't trigger the target bug; the sandbox stopped it
       doing something else.
    6. **Nothing classifiable** → ``NO_OBVIOUS_EFFECT`` (clean exit, no
       sanitizer trip, no enforcement). The exploit ran but produced
       no observable security-relevant event.

    ``UNKNOWN`` is reserved for "we couldn't even run the sandbox" /
    "the result object wasn't shaped like CompletedProcess" cases
    handled by the caller before this function is reached. ``NOT_RUN``
    is what callers use when they choose not to execute at all and
    never reaches here.

    ``FLAG_CAPTURED`` (the ExploitGym terminal-success outcome) is
    not derivable from sandbox_info alone — it requires an oracle
    that checks for a specific marker (file, stdout pattern, etc.).
    Producers that have such an oracle should call this function for
    the substrate classification, then upgrade to ``FLAG_CAPTURED``
    on a positive oracle match.

    Args:
        sandbox_info: Dict produced by
            ``core/sandbox/observe.py::_interpret_result``. May be
            ``None`` if the sandbox attached no info — treated as
            "nothing classifiable" (returns ``NO_OBVIOUS_EFFECT``,
            empty detail).
        returncode: Optional ``CompletedProcess.returncode`` for
            inclusion in ``outcome_detail``. Not used for
            classification (the sandbox layer already did that
            mapping into ``signal`` / ``signal_num``).

    Returns:
        ``(outcome, detail)`` where ``outcome`` is one of
        ``EXIT_SIGNAL`` / ``SANITIZER_REPORT`` / ``NO_OBVIOUS_EFFECT``
        and ``detail`` is a flat dict carrying only present fields
        (absent → omitted, matching the rest of the Witness
        outcome_detail convention).
    """
    detail: Dict[str, Any] = {}
    if returncode is not None:
        detail["returncode"] = returncode

    info = sandbox_info or {}

    # Sanitizer wins because it directly identifies a bug class, even
    # when the process exited cleanly via halt_on_error=0.
    sanitizer = info.get("sanitizer")
    if sanitizer:
        detail["sanitizer"] = sanitizer
        if info.get("crashed"):
            detail["crashed"] = True
        if info.get("signal"):
            detail["signal"] = info["signal"]
        if info.get("evidence"):
            detail["evidence"] = info["evidence"]
        return WitnessOutcome.SANITIZER_REPORT, detail

    # Signal-killed (crash, resource-exceeded, seccomp). All collapse
    # to EXIT_SIGNAL at the enum level; detail flags disambiguate.
    if info.get("signal"):
        detail["signal"] = info["signal"]
        if "signal_num" in info:
            detail["signal_num"] = info["signal_num"]
        if info.get("crashed"):
            detail["crashed"] = True
        if info.get("resource_exceeded"):
            detail["resource_exceeded"] = True
        if info.get("seccomp_killed"):
            detail["seccomp_killed"] = True
        if info.get("evidence"):
            detail["evidence"] = info["evidence"]
        if info.get("blocked"):
            detail["blocked"] = list(info["blocked"])
        return WitnessOutcome.EXIT_SIGNAL, detail

    # `crashed` without a signal: shouldn't happen with current
    # observe.py, but defensive — observe might add cases.
    if info.get("crashed"):
        detail["crashed"] = True
        if info.get("evidence"):
            detail["evidence"] = info["evidence"]
        return WitnessOutcome.EXIT_SIGNAL, detail

    # Sandbox enforcement only (no crash, no sanitizer).
    if info.get("blocked"):
        detail["blocked"] = list(info["blocked"])
        if info.get("evidence"):
            detail["evidence"] = info["evidence"]
        return WitnessOutcome.NO_OBVIOUS_EFFECT, detail

    # Nothing observed.
    if info.get("evidence"):
        detail["evidence"] = info["evidence"]
    return WitnessOutcome.NO_OBVIOUS_EFFECT, detail
