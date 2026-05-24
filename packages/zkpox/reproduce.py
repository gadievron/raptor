"""ZKPoX Tier 1.5 — native reproduction.

The strongest claim achievable *without* the heavy ZK stack: take
a bundle's witness, run it against the target N times in the
sandbox, and confirm the recorded outcome reproduces every time.
"Verified-reproducible exploit" — not zero-knowledge, but
empirically solid.

**On request** in the trigger model: N× sandbox execution is real
cost + a policy shift (running code repeatedly), so it never fires
automatically — the operator asks for it.

Reproduction is source-dispatched, because "re-run the witness"
means different things depending on what the witness *is*:

  * ``LLM_EMIT_RUN`` — the witness bytes are exploit *source code*.
    Reproduce = recompile + run, N times, via
    ``exploit_verify.compile_and_execute``. Self-contained for the
    inline-trigger PoCs the crash-analysis prompt now produces. If
    the recorded outcome is a sanitizer report, the recompile uses
    the matching ``-fsanitize`` flag so ASAN can fire again.

  * ``FUZZ`` / other input-replay sources — the witness bytes are
    *input* to a target binary. Reproduce = feed the bytes to the
    binary's stdin N times, mapping each run through
    ``core.witness.outcome_from_sandbox_info``. Needs the actual
    target binary supplied by the caller (the store holds only its
    hash); we verify the supplied binary's sha256 matches the
    bundle's ``target_binary_hash`` before trusting the result.

The full tier model lives in the package docstring
(``packages/zkpox/__init__.py``).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from core.witness.types import WitnessOutcome

from packages.zkpox.bundle import ZKPoXBundle

logger = logging.getLogger(__name__)


# Sanitizer enum-name (as observe.py records it) → gcc -fsanitize flag.
# Used to recompile an LLM_EMIT_RUN witness faithfully when its
# recorded outcome was a sanitizer report — without the matching
# flag the recompiled binary wouldn't fire the sanitizer and
# reproduction would spuriously fail.
_SANITIZER_FLAG = {
    "asan": "address",
    "ubsan": "undefined",
    "msan": "memory",
    "tsan": "thread",
}


@dataclass
class ReproductionResult:
    """Outcome of an N-run reproduction attempt."""
    attempted: bool
    runs: int
    expected_outcome: str
    observed_outcomes: List[str] = field(default_factory=list)
    reproduced: bool = False        # every run matched expected
    deterministic: bool = False     # every run produced the SAME outcome
    reason: str = ""

    def as_dict(self) -> dict:
        return {
            "attempted": self.attempted,
            "runs": self.runs,
            "expected_outcome": self.expected_outcome,
            "observed_outcomes": list(self.observed_outcomes),
            "reproduced": self.reproduced,
            "deterministic": self.deterministic,
            "reason": self.reason,
        }


def _finalize(
    expected: str,
    observed: List[str],
    n: int,
    *,
    reason: str = "",
) -> ReproductionResult:
    """Build the result from the per-run observed outcomes."""
    reproduced = bool(observed) and all(o == expected for o in observed)
    deterministic = bool(observed) and len(set(observed)) == 1
    if not reason:
        if reproduced:
            reason = f"all {len(observed)} runs reproduced {expected!r}"
        elif deterministic:
            reason = (
                f"deterministic but off-target: all runs produced "
                f"{observed[0]!r}, expected {expected!r}"
            )
        else:
            reason = (
                f"non-deterministic: outcomes varied across runs "
                f"({observed})"
            )
    return ReproductionResult(
        attempted=True,
        runs=n,
        expected_outcome=expected,
        observed_outcomes=observed,
        reproduced=reproduced,
        deterministic=deterministic,
        reason=reason,
    )


def reproduce_witness(
    bundle: ZKPoXBundle,
    witness_bytes: bytes,
    *,
    binary_path: Optional[Path] = None,
    n: int = 3,
    sandbox_timeout: int = 5,
    logger_: Optional[logging.Logger] = None,
) -> ReproductionResult:
    """Re-run ``bundle``'s witness ``n`` times; confirm the recorded
    outcome reproduces.

    Args:
        bundle: the Tier 0/1 bundle (carries source, expected
            outcome, target hashes).
        witness_bytes: the raw witness bytes (caller reads them from
            the bundle dir's ``witness.bin`` or the store).
        binary_path: required for input-replay sources (FUZZ); the
            target binary to feed the witness to. Its sha256 is
            verified against ``bundle.target_binary_hash`` before
            use. Ignored for LLM_EMIT_RUN (recompile) sources.
        n: number of consecutive runs (default 3). The recorded
            outcome must reproduce in ALL of them for
            ``reproduced=True``.
        sandbox_timeout: per-run timeout in seconds.
        logger_: optional logger.

    Returns:
        :class:`ReproductionResult`. ``attempted=False`` when the
        source isn't reproducible by this v1 (with the reason),
        rather than raising.

    Never raises — a compile failure, a hash mismatch, an
    unsupported source all surface as ``attempted=False`` /
    ``reproduced=False`` with a reason.
    """
    log = logger_ if logger_ is not None else logger

    if bundle.source == "llm_emit_run":
        return _reproduce_source(
            bundle, witness_bytes, n=n,
            sandbox_timeout=sandbox_timeout, log=log,
        )

    # Input-replay sources (FUZZ and any future input-shaped source).
    return _reproduce_replay(
        bundle, witness_bytes, binary_path=binary_path, n=n,
        sandbox_timeout=sandbox_timeout, log=log,
    )


def _reproduce_source(
    bundle: ZKPoXBundle,
    witness_bytes: bytes,
    *,
    n: int,
    sandbox_timeout: int,
    log: logging.Logger,
) -> ReproductionResult:
    """LLM_EMIT_RUN: the witness bytes are exploit source. Recompile
    + run N times via compile_and_execute."""
    expected = bundle.observed_outcome
    try:
        from packages.llm_analysis.exploit_verify import compile_and_execute
    except ImportError as e:
        return ReproductionResult(
            attempted=False, runs=0, expected_outcome=expected,
            reason=f"compile_and_execute unavailable: {e}",
        )

    exploit_code = witness_bytes.decode("utf-8", errors="replace")

    # Faithful recompile: if the recorded outcome was a sanitizer
    # report, recompile with the matching sanitizer flag so it can
    # fire again. Sanitizer name lives in the bundle's outcome_detail.
    sanitizers = None
    if expected == WitnessOutcome.SANITIZER_REPORT.value:
        san_name = (bundle.outcome_detail or {}).get("sanitizer")
        flag = _SANITIZER_FLAG.get(san_name)
        if flag:
            sanitizers = [flag]

    observed: List[str] = []
    for i in range(n):
        compiled, errors, outcome, _detail = compile_and_execute(
            exploit_code,
            None,  # no target source path → attempt gcc unconditionally
            f"{bundle.witness_hash[:12]}-rep{i}",
            timeout=sandbox_timeout,
            logger=log,
            sanitizers=sanitizers,
        )
        if not compiled:
            return ReproductionResult(
                attempted=True, runs=n, expected_outcome=expected,
                observed_outcomes=observed,
                reason=(
                    f"run {i + 1}/{n}: recompile failed "
                    f"({len(errors)} error(s)) — cannot reproduce"
                ),
            )
        observed.append(outcome.value if outcome is not None else "none")

    return _finalize(expected, observed, n)


def _reproduce_replay(
    bundle: ZKPoXBundle,
    witness_bytes: bytes,
    *,
    binary_path: Optional[Path],
    n: int,
    sandbox_timeout: int,
    log: logging.Logger,
) -> ReproductionResult:
    """FUZZ / input-replay: feed the witness bytes to the target
    binary's stdin N times."""
    expected = bundle.observed_outcome

    if binary_path is None:
        return ReproductionResult(
            attempted=False, runs=0, expected_outcome=expected,
            reason=(
                f"source {bundle.source!r} is input-replay; needs a "
                f"target binary (pass binary_path)"
            ),
        )
    binary_path = Path(binary_path)
    if not binary_path.is_file():
        return ReproductionResult(
            attempted=False, runs=0, expected_outcome=expected,
            reason=f"binary not found: {binary_path}",
        )

    # Verify we're reproducing against the RIGHT binary — the one the
    # witness was recorded against — before trusting the result.
    if bundle.target_binary_hash:
        from core.hash import sha256_file
        actual = sha256_file(binary_path)
        if actual != bundle.target_binary_hash:
            return ReproductionResult(
                attempted=False, runs=0, expected_outcome=expected,
                reason=(
                    f"binary hash mismatch: supplied {actual[:16]}... "
                    f"!= recorded {bundle.target_binary_hash[:16]}...; "
                    f"refusing to reproduce against a different build"
                ),
            )

    try:
        from core.config import RaptorConfig
        from core.sandbox import run as sandbox_run
        from core.witness import outcome_from_sandbox_info
    except ImportError as e:
        return ReproductionResult(
            attempted=False, runs=0, expected_outcome=expected,
            reason=f"sandbox unavailable: {e}",
        )

    observed: List[str] = []
    for _i in range(n):
        try:
            result = sandbox_run(
                [str(binary_path)],
                block_network=True,
                target=str(binary_path.parent),
                output=str(binary_path.parent),
                capture_output=True,
                text=False,
                input=witness_bytes,
                timeout=sandbox_timeout,
                env=RaptorConfig.get_safe_env(),
                strict_env=True,
            )
        except Exception as e:  # noqa: BLE001 — best-effort per run
            observed.append("error")
            log.debug("reproduce replay run raised: %s", e)
            continue
        sandbox_info = getattr(result, "sandbox_info", None)
        returncode = getattr(result, "returncode", None)
        outcome, _detail = outcome_from_sandbox_info(
            sandbox_info, returncode=returncode,
        )
        observed.append(outcome.value)

    return _finalize(expected, observed, n)


def attach_reproduction(
    bundle: ZKPoXBundle,
    result: ReproductionResult,
) -> ZKPoXBundle:
    """Fold a reproduction result into a bundle: store it under
    ``bundle.reproduction`` and, when the witness reproduced, bump
    the tier label to ``"1.5"``.

    Mutates and returns the bundle (callers typically re-persist it
    with ``write_bundle``).
    """
    bundle.reproduction = result.as_dict()
    if result.reproduced:
        bundle.tier = "1.5"
    return bundle
