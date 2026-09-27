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

**Spawn failures are not outcomes.** A run whose child never
successfully exec'd the target (exec-status category from the sandbox,
the supervisor's ``spawn_failed`` record on the recompile lane, or the
bounded 125/126/127-with-no-output shape) is recorded in
``run_details`` with provenance ``spawn_failure``, retried once, and
excluded from the reproduced/deterministic verdict — counting it would
let a transient ETXTBSY read as "non-deterministic witness". The
verdict is judged over the EXECUTED runs (all must match, at least one
must execute): a run excluded after its retry cannot veto what every
executed run demonstrated, and the k-of-n execution count stays in the
result. The
bounded shape applies on EVERY lane, including the exec-status-pipe
one: the pipe reports failure best-effort only, so its silence never
vetoes the heuristic. See :func:`_spawn_failure_reason` for the
precise-vs-heuristic split and its bounds.

The full tier model lives in the package docstring
(``packages/zkpox/__init__.py``).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from core.sandbox import SandboxSetupError
from core.witness.types import WitnessOutcome
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
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

# Exit codes the spawn layers re-encode a failed exec of the TARGET as
# (shell/util-linux convention, from the spawn grandchild's exec
# lane): 127 file not found, 126 found but not executable, 125 the
# catch-all exec errno (ETXTBSY, ENOEXEC, ELOOP, ...).
# A run that exits with one of these MAY still be a genuine target
# outcome — see _spawn_failure_reason for how the ambiguity is bounded.
_EXEC_FAILURE_RETURNCODES = frozenset({125, 126, 127})

# Sentinel distinguishing "result has no _setup_status attribute at all"
# (lane without the exec-status pipe) from "_setup_status is None"
# (exec-status lane, and the pipe's EOF proved the target exec'd).
_NO_SETUP_STATUS = object()


def _stderr_is_sandbox_diagnostic_only(stderr: object) -> bool:
    """True iff ``stderr`` is empty or carries only the sandbox layer's
    own pre-exec diagnostics: lines prefixed ``sandbox:`` (the
    convention of ``warn_post_fork``, the seccomp preexec, and the
    spawn layers' exec-failure lines), or the spawn child's
    ``sandbox child failure:`` block (one marker line followed by the
    child's traceback — written before the target's first instruction,
    so the whole block is sandbox-layer by construction). A target
    could print either shape to have itself classified a spawn
    failure, but that buys it only retries and an honest "runs did not
    execute" non-reproduction — a target that wants to dodge
    reproduction can already just exit 0."""
    if not stderr:
        return True
    text = (stderr.decode("utf-8", errors="replace")
            if isinstance(stderr, bytes) else str(stderr))
    lines = [line for line in text.splitlines() if line.strip()]
    if lines and lines[0].startswith("sandbox child failure:"):
        return True
    return all(line.startswith("sandbox:") for line in lines)


def _spawn_failure_reason(result: Any) -> str | None:
    """Classify a completed replay run as a spawn failure — the child
    never successfully exec'd the target — or ``None`` (genuine
    outcome).

    Precise signal first: results from the exec-status-pipe lanes
    (mount-ns spawn path, macOS seatbelt shim) carry ``_setup_status``.
    Any category tuple means setup or exec failed before the target
    ran — authoritative, no heuristic needed.

    ``_setup_status`` ``None`` (pipe EOF) is authoritative only in the
    POSITIVE direction. EOF normally means the target exec'd (CLOEXEC
    reaped the write end), but the channel is best-effort at reporting
    failure: the child-side write runs suppressed in a dying process
    and the parent-side drain maps an unreadable pipe to the same
    ``None`` — so a lost status byte is indistinguishable from a clean
    exec. A spawn-lane replay run has been observed exiting 126 with
    pipe EOF, no output, and no crash evidence; counting it as an
    outcome flipped a deterministic SIGSEGV witness to
    "non-deterministic". Silence therefore never vetoes the bounded
    heuristic below — only a category tuple short-circuits.

    The heuristic (status ``None`` or attribute absent — the plain
    subprocess fallbacks, where exec failure is re-encoded as exit
    125/126/127 with no side channel): a bare 125-127 exit is
    ambiguous with a
    target that chooses those codes, so the reclassification is
    bounded to the pre-first-output window. A failed exec happens
    before the target's first instruction, so the child writes NOTHING
    except (possibly) the sandbox layer's own diagnostics
    (see :func:`_stderr_is_sandbox_diagnostic_only`); any
    signal/sanitizer evidence or any target output disqualifies the
    reclassification. The residual ambiguity — a target that exits
    125-127 without ever producing output — costs one bounded retry
    and, when persistent, an honest "runs did not execute"
    non-reproduction, never a false "reproduced". No new forgery power
    either: a target that wants to dodge reproduction can already just
    exit 0.
    """
    status: Any = getattr(result, "_setup_status", _NO_SETUP_STATUS)
    if status is not _NO_SETUP_STATUS and status is not None:
        try:
            cat, why = status[0], status[1]
        except (TypeError, IndexError, KeyError):
            cat, why = "?", str(status)
        return f"sandbox setup/exec failure ({cat}: {why})"
    rc = getattr(result, "returncode", None)
    if rc not in _EXEC_FAILURE_RETURNCODES:
        return None
    info = getattr(result, "sandbox_info", None) or {}
    if info.get("signal") or info.get("sanitizer") or info.get("crashed"):
        return None  # it demonstrably ran/died — a genuine outcome
    if getattr(result, "stdout", None):
        return None  # produced output — it ran
    if not _stderr_is_sandbox_diagnostic_only(
            getattr(result, "stderr", None)):
        return None
    return (
        f"exit code {rc} with no output and no signal — exec-failure "
        f"shape (spawn layers re-encode a failed target exec as "
        f"125/126/127)"
    )


@dataclass
class ReproductionResult:
    """Outcome of an N-run reproduction attempt."""
    attempted: bool
    runs: int
    expected_outcome: str
    observed_outcomes: list[str] = field(default_factory=list)
    # Every EXECUTED run matched the recorded outcome (>= 1 executed).
    # Spawn-failure exclusions never block or fake this — see _finalize.
    reproduced: bool = False
    deterministic: bool = False     # executed runs all produced the SAME outcome
    reason: str = ""
    # Weakest evidence grade across the runs: "mechanical" only when
    # EVERY run graded mechanical. What "mechanical" means differs by
    # lane: LLM_EMIT_RUN runs ride compile_and_execute's waitstatus
    # supervisor (oracle-anchored), while the input-replay lane
    # consumes the SUBSTRATE grade from
    # core.witness.outcome_from_sandbox_info ungated — i.e. parent
    # waitpid provenance only, with no sentinel/oracle upgrade, so on
    # spawn tiers that re-encode signals as 128+sig exit codes replay
    # runs grade heuristic even for genuine crashes. Either way a
    # deterministic reproduction of a target-forged outcome (fake
    # sanitizer stderr, exit(139) — the hostile binary replays its own
    # forgery perfectly under the binary-hash pin) grades "heuristic";
    # consumers must not read tier 1.5 as mechanical proof unless this
    # field says so.
    evidence_grade: str = ""
    # Count of spawn-failure ATTEMPTS: executions whose child never
    # successfully exec'd the target (exec-status category, or the
    # bounded 125/126/127-with-no-output shape — see
    # _spawn_failure_reason). Spawn failures are NOT observed outcomes:
    # they never enter observed_outcomes or the reproduced/deterministic
    # verdict; each planned run gets one bounded retry. Provenance for
    # every such attempt is recorded in run_details with
    # outcome="spawn_failure".
    spawn_failures: int = 0
    # Per-run diagnostics: returncode plus a bounded extract of
    # sandbox_info (signal, crashed, blocked, isolation degradation).
    # Outcome strings alone cannot distinguish "the witness genuinely
    # doesn't reproduce" from "the sandbox lane degraded / stdin never
    # arrived on one run" — these records name the lane and the shape
    # for each run so a divergent run is diagnosable from the report.
    run_details: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "attempted": self.attempted,
            "runs": self.runs,
            "expected_outcome": self.expected_outcome,
            "observed_outcomes": list(self.observed_outcomes),
            "reproduced": self.reproduced,
            "deterministic": self.deterministic,
            "reason": self.reason,
            "evidence_grade": self.evidence_grade,
            "spawn_failures": self.spawn_failures,
            "run_details": [dict(d) for d in self.run_details],
        }


def _finalize(
    expected: str,
    observed: list[str],
    n: int,
    *,
    reason: str = "",
    grades: list[str] | None = None,
    details: list[dict] | None = None,
    spawn_failures: int = 0,
) -> ReproductionResult:
    """Build the result from the per-run observed outcomes.

    ``observed`` carries only runs whose child actually exec'd the
    target; spawn-failure attempts (counted by ``spawn_failures``,
    detailed in ``details``) are excluded from the verdict entirely.
    ``reproduced`` is judged over the EXECUTED runs: every executed
    run matched the recorded outcome, with at least one executed. A
    run whose bounded retry also failed to spawn is an infrastructure
    exclusion, not evidence about the witness — it never blocks the
    verdict the executed runs earned, and it never reads as
    non-determinism (that word is reserved for executed runs that
    DISAGREE). The exclusion stays honestly in the record: ``runs``
    keeps the planned count, ``observed_outcomes`` carries only the
    executed ones, and the reason names "k of n executed" whenever
    they differ. Zero executed runs can confirm nothing:
    ``reproduced`` stays False with a "no run executed" reason.
    """
    executed = len(observed)
    reproduced = executed > 0 and all(o == expected for o in observed)
    # "error" entries are runs whose replay RAISED (infrastructure
    # noise), not observed target behaviour. They still block
    # ``reproduced`` (fail-safe: an errored run is not a match), but
    # they must not read as witness NON-DETERMINISM — that word is
    # reserved for clean executed runs that disagree — and an all-error
    # set is not "deterministic" either.
    non_error = [o for o in observed if o != "error"]
    errors = executed - len(non_error)
    deterministic = bool(non_error) and len(set(non_error)) == 1
    excluded_note = (
        f" ({executed}/{n} planned runs executed; the rest were "
        f"spawn-failure exclusions — infrastructure, not outcome "
        f"variance; see run_details)"
        if executed < n and spawn_failures else ""
    )
    if not reason:
        if executed == 0 and spawn_failures:
            reason = (
                f"no run executed: every attempt was a spawn failure "
                f"(the target never exec'd; see run_details)"
            )
        elif reproduced:
            reason = (
                f"all {executed} executed runs reproduced {expected!r}"
                + excluded_note
            )
        elif errors and not non_error:
            reason = (
                f"inconclusive: every executed run raised an "
                f"infrastructure error (not outcome evidence; see "
                f"run_details)" + excluded_note
            )
        elif errors and all(o == expected for o in non_error):
            reason = (
                f"inconclusive: {len(non_error)} clean run(s) "
                f"reproduced {expected!r} but {errors} run(s) raised "
                f"infrastructure errors (see run_details)"
                + excluded_note
            )
        elif errors and deterministic:
            reason = (
                f"deterministic but off-target: all clean runs "
                f"produced {non_error[0]!r}, expected {expected!r}; "
                f"{errors} infrastructure error(s) (see run_details)"
                + excluded_note
            )
        elif errors:
            reason = (
                f"non-deterministic: clean-run outcomes varied "
                f"({non_error}); {errors} infrastructure error(s) "
                f"excluded from that judgement (see run_details)"
                + excluded_note
            )
        elif deterministic:
            reason = (
                f"deterministic but off-target: all executed runs "
                f"produced {observed[0]!r}, expected {expected!r}"
                + excluded_note
            )
        else:
            reason = (
                f"non-deterministic: outcomes varied across executed "
                f"runs ({observed})" + excluded_note
            )
        if spawn_failures and executed == n:
            reason += (
                f" ({spawn_failures} spawn-failure attempt(s) retried "
                f"and excluded from the verdict)"
            )
    # Weakest-wins: one heuristic (or ungraded) run demotes the whole
    # reproduction — the honest reading of mixed evidence.
    grade = ""
    if observed:
        grade = "mechanical" if (
            grades
            and len(grades) == len(observed)
            and all(g == "mechanical" for g in grades)
        ) else "heuristic"
    return ReproductionResult(
        attempted=True,
        runs=n,
        expected_outcome=expected,
        observed_outcomes=observed,
        reproduced=reproduced,
        deterministic=deterministic,
        reason=reason,
        evidence_grade=grade,
        spawn_failures=spawn_failures,
        run_details=list(details or []),
    )


def reproduce_witness(
    bundle: ZKPoXBundle,
    witness_bytes: bytes,
    *,
    binary_path: Path | None = None,
    n: int = 3,
    sandbox_timeout: int = 5,
    logger_: logging.Logger | None = None,
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
        n: number of consecutive runs (default 3, must be >= 1).
            The recorded outcome must reproduce in every run that
            EXECUTES for ``reproduced=True`` (at least one must);
            spawn-failure attempts are retried once and excluded
            from the verdict, with the k-of-n execution count kept
            in the result.
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

    # Zero runs can't confirm anything — without this guard both
    # dispatch paths would skip their loops and report a misleading
    # "non-deterministic" reason over an empty outcome list.
    if n < 1:
        return ReproductionResult(
            attempted=False, runs=0,
            expected_outcome=bundle.observed_outcome,
            reason=f"n must be >= 1 (got {n}); nothing to reproduce",
        )

    # Verify we're reproducing the RIGHT witness — the bytes the
    # bundle was assembled from — before running anything. Mirrors
    # the binary-hash check in _reproduce_replay.
    if bundle.witness_hash:
        from core.hash import sha256_bytes
        actual = sha256_bytes(witness_bytes)
        if actual != bundle.witness_hash:
            return ReproductionResult(
                attempted=False, runs=0,
                expected_outcome=bundle.observed_outcome,
                reason=(
                    f"witness hash mismatch: supplied {actual[:16]}... "
                    f"!= recorded {bundle.witness_hash[:16]}...; "
                    f"refusing to reproduce a different witness"
                ),
            )

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
        san_name = (bundle.outcome_detail or {}).get("sanitizer") or ""
        flag = _SANITIZER_FLAG.get(san_name)
        if flag:
            sanitizers = [flag]

    observed: list[str] = []
    grades: list[str] = []
    details: list[dict] = []
    spawn_failures = 0
    for i in range(n):
        for _attempt in (1, 2):
            compiled, errors, outcome, detail = compile_and_execute(
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
            # Spawn failure, precise: the in-sandbox waitstatus
            # supervisor reports exit_kind="spawn_failed" when its own
            # Popen of the compiled exploit raised (ETXTBSY, ENOEXEC,
            # ...) — the exploit never ran, so this is not an observed
            # outcome. One bounded retry per planned run.
            oracle = (detail or {}).get("exec_oracle") or {}
            if oracle.get("exit_kind") == "spawn_failed":
                spawn_failures += 1
                details.append({
                    "run": i + 1, "attempt": _attempt,
                    "outcome": "spawn_failure",
                    "spawn_failure": (
                        f"supervisor reported spawn_failed "
                        f"({oracle.get('error') or 'OSError'})"
                    ),
                })
                if _attempt == 1:
                    log.info(
                        "reproduce run %d/%d: exploit spawn failed "
                        "(%s) — retrying once",
                        i + 1, n, oracle.get("error") or "OSError",
                    )
                    continue
                log.warning(
                    "reproduce run %d/%d: exploit spawn failed on the "
                    "retry as well — excluding the run from the verdict",
                    i + 1, n,
                )
                break
            observed.append(
                outcome.value if outcome is not None else "none")
            grades.append(str((detail or {}).get("evidence_grade") or ""))
            break

    return _finalize(expected, observed, n, grades=grades,
                     details=details, spawn_failures=spawn_failures)


def _reproduce_replay(
    bundle: ZKPoXBundle,
    witness_bytes: bytes,
    *,
    binary_path: Path | None,
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
        from core.sandbox import executable_stage as _executable_stage
        from core.sandbox import run_untrusted as sandbox_run_untrusted
        from core.witness import outcome_from_sandbox_info
    except ImportError as e:
        return ReproductionResult(
            attempted=False, runs=0, expected_outcome=expected,
            reason=f"sandbox unavailable: {e}",
        )

    observed: list[str] = []
    grades: list[str] = []
    details: list[dict] = []
    spawn_failures = 0
    for _i in range(n):
        for _attempt in (1, 2):
            try:
                # run_untrusted, not run: the target binary is untrusted
                # and the witness is attacker data, so reads must be
                # pinned to system dirs + the binary's own dir
                # (restrict_reads) with a credential-free fake $HOME —
                # a compromised target can't read ~/.ssh or ~/.aws.
                # block_network + strict_env are forced by the helper.
                # Consented-exec staging: an env-built binary_path
                # is 0444 in the run dir (core/env/build.py); replay a
                # private 0o500 copy. Per-attempt staging keeps the
                # diff minimal — n is small here.
                with _executable_stage(binary_path) as _staged:
                    result = sandbox_run_untrusted(
                        [str(_staged)],
                        target=str(_staged.parent),
                        output=str(_staged.parent),
                        capture_output=True,
                        text=False,
                        input=witness_bytes,
                        timeout=sandbox_timeout,
                        env=RaptorConfig.get_safe_env(),
                    )
            except SandboxSetupError as e:
                # setup_category "X" = every isolation layer engaged
                # and the TARGET's own exec failed inside the sandbox
                # (ETXTBSY from a still-open writer fd, and kin) — a
                # per-invocation spawn failure, not an isolation
                # refusal. One bounded retry at FULL isolation (no
                # degrade involved). Anything else keeps the fail-loud
                # contract: isolation could not engage, never mask as
                # a benign result.
                if (getattr(e, "setup_category", None) != "X"
                        or _attempt == 2):
                    raise
                spawn_failures += 1
                details.append({
                    "run": _i + 1,
                    "attempt": _attempt,
                    "outcome": "spawn_failure",
                    "spawn_failure": str(
                        getattr(e, "reason", None) or e)[:200],
                })
                log.info(
                    "reproduce replay run %d/%d: target exec failed "
                    "inside the sandbox (%s) — retrying once",
                    _i + 1, n,
                    str(getattr(e, "reason", None) or e)[:120],
                )
                continue
            except Exception as e:  # noqa: BLE001 — best-effort per run
                observed.append("error")
                grades.append("")
                details.append({
                    "run": _i + 1,
                    "outcome": "error",
                    "error": str(e)[:200],
                })
                log.debug("reproduce replay run raised: %s", e)
                break
            # Spawn failure: the child never successfully exec'd the
            # target, so this is NOT an observed outcome — the pre-fix
            # code counted the re-encoded exit (126/127) as
            # no_obvious_effect and flipped the verdict to
            # "non-deterministic". Precise signal preferred, bounded
            # heuristic otherwise; see _spawn_failure_reason.
            _sf_reason = _spawn_failure_reason(result)
            if _sf_reason is not None:
                spawn_failures += 1
                details.append({
                    "run": _i + 1,
                    "attempt": _attempt,
                    "outcome": "spawn_failure",
                    "returncode": getattr(result, "returncode", None),
                    "spawn_failure": _sf_reason,
                })
                if _attempt == 1:
                    log.info(
                        "reproduce replay run %d/%d: spawn failure "
                        "(%s) — retrying once", _i + 1, n, _sf_reason,
                    )
                    continue
                log.warning(
                    "reproduce replay run %d/%d: spawn failure on the "
                    "retry as well — excluding the run from the "
                    "verdict", _i + 1, n,
                )
                break
            sandbox_info = getattr(result, "sandbox_info", None)
            returncode = getattr(result, "returncode", None)
            outcome, _detail = outcome_from_sandbox_info(
                sandbox_info, returncode=returncode,
            )
            observed.append(outcome.value)
            grades.append(str(_detail.get("evidence_grade") or ""))
            rec: dict[str, Any] = {
                "run": _i + 1,
                "outcome": outcome.value,
                "returncode": returncode,
            }
            if _attempt > 1:
                rec["attempt"] = _attempt
            if isinstance(sandbox_info, dict):
                for key in ("signal", "signal_provenance", "crashed",
                            "seccomp_killed", "resource_exceeded",
                            "sanitizer", "mount_ns_degraded",
                            "sandbox_disabled"):
                    value = sandbox_info.get(key)
                    if value not in (None, False):
                        rec[key] = (value if isinstance(value, (bool, int))
                                    else str(value)[:200])
                blocked = sandbox_info.get("blocked")
                if blocked:
                    rec["blocked"] = [str(b)[:120]
                                      for b in list(blocked)[:5]]
            details.append(rec)
            break

    return _finalize(expected, observed, n, grades=grades,
                     details=details, spawn_failures=spawn_failures)


def attach_reproduction(
    bundle: ZKPoXBundle,
    result: ReproductionResult,
) -> ZKPoXBundle:
    """Fold a reproduction result into a bundle: store it under
    ``bundle.reproduction`` and, when the witness reproduced, bump
    the tier label to ``"1.5"``.

    Tier decision: ``"1.5"`` claims "every run that EXECUTED exhibited
    the recorded outcome" — k of n planned runs with k >= 1, where the
    n - k exclusions are spawn failures (infrastructure), not outcome
    evidence. The full honesty trail rides in the persisted
    ``reproduction`` block (``runs``, ``observed_outcomes``,
    ``spawn_failures``, ``run_details``, and a reason naming k of n),
    so no consumer has to infer it from the tier label; nothing
    downstream reads the label as an n-of-n claim.

    Mutates and returns the bundle (callers typically re-persist it
    with ``write_bundle``).
    """
    bundle.reproduction = result.as_dict()
    if result.reproduced:
        bundle.tier = "1.5"
    return bundle
