"""Adapter: ``packages.fuzzing.Crash`` → ``core.witness.Witness``.

AFL++ crashes are the cleanest "verified witness" RAPTOR has —
the fuzzer actually ran the target with these bytes and observed
the crash. Wrapping them in the canonical Witness type makes them
available to downstream consumers (reporting, future ZKPoX,
future calibrated IntentMatchJudge) on the same data path as
witnesses from other pipelines.

Adapter lives here in ``packages/fuzzing/`` rather than in
``core/witness/`` so the dependency arrow points the right way
(packages depend on core, not vice versa).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from core.hash import sha256_file
from core.source import read_bytes_capped
from core.witness import Witness, WitnessOutcome, WitnessSource
from core.witness.types import compute_bytes_hash

if TYPE_CHECKING:
    from packages.fuzzing.atheris_runner import PythonExceptionInfo
    from packages.fuzzing.cargofuzz_runner import RustPanicInfo
    from packages.fuzzing.crash_collector import Crash
    from packages.fuzzing.crash_attribution import CrashAttribution
    from packages.fuzzing.jazzer_runner import JavaExceptionInfo

# Cap on a single crash-input read. The crashes dir is written by the
# (untrusted, possibly attacker-built) fuzz target: CrashCollector
# refuses symlinks, but a hostile target can still plant an arbitrarily
# large REGULAR file named "id:..." there, and an unbounded
# read_bytes() loads it whole into host memory and then persists it
# into the durable witness store. Trade-off both ways: AFL++'s default
# max input is 1 MiB, so real crash inputs sit far below 4 MiB —
# raising the cap only admits plants deeper into host memory and the
# store; lowering it below AFL's configured max_len (operators can bump
# it with -G) risks dropping genuine oversized crash inputs. Callers
# treat the raise as a per-crash skip (logged), never a campaign abort.
_MAX_CRASH_INPUT_BYTES = 4 * 1024 * 1024


def witness_from_crash(
    crash: Crash,
    target_binary_path: Path | None = None,
    target_source_hash: str | None = None,
    produced_by: str = "afl++",
    smt_attribution: CrashAttribution | None = None,
) -> tuple[Witness, bytes]:
    """Wrap an AFL++ ``Crash`` as a ``Witness`` + the raw bytes.

    Returns ``(witness, bytes_)``. Callers typically pass both
    straight to ``WitnessStore.put(witness, bytes_)``.

    The ``Crash.signal`` field is AFL's two-char signal number
    (``"11"`` for SIGSEGV, ``"06"`` for SIGABRT, etc.). It's
    surfaced as ``outcome=EXIT_SIGNAL`` with the raw signal stamp
    in ``outcome_detail``; downstream consumers that want the
    signal *name* (SIGSEGV, etc.) should map themselves —
    ``packages.llm_analysis.crash_agent`` already has the table.

    ``target_binary_path`` is optional; when provided, the binary
    is hashed and recorded so a later run can verify it's still
    the same build before claiming the witness holds.

    ``smt_attribution`` is an exact-lineage attribution from
    ``crash_attribution.attribute_crashes_from_seeds``: the crash's recorded
    AFL mutation chain roots in an SMT-witness seed. It stamps
    ``finding_id`` into ``outcome_detail``, which the
    ``from_witness`` projection surfaces in
    ``raptor-verified-outcomes`` — a solver-predicted input family
    produced an observed crash.
    """
    # Bounded read (shared core.source helper: cap + 1 probe byte
    # rather than stat-then-read — the file is target-writable, so a
    # size check followed by an unbounded read would still race a
    # growing plant).
    got = read_bytes_capped(crash.input_file, _MAX_CRASH_INPUT_BYTES)
    if got is None:
        msg = f"crash input {crash.input_file} could not be read"
        raise OSError(msg)
    data, truncated = got
    if truncated:
        msg = (
            f"crash input {crash.input_file} exceeds the "
            f"{_MAX_CRASH_INPUT_BYTES}-byte witness cap — refusing to "
            f"load a target-planted oversized file into the witness "
            f"store"
        )
        raise ValueError(msg)
    bytes_hash = compute_bytes_hash(data)

    outcome_detail: dict = {
        "crash_id": crash.crash_id,
        "afl_signal": crash.signal or "unknown",
    }
    if crash.stack_hash:
        outcome_detail["stack_hash"] = crash.stack_hash
    if crash.timestamp is not None:
        outcome_detail["afl_observed_at"] = crash.timestamp
    if smt_attribution is not None:
        outcome_detail["finding_id"] = smt_attribution.origin_id
        outcome_detail["smt_seed"] = smt_attribution.seed_name
        outcome_detail["smt_attribution"] = "exact-lineage"

    target_binary_hash: str | None = None
    if target_binary_path is not None and target_binary_path.is_file():
        target_binary_hash = sha256_file(target_binary_path)

    # Outcome: AFL only surfaces a crash when the target exited via
    # a signal (its acceptance criterion). Signal-less crashes
    # don't reach this adapter — AFL would have classified them
    # as hangs / timeouts and routed them elsewhere.
    outcome = (
        WitnessOutcome.EXIT_SIGNAL if crash.signal
        else WitnessOutcome.UNKNOWN
    )

    witness = Witness(
        bytes_hash=bytes_hash,
        bytes_len=len(data),
        source=WitnessSource.FUZZ,
        observed_outcome=outcome,
        outcome_detail=outcome_detail,
        target_binary_hash=target_binary_hash,
        target_source_hash=target_source_hash,
        produced_by=produced_by,
    )
    return witness, data


def witness_from_atheris_artifact(
    artifact: Path,
    *,
    exception: PythonExceptionInfo | None = None,
    harness_path: Path | None = None,
    target_source_hash: str | None = None,
) -> tuple[Witness, bytes]:
    """Wrap an atheris crash artifact as a ``Witness`` + raw bytes.

    Same shape and store path as the AFL adapter above, so atheris
    crashes join /validate, reporting, and ``raptor-verified-outcomes``
    on the identical data path. Differences worth naming:

    * Atheris crashes are usually uncaught Python exceptions: atheris
      prints the traceback and aborts the process, and libFuzzer's
      crash handler writes the artifact. The fuzzer observed the
      target die on these bytes — the outcome is ``EXIT_SIGNAL``
      (same evidentiary weight as an AFL signal exit), with the
      Python-side truth carried precisely in ``outcome_detail``
      (``crash_kind=python_exception``, exception type/message,
      ``stack_hash`` from the traceback frames). Native crashes in C
      extensions surface identically minus the exception detail
      (``crash_kind=native``).
    * There is no target binary to hash — the harness file is hashed
      instead (``harness_hash``), binding the witness to the harness
      that produced it; ``target_source_hash`` binds the package tree
      when the caller has one.

    The artifact lives in the target-writable crashes dir: same
    bounded-read cap and oversize refusal as the AFL adapter.
    """
    got = read_bytes_capped(artifact, _MAX_CRASH_INPUT_BYTES)
    if got is None:
        msg = f"crash artifact {artifact} could not be read"
        raise OSError(msg)
    data, truncated = got
    if truncated:
        msg = (
            f"crash artifact {artifact} exceeds the "
            f"{_MAX_CRASH_INPUT_BYTES}-byte witness cap — refusing to "
            f"load a target-planted oversized file into the witness "
            f"store"
        )
        raise ValueError(msg)

    outcome_detail: dict = {"crash_id": artifact.name}
    if exception is not None:
        outcome_detail["crash_kind"] = "python_exception"
        outcome_detail["exception_type"] = exception.exception_type
        if exception.message:
            outcome_detail["exception_message"] = exception.message
        if exception.stack_key:
            outcome_detail["stack_hash"] = exception.stack_key
    else:
        outcome_detail["crash_kind"] = "native"

    harness_hash: str | None = None
    if harness_path is not None and Path(harness_path).is_file():
        harness_hash = sha256_file(Path(harness_path))
        outcome_detail["harness_hash"] = harness_hash

    witness = Witness(
        bytes_hash=compute_bytes_hash(data),
        bytes_len=len(data),
        source=WitnessSource.FUZZ,
        observed_outcome=WitnessOutcome.EXIT_SIGNAL,
        outcome_detail=outcome_detail,
        target_source_hash=target_source_hash,
        produced_by="atheris",
    )
    return witness, data


def witness_from_cargofuzz_artifact(
    artifact: Path,
    *,
    panic: RustPanicInfo | None = None,
    binary_path: Path | None = None,
    target_source_hash: str | None = None,
) -> tuple[Witness, bytes]:
    """Wrap a cargo-fuzz crash artifact as a ``Witness`` + raw bytes.

    Same shape and store path as the AFL and atheris adapters above,
    so cargo-fuzz crashes join /validate, reporting, and
    ``raptor-verified-outcomes`` on the identical data path.
    Differences worth naming:

    * cargo-fuzz crashes are usually Rust panics: the harness aborts
      on the panic and libFuzzer's crash handler writes the artifact.
      The fuzzer observed the target die on these bytes — the outcome
      is ``EXIT_SIGNAL`` (same evidentiary weight as an AFL signal
      exit), with the Rust-side truth carried precisely in
      ``outcome_detail`` (``crash_kind=rust_panic``, panic message /
      location, ``stack_hash`` from the backtrace frames). Native
      crashes (ASan reports, segfaults in unsafe code) surface
      identically minus the panic detail (``crash_kind=native``).
    * ``binary_path`` is the BUILT fuzz-target binary, hashed into
      ``target_binary_hash`` so a later run can verify it is still the
      same build; ``target_source_hash`` binds the crate tree when the
      caller has one.

    The artifact lives in the target-writable crashes dir: same
    bounded-read cap and oversize refusal as the AFL adapter.
    """
    got = read_bytes_capped(artifact, _MAX_CRASH_INPUT_BYTES)
    if got is None:
        msg = f"crash artifact {artifact} could not be read"
        raise OSError(msg)
    data, truncated = got
    if truncated:
        msg = (
            f"crash artifact {artifact} exceeds the "
            f"{_MAX_CRASH_INPUT_BYTES}-byte witness cap — refusing to "
            f"load a target-planted oversized file into the witness "
            f"store"
        )
        raise ValueError(msg)

    outcome_detail: dict = {"crash_id": artifact.name}
    if panic is not None:
        outcome_detail["crash_kind"] = "rust_panic"
        if panic.message:
            outcome_detail["panic_message"] = panic.message
        if panic.location:
            outcome_detail["panic_location"] = panic.location
        if panic.stack_key:
            outcome_detail["stack_hash"] = panic.stack_key
    else:
        outcome_detail["crash_kind"] = "native"

    target_binary_hash: str | None = None
    if binary_path is not None and Path(binary_path).is_file():
        target_binary_hash = sha256_file(Path(binary_path))

    witness = Witness(
        bytes_hash=compute_bytes_hash(data),
        bytes_len=len(data),
        source=WitnessSource.FUZZ,
        observed_outcome=WitnessOutcome.EXIT_SIGNAL,
        outcome_detail=outcome_detail,
        target_binary_hash=target_binary_hash,
        target_source_hash=target_source_hash,
        produced_by="cargo-fuzz",
    )
    return witness, data


def witness_from_jazzer_artifact(
    artifact: Path,
    *,
    exception: JavaExceptionInfo | None = None,
    harness_path: Path | None = None,
    target_source_hash: str | None = None,
) -> tuple[Witness, bytes]:
    """Wrap a jazzer crash artifact as a ``Witness`` + raw bytes.

    Same shape and store path as the AFL, atheris, and cargo-fuzz
    adapters above, so jazzer crashes join /validate, reporting, and
    ``raptor-verified-outcomes`` on the identical data path.
    Differences worth naming:

    * Jazzer crashes are usually uncaught Java exceptions (its
      security detectors raise ``FuzzerSecurityIssue*`` exception
      types through the same report): jazzer prints the report and
      aborts, and libFuzzer's crash handler writes the artifact. The
      fuzzer observed the target die on these bytes — the outcome is
      ``EXIT_SIGNAL`` (same evidentiary weight as an AFL signal
      exit), with the JVM-side truth carried precisely in
      ``outcome_detail`` (``crash_kind=java_exception``, exception
      type/message, ``stack_hash`` from the stack frames). Native
      crashes (JNI code, the JVM itself) surface identically minus
      the exception detail (``crash_kind=native``).
    * There is no per-target binary to hash — the jazzer driver is
      target-independent — so the harness SOURCE file is hashed
      instead (``harness_hash``), binding the witness to the harness
      that produced it; ``target_source_hash`` binds the project tree
      when the caller has one.

    The artifact lives in the target-writable crashes dir: same
    bounded-read cap and oversize refusal as the AFL adapter.
    """
    got = read_bytes_capped(artifact, _MAX_CRASH_INPUT_BYTES)
    if got is None:
        msg = f"crash artifact {artifact} could not be read"
        raise OSError(msg)
    data, truncated = got
    if truncated:
        msg = (
            f"crash artifact {artifact} exceeds the "
            f"{_MAX_CRASH_INPUT_BYTES}-byte witness cap — refusing to "
            f"load a target-planted oversized file into the witness "
            f"store"
        )
        raise ValueError(msg)

    outcome_detail: dict = {"crash_id": artifact.name}
    if exception is not None:
        outcome_detail["crash_kind"] = "java_exception"
        outcome_detail["exception_type"] = exception.exception_type
        if exception.message:
            outcome_detail["exception_message"] = exception.message
        if exception.stack_key:
            outcome_detail["stack_hash"] = exception.stack_key
    else:
        outcome_detail["crash_kind"] = "native"

    harness_hash: str | None = None
    if harness_path is not None and Path(harness_path).is_file():
        harness_hash = sha256_file(Path(harness_path))
        outcome_detail["harness_hash"] = harness_hash

    witness = Witness(
        bytes_hash=compute_bytes_hash(data),
        bytes_len=len(data),
        source=WitnessSource.FUZZ,
        observed_outcome=WitnessOutcome.EXIT_SIGNAL,
        outcome_detail=outcome_detail,
        target_source_hash=target_source_hash,
        produced_by="jazzer",
    )
    return witness, data
