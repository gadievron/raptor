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
from typing import Optional

from core.hash import sha256_file
from core.witness import Witness, WitnessOutcome, WitnessSource
from core.witness.types import compute_bytes_hash
from packages.fuzzing.crash_collector import Crash


def witness_from_crash(
    crash: Crash,
    target_binary_path: Optional[Path] = None,
    target_source_hash: Optional[str] = None,
    produced_by: str = "afl++",
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
    """
    data = Path(crash.input_file).read_bytes()
    bytes_hash = compute_bytes_hash(data)

    outcome_detail: dict = {
        "crash_id": crash.crash_id,
        "afl_signal": crash.signal or "unknown",
    }
    if crash.stack_hash:
        outcome_detail["stack_hash"] = crash.stack_hash
    if crash.timestamp is not None:
        outcome_detail["afl_observed_at"] = crash.timestamp

    target_binary_hash: Optional[str] = None
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
