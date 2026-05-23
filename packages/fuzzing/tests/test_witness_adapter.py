"""Tests for ``packages.fuzzing.witness_adapter.witness_from_crash``.

The adapter wraps an AFL++ ``Crash`` as a canonical ``Witness``.
These tests pin:

  * The hash matches ``sha256`` of the actual input file
  * ``source`` is always ``WitnessSource.FUZZ``
  * Signal info threads into ``outcome_detail``
  * Target binary hashing is optional and only fires when the
    path was provided AND exists
  * The (witness, bytes_) tuple round-trips cleanly through
    ``WitnessStore.put``
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path


# packages/fuzzing/tests/test_witness_adapter.py → parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from core.witness import WitnessOutcome, WitnessSource, WitnessStore  # noqa: E402
from packages.fuzzing.crash_collector import Crash  # noqa: E402
from packages.fuzzing.witness_adapter import witness_from_crash  # noqa: E402


def _make_crash(
    tmp_path: Path,
    data: bytes = b"crash input",
    signal: str = "11",
    crash_id: str = "000001",
    stack_hash: str = "",
) -> Crash:
    input_file = tmp_path / f"id_{crash_id}"
    input_file.write_bytes(data)
    return Crash(
        crash_id=crash_id,
        input_file=input_file,
        signal=signal,
        stack_hash=stack_hash,
        size=len(data),
    )


# ----------------------------------------------------------------------
# Basic adapter contract
# ----------------------------------------------------------------------


def test_adapter_returns_witness_and_bytes(tmp_path):
    data = b"long string overflow attack payload"
    crash = _make_crash(tmp_path, data=data)
    witness, bytes_ = witness_from_crash(crash)
    assert bytes_ == data
    assert witness.bytes_hash == hashlib.sha256(data).hexdigest()
    assert witness.bytes_len == len(data)


def test_adapter_source_is_fuzz(tmp_path):
    """Every Crash → Witness is sourced as fuzz. Downstream
    consumers filtering by source rely on this."""
    crash = _make_crash(tmp_path)
    witness, _ = witness_from_crash(crash)
    assert witness.source is WitnessSource.FUZZ


def test_adapter_outcome_exit_signal_when_signal_set(tmp_path):
    crash = _make_crash(tmp_path, signal="11")  # SIGSEGV
    witness, _ = witness_from_crash(crash)
    assert witness.observed_outcome is WitnessOutcome.EXIT_SIGNAL


def test_adapter_outcome_unknown_when_no_signal(tmp_path):
    """Defensive: a Crash without a signal (shouldn't happen in
    real AFL++ output, but the type allows it) gets UNKNOWN
    rather than a fabricated EXIT_SIGNAL."""
    crash = _make_crash(tmp_path, signal="")
    witness, _ = witness_from_crash(crash)
    assert witness.observed_outcome is WitnessOutcome.UNKNOWN


# ----------------------------------------------------------------------
# Outcome detail
# ----------------------------------------------------------------------


def test_outcome_detail_carries_crash_id_and_signal(tmp_path):
    crash = _make_crash(tmp_path, signal="11", crash_id="000042")
    witness, _ = witness_from_crash(crash)
    assert witness.outcome_detail["crash_id"] == "000042"
    assert witness.outcome_detail["afl_signal"] == "11"


def test_outcome_detail_includes_stack_hash_when_present(tmp_path):
    crash = _make_crash(tmp_path, stack_hash="deadbeefcafebabe")
    witness, _ = witness_from_crash(crash)
    assert witness.outcome_detail.get("stack_hash") == "deadbeefcafebabe"


def test_outcome_detail_omits_stack_hash_when_empty(tmp_path):
    crash = _make_crash(tmp_path, stack_hash="")
    witness, _ = witness_from_crash(crash)
    assert "stack_hash" not in witness.outcome_detail


# ----------------------------------------------------------------------
# Target binary hashing
# ----------------------------------------------------------------------


def test_target_binary_hashing_when_path_provided(tmp_path):
    """A real binary path → SHA-256 in target_binary_hash."""
    binary = tmp_path / "target"
    binary.write_bytes(b"#!/bin/sh\necho mock\n")
    crash = _make_crash(tmp_path)
    witness, _ = witness_from_crash(crash, target_binary_path=binary)
    assert witness.target_binary_hash is not None
    assert len(witness.target_binary_hash) == 64
    # Sanity: matches sha256 of the file content
    expected = hashlib.sha256(binary.read_bytes()).hexdigest()
    assert witness.target_binary_hash == expected


def test_target_binary_hash_none_when_path_missing(tmp_path):
    """A path that doesn't exist → target_binary_hash stays None
    rather than raising. Witness records are best-effort about
    bindings; absence is the right encoding for "we don't know"."""
    crash = _make_crash(tmp_path)
    witness, _ = witness_from_crash(
        crash, target_binary_path=tmp_path / "does_not_exist",
    )
    assert witness.target_binary_hash is None


def test_target_binary_hash_none_when_path_not_supplied(tmp_path):
    crash = _make_crash(tmp_path)
    witness, _ = witness_from_crash(crash, target_binary_path=None)
    assert witness.target_binary_hash is None


# ----------------------------------------------------------------------
# Optional target_source_hash + produced_by
# ----------------------------------------------------------------------


def test_target_source_hash_passes_through(tmp_path):
    crash = _make_crash(tmp_path)
    witness, _ = witness_from_crash(
        crash, target_source_hash="c0ffee" * 10 + "abcd",
    )
    assert witness.target_source_hash == "c0ffee" * 10 + "abcd"


def test_produced_by_defaults_to_afl(tmp_path):
    crash = _make_crash(tmp_path)
    witness, _ = witness_from_crash(crash)
    assert witness.produced_by == "afl++"


def test_produced_by_overrideable(tmp_path):
    crash = _make_crash(tmp_path)
    witness, _ = witness_from_crash(crash, produced_by="afl++-1.06c")
    assert witness.produced_by == "afl++-1.06c"


# ----------------------------------------------------------------------
# Store round-trip
# ----------------------------------------------------------------------


def test_round_trip_through_witness_store(tmp_path):
    """The (witness, bytes_) tuple plugs straight into
    WitnessStore.put with no impedance."""
    crash = _make_crash(tmp_path, data=b"\xde\xad\xbe\xef" * 64)
    witness, data = witness_from_crash(crash)

    store_root = tmp_path / "store"
    store = WitnessStore(store_root)
    store.put(witness, data)

    loaded = store.get_witness(witness.bytes_hash)
    loaded_bytes = store.get_bytes(witness.bytes_hash)
    assert loaded.bytes_hash == witness.bytes_hash
    assert loaded.source == WitnessSource.FUZZ
    assert loaded_bytes == data
