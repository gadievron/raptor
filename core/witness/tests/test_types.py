"""Tests for ``core.witness.types`` — the Witness dataclass + enums.

Pin the contract that downstream consumers (reporting, future
ZKPoX assembly, future calibrated IntentMatchJudge) will rely on:

  * Hash validation (rejects malformed inputs)
  * Round-trip via to_dict/from_dict
  * Tolerant load (extra keys ignored, missing optional keys default)
  * Enum string values are stable (subclass of str, JSON-clean)
"""

from __future__ import annotations

import hashlib
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest


# core/witness/tests/test_types.py → parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from core.witness.types import (  # noqa: E402
    Witness,
    WitnessOutcome,
    WitnessSource,
    compute_bytes_hash,
)


# ----------------------------------------------------------------------
# Hash helper
# ----------------------------------------------------------------------


def test_compute_bytes_hash_matches_hashlib():
    data = b"hello world"
    assert compute_bytes_hash(data) == hashlib.sha256(data).hexdigest()


def test_compute_bytes_hash_empty():
    # SHA-256 of empty bytes is a well-known constant; pin it so a
    # future refactor that changes the algorithm doesn't silently
    # invalidate every persisted witness in the wild.
    expected = (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4"
        "649b934ca495991b7852b855"
    )
    assert compute_bytes_hash(b"") == expected


# ----------------------------------------------------------------------
# Witness construction + validation
# ----------------------------------------------------------------------


VALID_HASH = "a" * 64


def test_witness_construction_with_required_fields():
    w = Witness(
        bytes_hash=VALID_HASH,
        source=WitnessSource.FUZZ,
        observed_outcome=WitnessOutcome.EXIT_SIGNAL,
    )
    assert w.bytes_hash == VALID_HASH
    assert w.source is WitnessSource.FUZZ
    assert w.observed_outcome is WitnessOutcome.EXIT_SIGNAL
    # Defaults
    assert w.bytes_len == 0
    assert w.target_binary_hash is None
    assert w.outcome_detail == {}
    # Auto-timestamp
    assert isinstance(w.timestamp, datetime)


def test_witness_rejects_truncated_hash():
    """64-char SHA-256 hex enforced — short hashes would silently
    collide in the store."""
    with pytest.raises(ValueError, match="64-char"):
        Witness(
            bytes_hash="a" * 32,
            source=WitnessSource.FUZZ,
            observed_outcome=WitnessOutcome.EXIT_SIGNAL,
        )


def test_witness_rejects_non_hex_hash():
    """Non-hex characters in the position-of-hash field are rejected.
    Catches the bug of passing a base64-encoded hash or a path."""
    with pytest.raises(ValueError, match="hex"):
        Witness(
            bytes_hash="z" * 64,
            source=WitnessSource.FUZZ,
            observed_outcome=WitnessOutcome.EXIT_SIGNAL,
        )


# ----------------------------------------------------------------------
# Serialisation round-trip
# ----------------------------------------------------------------------


def test_witness_round_trip_minimal():
    """Required fields round-trip cleanly."""
    w = Witness(
        bytes_hash=VALID_HASH,
        source=WitnessSource.FUZZ,
        observed_outcome=WitnessOutcome.EXIT_SIGNAL,
    )
    loaded = Witness.from_dict(w.to_dict())
    assert loaded.bytes_hash == w.bytes_hash
    assert loaded.source == w.source
    assert loaded.observed_outcome == w.observed_outcome


def test_witness_round_trip_full():
    """All fields including the optional ones survive round-trip."""
    ts = datetime(2026, 1, 15, 12, 30, 45, tzinfo=timezone.utc)
    w = Witness(
        bytes_hash=VALID_HASH,
        source=WitnessSource.CRASH_REPLAY,
        observed_outcome=WitnessOutcome.SANITIZER_REPORT,
        bytes_len=256,
        target_binary_hash="b" * 64,
        target_source_hash="c" * 64,
        outcome_detail={
            "sanitizer": "asan",
            "report": "heap-buffer-overflow",
        },
        produced_by="rr/replay",
        timestamp=ts,
    )
    loaded = Witness.from_dict(w.to_dict())
    assert loaded.bytes_hash == w.bytes_hash
    assert loaded.source == w.source
    assert loaded.observed_outcome == w.observed_outcome
    assert loaded.bytes_len == 256
    assert loaded.target_binary_hash == "b" * 64
    assert loaded.target_source_hash == "c" * 64
    assert loaded.outcome_detail == w.outcome_detail
    assert loaded.produced_by == "rr/replay"
    assert loaded.timestamp == ts


def test_from_dict_ignores_extra_keys():
    """Schema-tolerance: future versions writing extra metadata
    shouldn't break old loaders. Drop unknown keys silently."""
    data = {
        "bytes_hash": VALID_HASH,
        "source": "fuzz",
        "observed_outcome": "exit_signal",
        "future_field_we_dont_know_about": "ignored",
        "another_one": {"nested": "thing"},
    }
    w = Witness.from_dict(data)
    assert w.bytes_hash == VALID_HASH


def test_from_dict_missing_optional_keys_defaults():
    """Optional fields can be omitted entirely."""
    data = {
        "bytes_hash": VALID_HASH,
        "source": "fuzz",
        "observed_outcome": "exit_signal",
    }
    w = Witness.from_dict(data)
    assert w.target_binary_hash is None
    assert w.target_source_hash is None
    assert w.outcome_detail == {}
    assert w.produced_by is None


def test_from_dict_accepts_string_timestamp():
    """ISO-format string round-trips as a datetime."""
    data = {
        "bytes_hash": VALID_HASH,
        "source": "fuzz",
        "observed_outcome": "exit_signal",
        "timestamp": "2026-01-15T12:30:45+00:00",
    }
    w = Witness.from_dict(data)
    assert w.timestamp == datetime(
        2026, 1, 15, 12, 30, 45, tzinfo=timezone.utc,
    )


def test_from_dict_missing_timestamp_defaults_to_now():
    """If the manifest doesn't carry a timestamp, populate one
    rather than raise — defensive for older persisted records."""
    data = {
        "bytes_hash": VALID_HASH,
        "source": "fuzz",
        "observed_outcome": "exit_signal",
    }
    w = Witness.from_dict(data)
    assert isinstance(w.timestamp, datetime)


def test_from_dict_invalid_enum_raises():
    """Unknown enum values are an error — the schema is closed.
    Adding a new source / outcome requires a code change to the
    enum, not silent acceptance of arbitrary strings."""
    data = {
        "bytes_hash": VALID_HASH,
        "source": "from_my_dreams",  # not a real WitnessSource
        "observed_outcome": "exit_signal",
    }
    with pytest.raises(ValueError):
        Witness.from_dict(data)


# ----------------------------------------------------------------------
# Enum stability
# ----------------------------------------------------------------------


def test_enum_string_values_stable():
    """The string values are persisted-data contracts. Changing
    them silently invalidates every existing manifest. Pin the
    canonical values so a future refactor that rewrites the enum
    must update this test deliberately."""
    assert WitnessSource.FUZZ.value == "fuzz"
    assert WitnessSource.CRASH_REPLAY.value == "crash_replay"
    assert WitnessSource.VALIDATE_SKILL_POC.value == "validate_skill_poc"
    assert WitnessSource.LLM_EMIT_RUN.value == "llm_emit_run"
    assert WitnessSource.MANUAL.value == "manual"

    assert WitnessOutcome.NOT_RUN.value == "not_run"
    assert WitnessOutcome.NO_OBVIOUS_EFFECT.value == "no_obvious_effect"
    assert WitnessOutcome.EXIT_SIGNAL.value == "exit_signal"
    assert WitnessOutcome.SANITIZER_REPORT.value == "sanitizer_report"
    assert WitnessOutcome.FLAG_CAPTURED.value == "flag_captured"
    assert WitnessOutcome.UNKNOWN.value == "unknown"


def test_enums_are_str_subclasses():
    """Subclassing ``str`` means ``WitnessSource.FUZZ`` JSON-
    serialises as ``"fuzz"`` without a custom encoder — important
    because Witness.to_dict / from_dict round-trip relies on this."""
    assert isinstance(WitnessSource.FUZZ, str)
    assert isinstance(WitnessOutcome.EXIT_SIGNAL, str)
    assert WitnessSource.FUZZ == "fuzz"
