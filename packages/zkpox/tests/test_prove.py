"""Tests for packages.zkpox.prove.

The full SP1 round-trip is exercised by core/zkpox/test/run-tests.sh and
by `pytest -m sp1`-marked tests once we land them. This file just
covers the Python wrapper's parsing + error paths so a broken JSON
schema is caught fast.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("cbor2")

from packages.zkpox import prove


def test_default_binary_under_repo_root(monkeypatch, tmp_path):
    monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
    expected = tmp_path / "core" / "zkpox" / "target" / "release" / "zkpox-prove"
    assert prove._default_binary() == expected


def test_run_raises_if_binary_missing(tmp_path):
    nope = tmp_path / "definitely-not-here"
    with pytest.raises(prove.ProverError, match="prover binary not found"):
        prove.run(witness=tmp_path / "w.bin", binary=nope)


def test_run_rejects_unknown_mode():
    with pytest.raises(ValueError):
        prove.run(witness=Path("/nonexistent"), mode="schedule-it")


def test_parse_full_record_preserves_precision(tmp_path):
    """Full-schema record → ProveResult, no precision loss. Pure parser,
    no subprocess; the real prove path is covered by run-tests.sh."""
    record = {
        "tag": "smoke", "witness": str(tmp_path / "w.bin"), "witness_bytes": 32,
        "mode": "execute",
        "verdicts": {"target_id": 1, "crash_only_crashed": True, "oob_detected": True,
                     "oob_count": 16, "oob_first_offset": 16},
        "cycles": 9807, "wall_secs": 0.014, "proof_bytes": None, "verified": None,
    }
    result = prove._record_to_result(record)
    assert (result.tag, result.witness_bytes, result.mode) == ("smoke", 32, "execute")
    assert result.verdicts.target_id == 1
    assert result.verdicts.oob_count == result.verdicts.oob_first_offset == 16
    assert result.cycles == 9807 and result.wall_secs == 0.014
    assert result.proof_bytes is None and result.verified is None


def test_parse_record_defaults_target_id_for_pre_1_6(tmp_path):
    """Pre-1.6 record with no target_id defaults to 0x01."""
    record = {
        "tag": "old", "witness": str(tmp_path / "w.bin"), "witness_bytes": 8,
        "mode": "execute",
        "verdicts": {"crash_only_crashed": False, "oob_detected": False,
                     "oob_count": 0, "oob_first_offset": 0},
        "wall_secs": 0.001,
    }
    assert prove._record_to_result(record).verdicts.target_id == 0x01
