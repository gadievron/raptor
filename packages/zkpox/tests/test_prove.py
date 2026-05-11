"""Tests for packages.zkpox.prove.

The full SP1 round-trip is exercised by core/zkpox/test/run-tests.sh and
by `pytest -m sp1`-marked tests once we land them. This file just
covers the Python wrapper's parsing + error paths so a broken JSON
schema is caught fast.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

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


def test_parse_full_record_via_fake_binary(tmp_path, monkeypatch):
    """Smoke-test that a JSON record with the full schema parses back
    into a ProveResult without losing precision. Avoids spinning up
    SP1; uses a stub script that prints a fixed record."""
    record = {
        "tag": "smoke",
        "witness": str(tmp_path / "w.bin"),
        "witness_bytes": 32,
        "mode": "execute",
        "verdicts": {
            "target_id": 1,
            "crash_only_crashed": True,
            "oob_detected": True,
            "oob_count": 16,
            "oob_first_offset": 16,
        },
        "cycles": 9807,
        "wall_secs": 0.014,
        "proof_bytes": None,
        "verified": None,
    }
    fake = tmp_path / "fake-prove"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        f"print(json.dumps({record!r}))\n"
    )
    fake.chmod(0o755)

    witness_path = tmp_path / "w.bin"
    witness_path.write_bytes(b"x" * 32)

    result = prove.run(witness=witness_path, mode="execute", binary=fake, tag="smoke")
    assert result.tag == "smoke"
    assert result.mode == "execute"
    assert result.verdicts.crash_only_crashed is True
    assert result.verdicts.oob_count == 16
    assert result.cycles == 9807
    assert result.proof_bytes is None
