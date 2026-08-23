"""Scorecard sidecar integrity (HMAC provenance).

The sidecar steers model routing (``should_short_circuit``); pre-fix
it was fully forgeable by anyone with file write. These tests pin the
demotion semantics documented in :mod:`core.llm.scorecard.integrity`:

  * forged/unstamped content never steers routing and is never
    laundered by a re-stamping write (quarantine instead);
  * honest write -> read round-trips verify and behave as before;
  * an unusable key clamps the trust surface without destroying
    operator-readable history;
  * ``adopt`` is the deliberate operator path back for genuine
    pre-MAC history.

The suite-level conftest points XDG_DATA_HOME at a per-test tmp dir,
so every test runs against a fresh, usable key.
"""

from __future__ import annotations

import json

import pytest

from datetime import datetime, timezone

from core.llm.scorecard import integrity
from core.llm.scorecard.scorecard import (
    EventType,
    ModelScorecard,
    Policy,
)

_NOW_ISO = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
_NOW_MONTH = _NOW_ISO[:7]


def _forged_cells(n_correct: int = 100000) -> dict:
    """The PoC shape: fabricated cheap_short_circuit history that
    would trivially pass the Wilson gate. Timestamps are CURRENT so
    neither auto-GC retention nor the Wilson floor mask the trust
    question the tests probe."""
    return {
        "version": 2,
        "models": {"m": {"x:y": {
            "first_seen_at": _NOW_ISO,
            "last_seen_at": _NOW_ISO,
            "model_version": "", "policy_override": "auto",
            "events": {
                EventType.CHEAP_SHORT_CIRCUIT: {
                    _NOW_MONTH: {"correct": n_correct, "incorrect": 0},
                },
            },
            "disagreement_samples": [],
        }}},
    }


def _forged_pin() -> dict:
    """PoC1b: zero events, just a force_short_circuit pin."""
    return {
        "version": 2,
        "models": {"m": {"x:y": {
            "first_seen_at": _NOW_ISO,
            "last_seen_at": _NOW_ISO,
            "model_version": "",
            "policy_override": "force_short_circuit",
            "events": {},
            "disagreement_samples": [],
        }}},
    }


# ---------------------------------------------------------------------------
# Forgery is not honoured
# ---------------------------------------------------------------------------


def test_forged_counts_do_not_short_circuit(tmp_path):
    path = tmp_path / "sc.json"
    path.write_text(json.dumps(_forged_cells()), encoding="utf-8")
    sc = ModelScorecard(path)
    assert sc.should_short_circuit("x:y", "m") == Policy.LEARNING


def test_forged_force_short_circuit_pin_not_honoured(tmp_path):
    path = tmp_path / "sc.json"
    path.write_text(json.dumps(_forged_pin()), encoding="utf-8")
    sc = ModelScorecard(path)
    assert sc.should_short_circuit("x:y", "m") == Policy.LEARNING


def test_stamped_then_tampered_content_discarded(tmp_path):
    # A validly-stamped file whose cells are edited afterwards must
    # fail verification — the token covers the whole document.
    path = tmp_path / "sc.json"
    sc = ModelScorecard(path)
    sc.set_policy_override("x:y", "m", "force_fall_through")
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert integrity.extract_token(on_disk)  # honest write stamped it
    on_disk["models"]["m"]["x:y"]["policy_override"] = (
        "force_short_circuit"
    )
    path.write_text(json.dumps(on_disk), encoding="utf-8")
    assert ModelScorecard(path).should_short_circuit(
        "x:y", "m",
    ) == Policy.LEARNING


def test_unverified_content_never_restamped_by_write(tmp_path):
    # The laundering path: plant a forged file, then let an honest
    # writer record an event. The forged cells must NOT come back
    # stamped — the write starts from empty and quarantines the
    # forgery.
    path = tmp_path / "sc.json"
    path.write_text(json.dumps(_forged_cells()), encoding="utf-8")
    sc = ModelScorecard(path)
    sc.record_event("other:dc", "m2", EventType.JUDGE_REVIEW, "correct")

    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert "m" not in on_disk["models"]          # forged cells gone
    assert "m2" in on_disk["models"]             # honest event kept
    assert integrity.verify(
        on_disk, integrity.extract_token(on_disk),
    )
    quarantine = path.with_suffix(path.suffix + ".unverified")
    assert quarantine.exists()
    saved = json.loads(quarantine.read_text(encoding="utf-8"))
    assert "m" in saved["models"]                # audit trail kept


def test_read_only_paths_do_not_mutate_the_file(tmp_path):
    path = tmp_path / "sc.json"
    forged = json.dumps(_forged_cells())
    path.write_text(forged, encoding="utf-8")
    sc = ModelScorecard(path)
    assert sc.get_stats() == []                  # discarded in memory
    assert path.read_text(encoding="utf-8") == forged  # file untouched
    assert not path.with_suffix(
        path.suffix + ".unverified",
    ).exists()


# ---------------------------------------------------------------------------
# Honest flows keep working
# ---------------------------------------------------------------------------


def test_honest_write_read_roundtrip_verifies_and_trusts(tmp_path):
    path = tmp_path / "sc.json"
    sc = ModelScorecard(path)
    # 200 zero-failure observations: Wilson 95% UB ~= 0.019, safely
    # under the 0.05 ceiling (50 would sit at ~0.071 and fall through).
    for _ in range(200):
        sc.record_event(
            "x:y", "m", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
    # A fresh instance (fresh read) trusts the measured history.
    assert ModelScorecard(path).should_short_circuit(
        "x:y", "m",
    ) == Policy.SHORT_CIRCUIT
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert integrity.verify(on_disk, integrity.extract_token(on_disk))


def test_operator_pin_honoured_when_stamped(tmp_path):
    path = tmp_path / "sc.json"
    ModelScorecard(path).set_policy_override(
        "x:y", "m", "force_short_circuit",
    )
    assert ModelScorecard(path).should_short_circuit(
        "x:y", "m",
    ) == Policy.SHORT_CIRCUIT


def test_empty_or_absent_sidecar_is_fresh_not_suspect(tmp_path):
    path = tmp_path / "sc.json"
    assert ModelScorecard(path).should_short_circuit(
        "x:y", "m",
    ) == Policy.LEARNING
    path.write_text("", encoding="utf-8")
    assert ModelScorecard(path).get_stats() == []
    assert not path.with_suffix(path.suffix + ".unverified").exists()


# ---------------------------------------------------------------------------
# Key-unusable clamp
# ---------------------------------------------------------------------------


@pytest.fixture()
def _unusable_key(monkeypatch):
    monkeypatch.setattr(integrity, "_load_or_create_key", lambda: None)


def test_key_unusable_clamps_but_keeps_content(tmp_path, _unusable_key):
    path = tmp_path / "sc.json"
    path.write_text(json.dumps(_forged_cells()), encoding="utf-8")
    sc = ModelScorecard(path)
    # Content readable for introspection...
    stats = sc.get_stats()
    assert len(stats) == 1
    # ...but the trust surface clamps: no short-circuit.
    assert sc.should_short_circuit("x:y", "m") == Policy.LEARNING
    # No quarantine — this is an operator-side condition.
    assert not path.with_suffix(path.suffix + ".unverified").exists()


def test_key_unusable_pin_clamp_directions(tmp_path, _unusable_key):
    path = tmp_path / "sc.json"
    path.write_text(json.dumps(_forged_pin()), encoding="utf-8")
    # force_short_circuit not honoured...
    assert ModelScorecard(path).should_short_circuit(
        "x:y", "m",
    ) == Policy.LEARNING
    # ...but force_fall_through is (more analysis = safe direction).
    data = _forged_pin()
    data["models"]["m"]["x:y"]["policy_override"] = "force_fall_through"
    path.write_text(json.dumps(data), encoding="utf-8")
    assert ModelScorecard(path).should_short_circuit(
        "x:y", "m",
    ) == Policy.FALL_THROUGH


# ---------------------------------------------------------------------------
# Adopt: the deliberate operator path back
# ---------------------------------------------------------------------------


def test_adopt_restamps_pre_mac_history(tmp_path):
    path = tmp_path / "sc.json"
    path.write_text(json.dumps(_forged_cells(1000)), encoding="utf-8")
    sc = ModelScorecard(path)
    assert sc.get_stats() == []                  # demoted pre-adopt
    assert sc.adopt_unverified() is True
    sc2 = ModelScorecard(path)
    stats = sc2.get_stats()
    assert len(stats) == 1
    assert sc2.should_short_circuit("x:y", "m") == Policy.SHORT_CIRCUIT


def test_adopt_from_quarantine_file(tmp_path):
    path = tmp_path / "sc.json"
    path.write_text(json.dumps(_forged_cells(30)), encoding="utf-8")
    sc = ModelScorecard(path)
    # A write quarantines the unverified original...
    sc.record_event("a:b", "m2", EventType.JUDGE_REVIEW, "correct")
    quarantine = path.with_suffix(path.suffix + ".unverified")
    assert quarantine.exists()
    # ...and adopt (defaulting to the quarantine) restores it.
    assert sc.adopt_unverified() is True
    assert ModelScorecard(path).get_stat("x:y", "m") is not None


def test_adopt_migrates_v1_content(tmp_path):
    path = tmp_path / "sc.json"
    v1 = {
        "version": 1,
        "models": {"m": {"x:y": {
            "first_seen_at": _NOW_ISO,
            "last_seen_at": _NOW_ISO,
            "model_version": "", "policy_override": "auto",
            "events": {
                EventType.CHEAP_SHORT_CIRCUIT: {
                    "correct": 50, "incorrect": 1,
                },
            },
            "disagreement_samples": [],
        }}},
    }
    path.write_text(json.dumps(v1), encoding="utf-8")
    sc = ModelScorecard(path)
    assert sc.adopt_unverified() is True
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk["version"] == 2
    cheap = on_disk["models"]["m"]["x:y"]["events"][
        EventType.CHEAP_SHORT_CIRCUIT
    ]
    assert cheap == {_NOW_MONTH: {"correct": 50, "incorrect": 1}}


def test_adopt_refuses_without_usable_key(tmp_path, _unusable_key):
    path = tmp_path / "sc.json"
    path.write_text(json.dumps(_forged_cells(30)), encoding="utf-8")
    with pytest.raises(ValueError, match="no usable scorecard MAC key"):
        ModelScorecard(path).adopt_unverified()


def test_adopt_nothing_to_adopt(tmp_path):
    assert ModelScorecard(
        tmp_path / "sc.json",
    ).adopt_unverified() is False


# ---------------------------------------------------------------------------
# Key handling
# ---------------------------------------------------------------------------


def test_key_file_created_private(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert integrity.key_usable()
    key_path = tmp_path / "xdg" / "raptor" / "scorecard-mac.key"
    assert key_path.is_file()
    assert (key_path.stat().st_mode & 0o077) == 0


def test_symlinked_key_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    raptor_dir = tmp_path / "xdg" / "raptor"
    raptor_dir.mkdir(parents=True, mode=0o700)
    real = tmp_path / "elsewhere.key"
    real.write_bytes(b"k" * 32)
    (raptor_dir / "scorecard-mac.key").symlink_to(real)
    assert not integrity.key_usable()
    assert integrity.mint({"models": {}}) is None


def test_own_key_never_reuses_other_purpose_keys(tmp_path, monkeypatch):
    # Per-purpose key doctrine: the scorecard key path is its own
    # file, never rowmac.key or telemetry-mac.key.
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    p = integrity._key_path()
    assert p.name == "scorecard-mac.key"
    assert p.name not in ("rowmac.key", "telemetry-mac.key")
