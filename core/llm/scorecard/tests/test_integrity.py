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

import itertools
import json
import os

import pytest

from datetime import datetime, timezone

from core.llm.scorecard import integrity
from core.security import mac_key
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


def _quarantines(path):
    """All quarantine files for *path* (timestamped + legacy name)."""
    found = sorted(path.parent.glob(path.name + ".*.unverified"))
    legacy = path.with_suffix(path.suffix + ".unverified")
    if legacy.exists():
        found.append(legacy)
    return found


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
    quarantines = _quarantines(path)
    assert len(quarantines) == 1
    saved = json.loads(quarantines[0].read_text(encoding="utf-8"))
    assert "m" in saved["models"]                # audit trail kept


def test_read_only_paths_do_not_mutate_the_file(tmp_path):
    path = tmp_path / "sc.json"
    forged = json.dumps(_forged_cells())
    path.write_text(forged, encoding="utf-8")
    sc = ModelScorecard(path)
    assert sc.get_stats() == []                  # discarded in memory
    assert path.read_text(encoding="utf-8") == forged  # file untouched
    assert _quarantines(path) == []


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
    assert _quarantines(path) == []


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
    assert _quarantines(path) == []


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
    assert len(_quarantines(path)) == 1
    # ...and adopt (defaulting to the newest quarantine) restores it.
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


# ---------------------------------------------------------------------------
# Key loader: short-read tolerance
# ---------------------------------------------------------------------------


def test_chunked_key_read_loads_full_key(tmp_path, monkeypatch) -> None:
    """os.read may legally return fewer bytes than requested; chunked
    delivery must not land a healthy key in the wrong-length refusal
    (which would clamp the sidecar's trust surface for no reason)."""
    key_file = tmp_path / "scorecard-mac.key"
    data = os.urandom(32)
    key_file.write_bytes(data)
    key_file.chmod(0o600)
    real_read = os.read
    monkeypatch.setattr(os, "read", lambda fd, n: real_read(fd, min(n, 5)))
    assert integrity._read_existing_key(key_file) == data


def test_truncated_key_file_reads_exact_length(tmp_path, monkeypatch) -> None:
    # Two-direction guard: the loop reads to EOF, never pads — a torn
    # 10-byte key still fails the caller's length check (fail-closed).
    key_file = tmp_path / "scorecard-mac.key"
    key_file.write_bytes(os.urandom(10))
    key_file.chmod(0o600)
    real_read = os.read
    monkeypatch.setattr(os, "read", lambda fd, n: real_read(fd, min(n, 5)))
    got = integrity._read_existing_key(key_file)
    assert isinstance(got, bytes)
    assert len(got) == 10


# ---------------------------------------------------------------------------
# Key-creation race: the loser must tolerate the winner's write gap
# ---------------------------------------------------------------------------


@pytest.fixture()
def _race_warn_calls(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        integrity, "_warn_once_suspect_key",
        lambda *args: calls.append(args),
    )
    return calls


@pytest.fixture()
def _lose_creation_race(monkeypatch, tmp_path):
    """Make the key-create os.open lose the O_EXCL race."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    real_open = os.open

    def fake_open(path, flags, mode=0o777):
        if flags & os.O_EXCL:
            raise FileExistsError(path)
        return real_open(path, flags, mode)

    monkeypatch.setattr(os, "open", fake_open)
    monkeypatch.setattr(mac_key.time, "sleep", lambda s: None)


def test_race_loser_retries_through_empty_read(
        monkeypatch, _race_warn_calls, _lose_creation_race) -> None:
    """Between the winner's O_EXCL create and its write the key file
    exists with 0 bytes. The loser must keep polling through that
    transient shape and mint with the winner's full key — aborting on
    the first short read left the loser's sidecar write unstamped and
    flagged the operator's healthy key as suspect."""
    full_key = b"k" * 32
    reads = iter([None, b"", full_key])
    monkeypatch.setattr(
        integrity, "_read_existing_key", lambda path: next(reads),
    )

    assert integrity._load_or_create_key() == full_key
    assert _race_warn_calls == []


def test_persistent_wrong_length_warns_after_retries(
        monkeypatch, _race_warn_calls, _lose_creation_race) -> None:
    """A key file that STAYS short is genuinely suspect: the loop runs
    out of retries, warns once, and refuses (None)."""
    reads = itertools.chain([None], itertools.repeat(b"short"))
    monkeypatch.setattr(
        integrity, "_read_existing_key", lambda path: next(reads),
    )

    assert integrity._load_or_create_key() is None
    assert len(_race_warn_calls) == 1
    assert "wrong length" in _race_warn_calls[0][1]


def test_repeated_quarantines_preserve_each_other(tmp_path, monkeypatch):
    """Repeated tamper-then-rewrite cycles must not clobber earlier
    quarantine evidence — each cycle gets its own timestamped file,
    mirroring the ``.corrupt`` sibling. Pre-fix the fixed
    ``.unverified`` name left only the LAST forgery for the operator
    to inspect."""
    import itertools

    path = tmp_path / "sc.json"
    # Distinct second per call — two quarantines within the same
    # wall-clock second would share a name (same granularity
    # trade-off as the .corrupt sibling).
    ticks = itertools.count(1_000_000_001)

    import core.llm.scorecard.scorecard as sc_mod
    monkeypatch.setattr(sc_mod.time, "time", lambda: float(next(ticks)))

    # First tamper + honest write → first quarantine.
    path.write_text(json.dumps(_forged_cells()), encoding="utf-8")
    sc = ModelScorecard(path)
    sc.record_event("a:b", "m2", EventType.JUDGE_REVIEW, "correct")
    assert len(_quarantines(path)) == 1

    # Second tamper of the (now honest) sidecar + another write —
    # the first quarantine must survive.
    path.write_text(json.dumps(_forged_cells()), encoding="utf-8")
    sc2 = ModelScorecard(path)
    sc2.record_event("a:b", "m2", EventType.JUDGE_REVIEW, "correct")
    q = _quarantines(path)
    assert len(q) == 2
    for f in q:
        saved = json.loads(f.read_text(encoding="utf-8"))
        assert "m" in saved["models"]
