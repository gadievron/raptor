"""Malformed-but-readable sidecar shapes on the read/trust surfaces.

The write path normalises defensively (``_ensure_cell``,
``_migrate_events_v1_to_v2``) and the integrity layer's design is
"verification failure is a demote path, never an error" — so a
sidecar whose JSON parses but whose inner shapes are junk (a string
where a cell dict belongs, a cell missing ``events``) must degrade to
a structured refusal on every read/trust surface: skipped rows,
``LEARNING`` policy, ``None`` cell reads. It must never crash, and
``adopt_unverified`` must never stamp such shapes into trusted
content (its documented contract is ``ValueError`` on bad input).

Shapes under test mirror the two regimes a forger can reach:

* trusted (operator-adopted / freshly stamped) content that carries a
  dict cell missing newer keys — tolerated and normalised;
* the key-unusable clamp, where the file stays readable for
  introspection and its bytes are attacker-choosable — junk shapes
  included.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.llm.scorecard import integrity
from core.llm.scorecard.prefilter import prefilter_decision
from core.llm.scorecard.scorecard import ModelScorecard, Policy


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _write_sidecar(path: Path, models: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": 2, "models": models}))


def _make_key_unusable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A group-readable key file is refused, clamping the trust
    surface while content stays readable."""
    xdg = tmp_path / "xdg-clamped"
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg))
    key_dir = xdg / "raptor"
    key_dir.mkdir(parents=True)
    key = key_dir / "scorecard-mac.key"
    key.write_bytes(b"k" * 32)
    key.chmod(0o644)
    assert not integrity.key_usable()


# ---------------------------------------------------------------------------
# Trusted path: adopted cell missing "events"
# ---------------------------------------------------------------------------


def test_adopt_normalises_dict_cell_missing_events(tmp_path):
    path = tmp_path / "sc.json"
    _write_sidecar(path, {"m1": {"dc1": {"last_seen_at": _now()}}})
    sc = ModelScorecard(path)
    assert sc.adopt_unverified() is True
    # Both read surfaces must work on the adopted (TRUSTED) content.
    stats = sc.get_stats()
    assert [(s.model, s.decision_class) for s in stats] == [("m1", "dc1")]
    assert sc.should_short_circuit("dc1", "m1") == Policy.LEARNING


# ---------------------------------------------------------------------------
# adopt_unverified: the promised ValueError on junk shapes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "models",
    [
        "junk",                                  # models itself junk
        {"m2": "junk"},                          # per-model value junk
        {"m2": {"dc": "junk"}},                  # cell junk
        {"m2": {"dc": ["not", "a", "cell"]}},    # cell junk (list)
    ],
)
def test_adopt_rejects_junk_shapes_with_valueerror(tmp_path, models):
    path = tmp_path / "sc.json"
    _write_sidecar(path, models)
    before = path.read_text()
    sc = ModelScorecard(path)
    with pytest.raises(ValueError):
        sc.adopt_unverified()
    # Nothing adopted, nothing stamped: the junk was never laundered
    # into trusted content (and the auto-GC inside the locked write
    # exit never ran over it).
    assert path.read_text() == before


# ---------------------------------------------------------------------------
# Key-unusable clamp: junk shapes stay readable, never crash, never trust
# ---------------------------------------------------------------------------


def test_clamped_reads_degrade_on_junk_models_value(tmp_path, monkeypatch):
    _make_key_unusable(tmp_path, monkeypatch)
    path = tmp_path / "sc.json"
    _write_sidecar(path, {"m1": "junk", "m2": {"dc": {"last_seen_at": _now()}}})
    sc = ModelScorecard(path)

    # get_stats: junk model skipped (structured refusal), dict cell kept.
    stats = sc.get_stats()
    assert [(s.model, s.decision_class) for s in stats] == [("m2", "dc")]

    # Trust query on the junk cell: LEARNING, never a crash and never
    # a grant.
    assert sc.should_short_circuit("dc", "m1") == Policy.LEARNING
    assert sc.get_stat("dc", "m1") is None

    # Write path: the defensive normalisation replaces the junk value.
    sc.record_event("dc", "m1", "cheap_short_circuit", "correct")
    raw = json.loads(path.read_text())
    assert isinstance(raw["models"]["m1"], dict)


def test_clamped_reads_degrade_on_missing_events_cell(tmp_path, monkeypatch):
    _make_key_unusable(tmp_path, monkeypatch)
    path = tmp_path / "sc.json"
    _write_sidecar(path, {"m1": {"dc1": {"last_seen_at": _now()}}})
    sc = ModelScorecard(path)
    stats = sc.get_stats()
    assert len(stats) == 1
    assert stats[0].events["cheap_short_circuit"].total() == 0
    assert sc.should_short_circuit("dc1", "m1") == Policy.LEARNING


def test_clamped_reads_degrade_on_junk_event_buckets(tmp_path, monkeypatch):
    _make_key_unusable(tmp_path, monkeypatch)
    path = tmp_path / "sc.json"
    _write_sidecar(path, {
        "m1": {"dc1": {
            "last_seen_at": _now(),
            "events": {"cheap_short_circuit": "junk"},
        }},
    })
    sc = ModelScorecard(path)
    stats = sc.get_stats()
    assert stats[0].events["cheap_short_circuit"].total() == 0
    assert sc.should_short_circuit("dc1", "m1") == Policy.LEARNING


def test_clamped_junk_events_value_never_crashes(tmp_path, monkeypatch):
    _make_key_unusable(tmp_path, monkeypatch)
    path = tmp_path / "sc.json"
    _write_sidecar(path, {"m1": {"dc1": {
        "last_seen_at": _now(), "events": "junk",
        "disagreement_samples": "junk",
    }}})
    sc = ModelScorecard(path)
    stats = sc.get_stats()
    assert stats[0].events["cheap_short_circuit"].total() == 0
    assert stats[0].disagreement_samples == []
    assert sc.should_short_circuit("dc1", "m1") == Policy.LEARNING


# ---------------------------------------------------------------------------
# Consumer propagation: the default-path prefilter query
# ---------------------------------------------------------------------------


def test_prefilter_decision_on_malformed_sidecar(tmp_path, monkeypatch):
    _make_key_unusable(tmp_path, monkeypatch)
    path = tmp_path / "sc.json"
    _write_sidecar(path, {"m1": "junk"})
    sc = ModelScorecard(path)
    decision = prefilter_decision(
        sc, decision_class="dc", model="m1", cheap_says_fp=True,
    )
    assert decision.short_circuit is False
    assert decision.policy == Policy.LEARNING


# ---------------------------------------------------------------------------
# CLI read subcommands: every view degrades, none tracebacks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["list"],
        ["summary"],
        ["recommend", "dc"],
        ["compare", "m1", "m2"],
        ["chain-closure"],
    ],
)
def test_cli_read_subcommands_on_malformed_sidecar(
    tmp_path, monkeypatch, capsys, argv,
):
    from core.llm.scorecard.cli import main

    _make_key_unusable(tmp_path, monkeypatch)
    path = tmp_path / "sc.json"
    _write_sidecar(path, {
        "m1": "junk",
        "m2": {"dc": {"last_seen_at": _now()}},
    })
    rc = main(["--path", str(path), *argv])
    assert rc == 0
    capsys.readouterr()


# ---------------------------------------------------------------------------
# reset / auto-GC walks tolerate junk siblings
# ---------------------------------------------------------------------------


def test_reset_all_with_junk_by_dc(tmp_path, monkeypatch):
    _make_key_unusable(tmp_path, monkeypatch)
    path = tmp_path / "sc.json"
    _write_sidecar(path, {"m1": "junk", "m2": {"dc": {"last_seen_at": _now()}}})
    sc = ModelScorecard(path)
    # A junk by_dc holds no countable cells; only the real one deletes.
    assert sc.reset(all_=True) == 1


def test_auto_gc_walk_tolerates_junk_siblings(tmp_path, monkeypatch):
    _make_key_unusable(tmp_path, monkeypatch)
    path = tmp_path / "sc.json"
    _write_sidecar(path, {
        "m1": "junk",
        "m3": {"dc": "junk-cell"},
        "m2": {"dc": {"last_seen_at": _now(), "events": "junk"}},
    })
    # Force the GC walk to run on the next write.
    sc = ModelScorecard(path, auto_gc_after_days=1,
                        auto_gc_interval_seconds=0)
    # The locked write's __exit__ runs auto-GC over every model —
    # junk siblings must not crash it.
    sc.record_event("dc", "good-model", "cheap_short_circuit", "correct")
    raw = json.loads(path.read_text())
    assert "good-model" in raw["models"]
