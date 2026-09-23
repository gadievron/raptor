"""Trust gating on the TOOL_EVIDENCE idempotency seen-set.

``claim_and_record_tool_evidence`` consults each cell's
``tool_evidence_finding_ids`` to keep re-imports idempotent. The ids
are deterministic (rule:file:line-derived) and pre-seedable, so a
same-user forger — exactly the threat the integrity module names —
could park a bad model's ``incorrect`` outcomes behind forged ids:

* under the key-unusable clamp the sidecar stays readable but
  unverifiable, and an unverified seen-set must never SUPPRESS a
  truth event (recording a possible duplicate is the safe direction,
  per the MAX_TOOL_EVIDENCE_SEEN_IDS rationale);
* ``adopt_unverified`` re-blesses operator-inspected calibration
  history, but the seen-set is claim state, not calibration history —
  and no CLI view renders it, so inspect-before-adopt cannot surface
  it. Adoption strips it.

Unverifiable ids stay VISIBLE in the file (introspection is the
clamp's whole point) — they are inert, never suppressing.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.llm.scorecard import integrity
from core.llm.scorecard.scorecard import ModelScorecard


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _forged_sidecar(path: Path) -> None:
    path.write_text(json.dumps({
        "version": 2,
        "models": {"cheap-model": {"agentic:rule-x": {
            "last_seen_at": _now(),
            "events": {},
            "tool_evidence_finding_ids": ["finding-123"],
        }}},
    }))


def _make_key_unusable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    xdg = tmp_path / "xdg-clamped"
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg))
    key_dir = xdg / "raptor"
    key_dir.mkdir(parents=True)
    key = key_dir / "scorecard-mac.key"
    key.write_bytes(b"k" * 32)
    key.chmod(0o644)
    assert not integrity.key_usable()


def test_unverified_seen_set_never_suppresses_under_clamp(
    tmp_path, monkeypatch,
):
    _make_key_unusable(tmp_path, monkeypatch)
    path = tmp_path / "sc.json"
    _forged_sidecar(path)
    sc = ModelScorecard(path)
    recorded = sc.claim_and_record_tool_evidence(
        "agentic:rule-x", "cheap-model", "finding-123", "incorrect",
    )
    assert recorded is True, (
        "an unverifiable seen-set must be inert — the truth event "
        "records"
    )
    raw = json.loads(path.read_text())
    cell = raw["models"]["cheap-model"]["agentic:rule-x"]
    buckets = cell["events"]["tool_evidence"]
    assert sum(b["incorrect"] for b in buckets.values()) == 1
    # The forged ids stay visible for introspection (not scrubbed by
    # a read), and the claimed id is tracked exactly once.
    assert cell["tool_evidence_finding_ids"].count("finding-123") == 1


def test_usable_key_control_quarantines_forged_bytes(tmp_path):
    # Control: under a usable key the forged (unstamped) bytes are
    # quarantined at read, so the claim records against fresh state.
    path = tmp_path / "sc.json"
    _forged_sidecar(path)
    sc = ModelScorecard(path)
    assert sc.claim_and_record_tool_evidence(
        "agentic:rule-x", "cheap-model", "finding-123", "incorrect",
    ) is True


def test_verified_seen_set_still_suppresses(tmp_path):
    # The idempotency contract is untouched for trusted content: a
    # claim recorded by this install suppresses its own re-import.
    path = tmp_path / "sc.json"
    sc = ModelScorecard(path)
    assert sc.claim_and_record_tool_evidence(
        "agentic:rule-x", "m", "finding-1", "incorrect",
    ) is True
    assert sc.claim_and_record_tool_evidence(
        "agentic:rule-x", "m", "finding-1", "incorrect",
    ) is False


def test_adopt_strips_seen_set_claim_state(tmp_path):
    path = tmp_path / "sc.json"
    _forged_sidecar(path)
    sc = ModelScorecard(path)
    assert sc.adopt_unverified() is True
    raw = json.loads(path.read_text())
    cell = raw["models"]["cheap-model"]["agentic:rule-x"]
    assert "tool_evidence_finding_ids" not in cell
    # The forged claim cannot survive adoption into standing
    # suppression authority: post-adopt (usable key, trusted read)
    # the truth event records.
    assert sc.claim_and_record_tool_evidence(
        "agentic:rule-x", "cheap-model", "finding-123", "incorrect",
    ) is True


def test_junk_seen_set_shape_is_inert(tmp_path, monkeypatch):
    _make_key_unusable(tmp_path, monkeypatch)
    path = tmp_path / "sc.json"
    path.write_text(json.dumps({
        "version": 2,
        "models": {"m": {"dc": {
            "last_seen_at": _now(),
            "events": {},
            # Junk shape: substring membership on a str must not
            # suppress, and append must not crash.
            "tool_evidence_finding_ids": "finding-123",
        }}},
    }))
    sc = ModelScorecard(path)
    assert sc.claim_and_record_tool_evidence(
        "dc", "m", "finding-123", "incorrect",
    ) is True


class TestUnverifiedStatsNeverGrantReliabilityWeight:
    """Adversarial-route closure: the calibrated-merge reliability
    weight consumes ``get_stat`` as AUTHORITY (it steers which model's
    verdict wins an audit panel merge), but the key-unusable clamp
    keeps unverified content readable through exactly that surface —
    a forged 100000-correct cell earned a ~0.99 weight. Stats rows now
    carry the read's integrity verdict, and the weight treats an
    untrusted row as uninformative (condemn-toward-abstain: 0.5 moves
    nothing)."""

    def _forged_reliability_sidecar(self, path: Path) -> None:
        path.write_text(json.dumps({
            "version": 2,
            "models": {"bad-model": {"audit:CWE-89": {
                "last_seen_at": _now(),
                "events": {"tool_evidence": {
                    "2026-09": {"correct": 100000, "incorrect": 0},
                }},
            }}},
        }))

    def test_stats_rows_carry_trust_verdict(self, tmp_path, monkeypatch):
        _make_key_unusable(tmp_path, monkeypatch)
        path = tmp_path / "sc.json"
        self._forged_reliability_sidecar(path)
        stats = ModelScorecard(path).get_stats()
        assert stats and all(s.trusted is False for s in stats)

    def test_trusted_read_marks_rows_trusted(self, tmp_path):
        path = tmp_path / "sc.json"
        sc = ModelScorecard(path)
        sc.record_event("dc", "m", "cheap_short_circuit", "correct")
        stats = sc.get_stats()
        assert stats and all(s.trusted is True for s in stats)

    def test_calibrated_weight_uninformative_under_clamp(
        self, tmp_path, monkeypatch,
    ):
        from core.audit.calibrated_merge import model_reliability

        _make_key_unusable(tmp_path, monkeypatch)
        path = tmp_path / "sc.json"
        self._forged_reliability_sidecar(path)
        sc = ModelScorecard(path)
        assert model_reliability(sc, "audit:CWE-89", "bad-model") is None

    def test_calibrated_weight_still_earned_when_trusted(self, tmp_path):
        from core.audit.calibrated_merge import model_reliability

        path = tmp_path / "sc.json"
        sc = ModelScorecard(path)
        for _ in range(8):
            sc.claim_and_record_tool_evidence(
                "audit:CWE-89", "m", f"f-{_}", "correct",
            )
        weight = model_reliability(sc, "audit:CWE-89", "m")
        assert weight is not None and weight > 0.5
