"""Tests for the engagement supervisor (``core.engagement.supervise``).

Fixture discipline mirrors the governor battery: ELF install trees
are crafted in-test (never a host compiler), the sandboxed build-id
probe is stubbed autouse, the session registry is pointed at a
scratch directory, and the per-artifact chain is a recording stub —
the chain's own behavior is the chain battery's subject. The code
pin is stubbed deterministic so drift is a test decision, never an
artifact of a busy working tree.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Any

import pytest

from core.binary import elf as elf_mod
from core.engagement import chain_elf
from core.engagement import governor as gov
from core.engagement import ledger as ledger_mod
from core.engagement import supervise as sup
from core.json import load_json, save_json
from core.project import sessions

_PIN = {"base_sha": "a" * 40, "dirty": False,
        "diff_sha256": None, "models_sha256": "m" * 64}

# The real pin builder, grabbed before the autouse fixture stubs the
# module attribute — the carry-through tests exercise the genuine one.
_REAL_CODE_SNAPSHOT = sup.code_snapshot


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch, tmp_path):
    monkeypatch.setattr(elf_mod, "_read_build_id",
                        lambda p: (None, None))
    monkeypatch.setattr(sessions, "SESSIONS_DIR",
                        tmp_path / "sessions.d")
    monkeypatch.setattr(sup, "code_snapshot", lambda: dict(_PIN))
    # The host may or may not run tests under a capped subagent
    # shell — pin the wall bound off unless a test opts in.
    import core.run.supervisor as run_supervisor
    monkeypatch.setattr(run_supervisor, "supervisor_wall_bound",
                        lambda: None)


# ── fixture builders ─────────────────────────────────────────────────

def _write_elf(path: Path) -> None:
    path.write_bytes(
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
        + struct.pack("<HHIQQQIHHHHHH",
                      3, 0x3E, 1, 0, 0, 0, 0, 64, 0, 0, 64, 0, 0)
        + path.name.encode())


def _build(tmp_path: Path,
           names: tuple[str, ...] = ("alpha", "beta")
           ) -> tuple[Path, dict[str, Any]]:
    target = tmp_path / "install"
    target.mkdir(exist_ok=True)
    for n in names:
        _write_elf(target / n)
    out_dir = tmp_path / "out"
    doc = ledger_mod.build_ledger(target, out_dir)
    return out_dir, doc


class _ChainStub:
    """Recording chain stub with a per-call rc script."""

    def __init__(self, monkeypatch, *rcs: int,
                 default: int = chain_elf.RC_NOTHING):
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._rcs = list(rcs)
        self._default = default
        monkeypatch.setattr(chain_elf, "run_chain", self)

    def __call__(self, output_dir: Any, artifact_id: str,
                 **kwargs: Any) -> int:
        self.calls.append((artifact_id, kwargs))
        return self._rcs.pop(0) if self._rcs else self._default


def _row(out: Path, aid: str) -> dict[str, Any]:
    doc = ledger_mod.load_ledger(out)
    return next(r for r in doc["rows"] if r["artifact_id"] == aid)


def _residual_kinds(out: Path) -> list[str]:
    doc = ledger_mod.load_ledger(out)
    return [r.get("kind") for r in doc.get("residuals") or []]


# ── usage contract (Q5) ──────────────────────────────────────────────

def test_missing_ledger_is_usage(tmp_path):
    assert sup.supervise(tmp_path) == sup.RC_USAGE


def test_relaunch_without_resume_is_usage(tmp_path, monkeypatch):
    out, _ = _build(tmp_path)
    _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    assert sup.supervise(out, uncapped=True) == sup.RC_NOTHING
    assert sup.supervise(out, uncapped=True) == sup.RC_USAGE


def test_resume_without_launch_is_usage(tmp_path):
    out, _ = _build(tmp_path)
    assert sup.supervise(out, resume=True) == sup.RC_USAGE


# ── spend gate (DF: silent uncapped launches) ────────────────────────

def test_bare_llm_launch_refuses_uncapped_spend(
        tmp_path, monkeypatch, capsys):
    """A fresh LLM-capable launch with no budget and no --uncapped
    never starts: uncapped engagement spend is an operator decision,
    not a default."""
    out, _ = _build(tmp_path)
    stub = _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    assert sup.supervise(out) == sup.RC_USAGE
    assert sup.load_state(out) is None, "gate must refuse pre-state"
    assert not stub.calls, "no chain work before the spend decision"
    msg = capsys.readouterr().out
    assert "uncapped" in msg
    assert "--max-cost" in msg and "--envelope" in msg
    assert "--uncapped" in msg


def test_budgeted_launch_passes_the_gate(tmp_path, monkeypatch):
    out, _ = _build(tmp_path)
    _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    assert sup.supervise(out, max_cost=1.0) == sup.RC_NOTHING


def test_uncapped_launch_persists_the_choice(tmp_path, monkeypatch):
    out, _ = _build(tmp_path)
    _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    assert sup.supervise(out, uncapped=True) == sup.RC_NOTHING
    assert sup.load_state(out).get("uncapped") is True
    assert "uncapped_launch" in _residual_kinds(out)
    # The interim report distinguishes a chosen uncapped run from an
    # accidental one.
    report = sup.write_interim_report(out, trigger="test")
    assert "uncapped (operator choice)" in report.read_text()


def test_uncapped_contradicts_budget_flags(tmp_path, monkeypatch):
    out, _ = _build(tmp_path)
    stub = _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    assert sup.supervise(out, uncapped=True,
                         max_cost=1.0) == sup.RC_USAGE
    assert sup.supervise(out, uncapped=True,
                         envelope_usd=5.0) == sup.RC_USAGE
    assert sup.load_state(out) is None
    assert not stub.calls


def test_mechanical_only_launch_is_exempt_from_the_gate(
        tmp_path, monkeypatch):
    """Mechanical-only dispatches no LLM stages — there is no spend
    to gate at that launch."""
    out, _ = _build(tmp_path)
    _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    assert sup.supervise(out,
                         mechanical_only=True) == sup.RC_NOTHING


def test_undecided_resume_warns_but_proceeds(
        tmp_path, monkeypatch, capsys):
    """A ledger with no budget and no recorded uncapped choice (a
    pre-gate launch, or a mechanical-only one) must keep resuming —
    refusing would strand live engagements — but never silently."""
    out, _ = _build(tmp_path)
    _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    sup.supervise(out, mechanical_only=True)
    capsys.readouterr()
    assert sup.supervise(out, resume=True) == sup.RC_NOTHING
    msg = capsys.readouterr().out
    assert "uncapped" in msg
    assert "--uncapped" in msg


def test_resume_uncapped_records_choice_and_silences_the_notice(
        tmp_path, monkeypatch, capsys):
    out, _ = _build(tmp_path)
    _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    sup.supervise(out, mechanical_only=True)
    assert sup.supervise(out, resume=True,
                         uncapped=True) == sup.RC_NOTHING
    assert sup.load_state(out).get("uncapped") is True
    assert "uncapped_recorded" in _residual_kinds(out)
    capsys.readouterr()
    assert sup.supervise(out, resume=True) == sup.RC_NOTHING
    assert "LLM spend is uncapped" not in capsys.readouterr().out


def test_resume_uncapped_refuses_when_a_budget_persists(
        tmp_path, monkeypatch):
    out, _ = _build(tmp_path)
    _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    sup.supervise(out, max_cost=1.0)
    assert sup.supervise(out, resume=True,
                         uncapped=True) == sup.RC_USAGE
    assert sup.load_state(out).get("uncapped") is None


def test_resume_is_idempotent_and_cron_safe(tmp_path, monkeypatch):
    """A complete engagement reports nothing-to-do forever — no
    park, no failure, no state churn beyond the report refresh."""
    out, _ = _build(tmp_path)
    stub = _ChainStub(monkeypatch,
                      chain_elf.RC_OK, chain_elf.RC_OK)
    assert sup.supervise(out, uncapped=True) == sup.RC_OK
    for _ in range(3):
        assert sup.supervise(out, resume=True) == sup.RC_NOTHING
    assert not sup.marker_path(out).exists()
    assert sup.interim_report_path(out).is_file()
    assert stub.calls  # the loop really attempted rows


def test_launch_records_code_pin_and_segments(tmp_path, monkeypatch):
    out, _ = _build(tmp_path)
    _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    sup.supervise(out, uncapped=True)
    state = sup.load_state(out)
    assert state["code_pin"] == _PIN
    assert state["segments"] >= 2
    assert state["launched_at"]


def test_code_snapshot_carries_dirt_accounting(monkeypatch):
    """RECORD HONESTY: when the framework snapshot states the dirt
    composition, status fingerprint, and null-diff reason, the pin
    carries them through — a reader of engagement-state.json can then
    verify WHAT was dirty and why the diff hash is null, instead of
    facing a bare ``dirty: true, diff_sha256: null`` claim."""
    import core.run.provenance as prov
    snap = {"base_sha": "b" * 40, "dirty": True, "diff_sha256": None,
            "version": "3.0.0-test",
            "dirty_reason": "untracked_only",
            "status_sha256": "d" * 64,
            "diff_sha256_reason": "untracked_only"}
    monkeypatch.setattr(prov, "source_control_snapshot",
                        lambda: dict(snap))
    monkeypatch.setattr(sup, "_models_config_hash", lambda: "m" * 64)
    pin = _REAL_CODE_SNAPSHOT()
    assert pin["dirty"] is True
    assert pin["diff_sha256"] is None
    assert pin["dirty_reason"] == "untracked_only"
    assert pin["status_sha256"] == "d" * 64
    assert pin["diff_sha256_reason"] == "untracked_only"
    assert pin["models_sha256"] == "m" * 64


def test_code_snapshot_clean_tree_pin_shape_unchanged(monkeypatch):
    """A clean tree makes no dirt claim — the pin keeps exactly the
    legacy four-field shape (no additive keys to drift against)."""
    import core.run.provenance as prov
    snap = {"base_sha": "b" * 40, "dirty": False, "diff_sha256": None,
            "version": "3.0.0-test"}
    monkeypatch.setattr(prov, "source_control_snapshot",
                        lambda: dict(snap))
    monkeypatch.setattr(sup, "_models_config_hash", lambda: "m" * 64)
    pin = _REAL_CODE_SNAPSHOT()
    assert set(pin) == {"base_sha", "dirty", "diff_sha256",
                        "models_sha256"}


def test_pin_drift_ignores_additive_dirt_fields():
    """A legacy pin (recorded before the dirt-accounting fields) must
    not read as drifted against a current pin that carries them —
    additive fields are record honesty, never drift triggers (a
    status fingerprint over untracked scratch churn would otherwise
    park the engagement on every unrelated scratch file)."""
    legacy = {"base_sha": "a" * 40, "dirty": True,
              "diff_sha256": None, "models_sha256": "m" * 64}
    current = dict(legacy, dirty_reason="untracked_only",
                   status_sha256="e" * 64,
                   diff_sha256_reason="untracked_only")
    assert sup.pin_drift(legacy, current) == []


def test_interim_report_shows_dirt_reason(tmp_path, monkeypatch):
    """The report's code-pin line surfaces the dirt composition, so a
    dirty pin is never an unexplained ``dirty=True``."""
    pin = dict(_PIN, dirty=True, dirty_reason="untracked_only")
    monkeypatch.setattr(sup, "code_snapshot", lambda: dict(pin))
    out, _ = _build(tmp_path)
    _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    sup.supervise(out, uncapped=True)
    report = sup.interim_report_path(out).read_text()
    assert "untracked_only" in report


# ── failure → deaths → sticky artifact park (M4/M5) ──────────────────

def test_chain_failure_returns_failed_and_records_death(
        tmp_path, monkeypatch):
    out, doc = _build(tmp_path, names=("alpha",))
    _ChainStub(monkeypatch, default=chain_elf.RC_FAILED)
    assert sup.supervise(out, uncapped=True) == sup.RC_FAILED
    aid = doc["rows"][0]["artifact_id"]
    res = _row(out, aid)["reservation"]
    assert res["deaths"] == 1
    assert res["state"] == "reserved"  # never reconciled


def test_death_cap_parks_with_operator_park_id(tmp_path, monkeypatch):
    out, doc = _build(tmp_path, names=("alpha",))
    aid = doc["rows"][0]["artifact_id"]
    _ChainStub(monkeypatch, default=chain_elf.RC_FAILED)
    assert sup.supervise(out, uncapped=True) == sup.RC_FAILED
    for _ in range(gov.PARK_AFTER_DEATHS - 1):
        sup.supervise(out, resume=True)
    # Row parked at the cap; the registry carries an operator target.
    status = _row(out, aid)["status"]
    assert status["state"] == "parked"
    parks = sup.unacknowledged_parks(out, scope="artifact")
    assert len(parks) == 1
    assert parks[0]["kind"] == "segment_deaths"
    assert parks[0]["artifact_id"] == aid
    assert parks[0]["park_id"].startswith("park-")
    assert sup.marker_path(out).is_file()
    # A later tick attempts nothing and reports the waiting park.
    assert sup.supervise(out, resume=True) == sup.RC_PARKED


def test_acknowledge_artifact_park_requeues_and_resets_deaths(
        tmp_path, monkeypatch):
    out, doc = _build(tmp_path, names=("alpha",))
    aid = doc["rows"][0]["artifact_id"]
    _ChainStub(monkeypatch, default=chain_elf.RC_FAILED)
    for _ in range(gov.PARK_AFTER_DEATHS):
        sup.supervise(out, uncapped=True) if not sup.load_state(out) \
            else sup.supervise(out, resume=True)
    park_id = sup.unacknowledged_parks(out)[0]["park_id"]
    stub = _ChainStub(monkeypatch, default=chain_elf.RC_OK)
    rc = sup.supervise(out, resume=True, acknowledge=park_id)
    assert rc == sup.RC_OK
    assert stub.calls  # the row ran again
    assert _row(out, aid)["reservation"]["deaths"] == 0
    assert not sup.unacknowledged_parks(out)
    assert not sup.marker_path(out).exists()


def test_acknowledge_resets_deaths_before_any_rerun(
        tmp_path, monkeypatch):
    # The reset must land at acknowledgment time, not as a side effect
    # of the next clean reconcile — otherwise the first post-park
    # failure re-parks instantly instead of granting fresh attempts.
    out, doc = _build(tmp_path, names=("alpha",))
    aid = doc["rows"][0]["artifact_id"]
    _ChainStub(monkeypatch, default=chain_elf.RC_FAILED)
    for _ in range(gov.PARK_AFTER_DEATHS):
        sup.supervise(out, uncapped=True) if not sup.load_state(out) \
            else sup.supervise(out, resume=True)
    park_id = sup.unacknowledged_parks(out)[0]["park_id"]
    assert _row(out, aid)["reservation"]["deaths"] \
        == gov.PARK_AFTER_DEATHS
    ok, _msg = sup.acknowledge_park(out, park_id)
    assert ok
    assert _row(out, aid)["reservation"]["deaths"] == 0


def test_acknowledge_unknown_park_is_usage(tmp_path, monkeypatch):
    out, _ = _build(tmp_path)
    _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    sup.supervise(out, uncapped=True)
    rc = sup.supervise(out, resume=True, acknowledge="park-bogus00")
    assert rc == sup.RC_USAGE


# ── code drift (M6) ──────────────────────────────────────────────────

def test_code_drift_parks_sticky(tmp_path, monkeypatch):
    out, _ = _build(tmp_path)
    stub = _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    sup.supervise(out, uncapped=True)
    n_launch_calls = len(stub.calls)
    moved = dict(_PIN, base_sha="b" * 40, dirty=True)
    monkeypatch.setattr(sup, "code_snapshot", lambda: moved)
    assert sup.supervise(out, resume=True) == sup.RC_PARKED
    assert len(stub.calls) == n_launch_calls  # parked pre-loop
    parks = sup.unacknowledged_parks(out, scope="engagement")
    assert len(parks) == 1
    assert parks[0]["kind"] == "code_drift"
    assert "code moved under the engagement" in parks[0]["reason"]
    # Sticky: a plain resume stays parked and does not double-mint.
    assert sup.supervise(out, resume=True) == sup.RC_PARKED
    assert len(sup.unacknowledged_parks(out, scope="engagement")) == 1
    assert sup.marker_path(out).is_file()


def test_accept_code_drift_resumes_and_records_acceptance(
        tmp_path, monkeypatch):
    out, _ = _build(tmp_path)
    _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    sup.supervise(out, uncapped=True)
    moved = dict(_PIN, base_sha="b" * 40)
    monkeypatch.setattr(sup, "code_snapshot", lambda: moved)
    sup.supervise(out, resume=True)  # parks
    rc = sup.supervise(out, resume=True, accept_code_drift=True)
    assert rc == sup.RC_NOTHING
    state = sup.load_state(out)
    assert state["code_pin"] == moved  # pin refreshed
    acceptances = state["code_drift_acceptances"]
    assert acceptances and "base_sha" in acceptances[0]["fields"]
    assert "code_drift_accepted" in _residual_kinds(out)
    # The consent flag acknowledged the code-drift park.
    assert not sup.unacknowledged_parks(out)
    assert not sup.marker_path(out).exists()
    # And the NEXT plain resume runs under the refreshed pin.
    assert sup.supervise(out, resume=True) == sup.RC_NOTHING


def test_models_hash_alone_is_drift(tmp_path, monkeypatch):
    out, _ = _build(tmp_path)
    _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    sup.supervise(out, uncapped=True)
    monkeypatch.setattr(
        sup, "code_snapshot",
        lambda: dict(_PIN, models_sha256="n" * 64))
    assert sup.supervise(out, resume=True) == sup.RC_PARKED


def test_unverifiable_pin_records_residual_not_drift(
        tmp_path, monkeypatch):
    """base_sha=None at launch AND resume is agreement (detection
    degrades to the models hash), flagged once at pin time."""
    blind = {"base_sha": None, "dirty": None, "diff_sha256": None,
             "models_sha256": "m" * 64}
    monkeypatch.setattr(sup, "code_snapshot", lambda: dict(blind))
    out, _ = _build(tmp_path)
    _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    assert sup.supervise(out, uncapped=True) == sup.RC_NOTHING
    assert "code_pin_unverifiable" in _residual_kinds(out)
    assert sup.supervise(out, resume=True) == sup.RC_NOTHING


# ── feasibility (S16) + envelope exhaustion ──────────────────────────

def test_unattended_feasibility_conflict_parks_pre_spend(
        tmp_path, monkeypatch):
    out, _ = _build(tmp_path)
    stub = _ChainStub(monkeypatch, default=chain_elf.RC_OK)
    rc = sup.supervise(out, envelope_usd=0.01)
    assert rc == sup.RC_PARKED
    assert not stub.calls  # parked BEFORE any segment spend
    parks = sup.unacknowledged_parks(out, scope="engagement")
    assert parks and parks[0]["kind"] == "feasibility_conflict"


def test_acknowledged_feasibility_then_exhaustion_parks_again(
        tmp_path, monkeypatch):
    """Owning the feasibility conflict does not disarm the envelope:
    when every remaining reservation is refused over it, the
    engagement re-parks pre-spend instead of grinding refusals on
    every cron tick."""
    out, _ = _build(tmp_path)
    stub = _ChainStub(monkeypatch, default=chain_elf.RC_OK)
    sup.supervise(out, envelope_usd=0.01)
    park_id = sup.unacknowledged_parks(out)[0]["park_id"]
    rc = sup.supervise(out, resume=True, acknowledge=park_id,
                       envelope_usd=0.01)
    assert rc == sup.RC_PARKED
    assert not stub.calls  # reservations refused — no chain spend
    parks = sup.unacknowledged_parks(out, scope="engagement")
    assert parks and parks[0]["kind"] == "envelope_exhausted"
    assert "reservation_refused" in _residual_kinds(out)


# ── drain citizenship + wall bound ───────────────────────────────────

def _register_session(monkeypatch):
    monkeypatch.setattr(sessions, "_comm",
                        lambda pid: "claude" if pid == os.getpid()
                        else None)
    sessions.record_session("engsup", pid=os.getpid())


def test_drain_request_pauses_at_the_boundary(tmp_path, monkeypatch):
    out, _ = _build(tmp_path)
    stub = _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    sup.supervise(out, uncapped=True)
    n = len(stub.calls)
    _register_session(monkeypatch)
    assert sessions.ledger_record_drain_request(out, pid=os.getpid())
    assert sup.supervise(out, resume=True) == sup.RC_DRAINED
    assert len(stub.calls) == n  # paused before any segment
    # Honoring cleared the request — the next tick resumes normally.
    assert sessions.ledger_drain_requests(out) == []
    assert sup.load_state(out)["last_pause"]["kind"] == "drain_honored"
    assert "drain_honored" in _residual_kinds(out)
    assert sup.supervise(out, resume=True) == sup.RC_NOTHING


def test_wall_bound_pauses_resumable(tmp_path, monkeypatch):
    out, _ = _build(tmp_path)
    stub = _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    sup.supervise(out, uncapped=True)
    n = len(stub.calls)
    import core.run.supervisor as run_supervisor
    monkeypatch.setattr(
        run_supervisor, "supervisor_wall_bound",
        lambda: run_supervisor.SupervisorBound(bound_s=0, cap_s=300))
    assert sup.supervise(out, resume=True) == sup.RC_DRAINED
    assert len(stub.calls) == n
    assert (sup.load_state(out)["last_pause"]["kind"]
            == "wall_bound_pause")
    monkeypatch.setattr(run_supervisor, "supervisor_wall_bound",
                        lambda: None)
    assert sup.supervise(out, resume=True) == sup.RC_NOTHING


# ── spend reconcile (M4 evidence path) ───────────────────────────────

def test_measured_spend_sums_max_of_evidence_per_stage(tmp_path):
    out, doc = _build(tmp_path, names=("alpha",))
    aid = doc["rows"][0]["artifact_id"]
    chain_dir = chain_elf.chain_dir_for(out, aid)
    study = chain_dir / "study"
    study.mkdir(parents=True)
    save_json(study / "spend-floor.json", {"spend_usd": 0.5})
    save_json(study / "cost-breakdown.json",
              {"totals": {"total_spend_usd": 0.2}})
    audit = chain_dir / "audit"
    audit.mkdir()
    save_json(audit / "cost-breakdown.json",
              {"totals": {"total_spend_usd": 1.25}})
    assert sup.measured_artifact_spend(out, aid) == pytest.approx(1.75)
    assert sup.measured_artifact_spend(out, "not-an-id") == 0.0


def test_clean_close_reconciles_reservation_to_measured(
        tmp_path, monkeypatch):
    out, doc = _build(tmp_path, names=("alpha",))
    aid = doc["rows"][0]["artifact_id"]
    chain_dir = chain_elf.chain_dir_for(out, aid)
    (chain_dir / "study").mkdir(parents=True)
    save_json(chain_dir / "study" / "spend-floor.json",
              {"spend_usd": 0.75})
    _ChainStub(monkeypatch, chain_elf.RC_OK)
    sup.supervise(out, uncapped=True)
    res = _row(out, aid)["reservation"]
    assert res["state"] == "reconciled"
    assert res["actual_usd"] == pytest.approx(0.75)


# ── settled-row and tier skips ───────────────────────────────────────

def test_verdicted_at_tier_is_skipped(tmp_path, monkeypatch):
    out, doc = _build(tmp_path, names=("alpha",))
    aid = doc["rows"][0]["artifact_id"]
    _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    sup.supervise(out, uncapped=True)
    tier = _row(out, aid)["policy"]["tier"]
    ledger_mod.set_artifact_status(out, aid, "verdicted", depth=tier)
    stub = _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    assert sup.supervise(out, resume=True) == sup.RC_NOTHING
    assert not stub.calls


def test_analysed_settles_only_under_mechanical_only(
        tmp_path, monkeypatch):
    """A mechanical-only tick treats analysed-at-tier as settled; a
    full-capability tick re-attempts it so the chain can lift the
    recorded degradations."""
    out, doc = _build(tmp_path, names=("alpha",))
    aid = doc["rows"][0]["artifact_id"]
    _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    sup.supervise(out, uncapped=True)
    tier = _row(out, aid)["policy"]["tier"]
    ledger_mod.set_artifact_status(out, aid, "analysed", depth=tier)
    stub = _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    assert sup.supervise(out, resume=True,
                         mechanical_only=True) == sup.RC_NOTHING
    assert not stub.calls
    assert sup.supervise(out, resume=True) == sup.RC_NOTHING
    assert stub.calls  # full capability re-attempted the row


def test_non_elf_row_runs_without_reservation(tmp_path, monkeypatch):
    """Non-ELF chains only record the honesty degradation — no LLM
    spend, so no reservation rides the call."""
    out, doc = _build(tmp_path, names=("alpha",))
    aid = doc["rows"][0]["artifact_id"]
    lp = ledger_mod.ledger_path(out)
    raw = load_json(lp)
    row = next(r for r in raw["rows"] if r["artifact_id"] == aid)
    row["class"] = "script-shell"
    row["exposure"] = [{
        "feature": "input_channels", "value": ["network"],
        "extractor": "packages.binary_analysis.input_channels"
                     ".recover_static_channels"}]
    save_json(lp, raw)
    stub = _ChainStub(monkeypatch, chain_elf.RC_OK)
    assert sup.supervise(out, uncapped=True) == sup.RC_OK
    assert stub.calls and stub.calls[0][0] == aid
    assert "reservation" not in _row(out, aid)


def test_t0_rows_never_enter_the_chain(tmp_path, monkeypatch):
    """Inventory tier means inventory only — a T0 row (non-ELF, no
    signals) is settled by policy, and a ledger of nothing else
    reads complete."""
    out, doc = _build(tmp_path, names=("alpha",))
    aid = doc["rows"][0]["artifact_id"]
    lp = ledger_mod.ledger_path(out)
    raw = load_json(lp)
    next(r for r in raw["rows"]
         if r["artifact_id"] == aid)["class"] = "data-opaque"
    save_json(lp, raw)
    stub = _ChainStub(monkeypatch, default=chain_elf.RC_OK)
    assert sup.supervise(out, uncapped=True) == sup.RC_NOTHING
    assert not stub.calls


# ── M5 surfaces: marker line + interim report ────────────────────────

def test_parked_run_line_escapes_and_names_the_route(tmp_path):
    assert sup.parked_run_line(tmp_path) is None
    save_json(sup.marker_path(tmp_path), {
        "schema_version": 1,
        "parks": [{"park_id": "park-deadbeef", "scope": "engagement",
                   "kind": "code_drift",
                   "reason": "evil \x1b]0;pwn\x07 title", "at": "t"}],
    })
    line = sup.parked_run_line(tmp_path)
    assert "\x1b" not in line and "\x07" not in line
    assert "park-deadbeef" in line
    assert "libexec/raptor-engage-supervise" in line


def test_interim_report_escapes_hostile_reasons(
        tmp_path, monkeypatch):
    out, _ = _build(tmp_path)
    _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    sup.supervise(out, uncapped=True)
    sup.mint_park(out, scope="engagement", kind="governor_park",
                  reason="bad \x1b[31mreason\x1b[0m")
    path = sup.write_interim_report(out, trigger="test")
    text = path.read_text(encoding="utf-8")
    assert "\x1b" not in text
    assert "WAITING" in text
    assert "--acknowledge" in text
    assert "Code pin:" in text


def test_park_registry_caps_and_ledger_park_still_holds(
        tmp_path, monkeypatch, caplog):
    out, _ = _build(tmp_path)
    monkeypatch.setattr(sup, "_MAX_PARKS", 1)
    sup.mint_park(out, scope="engagement", kind="governor_park",
                  reason="one")
    with caplog.at_level("WARNING"):
        sup.mint_park(out, scope="engagement", kind="governor_park",
                      reason="two")
    assert len(sup.list_parks(out)) == 1
    assert any("registry refused" in r.message
               for r in caplog.records)


# ── budget persistence: launch figures survive a bare resume ─────────

def test_bare_resume_enforces_the_launch_envelope(
        tmp_path, monkeypatch):
    """The launch envelope lands on the ledger policy block — a cron
    tick that does not repeat the flag still refuses over it. (The
    fallback estimates want T2 $8 + T1 $1; $8.05 funds exactly one
    reservation.)"""
    out, _ = _build(tmp_path)
    _ChainStub(monkeypatch, default=chain_elf.RC_FAILED)
    assert sup.supervise(out, envelope_usd=8.05) == sup.RC_FAILED
    doc = ledger_mod.load_ledger(out)
    assert doc["policy"]["envelope_usd"] == pytest.approx(8.05)
    assert gov.committed_usd(doc) <= 8.05
    assert "reservation_refused" in _residual_kinds(out)
    # The cron re-entry: bare --resume, flag not repeated. The
    # persisted envelope drives the S16 gate — with $8 still open
    # against $8.05, the remaining $1 want is a conflict, parked
    # PRE-SPEND (r1 ran this tick uncapped instead).
    assert sup.supervise(out, resume=True) == sup.RC_PARKED
    parks = sup.unacknowledged_parks(out, scope="engagement")
    assert parks and parks[0]["kind"] == "feasibility_conflict"
    doc = ledger_mod.load_ledger(out)
    assert gov.committed_usd(doc) <= 8.05, (
        "bare --resume spent past the launch envelope")


def test_bare_resume_uses_the_persisted_max_cost(
        tmp_path, monkeypatch):
    out, _ = _build(tmp_path)
    stub = _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    sup.supervise(out, max_cost=1.25)
    assert sup.load_state(out)["max_cost_usd"] == pytest.approx(1.25)
    n = len(stub.calls)
    sup.supervise(out, resume=True)
    resumed = stub.calls[n:]
    assert resumed
    assert all(kw.get("max_cost") == pytest.approx(1.25)
               for _aid, kw in resumed), (
        "bare --resume dropped the launch --max-cost")


def test_resume_flags_update_the_persisted_budgets(
        tmp_path, monkeypatch):
    out, _ = _build(tmp_path)
    stub = _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    sup.supervise(out, envelope_usd=8.05, max_cost=1.25)
    sup.supervise(out, resume=True, envelope_usd=9.5, max_cost=0.5)
    doc = ledger_mod.load_ledger(out)
    assert doc["policy"]["envelope_usd"] == pytest.approx(9.5)
    assert sup.load_state(out)["max_cost_usd"] == pytest.approx(0.5)
    kinds = _residual_kinds(out)
    assert "envelope_updated" in kinds
    assert "max_cost_updated" in kinds
    assert any(a.get("kind") == "envelope_updated"
               for a in doc.get("policy_amendments") or [])
    # The NEXT bare tick runs under the replaced figures.
    n = len(stub.calls)
    sup.supervise(out, resume=True)
    assert all(kw.get("max_cost") == pytest.approx(0.5)
               for _aid, kw in stub.calls[n:])
    # Repeating the same figures is a no-op, not residual churn.
    sup.supervise(out, resume=True, envelope_usd=9.5, max_cost=0.5)
    assert _residual_kinds(out).count("envelope_updated") == 1
    assert _residual_kinds(out).count("max_cost_updated") == 1


def test_invalid_budget_figures_refuse_as_usage(tmp_path):
    out, _ = _build(tmp_path)
    assert sup.supervise(
        out, envelope_usd=float("nan")) == sup.RC_USAGE
    assert sup.supervise(out, max_cost=-1.0) == sup.RC_USAGE
    assert sup.load_state(out) is None  # refused before launch


# ── partial refusal: exit-code honesty ───────────────────────────────

def _acked_feasibility(out: Path, envelope: float) -> None:
    """Launch under a conflicting envelope and own the feasibility
    park — returns after the acknowledgment, ready for the resume
    tick under test."""
    rc = sup.supervise(out, envelope_usd=envelope)
    assert rc == sup.RC_PARKED
    park_id = sup.unacknowledged_parks(out)[0]["park_id"]
    ok, _msg = sup.acknowledge_park(out, park_id)
    assert ok


def test_partial_refusal_never_reads_complete(tmp_path, monkeypatch):
    """One refused reservation + one RC_NOTHING sibling in the same
    tick is NOT a complete engagement — the unfunded live row parks
    the engagement (envelope_exhausted) instead of exiting
    nothing-to-do while a cron loop grinds refusals."""
    out, _ = _build(tmp_path)
    _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    _acked_feasibility(out, envelope=2.0)
    rc = sup.supervise(out, resume=True)
    assert rc == sup.RC_PARKED
    parks = sup.unacknowledged_parks(out, scope="engagement")
    assert parks and parks[0]["kind"] == "envelope_exhausted"
    assert "reservation_refused" in _residual_kinds(out)


def test_refusal_with_progress_stays_ok(tmp_path, monkeypatch):
    """A refusal beside FUNDED progress is a normal advancing tick —
    no envelope_exhausted park, exit code says advanced."""
    out, _ = _build(tmp_path)
    _ChainStub(monkeypatch, default=chain_elf.RC_OK)
    _acked_feasibility(out, envelope=2.0)
    assert sup.supervise(out, resume=True) == sup.RC_OK
    assert not any(p["kind"] == "envelope_exhausted"
                   for p in sup.list_parks(out))


def test_refusal_with_failure_stays_failed(tmp_path, monkeypatch):
    """A refusal beside a funded FAILURE keeps the failure exit —
    the retry path (RC_FAILED, resume retries) must not be masked
    by an envelope park."""
    out, _ = _build(tmp_path)
    _ChainStub(monkeypatch, default=chain_elf.RC_FAILED)
    _acked_feasibility(out, envelope=2.0)
    assert sup.supervise(out, resume=True) == sup.RC_FAILED
    assert not any(p["kind"] == "envelope_exhausted"
                   for p in sup.list_parks(out))


# ── acknowledge refusal escapes registry-derived ids ─────────────────

def test_unknown_ack_refusal_escapes_registry_ids(tmp_path):
    """The known-id list in the refusal message comes from the
    sandbox-writable registry — hostile bytes must reach the
    operator escaped."""
    out, _ = _build(tmp_path)
    save_json(out / sup.PARKS_FILENAME, {
        "schema_version": 1,
        "parks": [{"park_id": "park-\x1b]0;pwned\x07\x1b[31mRED",
                   "scope": "artifact", "kind": "segment_deaths",
                   "reason": "r", "at": "2026-09-27T00:00:00Z"}],
    })
    ok, message = sup.acknowledge_park(out, "park-doesnotexist")
    assert not ok
    assert "\x1b" not in message and "\x07" not in message
    assert "park-" in message  # the escaped id is still named


# ── supervisor-fatal segments still reach the death cap ──────────────

def test_dispatch_marker_written_during_and_cleared_after(
        tmp_path, monkeypatch):
    out, doc = _build(tmp_path, names=("alpha",))
    aid = doc["rows"][0]["artifact_id"]
    seen: list[tuple[str, Any]] = []

    def _chain(output_dir: Any, artifact_id: str, **kwargs: Any) -> int:
        st = sup.load_state(output_dir) or {}
        seen.append((artifact_id,
                     (st.get("in_flight") or {}).get("artifact_id")))
        return chain_elf.RC_OK

    monkeypatch.setattr(chain_elf, "run_chain", _chain)
    sup.supervise(out, uncapped=True)
    assert seen and all(a == m for a, m in seen), (
        "the durable dispatch marker must name the in-flight "
        "artifact while the chain runs")
    assert aid in [a for a, _m in seen]
    assert "in_flight" not in (sup.load_state(out) or {})


def test_supervisor_fatal_segment_books_the_death(
        tmp_path, monkeypatch):
    """A supervisor killed inside run_chain leaves the dispatch
    marker behind; the next resume books the unobserved death so
    PARK_AFTER_DEATHS still bounds an unattended crash loop."""
    out, doc = _build(tmp_path, names=("alpha",))
    aid = doc["rows"][0]["artifact_id"]
    _ChainStub(monkeypatch, default=chain_elf.RC_FAILED)
    sup.supervise(out, uncapped=True)  # one observed death, reservation stays open
    state = sup.load_state(out)
    state["in_flight"] = {"artifact_id": aid,
                          "segment": state["segments"], "at": "t"}
    save_json(out / sup.STATE_FILENAME, state)
    assert sup.supervise(out, resume=True) == sup.RC_FAILED
    assert "supervisor_fatal_segment" in _residual_kinds(out)
    assert "in_flight" not in (sup.load_state(out) or {})
    # observed(1) + fatal(1) + this tick's failure(1) = the cap.
    row = _row(out, aid)
    assert row["reservation"]["deaths"] == gov.PARK_AFTER_DEATHS
    assert row["status"]["state"] == "parked"
    parks = sup.unacknowledged_parks(out, scope="artifact")
    assert parks and parks[0]["kind"] == "segment_deaths"


def test_out_of_band_governor_park_is_adopted(tmp_path, monkeypatch):
    """An engagement park set by the governor without the supervisor
    (feasibility CLI, operator tooling) still gets an acknowledge
    target on the next tick."""
    out, _ = _build(tmp_path)
    _ChainStub(monkeypatch, default=chain_elf.RC_NOTHING)
    sup.supervise(out, uncapped=True)
    gov.park_engagement(out, "operator hold")
    assert sup.supervise(out, resume=True) == sup.RC_PARKED
    parks = sup.unacknowledged_parks(out, scope="engagement")
    assert len(parks) == 1
    assert parks[0]["kind"] == "governor_park"
    park_id = parks[0]["park_id"]
    rc = sup.supervise(out, resume=True, acknowledge=park_id)
    assert rc == sup.RC_NOTHING
