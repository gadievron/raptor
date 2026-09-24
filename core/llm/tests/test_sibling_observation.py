"""Tests for the sibling-run observation heuristic: ledger-count
classification against fixture run dirs, fail-open behavior, and the
startup banner's content (accurate counts, inert text, honest
unreadable note).
"""

from __future__ import annotations

import json

import pytest

import core.llm.concurrency as conc


def _mk_run(tmp_path, name: str, command: str, status: str = "running"):
    d = tmp_path / name
    d.mkdir()
    (d / ".raptor-run.json").write_text(
        json.dumps({"status": status, "command": command}),
        encoding="utf-8")
    return d


def _ledger(monkeypatch, records):
    monkeypatch.setattr(
        "core.project.sessions.ledger_running_runs_all_sessions",
        lambda: records)


def _rec(d, pid=1234):
    return {"status": "running", "epoch": 100, "run_id": d.name,
            "run_dir": str(d), "session_pid": pid}


class TestObserve:

    def test_llm_commands_counted_non_llm_not(self, tmp_path, monkeypatch):
        audit = _mk_run(tmp_path, "audit_1", "audit")
        agentic = _mk_run(tmp_path, "agentic_1", "agentic")
        scan = _mk_run(tmp_path, "scan_1", "scan")
        _ledger(monkeypatch, [_rec(audit), _rec(agentic), _rec(scan)])
        obs = conc.observe_llm_sibling_runs()
        assert obs.count == 2
        assert obs.commands == ("agentic", "audit")

    def test_stale_ledger_line_not_counted(self, tmp_path, monkeypatch):
        # Ledger says running, the run's own metadata is terminal —
        # the crashed/finished run must not inflate the count.
        done = _mk_run(tmp_path, "audit_2", "audit", status="completed")
        _ledger(monkeypatch, [_rec(done)])
        assert conc.observe_llm_sibling_runs().count == 0

    def test_missing_metadata_not_counted(self, tmp_path, monkeypatch):
        gone = tmp_path / "audit_gone"
        _ledger(monkeypatch, [_rec(gone)])
        assert conc.observe_llm_sibling_runs().count == 0

    def test_self_run_excluded(self, tmp_path, monkeypatch):
        mine = _mk_run(tmp_path, "audit_mine", "audit")
        other = _mk_run(tmp_path, "audit_other", "audit")
        _ledger(monkeypatch, [_rec(mine), _rec(other)])
        obs = conc.observe_llm_sibling_runs(self_run_dir=mine)
        assert obs.count == 1

    def test_duplicate_run_dir_counted_once(self, tmp_path, monkeypatch):
        # A resumed run can transiently sit in two sessions' ledgers.
        d = _mk_run(tmp_path, "audit_3", "audit")
        _ledger(monkeypatch, [_rec(d, pid=1), _rec(d, pid=2)])
        assert conc.observe_llm_sibling_runs().count == 1

    def test_unknown_command_not_counted(self, tmp_path, monkeypatch):
        # Includes hostile metadata: a planted command name never
        # reaches the count (or, downstream, the banner).
        weird = _mk_run(tmp_path, "w_1", "audit\x1b[2J")
        _ledger(monkeypatch, [_rec(weird)])
        assert conc.observe_llm_sibling_runs().count == 0

    def test_unhashable_command_skipped_without_raising(self, tmp_path,
                                                        monkeypatch):
        # The metadata file is sandbox-writable: a planted list/dict
        # command must be SKIPPED, not TypeError the frozenset probe —
        # one poisoned sibling run dir would otherwise abort every
        # subsequent auto-worker startup on the box.
        poisoned = tmp_path / "audit_p"
        poisoned.mkdir()
        (poisoned / ".raptor-run.json").write_text(
            json.dumps({"status": "running", "command": ["audit"]}),
            encoding="utf-8")
        real = _mk_run(tmp_path, "audit_r", "audit")
        _ledger(monkeypatch, [_rec(poisoned), _rec(real)])
        obs = conc.observe_llm_sibling_runs()
        assert obs.count == 1
        assert obs.commands == ("audit",)

    def test_ledger_failure_fails_open(self, monkeypatch):
        def _boom():
            raise OSError("sessions.d unreadable")
        monkeypatch.setattr(
            "core.project.sessions.ledger_running_runs_all_sessions",
            _boom)
        obs = conc.observe_llm_sibling_runs()
        assert obs.count is None
        assert obs.commands == ()


class TestBanner:

    def test_shared_names_observation_and_fair_share(self):
        obs = conc.LLMSiblingObservation(3, ("agentic", "audit", "audit"))
        line = conc.format_llm_sibling_banner(obs, "shared", 8)
        assert "3 live LLM runs" in line
        assert "audit x2" in line
        assert "agentic" in line
        assert "holding fair-share concurrency 8" in line
        assert "posture=shared" in line

    def test_solo_names_solo_ceiling(self):
        obs = conc.LLMSiblingObservation(1, ("audit",))
        line = conc.format_llm_sibling_banner(obs, "solo", 16)
        assert "1 live LLM run (" in line
        assert "using solo ceiling 16" in line

    def test_zero_observed(self):
        line = conc.format_llm_sibling_banner(
            conc.LLMSiblingObservation(0), "shared", 8)
        assert "none observed" in line
        assert "holding fair-share concurrency 8" in line

    def test_unreadable_ledger_is_a_quiet_honest_note(self):
        line = conc.format_llm_sibling_banner(
            conc.LLMSiblingObservation(None), "shared", 8)
        assert "unreadable" in line
        assert "assuming none" in line

    @pytest.mark.parametrize("posture,workers", [
        ("shared", 8), ("solo", 16)])
    def test_banner_is_terminal_inert(self, posture, workers):
        # Command entries are frozenset constants by construction, but
        # the banner sanitises anyway — pin the belt-and-braces: even
        # a hand-built observation carrying control bytes renders
        # them escaped, never raw.
        obs = conc.LLMSiblingObservation(1, ("audit\x1b[2J",))
        line = conc.format_llm_sibling_banner(obs, posture, workers)
        assert "\x1b" not in line


class TestConsumerContainment:

    def test_emit_contains_any_observation_failure(self, monkeypatch,
                                                   caplog):
        # The consumer chokepoint both banner sites call: an
        # unexpected raise anywhere in observe/format degrades to a
        # debug note — LLM startup never aborts over the banner.
        def _boom(self_run_dir=None):
            raise AssertionError("poisoned sibling")
        monkeypatch.setattr(conc, "observe_llm_sibling_runs", _boom)
        with caplog.at_level("DEBUG", logger="core.llm.concurrency"):
            conc.emit_llm_sibling_banner("shared", 8)  # must not raise
        assert "suppressed" in caplog.text

    def test_emit_logs_banner_on_success(self, monkeypatch, caplog):
        monkeypatch.setattr(
            conc, "observe_llm_sibling_runs",
            lambda self_run_dir=None: conc.LLMSiblingObservation(
                1, ("audit",)))
        with caplog.at_level("INFO", logger="core.llm.concurrency"):
            conc.emit_llm_sibling_banner("shared", 8)
        assert "llm siblings: 1 live LLM run (audit)" in caplog.text


class TestDerivationIndependence:

    def test_derive_never_consults_the_observation(self, monkeypatch):
        # Observe-don't-divide pin: the sibling count is a banner
        # heuristic — the worker DERIVATION must not read the ledger
        # or divide by the count. A derivation that consulted the
        # observation would raise here.
        from core.llm.config import ModelConfig
        mc = ModelConfig(provider="bedrock",
                         model_name="anthropic.claude-sonnet-5")
        monkeypatch.setattr(
            "core.llm.config._get_default_primary_model",
            lambda prefer=None: mc)
        monkeypatch.setattr(conc, "read_tuning_max_llm_workers",
                            lambda: None)
        monkeypatch.setattr(conc, "_read_tuning",
                            lambda: {"llm_account_posture": "shared"})
        monkeypatch.delenv("RAPTOR_BEDROCK_MAX_WORKERS", raising=False)

        def _boom(*a, **k):
            raise AssertionError("derivation consulted the ledger")
        monkeypatch.setattr(conc, "observe_llm_sibling_runs", _boom)
        monkeypatch.setattr(
            "core.project.sessions.ledger_running_runs_all_sessions",
            _boom)
        assert (conc.derive_max_workers("anthropic.claude-sonnet-5")
                == conc.BEDROCK_MAX_WORKERS_DEFAULT)
