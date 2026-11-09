"""Triage receipts observe existing calls and preserve native curation output."""
from types import SimpleNamespace

import pytest

from core.reporting.writer import load_committed_report
from core.testing.logging_state import isolated_cli_logging
from packages.sca.supply_chain import typosquat_audit as audit
from packages.sca.supply_chain.typosquat_triage import Disposition, Evidence, GateResult, TriageOutcome, Verdict


def _paths(tmp_path, monkeypatch):
    reviewed = tmp_path / "reviewed.json"
    denylist = tmp_path / "denylist.json"
    reviewed.write_text("{}")
    denylist.write_text("{}")
    monkeypatch.setattr(audit, "_REVIEWED_LEGIT_PATH", reviewed)
    monkeypatch.setattr(audit, "_DENYLIST_PATH", denylist)
    monkeypatch.setattr("packages.sca.sca_cache_root", lambda: tmp_path / "cache")
    monkeypatch.setattr("packages.sca.default_client", lambda: object())


def _args(tmp_path):
    return ["--only", "npm", "--report-format", "json", "--report-output", str(tmp_path / "receipt.json")]


@isolated_cli_logging()
def test_candidate_receipt_reuses_feed_results_and_exposes_missing_coverage(tmp_path, monkeypatch, capsys):
    from packages.sca.supply_chain import triage_reporting
    _paths(tmp_path, monkeypatch)
    candidate = audit.Candidate("expresss", "express", 3000, 5, 1)
    candidates = [candidate, candidate]
    calls = []
    monkeypatch.setattr(audit, "audit", lambda *args, **kwargs: calls.append(kwargs) or {"npm": candidates})
    monkeypatch.setattr(triage_reporting, "DETAIL_LIMIT", 1)
    assert audit.main(_args(tmp_path) + ["--only", "PyPI"]) == 0
    assert len(calls) == 1 and len(candidates) == 2
    context, _, _ = load_committed_report(tmp_path / ".receipt-report")
    payload = context.extensions["raptor.result"]
    assert payload["candidate counts"] == {"npm": 2} and len(payload["candidates"]["npm"]) == 1
    assert payload["unrecorded requested ecosystems"] == ["PyPI"] and context.state == "partial"
    assert "expresss" in capsys.readouterr().out


@isolated_cli_logging()
def test_requested_llm_unavailable_stays_partial_without_evidence_calls(tmp_path, monkeypatch):
    _paths(tmp_path, monkeypatch)
    monkeypatch.setattr(audit, "audit", lambda *args, **kwargs: {"npm": [audit.Candidate("expresss", "express", 3000, 5, 1)]})
    monkeypatch.setattr("packages.sca.llm.get_llm_client", lambda: None)
    monkeypatch.setattr(audit, "_registry_clients", lambda *args: pytest.fail("missing LLM must not collect evidence"))
    assert audit.main(_args(tmp_path) + ["--llm"]) == 0
    context, _, _ = load_committed_report(tmp_path / ".receipt-report")
    assert context.state == "partial" and context.extensions["raptor.result"]["LLM available"] is False


@isolated_cli_logging()
def test_triage_receipt_retains_proposal_evidence_and_final_gate_without_replay(tmp_path, monkeypatch, capsys):
    from packages.sca.supply_chain import typosquat_triage, triage_reporting
    _paths(tmp_path, monkeypatch)
    monkeypatch.setattr(triage_reporting, "DETAIL_LIMIT", 1)
    candidate = audit.Candidate("expresss", "express", 3000, 5, 1)
    evidence = Evidence(candidate, description="https://user:owned-secret@[invalid", num_versions=1)
    proposal = Verdict("expresss", "typosquat", "high", "needs confirmation", ["description"])
    outcome = TriageOutcome(candidate, evidence, proposal, GateResult(Disposition.CONFIRM_SQUAT, "confirm before denylisting"))
    monkeypatch.setattr(audit, "audit", lambda *args, **kwargs: {"npm": [candidate, candidate]})
    monkeypatch.setattr("packages.sca.llm.get_llm_client", lambda: SimpleNamespace())
    monkeypatch.setattr(audit, "_registry_clients", lambda *args: {"npm": SimpleNamespace(get_metadata=lambda name: None)})
    monkeypatch.setattr(typosquat_triage, "make_llm_verdict_fn", lambda *args: object())
    calls = []
    monkeypatch.setattr(typosquat_triage, "triage_ecosystem", lambda *args, **kwargs: calls.append(kwargs) or [outcome, outcome])
    assert audit.main(_args(tmp_path) + ["--llm"]) == 0
    assert len(calls) == 1
    context, _, _ = load_committed_report(tmp_path / ".receipt-report")
    row = context.extensions["raptor.result"]["triage outcomes"]["npm"][0]
    assert row["LLM proposal"]["verdict"] == "typosquat" and row["gate"]["disposition"] == "confirm_squat"
    assert "owned-secret" not in row["evidence"]["description"] and "owned-secret" in evidence.description
    assert context.extensions["raptor.metrics"]["Gate confirm_squat"] == 2
    assert context.extensions["raptor.metrics"]["Triage outcomes"] == 2
    assert len(context.extensions["raptor.result"]["triage outcomes"]["npm"]) == 1
    assert "CONFIRM before denylisting (2)" in capsys.readouterr().out


@isolated_cli_logging()
def test_reaudit_receipt_preserves_empty_native_markdown_without_second_audit(tmp_path, monkeypatch):
    from packages.sca.supply_chain import typosquat_triage
    _paths(tmp_path, monkeypatch)
    monkeypatch.setattr(audit, "audit", lambda *args, **kwargs: pytest.fail("re-audit must not fetch candidate feeds"))
    monkeypatch.setattr(audit, "_registry_clients", lambda *args: {})
    calls = []
    monkeypatch.setattr(typosquat_triage, "reaudit_reviewed_legit", lambda *args, **kwargs: calls.append(kwargs) or {})
    native = tmp_path / "native.md"
    assert audit.main(_args(tmp_path) + ["--reaudit", "--out", str(native)]) == 0
    assert len(calls) == 1 and native.read_text() == ""
    context, _, _ = load_committed_report(tmp_path / ".receipt-report")
    assert context.extensions["raptor.metrics"]["Re-audit flags"] == 0
    assert any("not a verified total" in note for note in context.diagnostics)


@isolated_cli_logging()
def test_triage_report_cannot_replace_native_refresh_output(tmp_path, monkeypatch, capsys):
    _paths(tmp_path, monkeypatch)
    monkeypatch.setattr(audit, "audit", lambda *args, **kwargs: {"npm": []})
    native = tmp_path / "native.md"
    assert audit.main(["--only", "npm", "--format", "markdown", "--out", str(native),
                       "--report-format", "markdown", "--report-output", str(native)]) == 0
    assert native.read_text() == "" and "Report persistence failed" in capsys.readouterr().err


def test_triage_report_preflight_before_candidate_feed(monkeypatch):
    monkeypatch.setattr(audit, "audit", lambda *args, **kwargs: pytest.fail("must preflight"))
    with pytest.raises(SystemExit) as error:
        audit.main(["--report-format", "json"])
    assert error.value.code == 2
