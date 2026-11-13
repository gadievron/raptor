"""Owned provisional journal identity; no tool-grounding proof."""
import pytest

from core.audit import orchestrator as orch
from core.coverage.journal import load_entries


def test_provisional_row_keeps_the_declared_outcome_occurrence(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    (target / "unit.c").write_text("#ifdef FIRST\nunsigned f(unsigned n) { return n; }\n#else\nunsigned f(unsigned n) { return n + 1; }\n#endif\n")
    checklist = {"files": [{"path": "unit.c", "items": [
        {"name": "f", "line_start": 2, "line_end": 2},
        {"name": "f", "line_start": 4, "line_end": 4}]}]}
    config = orch.OrchestratorConfig(target_path=target, out_dir=out)
    outcome = orch.ReviewOutcome("unit.c", "f", "finding", "Owned declared promotion", line=4,
                                provisional=True)
    result = orch.OrchestratorResult()
    # Do not claim this declared metadata is tool-grounded; existing journal
    # promotion alarms remain active and may demote it. Identity is the subject.
    orch._journal_provisional_promotion(result, config, outcome, checklist)
    rows = load_entries(out, fresh=True)
    assert outcome.line == 4
    assert outcome.status == "suspicious"
    assert len(rows) == 1 and rows[0].provisional is True
    assert rows[0].verdict == "suspicious"
    assert rows[0].line_start == 4


@pytest.mark.parametrize("mode", ["matched", "mismatched", "unknown", "bool_gap", "missing"])
def test_provisional_metadata_never_comes_from_another_or_unknown_site(tmp_path, monkeypatch, mode):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    (target / "unit.c").write_text("unsigned f(unsigned n) { return n; }\n\n\nunsigned f(unsigned n) { return n + 1; }\n")
    line = 0 if mode == "unknown" else 1 if mode == "bool_gap" else 4
    gap_line = 4 if mode in {"matched", "unknown"} else True if mode == "bool_gap" else 1
    item = {"name": "f", "line_start": gap_line, "line_end": gap_line,
            "qualified_name": "selected::f", "strategies": ["owned-strategy"]}
    checklist = {"files": [] if mode == "missing" else [{"path": "unit.c", "items": [item]}]}
    config = orch.OrchestratorConfig(target_path=target, out_dir=out)
    outcome = orch.ReviewOutcome("unit.c", "f", "suspicious", "Owned provisional metadata", line=line,
                                provisional=True)
    orch._journal_provisional_promotion(orch.OrchestratorResult(), config, outcome, checklist)
    rows = load_entries(out, fresh=True)
    assert len(rows) == 1
    row = rows[0]
    assert type(row.line_start) is int and row.line_start == line
    assert row.provisional is True and outcome.line == line
    if mode == "matched":
        assert row.line_end == 4
        # The real checklist lookup returns geometry only; qualified names
        # and strategies in the raw checklist are not part of that contract.
        assert row.function_qualified is None and row.strategies == []
        assert not outcome.function_qualified
    else:
        assert row.line_end is None and row.function_qualified is None
        assert row.strategies == [] and not outcome.function_qualified


def test_provisional_lookup_failure_keeps_existing_nonraising_fallback(tmp_path, monkeypatch):
    from core.testing.module_views import module_function_view

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    (target / "unit.c").write_text("unsigned f(unsigned n) { return n; }\n")
    outcome = orch.ReviewOutcome("unit.c", "f", "suspicious", "Owned provisional metadata", line=1,
                                provisional=True)

    def fail_lookup(*args):
        raise OSError("owned checklist lookup failure")

    private = module_function_view(orch, bindings={"_find_gap_in_checklist": fail_lookup})
    private._journal_provisional_promotion(orch.OrchestratorResult(),
        orch.OrchestratorConfig(target_path=target, out_dir=out), outcome, {"files": []})
    rows = load_entries(out, fresh=True)
    assert len(rows) == 1 and rows[0].line_start == 1 and rows[0].provisional is True
    assert rows[0].line_end is None


@pytest.mark.parametrize("prior_site", [2, 4], ids=["other", "same"])
def test_fallback_strategy_inheritance_remains_at_the_outcome_site(tmp_path, monkeypatch, prior_site):
    from core.audit.collector import append_journal_for_outcome

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    (target / "unit.c").write_text("#ifdef FIRST\nunsigned f(unsigned n) { return n; }\n#else\nunsigned f(unsigned n) { return n + 1; }\n#endif\n")
    checklist = {"files": [{"path": "unit.c", "items": [
        {"name": "f", "line_start": 2, "line_end": 2},
        {"name": "f", "line_start": 4, "line_end": 4}]}]}
    prior = orch.ReviewOutcome("unit.c", "f", "suspicious", "Owned prior metadata", line=prior_site)
    assert append_journal_for_outcome(out_dir=out, target_path=target, run_id=out.name, outcome=prior,
        gap={"line_start": prior_site, "line_end": prior_site, "strategies": ["owned-prior"]}) is not None
    outcome = orch.ReviewOutcome("unit.c", "f", "suspicious", "Owned provisional metadata", line=4,
                                provisional=True)
    orch._journal_provisional_promotion(orch.OrchestratorResult(),
        orch.OrchestratorConfig(target_path=target, out_dir=out), outcome, checklist)
    rows = load_entries(out, fresh=True)
    assert len(rows) == 2 and rows[0].line_start == prior_site
    assert rows[1].line_start == 4 and rows[1].provisional is True
    assert rows[1].strategies == (["owned-prior"] if prior_site == 4 else [])
