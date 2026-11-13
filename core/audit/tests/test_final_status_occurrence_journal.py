"""Owned final-status journal identity; no verdict assurance."""
import pytest

from core.audit import collector, orchestrator as orch
from core.coverage.journal import is_mechanical_echo, load_entries
from core.testing.module_views import module_function_view


def test_sibling_latest_status_cannot_hide_another_occurrence_drift(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    (target / "unit.c").write_text("#ifdef FIRST\nunsigned f(unsigned n) { return n; }\n#else\nunsigned f(unsigned n) { return n + 1; }\n#endif\n")
    times = iter(("2026-11-12T00:00:00+00:00", "2026-11-12T00:00:01+00:00"))
    writer = module_function_view(collector, bindings={"now_iso": lambda: next(times)})
    first = orch.ReviewOutcome("unit.c", "f", "clean", "Owned original first status", line=2)
    sibling = orch.ReviewOutcome("unit.c", "f", "suspicious", "Owned sibling status", line=4)
    for outcome in (first, sibling):
        assert writer.append_journal_for_outcome(out_dir=out, target_path=target, run_id=out.name,
            outcome=outcome, gap={"line_start": outcome.line, "line_end": outcome.line}) is not None
    final = orch.ReviewOutcome("unit.c", "f", "suspicious", "Owned corrected first status", line=2)
    result = orch.OrchestratorResult(outcomes=[final, sibling], suspicious=2)
    updated = orch._rejournal_final_statuses(result, orch.OrchestratorConfig(target_path=target, out_dir=out))
    rows = load_entries(out, fresh=True)
    assert result.outcomes[0] is final and result.outcomes[1] is sibling
    assert len(rows) == 3 and rows[-1].line_start == 2
    assert rows[-1].verdict == "suspicious" and updated == 1


def _journal_case(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    (target / "unit.c").write_text("#ifdef FIRST\nunsigned f(unsigned n) { return n; }\n#else\nunsigned f(unsigned n) { return n + 1; }\n#endif\n")
    ticks = iter(f"2026-11-12T00:00:{second:02d}+00:00" for second in range(10))
    writer = module_function_view(collector, bindings={"now_iso": lambda: next(ticks)})

    def append(line, status, strategies, *, end=None):
        prior = orch.ReviewOutcome("unit.c", "f", status, "Owned journal history", line=line)
        return writer.append_journal_for_outcome(out_dir=out, target_path=target, run_id=out.name,
            outcome=prior, gap={"line_start": line, "line_end": end, "strategies": strategies})

    return orch.OrchestratorConfig(target_path=target, out_dir=out), append


def test_corrective_donor_is_the_same_occurrence_despite_later_sibling(tmp_path, monkeypatch):
    config, append = _journal_case(tmp_path, monkeypatch)
    assert append(2, "suspicious", ["auth"], end=2) is not None
    assert append(4, "dark", ["general"], end=4) is not None
    final = orch.ReviewOutcome("unit.c", "f", "clean", "Owned corrected first status", line=2)
    result = orch.OrchestratorResult(outcomes=[final], clean=1)
    assert orch._rejournal_final_statuses(result, config) == 1
    rows = load_entries(config.out_dir, fresh=True)
    assert len(rows) == 3 and rows[-1].line_start == rows[-1].line_end == 2
    assert rows[-1].strategies == ["auth"] and rows[-1].verdict == "clean"
    assert orch._rejournal_final_statuses(result, config) == 0
    assert len(load_entries(config.out_dir, fresh=True)) == 3


@pytest.mark.parametrize("history", ["unknown_only", "unknown_and_sibling", "sibling_only"])
def test_unknown_outcome_joins_only_unknown_history(tmp_path, monkeypatch, history):
    config, append = _journal_case(tmp_path, monkeypatch)
    initial = 0
    if history != "sibling_only":
        assert append(0, "clean", ["legacy"]) is not None
        initial += 1
    if history != "unknown_only":
        assert append(4, "dark", ["general"], end=4) is not None
        initial += 1
    final = orch.ReviewOutcome("unit.c", "f", "suspicious", "Owned unknown-site status", line=0)
    result = orch.OrchestratorResult(outcomes=[final], suspicious=1)
    changed = history != "sibling_only"
    assert orch._rejournal_final_statuses(result, config) == int(changed)
    rows = load_entries(config.out_dir, fresh=True)
    assert len(rows) == initial + int(changed)
    assert final.line == 0
    if changed:
        assert rows[-1].line_start == 0 and rows[-1].line_end is None
        assert rows[-1].strategies == ["legacy"] and rows[-1].verdict == "suspicious"


@pytest.mark.parametrize("final_status", ["clean", "suspicious"])
def test_unscoped_echo_triggers_refresh_without_masking_real_site_drift(tmp_path, monkeypatch, final_status):
    config, append = _journal_case(tmp_path, monkeypatch)
    assert append(2, "clean", ["auth"], end=2) is not None
    assert append(0, "suspicious", ["post-loop-mechanical"]) is not None
    final = orch.ReviewOutcome("unit.c", "f", final_status, "Owned final status", line=2)
    result = orch.OrchestratorResult(outcomes=[final], clean=int(final_status == "clean"),
                                     suspicious=int(final_status == "suspicious"))
    assert orch._rejournal_final_statuses(result, config) == 1
    rows = load_entries(config.out_dir, fresh=True)
    assert len(rows) == 3 and rows[-1].line_start == rows[-1].line_end == 2
    assert rows[-1].strategies == ["auth"] and rows[-1].verdict == final_status
    assert not is_mechanical_echo(rows[-1])
