"""Standing-rule batching preserves routing, ordering and per-file cache eligibility."""

import pytest

from core.audit import cwe_dispatch, detector_cache, orchestrator
from packages.coccinelle import runner
from packages.coccinelle.models import SpatchMatch, SpatchResult


@pytest.fixture
def case(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    for name in ("a", "b"):
        (target / f"{name}.c").write_text(f"int {name}(void) {{\n    return 0;\n}}\n")
    rules = tmp_path / "raptor" / "engine" / "coccinelle" / "rules"
    rules.mkdir(parents=True)
    for name in ("a", "z"):
        (rules / f"{name}.cocci").write_text(f"// {name} standing rule\n")
    monkeypatch.setenv("RAPTOR_DIR", str(tmp_path / "raptor"))
    monkeypatch.setattr(cwe_dispatch, "CWE_TO_TOOL_DISPATCH", {"CWE-X": {"cocci": ["z.cocci", "a.cocci"]}})
    monkeypatch.setattr(runner, "is_available", lambda: True)
    monkeypatch.setattr(detector_cache, "spatch_marker", lambda: "test-spatch")
    config = orchestrator.OrchestratorConfig(target_path=target, out_dir=tmp_path / "out")
    gaps = [{"file": "a.c", "name": "first", "line_start": 1, "line_end": 3},
            {"file": "a.c", "name": "overlap", "line_start": 1, "line_end": 3},
            {"file": "b.c", "name": "second", "line_start": 1, "line_end": 3}]
    return config, gaps, rules


def result(path, stem, *, errors=None):
    return SpatchResult(
        rule="a_report" if stem == "a" else "", matches=[SpatchMatch(
            str(path), 2, rule="emitted_alias", message=f"{stem}/{path.name}")],
        errors=errors or [],
    )


def cocci_only(findings):
    return {key: [r for r in rows if r["detector"].startswith("cocci:")]
            for key, rows in findings.items() if any(r["detector"].startswith("cocci:") for r in rows)}


def test_file_batches_keep_sorted_rule_order_and_first_gap(case, monkeypatch):
    config, gaps, rules = case
    calls = []
    def batch(path, selected, **kwargs):
        calls.append(path.name)
        assert selected == [rules / "a.cocci", rules / "z.cocci"]
        assert kwargs == {"no_includes": True, "timeout": 60, "allow_scripting": True}
        return {"z": result(path, "z"), "a": result(path, "a")}
    def forbidden(*args, **kwargs):
        raise AssertionError("complete batch must not re-run individual rules")
    monkeypatch.setattr(runner, "run_rules_batched", batch)
    monkeypatch.setattr(runner, "run_rule", forbidden)
    findings, _ = orchestrator._run_mechanical_detectors(gaps, config)
    records = cocci_only(findings)
    assert calls == ["a.c", "b.c"]
    steps = config.prep_profile.snapshot()["steps"]
    assert steps["mechanical.coccinelle_batch"]["calls"] == 2
    assert "mechanical.coccinelle" not in steps
    assert list(records) == ["a.c:first", "b.c:second"]
    for key, rows in records.items():
        assert [r["detector"] for r in rows] == ["cocci:a_report", "cocci:z"]
        assert [r["description"] for r in rows] == [f"a/{key[0]}.c", f"z/{key[0]}.c"]
    calls.clear()
    cached, _ = orchestrator._run_mechanical_detectors(gaps, config)
    assert cocci_only(cached) == records
    assert calls == []
    # Source and gap edits invalidate only the affected file.
    source = config.target_path / "a.c"
    source.write_text(source.read_text() + "\n")
    orchestrator._run_mechanical_detectors(gaps, config)
    assert calls == ["a.c"]
    calls.clear()
    gaps[1]["line_start"] = 2
    orchestrator._run_mechanical_detectors(gaps, config)
    assert calls == ["a.c"]
    calls.clear()
    # A standing-rule edit invalidates every file's Coccinelle lane.
    (rules / "z.cocci").write_text("// changed rule\n")
    orchestrator._run_mechanical_detectors(gaps, config)
    assert calls == ["a.c", "b.c"]


@pytest.mark.parametrize("mode", ["raise", "missing", "wrong_shape"])
def test_unexpected_batch_failures_keep_serial_fallback(case, monkeypatch, mode):
    config, gaps, _ = case
    calls = []
    def batch(path, selected, **kwargs):
        if mode == "raise":
            raise RuntimeError("unexpected adapter failure")
        if mode == "wrong_shape":
            return None
        return {"a": result(path, "a")}
    def individual(path, rule, **kwargs):
        assert kwargs == {"no_includes": True, "timeout": 60, "allow_scripting": True}
        calls.append((path.name, rule.stem))
        return result(path, rule.stem)
    monkeypatch.setattr(runner, "run_rules_batched", batch)
    monkeypatch.setattr(runner, "run_rule", individual)
    findings, _ = orchestrator._run_mechanical_detectors(gaps, config)
    assert len(cocci_only(findings)) == 2
    expected = [(f"{file}.c", rule) for file in ("a", "b")
                for rule in (("z",) if mode == "missing" else ("a", "z"))]
    assert calls == expected


def test_error_results_are_not_cached(case, monkeypatch):
    config, gaps, _ = case
    calls = []
    def batch(path, selected, **kwargs):
        calls.append(path.name)
        return {"a": result(path, "a"), "z": result(path, "z", errors=["rule failed"])}
    monkeypatch.setattr(runner, "run_rules_batched", batch)
    for _ in range(2):
        findings, _ = orchestrator._run_mechanical_detectors(gaps, config)
        assert len(cocci_only(findings)) == 2  # Retain partial matches as before.
    assert calls == ["a.c", "b.c", "a.c", "b.c"]
