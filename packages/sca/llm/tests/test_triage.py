"""Tests for LLM triage stage."""

from __future__ import annotations


from packages.sca.llm.schemas import TriageResult
from packages.sca.llm.triage import _trim_for_llm, triage_findings


class TestTrimForLLM:
    def test_keeps_relevant_keys(self):
        rows = [
            {
                "id": "F-001",
                "finding_id": "F-001",
                "vuln_type": "sca:vulnerable_dependency",
                "severity": "critical",
                "description": "Known RCE",
                "irrelevant_key": "should be dropped",
                "sca": {
                    "ecosystem": "npm",
                    "name": "evil-pkg",
                    "version": "1.0.0",
                    "reachability": "imported",
                    "in_kev": True,
                    "epss": 0.95,
                    "supply_chain_kind": None,
                    "extra_junk": "should be dropped",
                },
            },
        ]
        trimmed = _trim_for_llm(rows)
        assert len(trimmed) == 1
        t = trimmed[0]
        assert "id" in t
        assert "severity" in t
        assert "irrelevant_key" not in t
        assert t["sca"]["ecosystem"] == "npm"
        assert "extra_junk" not in t.get("sca", {})

    def test_caps_at_limit(self):
        rows = [{"id": f"F-{i}", "severity": "low"} for i in range(100)]
        trimmed = _trim_for_llm(rows, limit=10)
        assert len(trimmed) == 10

    def test_empty_input(self):
        assert _trim_for_llm([]) == []

    def test_sca_not_dict_handled(self):
        rows = [{"id": "F-001", "sca": "not a dict"}]
        trimmed = _trim_for_llm(rows)
        assert len(trimmed) == 1


class TestTriageFindings:
    def test_empty_findings_returns_empty_result(self):
        result = triage_findings(object(), [], None)
        assert isinstance(result, TriageResult)
        assert result.items == []
        assert "No findings" in result.project_context_summary


class TestPreflightHaircut:
    """Triage is a run_stage consumer like every other stage: a
    preflight hit means the advisory-derived FINDINGS_LIST may have
    steered the ranking, so no per-item verdict ships at full
    confidence."""

    @staticmethod
    def _run(monkeypatch, *, preflight_hit: bool) -> TriageResult:
        from packages.sca.llm import StageResult
        from packages.sca.llm.schemas import TriageItem
        import packages.sca.llm.triage as triage_mod

        model = TriageResult(items=[
            TriageItem(finding_id="F-1", priority_bucket="accept",
                       confidence="high"),
            TriageItem(finding_id="F-2", priority_bucket="fix_today",
                       confidence="low"),
        ])

        def _stub_run_stage(**kw):
            return StageResult(
                model=model, raw="{}", preflight_hit=preflight_hit,
                confidence_haircut=1.0, cost=0.0,
            )

        monkeypatch.setattr(triage_mod, "run_stage", _stub_run_stage)
        result = triage_mod.triage_findings(
            object(), [{"id": "F-1", "severity": "low"}],
        )
        assert result is not None
        return result

    def test_preflight_hit_caps_high_confidence(self, monkeypatch):
        result = self._run(monkeypatch, preflight_hit=True)
        by_id = {i.finding_id: i for i in result.items}
        assert by_id["F-1"].confidence == "medium"   # capped
        assert by_id["F-2"].confidence == "low"      # untouched

    def test_no_preflight_hit_leaves_confidence(self, monkeypatch):
        result = self._run(monkeypatch, preflight_hit=False)
        by_id = {i.finding_id: i for i in result.items}
        assert by_id["F-1"].confidence == "high"


def test_every_run_stage_consumer_consults_preflight_hit():
    """Registry closure over the enumeration boundary: every stage
    module in packages/sca/llm that consumes run_stage must consult
    ``preflight_hit`` — the injection haircut is a uniform defence,
    and a new stage shipping without it re-opens the gap."""
    from pathlib import Path
    import packages.sca.llm as llm_pkg

    llm_dir = Path(llm_pkg.__file__).parent
    consumers = []
    for py in sorted(llm_dir.glob("*.py")):
        if py.name == "__init__.py":
            continue
        src = py.read_text(encoding="utf-8")
        if "run_stage(" in src:
            consumers.append(py.name)
            assert "preflight_hit" in src, (
                f"{py.name} consumes run_stage but never consults "
                f"preflight_hit"
            )
    # The scan must actually see the known stage modules — an empty
    # consumer list would make the closure vacuous.
    assert "triage.py" in consumers
    assert "install_hook_review.py" in consumers
