"""The post-LLM SAGE verdict store never fires on errored analyses.

``vuln.analysis`` is assigned before raise-capable code in
``analyze_vulnerability`` (artifact save, response post-processing), so
a mid-flight crash leaves a populated analysis dict alongside a
``status=error`` record. Persisting that verdict would seed the 0c
SAGE pre-LLM suppression and silently skip the LLM on future runs for
the verdict's TTL — the operator expects an errored finding to be
re-tested, not suppressed.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import packages.llm_analysis.agent as agent_mod  # noqa: E402


def _make_agent(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    (repo / "src").mkdir(exist_ok=True)
    (repo / "src" / "auth.c").write_text(
        "".join(f"int line{i};\n" for i in range(1, 60))
    )
    mock_availability = MagicMock()
    mock_availability.external_llm = False
    mock_availability.claude_code = True
    with patch(
        "packages.llm_analysis.agent.detect_llm_availability",
        return_value=mock_availability,
    ):
        agent = agent_mod.AutonomousSecurityAgentV2(
            repo_path=repo,
            out_dir=tmp_path / "out",
            prep_only=True,
            synthesise_checkers=False,
        )
    return agent


def _finding() -> dict:
    return {
        "finding_id": "F1",
        "rule_id": "c.lang.security.strcpy",
        "message": "strcpy into fixed buffer",
        "file": "src/auth.c",
        "startLine": 42,
        "endLine": 42,
        "snippet": "strcpy(buf, input);",
        "level": "error",
        "cwe_id": "CWE-120",
        "tool": "semgrep",
        "has_dataflow": False,
        "dataflow_path": None,
        "metadata": {"name": "check_pw"},
    }


_ANALYSIS = {
    "is_true_positive": False,
    "is_exploitable": False,
    "exploitability_score": 0.1,
    "reasoning": "constant destination buffer, bounded source",
    "attack_scenario": "none identified",
    "severity_assessment": "low",
}


def _run(agent, monkeypatch, *, analysis_crashes: bool,
         finding: dict | None = None):
    import core.llm.response_validation as rv
    import core.sage.hooks as hooks

    # LLM returns a well-formed verdict; the crash (when requested)
    # lands AFTER ``vuln.analysis`` is assigned, via the analysis
    # artifact save — the schema-drift / OSError class the error path
    # exists for.
    llm = MagicMock()
    llm.generate_structured.return_value = (dict(_ANALYSIS), "raw")
    agent.llm = llm
    monkeypatch.setattr(
        rv, "attempt_quality_retry",
        lambda client, validated, *a, **k: validated,
    )
    if analysis_crashes:
        real_save_json = agent_mod.save_json

        def _failing_save_json(path, obj, **kw):
            # Only the per-finding artifact under out/analysis/ —
            # not the final report save.
            if str(Path(path).parent).endswith("/analysis"):
                raise OSError("disk full")
            return real_save_json(path, obj, **kw)

        monkeypatch.setattr(agent_mod, "save_json", _failing_save_json)

    stored: list[tuple] = []
    monkeypatch.setattr(
        hooks, "compute_finding_source_hash", lambda p, line: "h" * 16,
    )
    monkeypatch.setattr(
        hooks, "recall_prior_finding_verdict",
        lambda *a, **k: None,
    )
    monkeypatch.setattr(
        hooks, "store_finding_verdict",
        lambda *a, **k: (stored.append(a), True)[1],
    )

    the_finding = finding if finding is not None else _finding()
    monkeypatch.setattr(
        agent_mod, "parse_sarif_findings", lambda _p: [the_finding],
    )
    monkeypatch.setattr(agent_mod, "deduplicate_findings", lambda fs: fs)
    report = agent.process_findings(
        sarif_paths=["fake.sarif"], checklist=None, emit_journal=False,
    )
    return report, stored


class TestSageStoreGate:
    def test_errored_analysis_never_stores_a_verdict(
        self, tmp_path, monkeypatch,
    ):
        """A record marked status=error must not seed cross-run FP
        suppression — pre-fix the store gated on ``vuln.analysis``
        only, and the error path leaves that dict populated."""
        agent = _make_agent(tmp_path)
        report, stored = _run(agent, monkeypatch, analysis_crashes=True)

        rec = next(r for r in report["results"]
                   if r.get("finding_id") == "F1")
        assert rec.get("status") == "error"          # premise holds
        assert stored == []                          # no durable verdict

    def test_clean_analysis_still_stores(self, tmp_path, monkeypatch):
        """Control: the same verdict WITHOUT the crash stores as
        false_positive — the gate only excludes errored records."""
        agent = _make_agent(tmp_path)
        report, stored = _run(agent, monkeypatch, analysis_crashes=False)

        rec = next(r for r in report["results"]
                   if r.get("finding_id") == "F1")
        assert rec.get("status") != "error"
        assert len(stored) == 1
        assert stored[0][-1] == "false_positive"


class TestSageStoreAbstainedVerdicts:
    def test_nulled_verdict_fields_never_store(self, tmp_path, monkeypatch):
        """A CLEAN (non-errored) analysis whose verdict fields came
        back schema-nulled cast no verdict — `not None` reads as
        false_positive, so the pre-fix writer derived a durable
        suppression memory from an abstention."""
        agent = _make_agent(tmp_path)

        abstained = dict(_ANALYSIS)
        abstained["is_true_positive"] = None
        abstained["is_exploitable"] = None

        import core.llm.response_validation as rv
        import core.sage.hooks as hooks

        llm = MagicMock()
        llm.generate_structured.return_value = (abstained, "raw")
        agent.llm = llm
        monkeypatch.setattr(
            rv, "attempt_quality_retry",
            lambda client, validated, *a, **k: validated,
        )
        stored: list[tuple] = []
        monkeypatch.setattr(
            hooks, "compute_finding_source_hash", lambda p, line: "h" * 16,
        )
        monkeypatch.setattr(
            hooks, "recall_prior_finding_verdict", lambda *a, **k: None,
        )
        monkeypatch.setattr(
            hooks, "store_finding_verdict",
            lambda *a, **k: (stored.append(a), True)[1],
        )
        monkeypatch.setattr(
            agent_mod, "parse_sarif_findings", lambda _p: [_finding()],
        )
        monkeypatch.setattr(agent_mod, "deduplicate_findings", lambda fs: fs)
        report = agent.process_findings(
            sarif_paths=["fake.sarif"], checklist=None, emit_journal=False,
        )

        rec = next(r for r in report["results"]
                   if r.get("finding_id") == "F1")
        assert rec.get("status") != "error"          # clean run
        assert stored == []                          # no durable verdict


class TestSageHashReadBounded:
    def test_line0_fallback_hash_uses_capped_prefix(
        self, tmp_path, monkeypatch,
    ):
        """The whole-file hash fallback (finding with no line anchor)
        reads a target-repo file — bounded like every other read of
        that class. The stored identity is the hash of the capped
        prefix, so a giant mislabeled source file costs at most the
        cap instead of its full size."""
        from core.hash import sha256_string
        from core.source import DEFAULT_MAX_SOURCE_CHARS

        agent = _make_agent(tmp_path)
        big_text = "y" * (DEFAULT_MAX_SOURCE_CHARS + 4096)
        (tmp_path / "repo" / "src" / "auth.c").write_text(big_text)
        f = _finding()
        f["startLine"] = 0
        f["endLine"] = 0
        _report, stored = _run(
            agent, monkeypatch, analysis_crashes=False, finding=f,
        )
        assert len(stored) == 1
        expected = sha256_string(big_text[:DEFAULT_MAX_SOURCE_CHARS])[:12]
        assert stored[0][4] == expected
