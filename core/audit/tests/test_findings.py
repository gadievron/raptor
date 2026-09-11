"""Tests for core.audit.findings — findings emission."""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.findings import (
    emit_finding,
    load_findings,
    write_findings,
)


class TestEmitFinding:
    def test_basic_finding(self, tmp_path: Path):
        finding = emit_finding(
            out_dir=tmp_path,
            file_path="src/handler.c",
            function_name="parse_request",
            line=42,
            title="Buffer overflow in parse_request",
            description="Unbounded memcpy with user-controlled length.",
            cwe="CWE-120",
            severity="high",
            tool_evidence=[
                {"tool": "semgrep", "rule": "unbounded-memcpy", "output": "match at line 42"},
            ],
            hypothesis="If user-supplied length exceeds buffer size, memcpy overflows.",
        )

        assert finding["file"] == "src/handler.c"
        assert finding["cwe"] == "CWE-120"
        assert finding["origin"] == "audit"
        assert len(finding["tool_evidence"]) == 1

        findings = load_findings(tmp_path)
        assert len(findings) == 1

    def test_finding_without_cwe(self, tmp_path: Path):
        finding = emit_finding(
            out_dir=tmp_path,
            file_path="src/splice.c",
            function_name="do_splice",
            line=100,
            title="Page cache aliasing",
            description="Read-only pages aliased into writable buffer.",
        )

        assert finding["vuln_type"] == "novel"
        assert "cwe" not in finding

    def test_multiple_findings_appended(self, tmp_path: Path):
        emit_finding(
            out_dir=tmp_path,
            file_path="a.c",
            function_name="f1",
            line=10,
            title="First",
            description="First finding.",
        )
        emit_finding(
            out_dir=tmp_path,
            file_path="b.c",
            function_name="f2",
            line=20,
            title="Second",
            description="Second finding.",
        )

        findings = load_findings(tmp_path)
        assert len(findings) == 2
        assert findings[0]["title"] == "First"
        assert findings[1]["title"] == "Second"


class TestLoadFindings:
    def test_load_list_format(self, tmp_path: Path):
        (tmp_path / "findings.json").write_text(json.dumps([
            {"title": "A", "file": "a.c"},
        ]))
        findings = load_findings(tmp_path)
        assert len(findings) == 1

    def test_load_dict_format(self, tmp_path: Path):
        (tmp_path / "findings.json").write_text(json.dumps({
            "findings": [
                {"title": "A", "file": "a.c"},
            ],
        }))
        findings = load_findings(tmp_path)
        assert len(findings) == 1

    def test_load_missing(self, tmp_path: Path):
        findings = load_findings(tmp_path)
        assert findings == []


class TestWriteFindings:
    def test_writes_json(self, tmp_path: Path):
        findings = [{"title": "Test", "file": "a.c", "line": 1}]
        path = write_findings(findings, tmp_path)
        assert path.exists()

        with open(path) as f:
            data = json.load(f)
        assert len(data) == 1


class TestPersistFindings:
    """_persist_findings is the (idempotent, atomic) full rewrite the
    orchestrator repeats after the last status-mutating pass: late-
    minted findings must appear, retracted ones must disappear, and a
    zero-finding run must not create an empty file."""

    @staticmethod
    def _result(*statuses):
        from core.audit.orchestrator import OrchestratorResult, ReviewOutcome

        result = OrchestratorResult()
        for i, status in enumerate(statuses):
            result.outcomes.append(ReviewOutcome(
                file=f"src/f{i}.c", function=f"fn{i}", status=status,
                body="b", hypothesis=f"h{i}",
            ))
        return result

    @staticmethod
    def _config(tmp_path):
        from core.audit.orchestrator import OrchestratorConfig

        return OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)

    def test_late_minted_finding_written_after_re_persist(self, tmp_path):
        from core.audit.orchestrator import _persist_findings

        result = self._result("clean")
        config = self._config(tmp_path)
        _persist_findings(result, config)  # mid-pipeline: no findings yet
        assert not (tmp_path / "findings.json").exists()

        # A post-loop pass promotes the outcome to finding.
        result.outcomes[0].status = "finding"
        _persist_findings(result, config)
        data = json.loads((tmp_path / "findings.json").read_text())
        assert len(data) == 1
        assert data[0]["function"] == "fn0"

    def test_retracted_finding_removed_on_re_persist(self, tmp_path):
        from core.audit.orchestrator import _persist_findings

        result = self._result("finding", "finding")
        config = self._config(tmp_path)
        _persist_findings(result, config)
        assert len(json.loads((tmp_path / "findings.json").read_text())) == 2

        # A post-loop pass retracts both (e.g. absent demotion).
        for o in result.outcomes:
            o.status = "dormant"
        _persist_findings(result, config)
        assert json.loads((tmp_path / "findings.json").read_text()) == []

    def test_zero_findings_never_creates_file(self, tmp_path):
        from core.audit.orchestrator import _persist_findings

        _persist_findings(self._result("clean", "error"), self._config(tmp_path))
        assert not (tmp_path / "findings.json").exists()

    def test_idempotent_rewrite(self, tmp_path):
        from core.audit.orchestrator import _persist_findings

        result = self._result("finding")
        config = self._config(tmp_path)
        _persist_findings(result, config)
        first = (tmp_path / "findings.json").read_text()
        _persist_findings(result, config)
        assert (tmp_path / "findings.json").read_text() == first


class TestFindingsRobustness:
    def test_scalar_findings_json_degrades_to_empty(self, tmp_path):
        # Wrong-shaped VALID JSON must degrade like corrupt content
        # (the docstring contract) — it used to raise AttributeError
        # out of the record CLI.
        from core.audit.findings import load_findings

        (tmp_path / "findings.json").write_text("5")
        assert load_findings(tmp_path) == []

    def test_dict_with_non_list_findings_degrades(self, tmp_path):
        from core.audit.findings import load_findings

        (tmp_path / "findings.json").write_text('{"findings": 7}')
        assert load_findings(tmp_path) == []

    def test_next_id_survives_external_deletion(self, tmp_path):
        # len()+1 collided after any deletion; ids now go above every
        # existing numeric suffix.
        from core.audit.findings import emit_finding, load_findings

        for n in (1, 2, 3):
            emit_finding(
                out_dir=tmp_path, file_path="a.c", function_name="f",
                line=n, title=f"t{n}", description="d",
            )
        rows = load_findings(tmp_path)
        rows = [r for r in rows if r["id"] != "AUDIT-002"]
        from core.audit.findings import write_findings
        write_findings(rows, tmp_path)
        f4 = emit_finding(
            out_dir=tmp_path, file_path="a.c", function_name="f",
            line=4, title="t4", description="d",
        )
        assert f4["id"] == "AUDIT-004"
        ids = [r["id"] for r in load_findings(tmp_path)]
        assert len(ids) == len(set(ids))

    def test_concurrent_emitters_lose_nothing(self, tmp_path):
        # Two processes appending under the advisory lock: all
        # findings land, ids unique (the unlocked read-modify-write
        # lost one and duplicated the id).
        import multiprocessing as mp

        from core.audit.findings import load_findings

        procs = [
            mp.Process(target=_emit_many, args=(tmp_path, tag))
            for tag in ("a", "b")
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join()
        rows = load_findings(tmp_path)
        assert len(rows) == 10
        ids = [r["id"] for r in rows]
        assert len(set(ids)) == 10


def _emit_many(out_dir, tag):
    from core.audit.findings import emit_finding

    for i in range(5):
        emit_finding(
            out_dir=out_dir, file_path="a.c", function_name=f"{tag}{i}",
            line=i, title=f"{tag}{i}", description="d",
        )
