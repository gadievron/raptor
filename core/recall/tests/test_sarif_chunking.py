"""Oversized-SARIF chunking in collect_findings.

The scan pipeline's merge drops per-tool SARIFs above the parser's
size guard (with an ERROR); the measurement harness must re-read
those via chunking rather than silently undercount a tool — observed
live: a 218 MiB CodeQL SARIF reduced that engine's contribution to
zero on the Juliet corpus.
"""

from __future__ import annotations

import json
from pathlib import Path

import core.recall.runner as runner_mod
from core.recall.runner import collect_findings


def _sarif_doc(tool: str, n: int, rule: str = "java/sql-injection") -> dict:
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool, "rules": [{"id": rule}]}},
            "results": [
                {
                    "ruleId": rule,
                    "message": {"text": f"finding {i}"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"src/F{i}.java"},
                            "region": {"startLine": 10 + i},
                        },
                    }],
                }
                for i in range(n)
            ],
        }],
    }


def _write(path: Path, doc: dict) -> Path:
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


class TestChunkedCollection:
    def test_oversized_per_tool_sarif_is_recovered(self, tmp_path,
                                                   monkeypatch):
        # combined carries only the small tool (the merge dropped the
        # big one); the harness must still see the big tool's findings.
        _write(tmp_path / "combined.sarif", _sarif_doc("Semgrep OSS", 3))
        big = _write(tmp_path / "codeql_java.sarif",
                     _sarif_doc("CodeQL", 40))
        monkeypatch.setattr(runner_mod, "_SARIF_CHUNK_THRESHOLD",
                            big.stat().st_size - 1)
        monkeypatch.setattr(runner_mod, "_SARIF_CHUNK_TARGET",
                            big.stat().st_size // 4)
        found = collect_findings(tmp_path)
        tools = {f.get("tool") for f in found}
        assert "CodeQL" in tools
        codeql = [f for f in found if f.get("tool") == "CodeQL"]
        assert len(codeql) == 40

    def test_no_double_count_when_merge_kept_the_tool(self, tmp_path,
                                                      monkeypatch):
        # Same finding in combined AND the oversized per-tool file
        # must count once (dedup key: tool/rule/file/startLine).
        doc = _sarif_doc("CodeQL", 5)
        _write(tmp_path / "combined.sarif", doc)
        big = _write(tmp_path / "codeql_java.sarif", doc)
        monkeypatch.setattr(runner_mod, "_SARIF_CHUNK_THRESHOLD",
                            big.stat().st_size - 1)
        found = collect_findings(tmp_path)
        assert len([f for f in found if f.get("tool") == "CodeQL"]) == 5

    def test_above_hard_cap_refused_loudly(self, tmp_path, monkeypatch,
                                           caplog):
        _write(tmp_path / "codeql_java.sarif", _sarif_doc("CodeQL", 10))
        monkeypatch.setattr(runner_mod, "_SARIF_CHUNK_THRESHOLD", 1)
        monkeypatch.setattr(runner_mod, "_SARIF_CHUNK_CAP", 2)
        with caplog.at_level("ERROR"):
            found = collect_findings(tmp_path)
        assert not [f for f in found if f.get("tool") == "CodeQL"]
        assert any("measurement cap" in r.message for r in caplog.records)

    def test_normal_sizes_unchanged(self, tmp_path):
        _write(tmp_path / "combined.sarif", _sarif_doc("Semgrep OSS", 4))
        _write(tmp_path / "codeql_java.sarif", _sarif_doc("CodeQL", 2))
        found = collect_findings(tmp_path)
        # combined preferred; small per-tool not re-read
        assert {f.get("tool") for f in found} == {"Semgrep OSS"}
        assert len(found) == 4

    def test_chunker_covers_every_result(self, tmp_path, monkeypatch):
        big = _write(tmp_path / "codeql_java.sarif",
                     _sarif_doc("CodeQL", 101))
        monkeypatch.setattr(runner_mod, "_SARIF_CHUNK_THRESHOLD",
                            big.stat().st_size - 1)
        monkeypatch.setattr(runner_mod, "_SARIF_CHUNK_TARGET",
                            max(1, big.stat().st_size // 7))
        chunks = runner_mod._chunk_oversized_sarif(big, tmp_path)
        assert len(chunks) >= 2
        total = 0
        lines = set()
        for c in chunks:
            doc = json.loads(c.read_text())
            for run in doc["runs"]:
                total += len(run["results"])
                for res in run["results"]:
                    lines.add(res["locations"][0]["physicalLocation"]
                              ["region"]["startLine"])
        assert total == 101
        assert len(lines) == 101

    def test_nonuniform_results_never_exceed_target(self, tmp_path,
                                                    monkeypatch):
        # One fat result (simulating codeFlows) among thin ones must
        # not produce an over-target chunk — the live failure mode.
        doc = _sarif_doc("CodeQL", 30)
        doc["runs"][0]["results"][0]["codeFlows"] = [
            {"threadFlows": [{"locations": [{"x": "y" * 5000}] * 40}]}]
        big = _write(tmp_path / "codeql_java.sarif", doc)
        import json as _json
        target = 4000
        monkeypatch.setattr(runner_mod, "_SARIF_CHUNK_THRESHOLD",
                            big.stat().st_size - 1)
        monkeypatch.setattr(runner_mod, "_SARIF_CHUNK_TARGET", target)
        chunks = runner_mod._chunk_oversized_sarif(big, tmp_path)
        total = 0
        for c in chunks:
            d = _json.loads(c.read_text())
            results = d["runs"][0]["results"]
            total += len(results)
            body = sum(len(_json.dumps(r)) for r in results)
            # a single result may exceed the target on its own; a
            # multi-result batch must not
            assert len(results) == 1 or body <= target
        assert total == 30

    def test_fat_header_budgeted_and_artifacts_shed(self, tmp_path,
                                                    monkeypatch):
        # A huge run header (rules metadata + artifacts index) must not
        # ride every chunk over the parser guard — the live 133 MiB-
        # chunk failure mode. The droppable artifacts index is shed.
        import json as _json
        doc = _sarif_doc("CodeQL", 20)
        doc["runs"][0]["artifacts"] = [
            {"location": {"uri": f"src/F{i}.java", "x": "y" * 300}}
            for i in range(50)]
        big = _write(tmp_path / "codeql_java.sarif", doc)
        target = len(_json.dumps(doc["runs"][0]["artifacts"])) // 2
        monkeypatch.setattr(runner_mod, "_SARIF_CHUNK_THRESHOLD",
                            big.stat().st_size - 1)
        monkeypatch.setattr(runner_mod, "_SARIF_CHUNK_TARGET", target)
        chunks = runner_mod._chunk_oversized_sarif(big, tmp_path)
        assert chunks, "header shedding should have rescued the chunking"
        total = 0
        for c in chunks:
            d = _json.loads(c.read_text())
            assert "artifacts" not in d["runs"][0]
            total += len(d["runs"][0]["results"])
        assert total == 20

