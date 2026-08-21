"""Learned-models measurement pass on the /codeql agent."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.config import RaptorConfig
from packages.codeql.agent import CodeQLAgent, _write_candidates_sarif

REPO_ROOT = Path(__file__).resolve().parents[3]


def _sarif_result(uri: str, rule: str = "cpp/test-rule") -> dict:
    loc = {
        "location": {
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": 3},
            },
        },
    }
    return {
        "ruleId": rule,
        "message": {"text": "flow"},
        "locations": [loc["location"]],
        "codeFlows": [{"threadFlows": [{"locations": [loc, loc]}]}],
    }


def _augmented_sarif(tmp_path: Path, uris: list[str]) -> Path:
    sarif = {
        "version": "2.1.0",
        "runs": [{"results": [_sarif_result(u) for u in uris]}],
    }
    p = tmp_path / "augmented.sarif"
    p.write_text(json.dumps(sarif), encoding="utf-8")
    return p


def _new_ids_for(path: Path, rule: str | None = None) -> set[str]:
    from core.dataflow.adapters.codeql import from_sarif_result
    ids = set()
    for run in json.loads(path.read_text())["runs"]:
        for result in run["results"]:
            if rule is not None and result.get("ruleId") != rule:
                continue
            finding = from_sarif_result(result)
            if finding is not None:
                ids.add(finding.finding_id)
    return ids


class TestWriteCandidatesSarif:
    def test_filters_to_new_ids_and_stamps_provenance(self, tmp_path):
        sarif = {
            "version": "2.1.0",
            "runs": [{"results": [
                _sarif_result("a.c", rule="cpp/rule-a"),
                _sarif_result("b.c", rule="cpp/rule-b"),
            ]}],
        }
        aug = tmp_path / "augmented.sarif"
        aug.write_text(json.dumps(sarif), encoding="utf-8")
        only_b = _new_ids_for(aug, rule="cpp/rule-b")
        assert only_b
        out = _write_candidates_sarif(aug, only_b, tmp_path / "out.sarif")
        assert out is not None
        written = json.loads(Path(out).read_text())
        results = written["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["properties"]["provenance"] == "learned-model"

    def test_no_matching_ids_returns_none(self, tmp_path):
        aug = _augmented_sarif(tmp_path, ["a.c"])
        out = _write_candidates_sarif(
            aug, {"nonexistent"}, tmp_path / "out.sarif",
        )
        assert out is None
        assert not (tmp_path / "out.sarif").exists()

    def test_unreadable_input_returns_none(self, tmp_path):
        out = _write_candidates_sarif(
            tmp_path / "missing.sarif", {"x"}, tmp_path / "out.sarif",
        )
        assert out is None


class TestLearnedModelsPass:
    @pytest.fixture
    def agent(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "a.c").write_text("int main(void) { return 0; }\n")
        a = CodeQLAgent.__new__(CodeQLAgent)
        a.repo_path = repo
        a.out_dir = tmp_path / "out"
        a.out_dir.mkdir()
        return a

    @pytest.fixture
    def dbs(self):
        return {"cpp": SimpleNamespace(database_path="/tmp/db-cpp")}

    def test_kill_switch_returns_none(self, agent, dbs, monkeypatch):
        monkeypatch.setattr(
            RaptorConfig, "CODEQL_LEARNED_MODELS_ENABLED", False,
        )
        assert agent._run_learned_models_pass(dbs) is None

    def test_no_specs_returns_none(self, agent, dbs, monkeypatch):
        monkeypatch.setattr("core.iris.api.load_project_specs",
                            lambda **kw: [])
        assert agent._run_learned_models_pass(dbs) is None

    def test_unsupported_language_skipped(self, agent, monkeypatch):
        monkeypatch.setattr("core.iris.api.load_project_specs",
                            lambda **kw: [object()])
        dbs = {"go": SimpleNamespace(database_path="/tmp/db-go")}
        assert agent._run_learned_models_pass(dbs) is None

    def test_happy_path_records_cell_and_candidates(
        self, agent, dbs, tmp_path, monkeypatch,
    ):
        monkeypatch.setattr("core.iris.api.load_project_specs",
                            lambda **kw: [object()])
        conv = SimpleNamespace(rows=(object(),), rejected=())
        monkeypatch.setattr(
            "core.dataflow.extension_pack.rows_from_taint_specs",
            lambda specs, language: conv,
        )
        sarif = {
            "version": "2.1.0",
            "runs": [{"results": [
                _sarif_result("a.c", rule="cpp/rule-a"),
                _sarif_result("b.c", rule="cpp/rule-b"),
            ]}],
        }
        aug = tmp_path / "augmented.sarif"
        aug.write_text(json.dumps(sarif), encoding="utf-8")
        new = tuple(sorted(_new_ids_for(aug, rule="cpp/rule-b")))
        measurement = SimpleNamespace(
            pack=SimpleNamespace(rows_written=1, rejected=()),
            augmented=SimpleNamespace(sarif_path=aug),
            baseline=SimpleNamespace(sarif_path=aug),
            diff=SimpleNamespace(
                new_ids=new,
                suppressed_ids=("gone",),
                baseline_count=2,
                augmented_count=2,
            ),
        )
        monkeypatch.setattr(
            "core.dataflow.codeql_augmented_run"
            ".run_learned_models_measurement",
            lambda *a, **kw: measurement,
        )
        out = agent._run_learned_models_pass(dbs)
        assert out is not None and "cpp" in out
        cell = out["cpp"]
        assert cell["rows_written"] == 1
        assert cell["suppressed_ids"] == ["gone"]
        assert cell["candidates"] == 1
        assert cell["candidates_sarif"].endswith("codeql_cpp_learned.sarif")

    def test_measurement_failure_degrades(self, agent, dbs, monkeypatch):
        monkeypatch.setattr("core.iris.api.load_project_specs",
                            lambda **kw: [object()])
        conv = SimpleNamespace(rows=(object(),), rejected=())
        monkeypatch.setattr(
            "core.dataflow.extension_pack.rows_from_taint_specs",
            lambda specs, language: conv,
        )

        def boom(*a, **kw):
            raise ValueError("all rows rejected")

        monkeypatch.setattr(
            "core.dataflow.codeql_augmented_run"
            ".run_learned_models_measurement",
            boom,
        )
        assert agent._run_learned_models_pass(dbs) is None

    def test_zero_rows_skips_language(self, agent, dbs, monkeypatch):
        monkeypatch.setattr("core.iris.api.load_project_specs",
                            lambda **kw: [object()])
        conv = SimpleNamespace(rows=(), rejected=("r",))
        monkeypatch.setattr(
            "core.dataflow.extension_pack.rows_from_taint_specs",
            lambda specs, language: conv,
        )
        assert agent._run_learned_models_pass(dbs) is None


class TestCliFlag:
    @pytest.mark.parametrize("script", [
        REPO_ROOT / "packages" / "codeql" / "agent.py",
        REPO_ROOT / "raptor_codeql.py",
    ])
    def test_parsers_accept_no_learned_models(self, script):
        proc = subprocess.run(
            [sys.executable, str(script), "--help"],
            capture_output=True, text=True, timeout=60, check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert "--no-learned-models" in proc.stdout
