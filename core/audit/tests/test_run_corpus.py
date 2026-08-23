"""Tests for core.audit.corpus.run_corpus — bare-key fallback for
line-suffixed audit-log keys."""

import json
from types import SimpleNamespace

import pytest

import core.audit.corpus.run_corpus as rc


def _label(function_id, line_start=1, expected="finding", repo="repo",
           file="src/db.go"):
    return SimpleNamespace(
        function_id=function_id,
        bug_class="aliasing",
        expected_status=expected,
        # _run_audit reads these attribution/mode-expectation fields off
        # every label (FunctionLabel always carries them); the stub must
        # match the real shape.
        expected_mechanism="",
        expected_mode_results={},
        source=SimpleNamespace(
            repo=repo, file=file, line_start=line_start,
            line_end=line_start + 10,
        ),
    )


def _entry(key, status, action="orchestrator_review"):
    return {
        "action": action,
        "key": key,
        "status": status,
        "hypothesis": "h",
        "evidence_tool": "smt",
        "cost_usd": 0.0,
        "duration_s": 0.0,
    }


@pytest.fixture
def no_pipeline(monkeypatch):
    """Stop the real audit pipeline from running; the log is pre-written."""
    monkeypatch.setattr(
        "core.audit.pipeline.run_audit_pipeline", lambda opts: None,
    )


def _run_builder(tmp_path, log_entries):
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    (out / "checklist.json").write_text('{"files": []}\n')
    (out / ".audit-log.jsonl").write_text(
        "".join(json.dumps(e) + "\n" for e in log_entries),
    )
    outcomes, bare, _ = rc._run_audit_on_target(
        src, [_label("src/db.go:dummy")], out_dir=out,
    )
    return outcomes, bare


class TestBareKeyIndexBuilder:
    def test_line_suffixed_key_indexed_under_bare_form(
        self, tmp_path, no_pipeline,
    ):
        outcomes, bare = _run_builder(
            tmp_path, [_entry("src/db.go:Scan:33", "finding")],
        )
        assert "src/db.go:Scan:33" in outcomes
        assert "src/db.go:Scan" in outcomes
        assert bare["src/db.go:Scan"]["status"] == "finding"

    def test_highest_status_rank_wins_regardless_of_log_order(
        self, tmp_path, no_pipeline,
    ):
        _, bare = _run_builder(tmp_path, [
            _entry("src/db.go:Scan:33", "clean"),
            _entry("src/db.go:Scan:50", "finding"),
        ])
        assert bare["src/db.go:Scan"]["status"] == "finding"

        _, bare = _run_builder(tmp_path, [
            _entry("src/db.go:Scan:50", "finding"),
            _entry("src/db.go:Scan:33", "clean"),
        ])
        assert bare["src/db.go:Scan"]["status"] == "finding"

    def test_exact_bare_log_key_takes_precedence(self, tmp_path, no_pipeline):
        _, bare = _run_builder(tmp_path, [
            _entry("src/db.go:Scan:33", "finding"),
            _entry("src/db.go:Scan", "suspicious"),
        ])
        assert bare["src/db.go:Scan"]["status"] == "suspicious"

        _, bare = _run_builder(tmp_path, [
            _entry("src/db.go:Scan", "suspicious"),
            _entry("src/db.go:Scan:33", "finding"),
        ])
        assert bare["src/db.go:Scan"]["status"] == "suspicious"

    def test_rank_tie_keeps_first_log_entry(self, tmp_path, no_pipeline):
        _, bare = _run_builder(tmp_path, [
            _entry("src/db.go:Scan:33", "finding"),
            _entry("src/db.go:Scan:50", "finding"),
        ])
        assert bare["src/db.go:Scan"]["key"] == "src/db.go:Scan:33"


class TestAmbiguousStrippedKeyFallback:
    def test_line_mismatch_resolves_via_bare_fallback(
        self, tmp_path, no_pipeline, monkeypatch,
    ):
        """Two labels share a stripped method name (ambiguous).  The log
        verdict for one of them carries a line that matches neither label,
        so the exact line-key lookup misses — the bare fallback must still
        surface the finding instead of degrading it to error/clean."""
        monkeypatch.setattr(rc, "_start_shared_joern", lambda dirs: None)

        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        repo_out = out / "repo"
        repo_out.mkdir(parents=True)
        (repo_out / "checklist.json").write_text('{"files": []}\n')
        (repo_out / ".audit-log.jsonl").write_text(
            json.dumps(_entry("src/db.go:Scan:33", "finding")) + "\n"
            + json.dumps(_entry("src/db.go:Scan:50", "clean")) + "\n",
        )

        labels = [
            _label("src/db.go:Rows.Scan", line_start=10, expected="finding"),
            _label("src/db.go:Stmt.Scan", line_start=50, expected="clean"),
        ]
        results, _ = rc._run_audit(
            labels, {"repo": src}, out_dir=out,
        )

        by_id = {r["function_id"]: r for r in results}
        # Line 10 matches no log key: bare fallback resolves the finding.
        assert by_id["src/db.go:Rows.Scan"]["actual"] == "finding"
        assert by_id["src/db.go:Rows.Scan"]["match"] is True
        # Exact line-key match keeps precedence over the bare fallback.
        assert by_id["src/db.go:Stmt.Scan"]["actual"] == "clean"
        assert by_id["src/db.go:Stmt.Scan"]["match"] is True
