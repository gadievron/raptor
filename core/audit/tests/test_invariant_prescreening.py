"""Tests for _run_invariant_prescreening in orchestrator."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


def _make_config(target_path: Path, out_dir: Path) -> SimpleNamespace:
    return SimpleNamespace(target_path=target_path, out_dir=out_dir)


def _make_match(file: str, line: int, snippet: str = ""):
    return SimpleNamespace(file=file, line=line, snippet=snippet)


class TestInvariantPrescreening:
    def test_no_domain_model(self, tmp_path):
        from core.audit.orchestrator import _run_invariant_prescreening

        config = _make_config(tmp_path, tmp_path / "out")
        result = _run_invariant_prescreening(None, config, [], {})
        assert result == 0

    def test_no_compiled_invariants(self, tmp_path):
        from core.audit.orchestrator import _run_invariant_prescreening

        dm = {"invariants": [{"id": "x", "statement": "y"}]}
        config = _make_config(tmp_path, tmp_path / "out")
        result = _run_invariant_prescreening(dm, config, [], {})
        assert result == 0

    def test_rule_file_not_found(self, tmp_path):
        from core.audit.orchestrator import _run_invariant_prescreening

        dm = {
            "invariants": [
                {
                    "id": "fmt",
                    "statement": "no user-controlled format strings",
                    "mechanical_rule": "inv.fmt.semgrep.0",
                },
            ],
        }
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        config = _make_config(tmp_path, out_dir)
        result = _run_invariant_prescreening(dm, config, [], {})
        assert result == 0

    def test_matches_injected(self, tmp_path):
        from core.audit.orchestrator import _run_invariant_prescreening

        out_dir = tmp_path / "out"
        checkers_dir = out_dir / "checkers"
        checkers_dir.mkdir(parents=True)
        rule_file = checkers_dir / "inv.fmt.semgrep.0.yml"
        rule_file.write_text("rules:\n- id: test\n  pattern: printf($FMT)\n")

        dm = {
            "invariants": [
                {
                    "id": "fmt",
                    "statement": "no user-controlled format strings",
                    "mechanical_rule": "inv.fmt.semgrep.0",
                },
            ],
        }

        gaps = [
            {"file": "src/log.c", "name": "do_log", "line_start": 10, "line_end": 30},
            {"file": "src/log.c", "name": "init_log", "line_start": 1, "line_end": 9},
        ]

        matches = [_make_match("src/log.c", 15), _make_match("src/log.c", 25)]
        mechanical_findings: dict = {}

        config = _make_config(tmp_path, out_dir)

        with patch(
            "packages.checker_synthesis.synthesise._run_engine",
            return_value=(matches, []),
        ):
            result = _run_invariant_prescreening(
                dm, config, gaps, mechanical_findings,
            )

        assert result == 2
        key = "src/log.c:do_log"
        assert key in mechanical_findings
        assert len(mechanical_findings[key]) == 2
        assert mechanical_findings[key][0]["detector"] == "invariant_rule"
        assert mechanical_findings[key][0]["line"] == 15
        assert "inv.fmt.semgrep.0" in mechanical_findings[key][0]["description"]

    def test_match_outside_any_function_skipped(self, tmp_path):
        from core.audit.orchestrator import _run_invariant_prescreening

        out_dir = tmp_path / "out"
        checkers_dir = out_dir / "checkers"
        checkers_dir.mkdir(parents=True)
        (checkers_dir / "inv.x.semgrep.0.yml").write_text("rules: []")

        dm = {
            "invariants": [
                {"id": "x", "statement": "s", "mechanical_rule": "inv.x.semgrep.0"},
            ],
        }
        gaps = [
            {"file": "a.c", "name": "foo", "line_start": 10, "line_end": 20},
        ]
        matches = [_make_match("a.c", 5)]  # outside foo's range
        mechanical_findings: dict = {}
        config = _make_config(tmp_path, out_dir)

        with patch(
            "packages.checker_synthesis.synthesise._run_engine",
            return_value=(matches, []),
        ):
            result = _run_invariant_prescreening(
                dm, config, gaps, mechanical_findings,
            )

        assert result == 0
        assert not mechanical_findings

    def test_coccinelle_engine_detected(self, tmp_path):
        from core.audit.orchestrator import _run_invariant_prescreening

        out_dir = tmp_path / "out"
        checkers_dir = out_dir / "checkers"
        checkers_dir.mkdir(parents=True)
        rule_file = checkers_dir / "inv.dbl.coccinelle.0.cocci"
        rule_file.write_text("@@\nexpression E;\n@@\n- free(E);\n  ...\n- free(E);\n")

        dm = {
            "invariants": [
                {
                    "id": "dbl",
                    "statement": "no double free",
                    "mechanical_rule": "inv.dbl.coccinelle.0",
                },
            ],
        }
        gaps = [
            {"file": "mem.c", "name": "cleanup", "line_start": 1, "line_end": 50},
        ]
        matches = [_make_match("mem.c", 30)]
        mechanical_findings: dict = {}
        config = _make_config(tmp_path, out_dir)

        with patch(
            "packages.checker_synthesis.synthesise._run_engine",
            return_value=(matches, []),
        ) as mock_run:
            result = _run_invariant_prescreening(
                dm, config, gaps, mechanical_findings,
            )

        assert result == 1
        rule_arg = mock_run.call_args[0][0]
        assert rule_arg.engine == "coccinelle"

    def test_appends_to_existing_findings(self, tmp_path):
        from core.audit.orchestrator import _run_invariant_prescreening

        out_dir = tmp_path / "out"
        checkers_dir = out_dir / "checkers"
        checkers_dir.mkdir(parents=True)
        (checkers_dir / "inv.x.semgrep.0.yml").write_text("rules: []")

        dm = {
            "invariants": [
                {"id": "x", "statement": "s", "mechanical_rule": "inv.x.semgrep.0"},
            ],
        }
        gaps = [
            {"file": "a.c", "name": "foo", "line_start": 1, "line_end": 50},
        ]
        mechanical_findings: dict = {
            "a.c:foo": [
                {"file": "a.c", "function": "foo", "detector": "condition_chain",
                 "line": 5, "description": "existing"},
            ],
        }
        config = _make_config(tmp_path, out_dir)

        with patch(
            "packages.checker_synthesis.synthesise._run_engine",
            return_value=([_make_match("a.c", 10)], []),
        ):
            result = _run_invariant_prescreening(
                dm, config, gaps, mechanical_findings,
            )

        assert result == 1
        assert len(mechanical_findings["a.c:foo"]) == 2
        assert mechanical_findings["a.c:foo"][1]["detector"] == "invariant_rule"

    def test_checkers_in_project_concepts_dir(self, tmp_path):
        """Rule found in <project>/concepts/checkers/ (canonical location)."""
        from core.audit.orchestrator import _run_invariant_prescreening

        project_dir = tmp_path / "project"
        out_dir = project_dir / "run_001"
        out_dir.mkdir(parents=True)
        concepts_checkers = project_dir / "concepts" / "checkers"
        concepts_checkers.mkdir(parents=True)
        (concepts_checkers / "inv.x.semgrep.0.yml").write_text("rules: []")

        dm = {
            "invariants": [
                {"id": "x", "statement": "s", "mechanical_rule": "inv.x.semgrep.0"},
            ],
        }
        gaps = [
            {"file": "a.c", "name": "foo", "line_start": 1, "line_end": 50},
        ]
        mechanical_findings: dict = {}
        config = _make_config(tmp_path, out_dir)

        with patch(
            "packages.checker_synthesis.synthesise._run_engine",
            return_value=([_make_match("a.c", 10)], []),
        ):
            result = _run_invariant_prescreening(
                dm, config, gaps, mechanical_findings,
            )

        assert result == 1
