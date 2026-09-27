"""File-scoped Coccinelle memoization.

spatch scans the whole file regardless of which function is under
audit, so the orchestrator's coccinelle leg memoizes the FILE sweep
(one spatch per rule-content x file-content) and derives each
function's verdict afterwards. Covers: per-function match
attribution, single-spawn across functions, error results never
pinned, substrate skips preserved, and the byte-compatible
single-function wrapper (including both directions of its +50
fallback window). Hermetic — spatch is stubbed at the
``packages.coccinelle.runner`` boundary.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from core.audit.orchestrator import _run_tool_chain
from core.audit.substrate import _reset_substrate_caches
from core.audit.sweep import (
    run_coccinelle_file_sweep,
    run_coccinelle_sweep,
    scope_coccinelle_result,
)
from core.audit.sweep_memo import SweepMemo


@pytest.fixture(autouse=True)
def _fresh_caches():
    _reset_substrate_caches()
    yield
    _reset_substrate_caches()


class _Cfg:
    """Minimal OrchestratorConfig stand-in for _run_tool_chain."""

    def __init__(self, target: Path):
        self.target_path = target
        self.out_dir = None
        self.codeql_db_path = None
        self.project_sinks = None
        self.sweep_memo = SweepMemo()


class _Match:
    def __init__(self, line: int):
        self.line = line

    def to_dict(self) -> dict[str, Any]:
        return {"line": self.line, "file": "src/a.c"}


def _stub_runner(
    monkeypatch,
    *,
    match_lines: list[int] | None = None,
    returncode: int = 0,
    errors: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Fake ``packages.coccinelle.runner``; returns the call log."""
    import packages.coccinelle.runner as cocci_runner

    calls: list[dict[str, Any]] = []

    def _run_rule(target, rule, **kw):
        rule_text = ""
        try:
            rule_text = Path(rule).read_text()
        except OSError:
            pass
        calls.append({
            "target": str(target), "rule": str(rule),
            "rule_text": rule_text,
        })
        return SimpleNamespace(
            matches=[_Match(n) for n in (match_lines or [])],
            errors=list(errors or []),
            returncode=returncode,
        )

    monkeypatch.setattr(cocci_runner, "is_available", lambda: True)
    monkeypatch.setattr(cocci_runner, "run_rule", _run_rule)
    return calls


def _write_tree(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir(exist_ok=True)
    body = "int f(void){ return 0; }\n" * 120
    (tmp_path / "src" / "a.c").write_text(body)
    (tmp_path / "src" / "index.php").write_text(
        "<?php function f() { return 0; }\n",
    )
    rule = tmp_path / "rules" / "check.cocci"
    rule.parent.mkdir(exist_ok=True)
    rule.write_text("@@ @@\n")
    return rule


def _dispatch(
    cfg: _Cfg,
    rule: Path,
    *,
    function_name: str,
    line_start: int,
    file_path: str = "src/a.c",
    domain_vocab: Any = None,
    skipped: set | None = None,
) -> list[str]:
    return _run_tool_chain(
        [{"type": "coccinelle", "config": {"rule": str(rule)}}],
        config=cfg,
        file_path=file_path,
        function_name=function_name,
        source="",
        hypothesis="use after free of `p`",
        line_start=line_start,
        domain_vocab=domain_vocab,
        skipped_types=skipped,
    )


class TestFileScopedMemoAttribution:
    def test_match_confirms_the_owning_function_only(
        self, tmp_path, monkeypatch,
    ):
        """One spatch run; the match at line 2 confirms the function
        that spans it and NOT a later function in the same file."""
        rule = _write_tree(tmp_path)
        calls = _stub_runner(monkeypatch, match_lines=[2])
        cfg = _Cfg(tmp_path)

        confirmed_a = _dispatch(cfg, rule, function_name="a", line_start=1)
        confirmed_b = _dispatch(cfg, rule, function_name="b", line_start=100)

        assert confirmed_a == ["coccinelle:check"]
        assert confirmed_b == []
        assert len(calls) == 1, (
            "the second function in the same file must replay the "
            "memoized file sweep, not spawn a second spatch"
        )

    def test_error_results_never_pinned(self, tmp_path, monkeypatch):
        rule = _write_tree(tmp_path)
        calls = _stub_runner(monkeypatch, returncode=2)
        cfg = _Cfg(tmp_path)

        _dispatch(cfg, rule, function_name="a", line_start=1)
        _dispatch(cfg, rule, function_name="b", line_start=100)

        assert len(calls) == 2, (
            "a failed spatch run must be retried on the next dispatch"
        )

    def test_substrate_skip_preserved_without_spawning(
        self, tmp_path, monkeypatch,
    ):
        rule = _write_tree(tmp_path)
        calls = _stub_runner(monkeypatch, match_lines=[2])
        cfg = _Cfg(tmp_path)

        skipped: set = set()
        confirmed = _dispatch(
            cfg, rule, function_name="f", line_start=1,
            file_path="src/index.php", skipped=skipped,
        )
        assert confirmed == []
        assert "coccinelle" in skipped
        assert not calls, "spatch must not spawn on a PHP subject"


class TestSingleFunctionWrapper:
    """run_coccinelle_sweep keeps its historical semantics."""

    def test_in_range_match_confirms(self, tmp_path, monkeypatch):
        rule = _write_tree(tmp_path)
        _stub_runner(monkeypatch, match_lines=[2])
        res = run_coccinelle_sweep(
            target_path=tmp_path, file_path="src/a.c",
            function_name="f", cocci_rule=str(rule),
            line_start=1, line_end=10,
        )
        assert res.outcome == "confirmed"
        assert res.function_name == "f"
        assert res.matches == [{"line": 2, "file": "src/a.c"}]
        assert res.rule_id == str(rule)

    def test_out_of_range_match_refutes(self, tmp_path, monkeypatch):
        rule = _write_tree(tmp_path)
        _stub_runner(monkeypatch, match_lines=[80])
        res = run_coccinelle_sweep(
            target_path=tmp_path, file_path="src/a.c",
            function_name="f", cocci_rule=str(rule),
            line_start=1, line_end=10,
        )
        assert res.outcome == "refuted"
        assert res.matches == []

    def test_fallback_window_boundary_both_directions(
        self, tmp_path, monkeypatch,
    ):
        """Without line_end, the +50 window binds exactly: a match AT
        line_start+50 confirms, one line past it refutes."""
        rule = _write_tree(tmp_path)
        _stub_runner(monkeypatch, match_lines=[51])
        inside = run_coccinelle_sweep(
            target_path=tmp_path, file_path="src/a.c",
            function_name="f", cocci_rule=str(rule), line_start=1,
        )
        assert inside.outcome == "confirmed"

        _stub_runner(monkeypatch, match_lines=[52])
        outside = run_coccinelle_sweep(
            target_path=tmp_path, file_path="src/a.c",
            function_name="f", cocci_rule=str(rule), line_start=1,
        )
        assert outside.outcome == "refuted"

    def test_containment_escape_keeps_empty_function_name(
        self, tmp_path, monkeypatch,
    ):
        _stub_runner(monkeypatch)
        res = run_coccinelle_sweep(
            target_path=tmp_path, file_path="../../etc/shadow",
            function_name="foo", cocci_rule="rule.cocci",
        )
        assert res.outcome == "error"
        assert res.function_name == ""
        assert any("escapes" in e for e in res.errors)

    def test_refutation_carries_substrate_receipt(
        self, tmp_path, monkeypatch,
    ):
        rule = _write_tree(tmp_path)
        _stub_runner(monkeypatch, match_lines=[])
        res = run_coccinelle_sweep(
            target_path=tmp_path, file_path="src/a.c",
            function_name="f", cocci_rule=str(rule), line_start=1,
        )
        assert res.outcome == "refuted"
        assert res.details["substrate"]["covered"] is True


class TestScoperIsolation:
    def test_scoping_never_mutates_the_file_result(self, tmp_path):
        from core.audit.sweep import SweepResult

        file_result = SweepResult(
            tool="coccinelle", file_path="src/a.c", function_name="",
            outcome="confirmed", rule_id="r.cocci",
            matches=[{"line": 2}, {"line": 80}],
        )
        scoped = scope_coccinelle_result(
            file_result, target_path=tmp_path, function_name="f",
            line_start=1, line_end=10,
        )
        assert scoped.matches == [{"line": 2}]
        scoped.matches.append({"line": 999})
        assert file_result.matches == [{"line": 2}, {"line": 80}]
        assert file_result.function_name == ""

    def test_file_sweep_is_file_scoped(self, tmp_path, monkeypatch):
        rule = _write_tree(tmp_path)
        _stub_runner(monkeypatch, match_lines=[80])
        res = run_coccinelle_file_sweep(
            target_path=tmp_path, file_path="src/a.c",
            cocci_rule=str(rule),
        )
        assert res.outcome == "confirmed"
        assert res.function_name == ""
        assert res.matches == [{"line": 80, "file": "src/a.c"}]
