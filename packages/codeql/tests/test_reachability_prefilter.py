"""Tests for the CodeQL autonomous analyzer's reachability
prefilter — the inventory-based pre-check that short-circuits
expensive LLM analysis when the sink function isn't called from
anywhere in the project."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from packages.codeql.autonomous_analyzer import (
    AutonomousCodeQLAnalyzer,
    CodeQLFinding,
)


def _analyzer() -> AutonomousCodeQLAnalyzer:
    """Construct an analyzer with mocked LLM + validator."""
    return AutonomousCodeQLAnalyzer(
        llm_client=MagicMock(),
        exploit_validator=MagicMock(),
        multi_turn_analyzer=None,
        enable_visualization=False,
    )


def _finding(file_path: str, line: int = 10) -> CodeQLFinding:
    return CodeQLFinding(
        rule_id="py/sql-injection",
        rule_name="SQL injection",
        message="Tainted data flows to a SQL query",
        level="error",
        file_path=file_path,
        start_line=line,
        end_line=line,
        snippet="cursor.execute(query)",
    )


# ---------------------------------------------------------------------------
# _path_to_module helper
# ---------------------------------------------------------------------------


def test_path_to_module_simple():
    a = _analyzer()
    assert a._path_to_module("packages/foo/bar.py") == "packages.foo.bar"


def test_path_to_module_handles_windows_separators():
    a = _analyzer()
    assert a._path_to_module(
        "packages\\foo\\bar.py"
    ) == "packages.foo.bar"


def test_path_to_module_returns_none_without_extension():
    a = _analyzer()
    assert a._path_to_module("Makefile") is None


def test_path_to_module_strips_extension():
    a = _analyzer()
    assert a._path_to_module("src/main.go") == "src.main"
    assert a._path_to_module("src/main.js") == "src.main"


def test_path_to_module_empty():
    a = _analyzer()
    assert a._path_to_module("") is None


# ---------------------------------------------------------------------------
# _check_reachability — end-to-end on a real source tree
# ---------------------------------------------------------------------------


def test_reachability_called_for_used_function(tmp_path):
    """A function that's called from another function in the
    project returns ``"called"``."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "vuln.py").write_text(
        "def vulnerable(query):\n"
        "    cursor.execute(query)\n"
    )
    (src / "main.py").write_text(
        "from src.vuln import vulnerable\n"
        "def main():\n"
        "    vulnerable('SELECT 1')\n"
    )
    a = _analyzer()
    finding = _finding("src/vuln.py", line=2)
    verdict = a._check_reachability(finding, tmp_path)
    assert verdict == "called"


def test_reachability_not_called_for_dead_function(tmp_path):
    """A function that nothing else calls — sink is in dead code."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "vuln.py").write_text(
        "def dead_handler(query):\n"
        "    cursor.execute(query)\n"
        "\n"
        "def other():\n"
        "    pass\n"
    )
    (src / "main.py").write_text(
        "from src.vuln import other\n"
        "def main():\n"
        "    other()\n"
    )
    a = _analyzer()
    finding = _finding("src/vuln.py", line=2)
    verdict = a._check_reachability(finding, tmp_path)
    assert verdict == "not_called"


def test_reachability_uncertain_with_dynamic_dispatch(tmp_path):
    """A file using getattr to dispatch by name on a tail-matching
    target → UNCERTAIN."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "vuln.py").write_text(
        "def affected(query):\n"
        "    cursor.execute(query)\n"
    )
    (src / "main.py").write_text(
        "from src import vuln\n"
        "def main():\n"
        "    fn = getattr(vuln, 'affected')\n"
        "    fn('SELECT 1')\n"
    )
    a = _analyzer()
    finding = _finding("src/vuln.py", line=2)
    verdict = a._check_reachability(finding, tmp_path)
    assert verdict == "uncertain"


def test_reachability_returns_none_for_unknown_file(tmp_path):
    """Sink path doesn't exist in the inventory → can't determine."""
    (tmp_path / "main.py").write_text("def f(): pass\n")
    a = _analyzer()
    finding = _finding("nonexistent/file.py", line=1)
    verdict = a._check_reachability(finding, tmp_path)
    assert verdict is None


def test_reachability_returns_none_when_sink_outside_function(tmp_path):
    """Sink line outside any function (module-level statement) →
    no enclosing function to query → None."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "vuln.py").write_text(
        "# line 1\n"
        "x = 1\n"               # module-level, no enclosing function
        "def f():\n"
        "    pass\n"
    )
    a = _analyzer()
    finding = _finding("src/vuln.py", line=2)
    verdict = a._check_reachability(finding, tmp_path)
    assert verdict is None


def test_reachability_inventory_cache_reused(tmp_path):
    """Two consecutive calls reuse the inventory build."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "f.py").write_text("def x(): pass\n")
    a = _analyzer()
    f1 = _finding("src/f.py", line=1)
    a._check_reachability(f1, tmp_path)
    inv_after_first = a._reachability_inventory
    a._check_reachability(f1, tmp_path)
    assert a._reachability_inventory is inv_after_first


def test_reachability_failed_build_doesnt_retry(tmp_path):
    """If inventory build fails once (e.g. inaccessible target),
    subsequent calls return None without retrying."""
    a = _analyzer()
    # Force the cache to the "failed" sentinel.
    a._reachability_inventory = False
    finding = _finding("src/f.py", line=1)
    assert a._check_reachability(finding, tmp_path) is None


# ---------------------------------------------------------------------------
# DI'd inventory + checklist-from-disk (in-process / cross-process sharing)
# ---------------------------------------------------------------------------


def test_caller_provided_inventory_used_directly(tmp_path):
    """Caller passes ``reachability_inventory=`` at construction
    → no fresh build, used directly. Lets the agentic prepass
    share its inventory with codeql in the same process."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "vuln.py").write_text("def dead(): pass\n")
    (src / "main.py").write_text("x = 1\n")

    from core.inventory.builder import build_inventory
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        inv = build_inventory(str(tmp_path), td)

    a = AutonomousCodeQLAnalyzer(
        llm_client=MagicMock(),
        exploit_validator=MagicMock(),
        reachability_inventory=inv,
    )
    assert a._reachability_inventory is inv

    finding = _finding("src/vuln.py", line=1)
    verdict = a._check_reachability(finding, tmp_path)
    assert verdict == "not_called"


def test_checklist_path_loaded_when_no_inventory(tmp_path):
    """``reachability_checklist_path=`` provides a serialised
    checklist. Loaded in lieu of building. Lets a subprocess
    analyzer reuse the parent /agentic run's checklist."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "vuln.py").write_text("def dead(): pass\n")

    from core.inventory.builder import build_inventory
    out = tmp_path / "shared-out"
    build_inventory(str(tmp_path), str(out))
    checklist_path = out / "checklist.json"
    assert checklist_path.exists()

    a = AutonomousCodeQLAnalyzer(
        llm_client=MagicMock(),
        exploit_validator=MagicMock(),
        reachability_checklist_path=checklist_path,
    )
    finding = _finding("src/vuln.py", line=1)
    verdict = a._check_reachability(finding, tmp_path)
    assert verdict == "not_called"


def test_checklist_path_invalid_falls_back_to_build(tmp_path):
    """Missing checklist path → falls back to fresh build."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "vuln.py").write_text("def dead(): pass\n")

    a = AutonomousCodeQLAnalyzer(
        llm_client=MagicMock(),
        exploit_validator=MagicMock(),
        reachability_checklist_path=tmp_path / "does-not-exist.json",
    )
    finding = _finding("src/vuln.py", line=1)
    verdict = a._check_reachability(finding, tmp_path)
    # Fresh build worked; verdict same.
    assert verdict == "not_called"


# ---------------------------------------------------------------------------
# Short-circuit behaviour in analyze_finding_autonomous
# ---------------------------------------------------------------------------


def test_short_circuit_on_not_called(tmp_path, monkeypatch):
    """When the prefilter returns ``"not_called"``,
    analyze_finding_autonomous returns immediately — the
    expensive dataflow validator + LLM stages are NOT invoked."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "vuln.py").write_text(
        "def dead(q):\n"
        "    cursor.execute(q)\n"
        "\n"
        "def other():\n"
        "    pass\n"
    )
    (src / "main.py").write_text(
        "from src.vuln import other\nother()\n"
    )

    a = _analyzer()
    # Stub out the parser to skip SARIF shape parsing in this test.
    canned = _finding("src/vuln.py", line=2)
    monkeypatch.setattr(
        a, "parse_sarif_finding", lambda r, run: canned,
    )

    # Replace the dataflow_validator with a mock so we can assert
    # it was never called (short-circuit happened before stage 3).
    a.dataflow_validator = MagicMock()
    a.dataflow_validator.validate_finding.side_effect = AssertionError(
        "dataflow validator was invoked despite short-circuit"
    )

    result = a.analyze_finding_autonomous(
        sarif_result={}, sarif_run={},
        repo_path=tmp_path, out_dir=tmp_path / "out",
    )
    assert result.skipped_reason == "reachability_not_called"
    assert result.reachability_verdict == "not_called"
    assert result.exploitable is False
    # The dataflow validator must NOT have been invoked — its
    # side_effect would have raised. The short-circuit fires
    # before stage 3.
    a.dataflow_validator.validate_finding.assert_not_called()


def test_no_short_circuit_when_called(tmp_path, monkeypatch):
    """When the prefilter returns ``"called"``, we proceed past
    the early-exit. We don't run the FULL flow here (would need
    extensive LLM mocking); just verify the reachability_verdict
    is set and the early-return didn't fire."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "vuln.py").write_text(
        "def vulnerable(q):\n"
        "    cursor.execute(q)\n"
    )
    (src / "main.py").write_text(
        "from src.vuln import vulnerable\nvulnerable('x')\n"
    )

    a = _analyzer()
    canned = _finding("src/vuln.py", line=2)
    monkeypatch.setattr(
        a, "parse_sarif_finding", lambda r, run: canned,
    )
    # Stub read_vulnerable_code so we don't depend on actual file
    # reading here.
    monkeypatch.setattr(
        a, "read_vulnerable_code", lambda f, p: "stub",
    )
    # Stub analyze_vulnerability to short-circuit before exploit.
    fake_analysis = MagicMock(is_exploitable=False)
    monkeypatch.setattr(
        a, "analyze_vulnerability",
        lambda *args, **kwargs: fake_analysis,
    )
    # The finding has no dataflow → skip dataflow stage.

    result = a.analyze_finding_autonomous(
        sarif_result={}, sarif_run={},
        repo_path=tmp_path, out_dir=tmp_path / "out",
    )
    # Got past the early-exit (analysis was attempted).
    assert result.skipped_reason is None
    assert result.reachability_verdict == "called"
