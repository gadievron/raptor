"""Tests for the expanded-view second pass in run_semgrep_sweep.

The plain semgrep pass is mocked via ``packages.semgrep.runner``; the
expanded pass is exercised both through a mocked
``run_expanded_semgrep_rule`` (deterministic wiring tests) and through
the real preprocessor with a fake semgrep (integration).
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from core.audit import expanded_semgrep as es
from core.audit import preprocessor_view as pv
from core.audit.expanded_semgrep import ExpandedRuleResult
from core.audit.sweep import run_semgrep_sweep

pv._reset_probe_cache()
HAVE_CPP = pv._preprocessor_for(False) is not None
needs_cpp = pytest.mark.skipif(
    not HAVE_CPP, reason="no C preprocessor (gcc/cpp) installed",
)


@pytest.fixture(autouse=True)
def _fresh_state():
    pv._reset_probe_cache()
    es._reset_process_budget()
    yield
    pv._reset_probe_cache()
    es._reset_process_budget()


@pytest.fixture
def sandbox_spy(monkeypatch):
    calls: list[dict] = []

    def fake_sandbox_run(cmd, **kwargs):
        calls.append({"cmd": cmd, **kwargs})
        fwd = {
            k: kwargs[k]
            for k in ("capture_output", "text", "timeout", "cwd")
            if k in kwargs
        }
        return subprocess.run(cmd, check=False, **fwd)

    monkeypatch.setattr("core.sandbox.context.run", fake_sandbox_run)
    return calls


@dataclass
class FakeFinding:
    line: int
    rule_id: str = "no-strcpy"
    message: str = "strcpy is dangerous"
    file: str = ""


class FakeSemgrepResult:
    def __init__(self, findings=(), errors=()):
        self.findings = list(findings)
        self.errors = list(errors)


_MACRO_C = """\
#include "defs.h"

void copy_it(char *dst, const char *src) {
    UNSAFE_COPY(dst, src);
}
"""

_PLAIN_C = """\
void copy_it(char *dst, const char *src) {
    do_copy(dst, src);
}
"""


def _repo(tmp_path: Path, main_text: str) -> Path:
    target = tmp_path / "repo"
    target.mkdir(exist_ok=True)
    (target / "defs.h").write_text(
        "#define UNSAFE_COPY(d, s) strcpy(d, s)\n",
    )
    (target / "main.c").write_text(main_text)
    return target


def _mock_plain_no_findings(monkeypatch):
    """Plain pass sees nothing (macro hides the sink)."""
    monkeypatch.setattr(
        "packages.semgrep.runner.run_rule",
        lambda target_file, config, **kw: FakeSemgrepResult(),
    )
    monkeypatch.setattr("packages.semgrep.runner.is_available", lambda: True)


# ---------------------------------------------------------------------
# Wiring: second pass rescues macro-hidden matches
# ---------------------------------------------------------------------


def test_expanded_pass_confirms_with_distinct_stamp(tmp_path, monkeypatch):
    target = _repo(tmp_path, _MACRO_C)
    _mock_plain_no_findings(monkeypatch)

    calls = {}

    def fake_expanded(**kwargs):
        calls.update(kwargs)
        return ExpandedRuleResult(
            ok=True, file_path="main.c", rule_config=kwargs["rule_config"],
            matches=[{
                "line": 4, "expanded_line": 812, "rule_id": "no-strcpy",
                "message": "strcpy is dangerous", "file": "main.c",
                "expanded_view": True,
            }],
            dropped_out_of_file=1,
        )

    monkeypatch.setattr(es, "run_expanded_semgrep_rule", fake_expanded)

    result = run_semgrep_sweep(
        target_path=target, file_path="main.c", function_name="copy_it",
        rule_config="rules/no-strcpy.yaml", line_start=3, line_end=5,
    )
    assert result.outcome == "confirmed"
    # Evidence stamp: the orchestrator composes
    # f"semgrep:{rule_id}" — the :expanded suffix makes the stamp
    # semgrep:<rule>:expanded, distinct from the plain pass.
    assert result.rule_id == "rules/no-strcpy.yaml:expanded"
    assert result.matches[0]["line"] == 4
    assert result.details["expanded_view"] is True
    assert result.details["dropped_out_of_file"] == 1
    # The function range was forwarded.
    assert calls["line_start"] == 3
    assert calls["line_end"] == 5


def test_macro_gate_skips_expanded_pass(tmp_path, monkeypatch):
    target = _repo(tmp_path, _PLAIN_C)
    _mock_plain_no_findings(monkeypatch)

    def boom(**kwargs):
        raise AssertionError("expanded pass ran despite macro-free source")

    monkeypatch.setattr(es, "run_expanded_semgrep_rule", boom)

    result = run_semgrep_sweep(
        target_path=target, file_path="main.c", function_name="copy_it",
        rule_config="rules/no-strcpy.yaml", line_start=1, line_end=3,
    )
    assert result.outcome == "refuted"
    assert result.rule_id == "rules/no-strcpy.yaml"


def test_gate_checks_function_range_only(tmp_path, monkeypatch):
    # Macro OUTSIDE the audited function's range must not trigger the
    # second pass for that function.
    src = _PLAIN_C + "\nvoid other(void) {\n    BIG_MACRO(1);\n}\n"
    target = _repo(tmp_path, src)
    _mock_plain_no_findings(monkeypatch)

    def boom(**kwargs):
        raise AssertionError("expanded pass ran for a macro-free range")

    monkeypatch.setattr(es, "run_expanded_semgrep_rule", boom)
    result = run_semgrep_sweep(
        target_path=target, file_path="main.c", function_name="copy_it",
        rule_config="r.yaml", line_start=1, line_end=3,
    )
    assert result.outcome == "refuted"


def test_non_c_file_skips_expanded_pass(tmp_path, monkeypatch):
    target = tmp_path / "repo"
    target.mkdir()
    (target / "app.py").write_text("RUN_TASK(x)\n")
    _mock_plain_no_findings(monkeypatch)

    def boom(**kwargs):
        raise AssertionError("expanded pass ran for a non-C file")

    monkeypatch.setattr(es, "run_expanded_semgrep_rule", boom)
    result = run_semgrep_sweep(
        target_path=target, file_path="app.py", function_name="f",
        rule_config="r.yaml",
    )
    assert result.outcome == "refuted"


def test_confirmed_plain_pass_never_runs_expanded(tmp_path, monkeypatch):
    target = _repo(tmp_path, _MACRO_C)
    monkeypatch.setattr(
        "packages.semgrep.runner.run_rule",
        lambda target_file, config, **kw: FakeSemgrepResult(
            findings=[FakeFinding(line=4)],
        ),
    )
    monkeypatch.setattr("packages.semgrep.runner.is_available", lambda: True)

    def boom(**kwargs):
        raise AssertionError("expanded pass ran after a plain confirm")

    monkeypatch.setattr(es, "run_expanded_semgrep_rule", boom)
    result = run_semgrep_sweep(
        target_path=target, file_path="main.c", function_name="copy_it",
        rule_config="r.yaml", line_start=3, line_end=5,
    )
    assert result.outcome == "confirmed"
    assert result.rule_id == "r.yaml"  # no :expanded suffix


# ---------------------------------------------------------------------
# Degradation: the second pass never worsens the plain outcome
# ---------------------------------------------------------------------


def test_degraded_expanded_pass_keeps_refuted(tmp_path, monkeypatch):
    target = _repo(tmp_path, _MACRO_C)
    _mock_plain_no_findings(monkeypatch)
    monkeypatch.setattr(
        es, "run_expanded_semgrep_rule",
        lambda **kw: ExpandedRuleResult(
            ok=False, file_path="main.c", reason="preprocess failed",
        ),
    )
    result = run_semgrep_sweep(
        target_path=target, file_path="main.c", function_name="copy_it",
        rule_config="r.yaml", line_start=3, line_end=5,
    )
    assert result.outcome == "refuted"


def test_expanded_pass_exception_keeps_refuted(tmp_path, monkeypatch):
    target = _repo(tmp_path, _MACRO_C)
    _mock_plain_no_findings(monkeypatch)

    def raising(**kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(es, "run_expanded_semgrep_rule", raising)
    result = run_semgrep_sweep(
        target_path=target, file_path="main.c", function_name="copy_it",
        rule_config="r.yaml", line_start=3, line_end=5,
    )
    assert result.outcome == "refuted"


def test_budget_exhausted_keeps_refuted(tmp_path, monkeypatch):
    target = _repo(tmp_path, _MACRO_C)
    _mock_plain_no_findings(monkeypatch)
    es._reset_process_budget(0)  # per-run budget already spent
    result = run_semgrep_sweep(
        target_path=target, file_path="main.c", function_name="copy_it",
        rule_config="r.yaml", line_start=3, line_end=5,
    )
    assert result.outcome == "refuted"


def test_no_expanded_matches_keeps_refuted(tmp_path, monkeypatch):
    target = _repo(tmp_path, _MACRO_C)
    _mock_plain_no_findings(monkeypatch)
    monkeypatch.setattr(
        es, "run_expanded_semgrep_rule",
        lambda **kw: ExpandedRuleResult(ok=True, file_path="main.c"),
    )
    result = run_semgrep_sweep(
        target_path=target, file_path="main.c", function_name="copy_it",
        rule_config="r.yaml", line_start=3, line_end=5,
    )
    assert result.outcome == "refuted"


# ---------------------------------------------------------------------
# Identifier-consistency cap applies to expanded matches too
# ---------------------------------------------------------------------


def test_identifier_mismatch_caps_expanded_at_inconclusive(
    tmp_path, monkeypatch,
):
    target = _repo(tmp_path, _MACRO_C)
    _mock_plain_no_findings(monkeypatch)
    monkeypatch.setattr(
        es, "run_expanded_semgrep_rule",
        lambda **kw: ExpandedRuleResult(
            ok=True, file_path="main.c",
            matches=[{
                "line": 4, "expanded_line": 812, "rule_id": "no-strcpy",
                "message": "m", "file": "main.c", "expanded_view": True,
            }],
        ),
    )
    result = run_semgrep_sweep(
        target_path=target, file_path="main.c", function_name="copy_it",
        rule_config="r.yaml", line_start=3, line_end=5,
        hypothesis="`totally_absent_ident` overflows",
        rule_keyword="buffer overflow",
    )
    assert result.outcome == "inconclusive"
    assert result.rule_id == "r.yaml:expanded"
    assert "identifier mismatch" in result.details["reason"]


def test_identifier_match_confirms_expanded(tmp_path, monkeypatch):
    target = _repo(tmp_path, _MACRO_C)
    _mock_plain_no_findings(monkeypatch)
    # Negative-control lookup must not run semgrep here.
    monkeypatch.setattr(
        "core.audit.sweep._rule_matches_negative_control",
        lambda *a, **k: False,
    )
    monkeypatch.setattr(
        es, "run_expanded_semgrep_rule",
        lambda **kw: ExpandedRuleResult(
            ok=True, file_path="main.c",
            matches=[{
                "line": 4, "expanded_line": 812, "rule_id": "no-strcpy",
                "message": "m", "file": "main.c", "expanded_view": True,
            }],
        ),
    )
    result = run_semgrep_sweep(
        target_path=target, file_path="main.c", function_name="copy_it",
        rule_config="r.yaml", line_start=3, line_end=5,
        hypothesis="`UNSAFE_COPY` writes past `dst`",
        rule_keyword="buffer overflow",
    )
    assert result.outcome == "confirmed"
    assert result.rule_id == "r.yaml:expanded"


# ---------------------------------------------------------------------
# Integration: real preprocessor, fake semgrep
# ---------------------------------------------------------------------


@needs_cpp
def test_integration_real_preprocessor(tmp_path, sandbox_spy, monkeypatch):
    target = _repo(tmp_path, _MACRO_C)

    view = pv.expand_translation_unit(target_path=target, file_path="main.c")
    assert view.ok
    exp_line = next(
        idx + 1
        for idx in range(len(view.line_map))
        if view.line_map[idx] == ("main.c", 4)
    )
    assert "strcpy" in view.lines()[exp_line - 1]

    def fake_run_rule(target_file, config, **kw):
        # Plain pass scans the repo file; expanded pass scans the
        # scratch copy (prefix "expanded_").
        if Path(str(target_file)).name.startswith("expanded_"):
            return FakeSemgrepResult(findings=[FakeFinding(line=exp_line)])
        return FakeSemgrepResult()

    monkeypatch.setattr("packages.semgrep.runner.run_rule", fake_run_rule)
    monkeypatch.setattr("packages.semgrep.runner.is_available", lambda: True)

    result = run_semgrep_sweep(
        target_path=target, file_path="main.c", function_name="copy_it",
        rule_config="rules/no-strcpy.yaml", line_start=3, line_end=5,
    )
    assert result.outcome == "confirmed"
    assert result.rule_id == "rules/no-strcpy.yaml:expanded"
    assert result.matches[0]["line"] == 4
    assert result.matches[0]["expanded_line"] == exp_line
    assert result.details["expanded_view"] is True
