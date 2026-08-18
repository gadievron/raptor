"""Tests for core.audit.expanded_semgrep.

Preprocessing tests monkeypatch ``core.sandbox.context.run`` with a spy
that runs the preprocessor directly (same convention as
test_preprocessor_view — the suite must pass on hosts without
namespace isolation and never require network) and are skipped when no
C preprocessor is installed.  Semgrep is mocked for the deterministic
line-map / noise / budget tests; one E2E uses the real semgrep when
present.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from core.audit import expanded_semgrep as es
from core.audit import preprocessor_view as pv
from core.audit.expanded_semgrep import (
    ExpansionBudget,
    build_expanded_corpus,
    findings_to_sarif,
    has_macro_invocation,
    is_c_family,
    run_expanded_semgrep_rule,
    translate_corpus_findings,
)

pv._reset_probe_cache()
HAVE_CPP = pv._preprocessor_for(False) is not None
HAVE_SEMGREP = shutil.which("semgrep") is not None

needs_cpp = pytest.mark.skipif(
    not HAVE_CPP, reason="no C preprocessor (gcc/cpp) installed",
)
needs_semgrep = pytest.mark.skipif(
    not HAVE_SEMGREP, reason="semgrep not installed",
)


@pytest.fixture(autouse=True)
def _fresh_probe_cache():
    pv._reset_probe_cache()
    yield
    pv._reset_probe_cache()


@pytest.fixture
def sandbox_spy(monkeypatch):
    """Record sandbox kwargs, then execute the tool directly."""
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


# ---------------------------------------------------------------------
# Multi-include fixture
# ---------------------------------------------------------------------

_DEFS_H = """\
#define UNSAFE_COPY(d, s) strcpy(d, s)

static void header_helper(char *x) {
    strcpy(x, "header");
}
"""

_MAIN_C = """\
#include <string.h>
#include "defs.h"

void copy_it(char *dst, const char *src) {
    UNSAFE_COPY(dst, src);
}
"""

# Original line of the UNSAFE_COPY invocation in _MAIN_C (1-based).
_MACRO_CALL_LINE = 5


def _write_fixture(tmp_path: Path) -> Path:
    target = tmp_path / "repo"
    target.mkdir(exist_ok=True)
    (target / "defs.h").write_text(_DEFS_H)
    (target / "main.c").write_text(_MAIN_C)
    return target


def _expanded_line_of(view, needle: str, origin_file: str) -> int:
    """1-based expanded line containing *needle* attributed to *origin_file*."""
    for idx, text in enumerate(view.lines()):
        if needle not in text:
            continue
        origin = view.origin_of(idx + 1)
        if origin is not None and origin[0] == origin_file:
            return idx + 1
    raise AssertionError(
        f"no expanded line with {needle!r} attributed to {origin_file}",
    )


def _line_with_origin(view, origin_file: str, origin_line: int) -> int:
    for idx in range(len(view.line_map)):
        if view.line_map[idx] == (origin_file, origin_line):
            return idx + 1
    raise AssertionError(f"no expanded line for {origin_file}:{origin_line}")


def _system_header_line(view) -> int:
    """1-based expanded line in an unattributable (system-header) region."""
    for idx, entry in enumerate(view.line_map):
        if entry is None and (view.lines()[idx] or "").strip():
            return idx + 1
    raise AssertionError("no unattributable expanded line found")


# ---------------------------------------------------------------------
# Gate + suffix helpers
# ---------------------------------------------------------------------


def test_macro_gate_positive_indented():
    src = "void f(void) {\n    LIST_FOREACH(it, &head, entries) {\n    }\n}\n"
    assert has_macro_invocation(src) is True


def test_macro_gate_positive_column_zero():
    assert has_macro_invocation("DEFINE_HANDLER(foo)\n") is True


def test_macro_gate_negative_plain_c():
    src = "void f(void) {\n    do_copy(dst, src);\n    x = g(1);\n}\n"
    assert has_macro_invocation(src) is False


def test_macro_gate_negative_short_and_empty():
    assert has_macro_invocation("") is False
    # Two-char ALL-CAPS names don't clear the {2,} threshold's 3-char
    # minimum total.
    assert has_macro_invocation("y = IO(x);") is False


def test_is_c_family():
    assert is_c_family("src/a.c") is True
    assert is_c_family("src/a.h") is True
    assert is_c_family("src/a.cpp") is True
    assert is_c_family("src/a.py") is False
    assert is_c_family("Makefile") is False


# ---------------------------------------------------------------------
# Line-map translation (multi-include fixture)
# ---------------------------------------------------------------------


@needs_cpp
def test_translation_maps_macro_match_to_original_line(
    tmp_path, sandbox_spy, monkeypatch,
):
    target = _write_fixture(tmp_path)
    view = pv.expand_translation_unit(target_path=target, file_path="main.c")
    assert view.ok

    # The strcpy produced by UNSAFE_COPY's expansion sits at the
    # expanded line whose origin is main.c:_MACRO_CALL_LINE.
    exp_line = _line_with_origin(view, "main.c", _MACRO_CALL_LINE)
    assert "strcpy" in view.lines()[exp_line - 1]

    monkeypatch.setattr(
        "packages.semgrep.runner.run_rule",
        lambda target_file, config, **kw: FakeSemgrepResult(
            findings=[FakeFinding(line=exp_line)],
        ),
    )
    monkeypatch.setattr("packages.semgrep.runner.is_available", lambda: True)

    res = run_expanded_semgrep_rule(
        target_path=target, file_path="main.c", rule_config="rule.yaml",
        budget=ExpansionBudget(),
    )
    assert res.ok is True
    assert len(res.matches) == 1
    m = res.matches[0]
    assert m["line"] == _MACRO_CALL_LINE
    assert m["expanded_line"] == exp_line
    assert m["file"] == "main.c"
    assert m["expanded_view"] is True
    assert res.dropped_out_of_file == 0


@needs_cpp
def test_noise_exclusion_drops_header_and_system_matches(
    tmp_path, sandbox_spy, monkeypatch,
):
    target = _write_fixture(tmp_path)
    view = pv.expand_translation_unit(target_path=target, file_path="main.c")
    assert view.ok

    header_line = _expanded_line_of(view, "strcpy", "defs.h")
    system_line = _system_header_line(view)
    good_line = _line_with_origin(view, "main.c", _MACRO_CALL_LINE)

    monkeypatch.setattr(
        "packages.semgrep.runner.run_rule",
        lambda target_file, config, **kw: FakeSemgrepResult(findings=[
            FakeFinding(line=header_line),   # other-file expansion → noise
            FakeFinding(line=system_line),   # system header → noise
            FakeFinding(line=good_line),     # in-file → kept
        ]),
    )
    monkeypatch.setattr("packages.semgrep.runner.is_available", lambda: True)

    res = run_expanded_semgrep_rule(
        target_path=target, file_path="main.c", rule_config="rule.yaml",
        budget=ExpansionBudget(),
    )
    assert res.ok is True
    assert [m["line"] for m in res.matches] == [_MACRO_CALL_LINE]
    assert res.dropped_out_of_file == 2


@needs_cpp
def test_range_filter_excludes_out_of_range(tmp_path, sandbox_spy, monkeypatch):
    target = _write_fixture(tmp_path)
    view = pv.expand_translation_unit(target_path=target, file_path="main.c")
    good_line = _line_with_origin(view, "main.c", _MACRO_CALL_LINE)

    monkeypatch.setattr(
        "packages.semgrep.runner.run_rule",
        lambda target_file, config, **kw: FakeSemgrepResult(
            findings=[FakeFinding(line=good_line)],
        ),
    )
    monkeypatch.setattr("packages.semgrep.runner.is_available", lambda: True)

    res = run_expanded_semgrep_rule(
        target_path=target, file_path="main.c", rule_config="rule.yaml",
        line_start=1, line_end=2,  # macro call is at line 5 — out of range
        budget=ExpansionBudget(),
    )
    assert res.ok is True
    assert res.matches == []


# ---------------------------------------------------------------------
# Budget
# ---------------------------------------------------------------------


def test_budget_exhaustion_degrades_with_reason(tmp_path):
    target = _write_fixture(tmp_path)
    res = run_expanded_semgrep_rule(
        target_path=target, file_path="main.c", rule_config="rule.yaml",
        budget=ExpansionBudget(max_expansions=0),
    )
    assert res.ok is False
    assert "budget" in res.reason
    assert res.matches == []


@needs_cpp
def test_budget_caches_views_per_file(tmp_path, sandbox_spy, monkeypatch):
    target = _write_fixture(tmp_path)
    monkeypatch.setattr(
        "packages.semgrep.runner.run_rule",
        lambda target_file, config, **kw: FakeSemgrepResult(),
    )
    monkeypatch.setattr("packages.semgrep.runner.is_available", lambda: True)

    budget = ExpansionBudget(max_expansions=1)
    r1 = run_expanded_semgrep_rule(
        target_path=target, file_path="main.c", rule_config="a.yaml",
        budget=budget,
    )
    r2 = run_expanded_semgrep_rule(
        target_path=target, file_path="main.c", rule_config="b.yaml",
        budget=budget,
    )
    assert r1.ok is True
    assert r2.ok is True  # cached view, no second budget charge
    assert budget.used == 1

    # A DIFFERENT file now exceeds the budget.
    (target / "other.c").write_text("void o(void) {}\n")
    r3 = run_expanded_semgrep_rule(
        target_path=target, file_path="other.c", rule_config="a.yaml",
        budget=budget,
    )
    assert r3.ok is False
    assert "budget" in r3.reason


# ---------------------------------------------------------------------
# Degradation
# ---------------------------------------------------------------------


@needs_cpp
def test_preprocess_failure_degrades_never_raises(tmp_path, sandbox_spy):
    target = tmp_path / "repo"
    target.mkdir()
    (target / "broken.c").write_text(
        '#include "generated_not_here.h"\nvoid f(void) { MACRO_CALL(x); }\n',
    )
    res = run_expanded_semgrep_rule(
        target_path=target, file_path="broken.c", rule_config="rule.yaml",
        budget=ExpansionBudget(),
    )
    assert res.ok is False
    assert res.reason
    assert res.matches == []


def test_non_c_file_degrades(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    (target / "app.py").write_text("print('x')\n")
    res = run_expanded_semgrep_rule(
        target_path=target, file_path="app.py", rule_config="rule.yaml",
        budget=ExpansionBudget(),
    )
    assert res.ok is False
    assert "not a C/C++" in res.reason


def test_path_escape_degrades(tmp_path):
    res = run_expanded_semgrep_rule(
        target_path=tmp_path, file_path="../../etc/passwd.c",
        rule_config="rule.yaml", budget=ExpansionBudget(),
    )
    assert res.ok is False
    assert "escapes" in res.reason


@needs_cpp
def test_semgrep_error_degrades(tmp_path, sandbox_spy, monkeypatch):
    target = _write_fixture(tmp_path)
    monkeypatch.setattr(
        "packages.semgrep.runner.run_rule",
        lambda target_file, config, **kw: FakeSemgrepResult(
            errors=["rule failed to parse"],
        ),
    )
    monkeypatch.setattr("packages.semgrep.runner.is_available", lambda: True)
    res = run_expanded_semgrep_rule(
        target_path=target, file_path="main.c", rule_config="rule.yaml",
        budget=ExpansionBudget(),
    )
    assert res.ok is False
    assert "rule failed to parse" in res.reason


# ---------------------------------------------------------------------
# Scan-side corpus
# ---------------------------------------------------------------------


@needs_cpp
def test_corpus_gates_budgets_and_translates(tmp_path, sandbox_spy, caplog):
    target = _write_fixture(tmp_path)
    # A macro-free TU must not be expanded.
    (target / "plain.c").write_text("void plain(void) { int x = 1; }\n")
    # Vendored code must be excluded by the inventory rules.
    (target / "vendor").mkdir()
    (target / "vendor" / "dep.c").write_text("void v(void) { MACRO(1); }\n")

    corpus = build_expanded_corpus(target, tmp_path / "scratch")
    assert corpus.candidates_total == 1
    assert corpus.expanded == 1
    assert set(corpus.tus) == {"main.c"}
    assert (tmp_path / "scratch" / "main.c").is_file()

    tu = corpus.tus["main.c"]
    good_line = _line_with_origin(tu.view, "main.c", _MACRO_CALL_LINE)
    header_line = _expanded_line_of(tu.view, "strcpy", "defs.h")

    findings = [
        FakeFinding(line=good_line, file=str(corpus.root / "main.c")),
        FakeFinding(line=header_line, file=str(corpus.root / "main.c")),
        FakeFinding(line=good_line, file=str(corpus.root / "main.c")),  # dup
        FakeFinding(line=3, file="unrelated.c"),
    ]
    translated, dropped = translate_corpus_findings(corpus, findings)
    assert len(translated) == 1
    assert translated[0]["file"] == "main.c"
    assert translated[0]["line"] == _MACRO_CALL_LINE
    assert translated[0]["expanded_view"] is True
    assert dropped == 2  # header noise + non-corpus file


@needs_cpp
def test_corpus_budget_skips_loudly(tmp_path, sandbox_spy, caplog):
    target = tmp_path / "repo"
    target.mkdir()
    for i in range(3):
        (target / f"m{i}.c").write_text(
            f"#define M{i}(x) (x)\nvoid f{i}(void) {{ BIG_MACRO({i}); }}\n",
        )
    with caplog.at_level("WARNING"):
        corpus = build_expanded_corpus(target, tmp_path / "scratch", max_tus=1)
    assert corpus.candidates_total == 3
    assert corpus.expanded == 1
    assert corpus.skipped_budget == 2
    assert any("SKIPPED" in r.message for r in caplog.records)
    assert "SKIPPED" in corpus.summary_line()


def test_corpus_preprocess_failure_counted(tmp_path, monkeypatch):
    target = tmp_path / "repo"
    target.mkdir()
    (target / "broken.c").write_text("void f(void) { BIG_MACRO(1); }\n")
    monkeypatch.setattr(
        es, "expand_translation_unit",
        lambda **kw: pv.ExpandedView(
            ok=False, file_path=kw["file_path"], errors=["preprocess failed"],
        ),
    )
    corpus = build_expanded_corpus(target, tmp_path / "scratch")
    assert corpus.failed == 1
    assert corpus.expanded == 0
    assert "failed to preprocess" in corpus.summary_line()


def test_findings_to_sarif_marker_and_shape():
    sarif = findings_to_sarif([{
        "file": "main.c", "line": 5, "expanded_line": 812,
        "rule_id": "no-strcpy", "message": "strcpy is dangerous",
        "expanded_view": True,
    }])
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "semgrep-expanded"
    res = run["results"][0]
    assert res["ruleId"] == "no-strcpy"
    assert res["properties"]["expanded_view"] is True
    assert res["properties"]["expanded_line"] == 812
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "main.c"
    assert loc["region"]["startLine"] == 5

    # Consumable by the same SARIF machinery the scan pipeline uses.
    from packages.semgrep.models import SemgrepFinding
    finding = SemgrepFinding.from_sarif_result(res)
    assert finding.file == "main.c"
    assert finding.line == 5


# ---------------------------------------------------------------------
# Real-semgrep E2E
# ---------------------------------------------------------------------

_RULE_YAML = """\
rules:
  - id: no-strcpy
    languages: [c]
    severity: WARNING
    message: strcpy is dangerous
    pattern: strcpy(...)
"""


@needs_cpp
@needs_semgrep
def test_e2e_real_semgrep_finds_macro_hidden_strcpy(tmp_path, sandbox_spy):
    target = _write_fixture(tmp_path)
    rule = tmp_path / "rule.yaml"
    rule.write_text(_RULE_YAML)

    res = run_expanded_semgrep_rule(
        target_path=target, file_path="main.c", rule_config=str(rule),
        budget=ExpansionBudget(),
    )
    assert res.ok is True, res.reason
    assert any(m["line"] == _MACRO_CALL_LINE for m in res.matches), res.matches
    for m in res.matches:
        assert m["file"] == "main.c"
        assert m["expanded_view"] is True
