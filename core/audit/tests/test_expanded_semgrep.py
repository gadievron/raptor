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
from core.audit.tests._live_transport import (
    skip_if_expanded_view_transport_degraded,
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

# Lazy (probe only when a real-semgrep test actually runs — the
# ~1s child spawn is not paid at collection) and cached (one probe
# per session).
_SEMGREP_RUNNABLE: bool | None = None


def _skip_unless_semgrep_runnable() -> None:
    """Skip unless ``semgrep`` actually RUNS in this test environment.

    ``shutil.which`` only proves the entry point exists. semgrep is a
    Python program: an environment whose ``PYTHONPATH`` shadows its
    libraries — the CI preflight's hidden-optional-deps simulation
    stubs ``jsonschema``, which semgrep imports at startup — crashes
    it on launch while the PATH probe still passes, turning the E2E
    into an environment failure instead of a skip. The E2E child
    inherits this process's environment (``sandbox_spy`` executes the
    tool directly), so probe by running the binary the same way; a
    runner that cannot execute semgrep skips, never errors.
    """
    global _SEMGREP_RUNNABLE
    if _SEMGREP_RUNNABLE is None:
        try:
            _SEMGREP_RUNNABLE = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                timeout=120,
                check=False,
            ).returncode == 0
        except (OSError, subprocess.SubprocessError):
            _SEMGREP_RUNNABLE = False
    if not _SEMGREP_RUNNABLE:
        pytest.skip(
            "semgrep is on PATH but not runnable in this environment "
            "(its own imports fail under the active PYTHONPATH, or "
            "the version probe crashed/timed out)",
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


@needs_cpp
@pytest.mark.parametrize("fortified", [False, True], ids=["system-headers", "fortified-copy-macro"])
def test_audit_uses_shared_pipeline_and_retains_partial_findings(tmp_path, sandbox_spy, monkeypatch, fortified):
    from core.detectors import semgrep as detector

    target = _write_fixture(tmp_path)
    if fortified:
        # Exercise SDKs that rewrite strcpy without relying on their exact
        # builtin spelling, casts or whitespace in the preprocessed text.
        header = target / "defs.h"
        header.write_text(header.read_text() +
                          "\n#undef strcpy\n#define strcpy(d, s) __builtin___strcpy_chk(d, s, 0)\n")
    budget = ExpansionBudget(1)
    executions = []
    original = detector.run_detector

    def record(definition, state):
        result = original(definition, state)
        executions.append(result)
        return result

    def match(path, config, **kwargs):
        assert path.exists()
        assert kwargs == {"timeout": 19}
        view = budget.view_for(target, "main.c")
        assert view is not None and view.ok
        assert path.read_text() == view.text
        line = _line_with_origin(view, "main.c", _MACRO_CALL_LINE)
        return FakeSemgrepResult(findings=[FakeFinding(line)], errors=["partial parse elsewhere"])

    monkeypatch.setattr("packages.semgrep.runner.is_available", lambda: True)
    monkeypatch.setattr("packages.semgrep.runner.run_rule", match)
    monkeypatch.setattr(detector, "run_detector", record)
    result = run_expanded_semgrep_rule(
        target_path=target, file_path="main.c", rule_config="rule.yml",
        budget=budget, timeout=19,
    )
    assert result.ok and result.matches[0]["line"] == _MACRO_CALL_LINE
    assert budget.used == 1
    assert len(executions) == 1 and executions[0].status == "partial"
    assert not executions[0].value._input.target.exists()


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


def test_scratch_root_must_be_empty(tmp_path):
    """Expanded copies land at target-derived relative paths — a
    pre-populated scratch root (planted symlinks at those paths) could
    alias the writes onto foreign files, so anything but a fresh dir
    is refused loudly."""
    target = tmp_path / "repo"
    target.mkdir()
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "planted").write_text("x")
    with pytest.raises(ValueError, match="not empty"):
        build_expanded_corpus(target, scratch)


def test_scratch_root_symlink_refused(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "scratch"
    link.symlink_to(real)
    with pytest.raises(ValueError, match="symlink"):
        build_expanded_corpus(target, link)


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
    _skip_unless_semgrep_runnable()
    target = _write_fixture(tmp_path)
    rule = tmp_path / "rule.yaml"
    rule.write_text(_RULE_YAML)

    res = run_expanded_semgrep_rule(
        target_path=target, file_path="main.c", rule_config=str(rule),
        budget=ExpansionBudget(),
    )
    skip_if_expanded_view_transport_degraded(res)
    assert res.ok is True, res.reason
    assert any(m["line"] == _MACRO_CALL_LINE for m in res.matches), res.matches
    for m in res.matches:
        assert m["file"] == "main.c"
        assert m["expanded_view"] is True


def test_explicit_corpus_inputs_bypass_discovery_and_uppercase_gate(tmp_path, monkeypatch):
    target = tmp_path / 'repo'
    target.mkdir()
    (target / 'lower.c').write_text('void f(void) { lower_wrapper(); }\n')
    (target / 'unselected.c').write_text('void f(void) { MACRO(); }\n')
    seen = []

    def expand(**kw):
        seen.append(kw)
        return pv.ExpandedView(ok=True, file_path=kw['file_path'], text='memcpy(d,s,n);\n',
                               line_map=((kw['file_path'], 1),))

    monkeypatch.setattr(es, 'expand_translation_unit', expand)
    monkeypatch.setattr(es, '_iter_candidate_tus', lambda *a: pytest.fail('must not walk target'))
    corpus = build_expanded_corpus(target, tmp_path / 'views', files=('lower.c', 'lower.c'),
                                   preprocessor=('/pinned/gcc', '-E', '-x', 'c'))
    assert set(corpus.tus) == {'lower.c'} and corpus.expanded == 1
    assert seen[0]['preprocessor'][0] == '/pinned/gcc'


@pytest.mark.parametrize('bad', ['../outside.c', '/outside.c', 'link.c', 'missing.c', 'x.py'])
def test_explicit_corpus_rejects_invalid_inputs(tmp_path, monkeypatch, bad):
    target = tmp_path / 'repo'
    target.mkdir()
    outside = tmp_path / 'outside.c'
    outside.write_text('secret')
    (target / 'link.c').symlink_to(outside)
    (target / 'x.py').write_text('x')
    monkeypatch.setattr(es, 'expand_translation_unit', lambda **kw: pytest.fail('outside input'))
    corpus = build_expanded_corpus(target, tmp_path / 'views', files=(bad,))
    assert corpus.failed == 1 and not corpus.tus
    assert not any(corpus.root.iterdir())


def test_explicit_corpus_time_and_byte_budgets_preserve_prepared_views(tmp_path, monkeypatch):
    target = tmp_path / 'repo'
    target.mkdir()
    for name in ('a.c', 'b.c', 'c.c'):
        (target / name).write_text('lower();')
    now = [0.0]
    seen = []
    monkeypatch.setattr(es, 'monotonic', lambda: now[0])

    def expand(**kw):
        seen.append(kw['timeout'])
        now[0] += 3
        return pv.ExpandedView(ok=True, file_path=kw['file_path'], text='abc', line_map=())

    monkeypatch.setattr(es, 'expand_translation_unit', expand)
    corpus = build_expanded_corpus(target, tmp_path / 'views', files=('a.c', 'b.c', 'c.c'),
                                   timeout=5, max_bytes=4)
    assert list(corpus.tus) == ['a.c']
    assert seen == [5, 2]
    assert corpus.skipped_budget == 2 and corpus.failed == 0
