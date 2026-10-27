"""Tests for ``packages/static-analysis/compiler_scan.py``.

Same hyphenated-package importlib pattern as the other scanner tests.
Covers:
  * TU enumeration reusing the inventory exclusion rules
  * the TU cap (loud reporting, no silent truncation)
  * sandbox refusal (never runs the compiler unsandboxed)
  * diagnostic filtering + CWE mapping reuse from compiler_sweep
  * synthetic diagnostic → SARIF shape the dedup pipeline consumes
    (merge_sarif + SemgrepFinding round-trip)
  * 1 real-compiler E2E (skipped when no analyzer toolchain), with a
    sandbox spy asserting block_network=True
  * in-source analyzer suppression (TU or repo header) recorded as a
    coverage limitation — summary + SARIF notification, never a
    finding, never read as coverage downstream (clang path; skipped
    without clang)
"""

from __future__ import annotations

import functools
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

# parents[3]: tests/ → static-analysis/ → packages/ → repo root
_REPO_ROOT = str(Path(__file__).resolve().parents[3])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

_MODULE_PATH = Path(_REPO_ROOT) / "packages/static-analysis/compiler_scan.py"
_spec = importlib.util.spec_from_file_location(
    "static_analysis_compiler_scan", _MODULE_PATH,
)
_cs = importlib.util.module_from_spec(_spec)
# sys.modules registration BEFORE exec: the module defines dataclasses,
# and dataclass processing resolves the defining module via sys.modules.
sys.modules[_spec.name] = _cs
_spec.loader.exec_module(_cs)

from core.audit import compiler_sweep
from core.sarif.parser import merge_sarif
from packages.semgrep.models import SemgrepFinding

@functools.lru_cache(maxsize=None)
def _have_analyzer() -> bool:
    """Real-toolchain probe (gcc ``-fanalyzer`` test-compiles), memoised
    and evaluated lazily from ``_analyzer_or_skip`` — a module-level
    ``skipif`` condition would spawn the probe subprocesses at pytest
    COLLECTION in every invocation and every xdist worker. Probes on a
    fresh cache and resets afterwards so the test body starts from the
    same cold-cache state ``_fresh_probe_cache`` guarantees."""
    compiler_sweep._reset_probe_cache()
    have = (
        compiler_sweep._gcc_analyzer() is not None
        or compiler_sweep._clang_path() is not None
    )
    compiler_sweep._reset_probe_cache()
    return have


@pytest.fixture
def _analyzer_or_skip() -> None:
    if not _have_analyzer():
        pytest.skip("neither gcc -fanalyzer nor clang installed")


needs_analyzer = pytest.mark.usefixtures("_analyzer_or_skip")


@pytest.fixture(autouse=True)
def _fresh_probe_cache():
    compiler_sweep._reset_probe_cache()
    yield
    compiler_sweep._reset_probe_cache()


@pytest.fixture
def sandbox_spy(monkeypatch):
    """Record sandbox kwargs, then execute the compiler directly."""
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


# ---------------------------------------------------------------------
# TU enumeration — inventory exclusion reuse
# ---------------------------------------------------------------------


def test_enumerate_tus_respects_inventory_exclusions(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.c").write_text("int main(void){return 0;}\n")
    (tmp_path / "src" / "util.cpp").write_text("void u() {}\n")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "dep.c").write_text("void v(void){}\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "t.c").write_text("void t(void){}\n")
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "gen.c").write_text("void g(void){}\n")
    (tmp_path / "src" / "x_test.c").write_text("void xt(void){}\n")
    # Headers are not TUs.
    (tmp_path / "src" / "api.h").write_text("void u(void);\n")

    assert _cs.enumerate_tus(tmp_path) == ["src/main.c", "src/util.cpp"]


def test_enumerate_tus_empty_for_non_c_repo(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')\n")
    assert _cs.enumerate_tus(tmp_path) == []


# ---------------------------------------------------------------------
# Sandbox refusal
# ---------------------------------------------------------------------


def test_scan_refuses_without_sandbox(tmp_path, monkeypatch):
    (tmp_path / "a.c").write_text("int main(void){return 0;}\n")
    monkeypatch.setattr(_cs, "_sandbox_runner", lambda: None)
    result = _cs.scan_target(tmp_path)
    assert result.ok is False
    assert "sandbox" in result.reason
    assert result.findings == []


# ---------------------------------------------------------------------
# TU cap — loud, never silent
# ---------------------------------------------------------------------


def _fake_toolchain(monkeypatch):
    monkeypatch.setattr(_cs, "_sandbox_runner", lambda: object())
    monkeypatch.setattr(_cs, "_gcc_analyzer", lambda: ("gcc", "json"))
    monkeypatch.setattr(_cs, "_clang_path", lambda: None)


def test_tu_cap_reports_skipped(tmp_path, monkeypatch, caplog):
    for i in range(4):
        (tmp_path / f"f{i}.c").write_text("void f(void){}\n")
    _fake_toolchain(monkeypatch)

    analyzed: list[str] = []

    def fake_analyze(target, rel, **kwargs):
        analyzed.append(rel)
        return _cs.TuDiagnostics(rel, ok=True, compiler="gcc")

    monkeypatch.setattr(_cs, "analyze_tu", fake_analyze)
    with caplog.at_level("WARNING"):
        result = _cs.scan_target(tmp_path, max_tus=2)

    assert result.ok is True
    assert result.tus_total == 4
    assert result.tus_analyzed == 2
    assert result.tus_skipped_cap == 2
    assert sorted(analyzed) == ["f0.c", "f1.c"]
    assert any("SKIPPED" in r.message for r in caplog.records)
    assert "SKIPPED" in result.summary_line()
    assert "--compiler-scan-max-tus" in result.summary_line()


def test_no_cap_no_skip_report(tmp_path, monkeypatch):
    (tmp_path / "a.c").write_text("void a(void){}\n")
    _fake_toolchain(monkeypatch)
    monkeypatch.setattr(
        _cs, "analyze_tu",
        lambda target, rel, **kw: _cs.TuDiagnostics(rel, ok=True, compiler="gcc"),
    )
    result = _cs.scan_target(tmp_path, max_tus=2000)
    assert result.tus_skipped_cap == 0
    assert "SKIPPED" not in result.summary_line()


def test_failed_tus_counted_and_contribute_no_findings(tmp_path, monkeypatch):
    (tmp_path / "a.c").write_text("void a(void){}\n")
    (tmp_path / "b.c").write_text("void b(void){}\n")
    _fake_toolchain(monkeypatch)

    def fake_analyze(target, rel, **kwargs):
        if rel == "a.c":
            return _cs.TuDiagnostics(rel, ok=False, reason="compile failed")
        return _cs.TuDiagnostics(rel, ok=True, compiler="gcc", diagnostics=[{
            "rule_id": "-Wanalyzer-use-after-free", "file": "b.c", "line": 3,
            "message": "use after free", "cwe": "CWE-416",
            "compiler": "gcc", "tu": "b.c",
        }])

    monkeypatch.setattr(_cs, "analyze_tu", fake_analyze)
    result = _cs.scan_target(tmp_path)
    assert result.tus_failed == 1
    assert result.tus_analyzed == 1
    assert len(result.findings) == 1


def test_duplicate_diagnostics_deduped_across_tus(tmp_path, monkeypatch):
    (tmp_path / "a.c").write_text("void a(void){}\n")
    (tmp_path / "b.c").write_text("void b(void){}\n")
    _fake_toolchain(monkeypatch)
    shared = {
        "rule_id": "-Wanalyzer-null-dereference", "file": "common.h", "line": 7,
        "message": "null deref", "cwe": "CWE-476", "compiler": "gcc", "tu": "",
    }
    monkeypatch.setattr(
        _cs, "analyze_tu",
        lambda target, rel, **kw: _cs.TuDiagnostics(
            rel, ok=True, compiler="gcc", diagnostics=[dict(shared, tu=rel)],
        ),
    )
    result = _cs.scan_target(tmp_path)
    assert len(result.findings) == 1


# ---------------------------------------------------------------------
# CWE mapping + diagnostic filtering (compiler_sweep family map reuse)
# ---------------------------------------------------------------------


def test_cwe_mapping_reuses_family_map():
    assert _cs._cwe_for_diag_id("-Wanalyzer-use-after-free") == "CWE-416"
    assert _cs._cwe_for_diag_id("-Wanalyzer-double-free") == "CWE-415"
    assert _cs._cwe_for_diag_id("-Wanalyzer-null-dereference") == "CWE-476"
    assert _cs._cwe_for_diag_id("-Wformat-security") == "CWE-134"
    # Parameterised gcc option form matches too (see _id_matches).
    assert _cs._cwe_for_diag_id("-Wstringop-overflow=") is not None
    # clang checker-group prefix matching.
    assert _cs._cwe_for_diag_id("unix.Malloc") in ("CWE-416", "CWE-415", "CWE-401")
    assert _cs._cwe_for_diag_id("-Wanalyzer-file-leak") is None


def test_keep_diag_id_filter():
    assert _cs._keep_diag_id("-Wanalyzer-use-after-free") is True
    assert _cs._keep_diag_id("-Wanalyzer-file-leak") is True   # analyzer, unmapped
    assert _cs._keep_diag_id("core.NullDereference") is True   # clang checker
    assert _cs._keep_diag_id("-Wunused-variable") is False     # style noise
    assert _cs._keep_diag_id("") is False


# ---------------------------------------------------------------------
# Findings-shape compatibility with the dedup pipeline
# ---------------------------------------------------------------------


def test_synthetic_diagnostic_sarif_shape(tmp_path):
    result = _cs.CompilerScanResult(
        ok=True, tus_total=1, tus_analyzed=1,
        findings=[{
            "rule_id": "-Wanalyzer-use-after-free",
            "file": "src/main.c",
            "line": 42,
            "message": "use after 'free' of 'p'",
            "cwe": "CWE-416",
            "compiler": "gcc",
            "tu": "src/main.c",
        }],
    )
    sarif = _cs.to_sarif(result)

    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "compiler"
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["id"] == "-Wanalyzer-use-after-free"
    assert rule["properties"]["cwe"] == "CWE-416"
    assert "external/cwe/cwe-416" in rule["properties"]["tags"]
    res = run["results"][0]
    assert res["ruleId"] == "-Wanalyzer-use-after-free"
    assert res["message"]["text"] == "use after 'free' of 'p'"
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/main.c"
    assert loc["region"]["startLine"] == 42
    assert res["properties"]["cwe"] == "CWE-416"

    # Feed the SARIF through the same consumers the scan pipeline uses.
    import json
    sarif_path = tmp_path / "compiler.sarif"
    sarif_path.write_text(json.dumps(sarif), encoding="utf-8")
    merged = merge_sarif([str(sarif_path)])
    merged_results = merged["runs"][0]["results"]
    assert len(merged_results) == 1

    finding = SemgrepFinding.from_sarif_result(merged_results[0])
    assert finding.file == "src/main.c"
    assert finding.line == 42
    assert finding.rule_id == "-Wanalyzer-use-after-free"


def test_sarif_empty_result_still_valid(tmp_path):
    sarif = _cs.to_sarif(_cs.CompilerScanResult(ok=True))
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "compiler"


# ---------------------------------------------------------------------
# Real-compiler E2E
# ---------------------------------------------------------------------

_UAF_C = """\
#include <stdlib.h>

int use_after_free(void) {
    int *p = malloc(sizeof(int));
    if (!p) return -1;
    *p = 41;
    free(p);
    return *p; /* UAF */
}
"""


@needs_analyzer
def test_e2e_real_compiler_finds_uaf(tmp_path, sandbox_spy):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "uaf.c").write_text(_UAF_C)
    # An excluded dir with a broken file must never be compiled.
    (repo / "vendor").mkdir()
    (repo / "vendor" / "broken.c").write_text("#error never compile me\n")

    result = _cs.scan_target(repo, out_dir=tmp_path / "out")
    assert result.ok is True
    assert result.tus_total == 1
    assert result.tus_analyzed == 1

    rule_ids = {f["rule_id"] for f in result.findings}
    assert any(
        "use-after-free" in rid or rid.startswith("unix.") for rid in rule_ids
    ), rule_ids
    uaf = next(
        f for f in result.findings
        if "use-after-free" in f["rule_id"] or f["rule_id"].startswith("unix.")
    )
    assert uaf["file"] == "uaf.c"
    assert uaf["cwe"] in ("CWE-416", "CWE-415", "CWE-401")
    assert uaf["line"] > 0

    # Sandbox posture: every compile went through the sandbox with the
    # network blocked and Landlock target/output confinement.
    assert sandbox_spy, "compiler ran outside the sandbox"
    for call in sandbox_spy:
        assert call["block_network"] is True
        assert call["target"] == str(repo)
        assert "vendor" not in " ".join(call["cmd"][-3:])


# ---------------------------------------------------------------------
# In-source analyzer suppression — coverage limitation, never a finding
# ---------------------------------------------------------------------
# The scanned repo is untrusted: `[[clang::suppress]]`, `#ifndef
# __clang_analyzer__` and flag-3 linemarkers silence clang --analyze
# with rc 0, so "0 finding(s) from 1/1 TU(s)" would read as a clean
# analysis. compiler_sweep's suppression witness (file + include
# closure) flags each TU; the scan records it as a limitation and
# never drops, adds or rewrites a finding because of it.

_NULL_BODY = "int f(int c){ int *p = 0; if (c) return 0; return *p; }\n"

_SUPPRESSED_TUS = {
    "macro": (
        "#ifndef __clang_analyzer__\n" + _NULL_BODY
        + "#else\nint f(int c){return 0;}\n#endif\n"
    ),
    "attr": (
        "int f(int c){ int *p = 0; if (c) return 0; "
        "[[clang::suppress]] return *p; }\n"
    ),
    # Same constructs authored in a REPO HEADER: the TU text is clean.
    "hdrattr": (
        '#include "s.h"\n'
        "int f(int c){ int *p = 0; if (c) return 0; SUPP return *p; }\n"
    ),
    "hdrmacro": (
        '#include "m.h"\n'
        "int f(int c){ int *p = 0; if (c) return 0; return DEREF(p); }\n"
    ),
    "linemarker": '# 1 "x.h" 3\n' + _NULL_BODY,
}
_SUPPRESSION_HEADERS = {
    "s.h": "#define SUPP [[clang::suppress]]\n",
    "m.h": (
        "#ifndef __clang_analyzer__\n#define DEREF(p) (*(p))\n"
        "#else\n#define DEREF(p) 0\n#endif\n"
    ),
}


@pytest.fixture
def _clang_only(monkeypatch):
    """The constructs under test are clang-analyzer suppressions; pin
    the clang path (gcc -fanalyzer would reject `[[clang::suppress]]`
    in C on older dialects and is not available on every host)."""
    if compiler_sweep._clang_path() is None:
        pytest.skip("clang not installed")
    monkeypatch.setattr(_cs, "_gcc_analyzer", lambda: None)


@functools.lru_cache(maxsize=1)
def _clang_has_gnu_suppress() -> bool:
    """True when the host clang accepts ``__attribute__((suppress))``."""
    clang = compiler_sweep._clang_path()
    if clang is None:
        return False
    try:
        r = subprocess.run(
            [clang, "-fsyntax-only", "-xc", "-Werror", "-"],
            input="__attribute__((suppress)) int x;\n",
            capture_output=True, text=True, timeout=30,
        )
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


_NEEDS_GNU_SUPPRESS = frozenset({
    "annot_paste.c", "rawstr_ff.cpp", "rawstr_u2028.cpp", "splice.c",
    "hex3.c",
    "nested_parens.c", "struct_sizeof.c", "pasted_name.c",
    "pragma_in_args.c",
    "nodiscard_first", "dunder", "Clang_scope", "clang_dunder_scope",
    "gnu_dunder", "gnu_second", "gnu_second_via_header",
    "pasted_under_analyzer",
})


def _scan_snippet(tmp_path, source: str):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "t.c").write_text(source)
    for name, text in _SUPPRESSION_HEADERS.items():
        (repo / name).write_text(text)
    result = _cs.scan_target(repo, out_dir=tmp_path / "out")
    assert result.ok is True, result.reason
    return result


def _null_findings(result):
    return [
        f for f in result.findings
        if "nulldereference" in f["rule_id"].lower()
        or "null-dereference" in f["rule_id"]
    ]


@pytest.mark.parametrize("case", sorted(_SUPPRESSED_TUS))
def test_suppressed_tu_carries_coverage_limitation(
    tmp_path, sandbox_spy, _clang_only, case,
):
    """Each construct silences clang with rc 0; the TU must be reported
    as a coverage limitation in the result, summary and SARIF, with
    no result added."""
    result = _scan_snippet(tmp_path, _SUPPRESSED_TUS[case])

    # The analyzer was silenced (precondition — the bug's shape).
    assert _null_findings(result) == []
    assert result.tus_analyzed == 1
    # ...and the scan says so instead of reading as clean coverage.
    assert [s["tu"] for s in result.suppressed_tus] == ["t.c"], case
    assert result.suppressed_tus[0]["suppression_witness"]
    assert result.unvetted_tus == []
    assert "suppression" in result.summary_line()
    assert "not evidence" in result.summary_line()

    sarif = _cs.to_sarif(result)
    run = sarif["runs"][0]
    # A limitation, never a finding.
    assert run["results"] == []
    notes = [
        n for inv in run["invocations"]
        for n in inv["toolExecutionNotifications"]
    ]
    assert len(notes) == 1
    note = notes[0]
    assert note["properties"]["coverage_limitation"] == (
        "suppression_witness"
    )
    assert note["properties"]["suppression_witness"] == (
        result.suppressed_tus[0]["suppression_witness"]
    )
    uri = note["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "t.c"
    # The tool itself ran fine — this is not a failed execution.
    assert run["invocations"][0]["executionSuccessful"] is True
    # Every compiler run (analyze AND the -E closure vet) was sandboxed.
    assert sandbox_spy
    assert all(c["block_network"] is True for c in sandbox_spy)


def test_clean_control_has_no_limitation_and_keeps_finding(
    tmp_path, sandbox_spy, _clang_only,
):
    """A clean TU keeps its finding, gets no limitation, and its summary
    and SARIF stay the same as before this change."""
    result = _scan_snippet(tmp_path, _NULL_BODY)
    assert len(_null_findings(result)) == 1
    assert result.suppressed_tus == []
    assert result.unvetted_tus == []
    assert result.summary_line() == (
        f"compiler-scan: {len(result.findings)} finding(s) from 1/1 TU(s)"
    )
    run = _cs.to_sarif(result)["runs"][0]
    assert "invocations" not in run


def test_suppression_construct_in_comment_is_inert(
    tmp_path, sandbox_spy, _clang_only,
):
    """A construct inside a comment cannot affect the compile, so it
    must not annotate the TU."""
    # The file witness scans the sanitized view and -E strips
    # comments: a construct spelled inside a comment cannot act on the
    # compile. (A string-literal spelling survives -E and is flagged by
    # the shared closure vet — an over-approximation that only ever
    # ADDS a limitation, so it is not pinned here either way.)
    result = _scan_snippet(
        tmp_path,
        "/* [[clang::suppress]] #ifndef __clang_analyzer__ */\n"
        "// # 1 \"x.h\" 3\n" + _NULL_BODY,
    )
    assert len(_null_findings(result)) == 1
    assert result.suppressed_tus == []


def test_annotation_never_drops_a_finding_that_still_fires(
    tmp_path, sandbox_spy, _clang_only,
):
    """The annotation is additive: a finding clang still reports must
    survive even when the TU is flagged."""
    # clang --analyze ignores a GCC diagnostic pragma, so the finding
    # still fires; the witness still flags the TU. Both must survive:
    # the annotation is additive, never a filter.
    result = _scan_snippet(
        tmp_path,
        '#pragma GCC diagnostic ignored "-Wanalyzer-null-dereference"\n'
        + _NULL_BODY,
    )
    assert len(_null_findings(result)) == 1
    assert [s["tu"] for s in result.suppressed_tus] == ["t.c"]
    run = _cs.to_sarif(result)["runs"][0]
    assert len(run["results"]) == len(result.findings)


def test_failed_closure_vet_recorded_as_unvetted(tmp_path, monkeypatch):
    """A failed -E run means suppression cannot be ruled out; the TU is
    unvetted, not failed and not clean."""
    # The analyzer ran clean but the -E closure vet failed: suppression
    # cannot be ruled out, so the TU is reported as unvetted — still a
    # limitation, never a finding and never a failed TU.
    (tmp_path / "t.c").write_text("int f(void){return 0;}\n")
    monkeypatch.setattr(_cs, "_gcc_analyzer", lambda: None)
    monkeypatch.setattr(_cs, "_clang_path", lambda: "clang")

    def fake_run(cmd, **kwargs):
        rc = 1 if "-E" in cmd else 0
        return subprocess.CompletedProcess(cmd, rc, stdout="", stderr="")

    tu = _cs.analyze_tu(tmp_path, "t.c", sandbox_run=fake_run)
    assert tu.ok is True
    assert tu.diagnostics == []
    assert tu.suppression_witness == ""
    assert "preprocessor exited 1" in tu.suppression_unvetted


def test_vet_crash_keeps_findings_and_records_unvetted(
    tmp_path, sandbox_spy, _clang_only, monkeypatch,
):
    """An exception inside the vet must not cost an analysed TU its
    findings."""
    # The vet only annotates: an unexpected failure inside it must not
    # turn an analysed TU into a failed one and drop its findings.
    def boom(_text):
        raise RuntimeError("vet bug")

    monkeypatch.setattr(_cs, "_suppression_witness", boom)
    result = _scan_snippet(tmp_path, _NULL_BODY)
    assert result.tus_analyzed == 1 and result.tus_failed == 0
    assert len(_null_findings(result)) == 1
    assert result.suppressed_tus == []
    assert result.unvetted_tus == [{
        "tu": "t.c", "reason": "suppression vet failed: RuntimeError",
    }]


def test_witness_not_computed_for_failed_compile(tmp_path, monkeypatch):
    """A failed compile already counts as failed, so no -E vet is spent
    on it."""
    # A broken compile already contributes nothing and is counted as
    # failed; no -E vet is spent on it.
    (tmp_path / "t.c").write_text("[[clang::suppress]] int x;\n")
    monkeypatch.setattr(_cs, "_gcc_analyzer", lambda: None)
    monkeypatch.setattr(_cs, "_clang_path", lambda: "clang")
    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

    tu = _cs.analyze_tu(tmp_path, "t.c", sandbox_run=fake_run)
    assert tu.ok is False
    assert tu.suppression_witness == ""
    assert not any("-E" in c for c in calls)


def test_suppression_limitation_is_not_coverage_downstream(tmp_path):
    """The annotation must not read as coverage or as a finding in any
    consumer of compiler.sarif: merge_sarif keeps it out of results,
    SarifCache gains neither a scanned file nor a result row."""
    import json

    from core.audit.sweep import SarifCache

    result = _cs.CompilerScanResult(
        ok=True, tus_total=2, tus_analyzed=2,
        suppressed_tus=[{
            "tu": "src/a.c", "suppression_witness": "[[clang::suppress",
        }],
        unvetted_tus=[{"tu": "src/b.c", "reason": "preprocessor exited 1"}],
    )
    sarif = _cs.to_sarif(result)
    run = sarif["runs"][0]
    assert run["results"] == []
    assert "artifacts" not in run
    kinds = sorted(
        n["properties"]["coverage_limitation"]
        for inv in run["invocations"]
        for n in inv["toolExecutionNotifications"]
    )
    assert kinds == ["suppression_unvetted", "suppression_witness"]

    scan = tmp_path / "run" / "scan"
    scan.mkdir(parents=True)
    path = scan / "compiler.sarif"
    path.write_text(json.dumps(sarif), encoding="utf-8")

    merged = merge_sarif([str(path)])
    assert merged["runs"][0]["results"] == []
    assert merged["runs"][0]["invocations"] == run["invocations"]

    cache = SarifCache.from_directory(tmp_path / "run")
    assert cache.scanned_files == set()
    assert cache.lookup("src/a.c") is None
    assert cache.lookup("src/b.c") is None


# ---------------------------------------------------------------------
# Attribute-list spellings, odd header names, fail-closed vet
# ---------------------------------------------------------------------

# Each verified to silence clang --analyze (Apple clang 21) while the
# canonical-first-position witness missed it.
_ATTR_LIST_TUS = {
    "nodiscard_first": "[[nodiscard, clang::suppress]] " + _NULL_BODY,
    "dunder": "[[clang::__suppress__]] " + _NULL_BODY,
    "Clang_scope": "[[_Clang::suppress]] " + _NULL_BODY,
    "clang_dunder_scope": "[[__clang__::suppress]] " + _NULL_BODY,
    "gnu_dunder": "__attribute__((__suppress__)) " + _NULL_BODY,
    "gnu_second": "__attribute__((noinline, suppress)) " + _NULL_BODY,
    "gnu_second_via_header": '#include "a.h"\nNOCHECK ' + _NULL_BODY,
    # Pasted spellings: no construct in any repo file's TEXT; only the
    # analyzer-environment -E output (-D__clang_analyzer__=1) carries
    # the attribute — pins that the vet preprocesses as the analyzer.
    "pasted_under_analyzer": (
        "#define CA __clang_ ## analyzer__\n"
        "#if CA\n#define N [[clang::su ## ppress]]\n#else\n#define N\n"
        "#endif\nN " + _NULL_BODY
    ),
}


@pytest.mark.parametrize("case", sorted(_ATTR_LIST_TUS))
def test_attribute_list_spellings_carry_limitation(
    tmp_path, sandbox_spy, _clang_only, case,
):
    """Each spelling silences clang end to end and must produce a
    limitation, including the pasted form only visible in analyzer-
    environment -E output."""
    if case in _NEEDS_GNU_SUPPRESS and not _clang_has_gnu_suppress():
        pytest.skip("clang does not support __attribute__((suppress))")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "t.c").write_text(_ATTR_LIST_TUS[case])
    (repo / "a.h").write_text(
        "#define NOCHECK __attribute__((noinline, suppress))\n",
    )
    result = _cs.scan_target(repo, out_dir=tmp_path / "out")
    assert result.ok is True, result.reason
    assert _null_findings(result) == []  # analyzer really was silenced
    assert [s["tu"] for s in result.suppressed_tus] == ["t.c"], (
        case, result.summary_line(),
    )


def test_cpp_using_prefix_carries_limitation(
    tmp_path, sandbox_spy, _clang_only,
):
    """The C++ 'using clang:' attribute prefix silences clang and must
    produce a limitation."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "t.cpp").write_text(
        "int f(int c){ int *p = 0; if (c) return 0; "
        "[[using clang: suppress]] return *p; }\n",
    )
    result = _cs.scan_target(repo, out_dir=tmp_path / "out")
    assert result.ok is True, result.reason
    assert _null_findings(result) == []
    assert [s["tu"] for s in result.suppressed_tus] == ["t.cpp"]


def test_quoted_header_name_is_vetted(tmp_path, sandbox_spy, _clang_only):
    """-E escapes the quote in this header's name; its analyzer
    conditional must still be found rather than the TU reading as
    clean."""
    # clang escapes the `"` in the -E linemarker; the header must still
    # be raw-scanned (its __clang_analyzer__ conditional resolves away
    # in -E output) — previously the marker went unparsed and the TU
    # read as vetted clean.
    repo = tmp_path / "repo"
    (repo / "include").mkdir(parents=True)
    (repo / "include" / 'q"x.h').write_text(
        "#ifdef __clang_analyzer__\n#define DEREF(p) 0\n#else\n"
        "#define DEREF(p) (*(p))\n#endif\n",
    )
    (repo / "t.c").write_text(
        '#include <q"x.h>\n'
        "int f(int c){ int *p = 0; if (c) return 0; return DEREF(p); }\n",
    )
    result = _cs.scan_target(repo, out_dir=tmp_path / "out")
    assert result.ok is True, result.reason
    assert _null_findings(result) == []
    assert result.unvetted_tus == []
    assert [s["tu"] for s in result.suppressed_tus] == ["t.c"]
    assert 'q"x.h' in result.suppressed_tus[0]["suppression_witness"]


def _fake_clang(monkeypatch):
    monkeypatch.setattr(_cs, "_gcc_analyzer", lambda: None)
    monkeypatch.setattr(_cs, "_clang_path", lambda: "clang")


def _vet_with(tmp_path, monkeypatch, pp_behaviour):
    """Run analyze_tu on a clean TU whose analysis succeeds; the -E vet
    step behaves as *pp_behaviour(cmd)* (return a CompletedProcess or
    raise)."""
    (tmp_path / "t.c").write_text("int f(void){return 0;}\n")
    _fake_clang(monkeypatch)

    def fake_run(cmd, **kwargs):
        if "-E" in cmd:
            return pp_behaviour(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    return _cs.analyze_tu(tmp_path, "t.c", sandbox_run=fake_run)


@pytest.mark.parametrize("label,behaviour,expect", [
    ("stdout None", lambda c: subprocess.CompletedProcess(c, 0, None, ""),
     "no output"),
    ("stdout empty", lambda c: subprocess.CompletedProcess(c, 0, "", ""),
     "no output"),
    ("runner raises", lambda c: (_ for _ in ()).throw(
        subprocess.TimeoutExpired(c, 1)), "preprocessor run failed"),
    ("runner OSError", lambda c: (_ for _ in ()).throw(OSError("x")),
     "preprocessor run failed"),
])
def test_vet_without_usable_output_fails_closed(
    tmp_path, monkeypatch, label, behaviour, expect,
):
    """A missing or empty stdout, a timeout or an OSError from the -E
    run must leave the TU unvetted, never vetted clean."""
    tu = _vet_with(tmp_path, monkeypatch, behaviour)
    assert tu.ok is True
    assert tu.suppression_witness == ""
    assert expect in tu.suppression_unvetted, (label, tu)


def test_vet_preprocessed_output_over_cap_fails_closed(tmp_path, monkeypatch):
    """-E output over the cap is a partial closure and must not vet
    clean."""
    # The +1 slice is what lets the closure vet SEE that the output
    # overflowed the cap; a partial closure must never vet clean.
    monkeypatch.setattr(_cs, "_MAX_PP_TEXT_BYTES", 40)
    # The base vet reads the same module-level cap.
    monkeypatch.setattr(compiler_sweep, "_MAX_PP_TEXT_BYTES", 40)
    tu_path = str(tmp_path / "t.c")
    out = f'# 1 "{tu_path}"\n' + "int x;\n" * 20
    assert len(out) > 41
    tu = _vet_with(
        tmp_path, monkeypatch,
        lambda c: subprocess.CompletedProcess(c, 0, out, ""),
    )
    assert "exceeds the scan cap" in tu.suppression_unvetted


def test_vet_tu_over_byte_cap_fails_closed(tmp_path, monkeypatch):
    """A TU too large to scan cannot be vetted, and no -E run is spent
    on it."""
    monkeypatch.setattr(_cs, "_MAX_CLOSURE_FILE_BYTES", 5)
    tu = _vet_with(
        tmp_path, monkeypatch,
        lambda c: pytest.fail("no -E once the TU itself cannot be vetted"),
    )
    assert tu.suppression_unvetted == "TU exceeds the byte cap"


def test_vet_tu_unreadable_fails_closed(tmp_path, monkeypatch):
    """A TU that cannot be read cannot be vetted, and no -E run is spent
    on it."""
    monkeypatch.setattr(_cs, "read_text_capped", lambda *a, **k: None)
    tu = _vet_with(
        tmp_path, monkeypatch,
        lambda c: pytest.fail("no -E once the TU itself cannot be vetted"),
    )
    assert tu.suppression_unvetted == "TU unreadable"


def test_unvetted_summary_and_notification_level(tmp_path):
    """An unvetted TU must be visible to the operator: a summary clause
    and a warning-level SARIF notification."""
    result = _cs.CompilerScanResult(
        ok=True, tus_total=1, tus_analyzed=1,
        unvetted_tus=[{"tu": "a.c", "reason": "preprocessor exited 1"}],
    )
    line = result.summary_line()
    assert "1 TU(s) not vetted for analyzer suppression" in line
    assert "not evidence" in line
    note = _cs.to_sarif(result)["runs"][0]["invocations"][0][
        "toolExecutionNotifications"][0]
    # "warning" (not "note"): a limitation an operator must see.
    assert note["level"] == "warning"


# ---------------------------------------------------------------------
# Monotonic-witness cases, end to end on real clang
# ---------------------------------------------------------------------

_CAT = "#define CAT(a,b) a##b\n"
_E2E_SUPPRESSED = {
    "digraph.cpp": "int f(void){ <:<:clang::suppress:>:> "
                   "{ int *q = 0; return *q; } }\n",
    "digraph_mixed.cpp": "int f(void){ <:[clang::suppress]:> "
                         "{ int *q = 0; return *q; } }\n",
    "annot_paste.c": _CAT + '#define ATTRS(x) __attribute__((annotate("))"), x))\n'
                     "ATTRS(CAT(sup,press)) int f(void){ int *q = 0; return *q; }\n",
    "rawstr_ff.cpp": _CAT + 'static const char *s = R"(\f# 1 "/usr/include/stdio.h" 3\n)";\n'
                     "__attribute__((CAT(sup,press))) int f(void){ int *q = 0; return *q; }\n",
    "rawstr_u2028.cpp": _CAT + 'static const char *s = R"(\u2028# 1 "/usr/include/stdio.h" 3\n)";\n'
                        "__attribute__((CAT(sup,press))) int f(void){ int *q = 0; return *q; }\n",
    "splice.c": "__attribute__((sup\\\npress)) int f(void){ int *q = 0; return *q; }\n",
}
_E2E_UNVETTED = {
    "hex3.c": _CAT + '#line 1 "\\x02fusr/include/stdio.h"\n'
              "__attribute__((CAT(sup,press))) int f(void){ int *q = 0; return *q; }\n",
    "ff_line.c": '\f#line 1 "/usr/include/stdio.h"\nint f(void){ int *q = 0; return *q; }\n',
    "vt_line.c": '\v#line 1 "/usr/include/stdio.h"\nint f(void){ int *q = 0; return *q; }\n',
    "macro_line.c": '#define P "/usr/include/stdio.h"\n#line 1 P\n'
                    "int f(void){ int *q = 0; return *q; }\n",
}
# Documented false positives of the line-local additive checks: clang
# still reports the bug, the finding is KEPT, and the TU is annotated
# (suppressed / unvetted) — a limitation, never a dropped finding.
_E2E_DOCUMENTED_FP = {
    "cleanup.c": "static void suppress(int *p){ (void)p; }\n"
                 "int f(void){ __attribute__((cleanup(suppress))) int x = 0; (void)x; "
                 "int *q = 0; return *q; }\n",
    "deprecated.cpp": '[[deprecated("call suppress() instead")]] void g();\n'
                      "int f(void){ int *q = 0; return *q; }\n",
    "rawstr_hash.cpp": 'static const char *script = R"(\n# 1. install deps\n# 2 run\n)";\n'
                       "int f(void){ (void)script; int *q = 0; return *q; }\n",
}


def _scan_files(tmp_path, files):
    repo = tmp_path / "repo"
    repo.mkdir()
    for name, text in files.items():
        (repo / name).write_text(text)
    result = _cs.scan_target(repo, out_dir=tmp_path / "out")
    assert result.ok is True, result.reason
    return result


@pytest.mark.parametrize("name", sorted(_E2E_SUPPRESSED))
def test_e2e_suppressed_spellings(tmp_path, sandbox_spy, _clang_only, name):
    """Digraph, pasted, raw-string-adjacent and spliced attribute
    spellings silence clang end to end and must produce a limitation."""
    if name in _NEEDS_GNU_SUPPRESS and not _clang_has_gnu_suppress():
        pytest.skip("clang does not support __attribute__((suppress))")
    result = _scan_files(tmp_path, {name: _E2E_SUPPRESSED[name]})
    assert result.tus_analyzed == 1
    assert _null_findings(result) == []  # really silenced
    assert [s["tu"] for s in result.suppressed_tus] == [name], (
        result.summary_line(), result.unvetted_tus,
    )


@pytest.mark.parametrize("name", sorted(_E2E_UNVETTED))
def test_e2e_laundering_line_is_unvetted(
    tmp_path, sandbox_spy, _clang_only, name,
):
    """A #line that relabels repo code as a system header drops clang's
    finding; the TU must be reported as unvetted."""
    if name in _NEEDS_GNU_SUPPRESS and not _clang_has_gnu_suppress():
        pytest.skip("clang does not support __attribute__((suppress))")
    result = _scan_files(tmp_path, {name: _E2E_UNVETTED[name]})
    assert result.tus_analyzed == 1
    # The finding was re-attributed to a system path (dropped) — the
    # TU must not read as clean.
    assert _null_findings(result) == []
    assert [u["tu"] for u in result.unvetted_tus] == [name], (
        result.summary_line(), result.suppressed_tus,
    )


@pytest.mark.parametrize("name", sorted(_E2E_DOCUMENTED_FP))
def test_e2e_documented_false_positive_keeps_finding(
    tmp_path, sandbox_spy, _clang_only, name,
):
    """The documented false positives annotate the TU but must keep the
    finding clang still reports."""
    result = _scan_files(tmp_path, {name: _E2E_DOCUMENTED_FP[name]})
    assert len(_null_findings(result)) == 1
    assert result.suppressed_tus or result.unvetted_tus, (
        result.summary_line(),
    )


# ---------------------------------------------------------------------
# Layer-2 witness end to end, witness kinds, SARIF paths
# ---------------------------------------------------------------------

_LAYER2_UNVETTED = {
    "rel_line.c": '#line 1 "../outside.c"\n'
                  "int f(int c){ int *p = 0; if (c) return 0; return *p; }\n",
    "nbsp_line.c": '\u00a0#line 1 "/usr/include/zz.h"\n'
                   "int f(int c){ int *p = 0; if (c) return 0; return *p; }\n",
}
_LAYER2_SUPPRESSED = {
    "nested_parens.c": "__attribute__((aligned(sizeof(int)),\n  suppress)) "
                       "int f(int c){ int *p = 0; if (c) return 0; return *p; }\n",
    "struct_sizeof.c": "__attribute__((aligned(sizeof(struct { int x; })),\n  suppress)) "
                       "int f(int c){ int *p = 0; if (c) return 0; return *p; }\n",
    "pasted_name.c": "#define CAT(a,b) a##b\n__attribute__((aligned(sizeof(int)),\n"
                     "  CAT(sup,press))) int f(int c){ int *p = 0; if (c) return 0; return *p; }\n",
    "pragma_in_args.c": "#define P(x) _Pragma(#x)\n__attribute__((aligned(sizeof(int)) "
                        "P(clang diagnostic push),\n  suppress)) "
                        "int f(int c){ int *p = 0; if (c) return 0; return *p; }\n",
}


@pytest.mark.parametrize("name", sorted(_LAYER2_UNVETTED))
def test_layer2_escaping_relabel_is_unvetted(tmp_path, sandbox_spy, _clang_only, name):
    result = _scan_files(tmp_path, {name: _LAYER2_UNVETTED[name]})
    assert _null_findings(result) == []          # the finding was relabelled away
    assert [u["tu"] for u in result.unvetted_tus] == [name], result.summary_line()


@pytest.mark.parametrize("name", sorted(_LAYER2_SUPPRESSED))
def test_layer2_suppression_is_annotated(tmp_path, sandbox_spy, _clang_only, name):
    if name in _NEEDS_GNU_SUPPRESS and not _clang_has_gnu_suppress():
        pytest.skip("clang does not support __attribute__((suppress))")
    result = _scan_files(tmp_path, {name: _LAYER2_SUPPRESSED[name]})
    assert _null_findings(result) == []          # clang really was silenced
    assert [s["tu"] for s in result.suppressed_tus] == [name], result.summary_line()


def test_summary_names_witness_kinds(tmp_path):
    result = _cs.CompilerScanResult(
        ok=True, tus_total=3, tus_analyzed=3,
        suppressed_tus=[
            {"tu": "a.c", "suppression_witness": "_Pragma( (in common/platform.h)"},
            {"tu": "b.c", "suppression_witness": "_Pragma("},
            {"tu": "c.c", "suppression_witness": "__clang_analyzer__ (in enc/memory.h)"},
        ],
    )
    line = result.summary_line()
    assert "3 TU(s)" in line
    assert "2 `_Pragma` operator, payload not checked" in line
    assert "1 analyzer-conditional code" in line
    assert "silence there is not evidence" in line


def test_uncertain_list_is_not_labelled_a_suppress_attribute(tmp_path):
    result = _cs.CompilerScanResult(
        ok=True, tus_total=1, tus_analyzed=1,
        suppressed_tus=[{"tu": "a.c", "suppression_witness":
                         "[[gnu::cold … (attribute list still open at end of input)"}],
    )
    line = result.summary_line()
    assert "unverifiable attribute list" in line
    assert "`suppress` attribute" not in line
    note = _cs.to_sarif(result)["runs"][0]["invocations"][0][
        "toolExecutionNotifications"][0]
    assert note["properties"]["witness_kind"] == "unverifiable_attribute_list"


def test_sarif_notification_has_witness_kind(tmp_path):
    result = _cs.CompilerScanResult(
        ok=True, tus_total=1, tus_analyzed=1,
        suppressed_tus=[{"tu": "a.c", "suppression_witness": "_Pragma("}],
    )
    note = _cs.to_sarif(result)["runs"][0]["invocations"][0][
        "toolExecutionNotifications"][0]
    assert note["properties"]["witness_kind"] == "pragma_operator"
    assert note["properties"]["suppression_witness"] == "_Pragma("


def test_sarif_carries_no_absolute_target_path(tmp_path, sandbox_spy, _clang_only):
    import json
    hdr_dir = tmp_path / "repo" / "inc"
    hdr_dir.mkdir(parents=True)
    (hdr_dir / "m.h").write_text(
        '#define NOWARN _Pragma("clang diagnostic ignored \\"-Wall\\"")\n')
    (tmp_path / "repo" / "t.c").write_text(
        '#include "inc/m.h"\nNOWARN\n'
        '#line 1 "/usr/include/zz.h"\n'
        "int f(int c){ int *p = 0; if (c) return 0; return *p; }\n")
    (tmp_path / "repo" / "u.c").write_text(
        '#line 1 "/usr/include/zz.h"\n'
        "int f(int c){ int *p = 0; if (c) return 0; return *p; }\n")
    result = _cs.scan_target(tmp_path / "repo", out_dir=tmp_path / "out")
    assert result.suppressed_tus and result.unvetted_tus, result.summary_line()
    text = json.dumps(_cs.to_sarif(result))
    assert str(tmp_path) not in text
    assert str((tmp_path / "repo").resolve()) not in text


# ---------------------------------------------------------------------
# SARIF carries no host path from -E linemarkers; resolution limits
# ---------------------------------------------------------------------

def _sarif_strings(obj):
    """Every string in a decoded SARIF object (keys and values)."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _sarif_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _sarif_strings(v)


_ABS_PATH_RES = (
    # POSIX absolute path after whitespace, a quote or "("
    r"""(?:^|[\s"'(])/[^\s/"'()]""",
    # Windows drive path, either separator
    r"""(?:^|[\s"'(])[A-Za-z]:[\\/]""",
    # UNC path
    r"""(?:^|[\s"'(])\\\\[^\s\\]""",
    # backslash-separated path segment
    r"""[A-Za-z0-9_.-]\\[A-Za-z0-9_.-]+\\""",
)

_LEAK_TU = ("#define S suppress\n[[gnu::aligned(sizeof(int)),\n"
            "#include <stdbool.h>\n clang::S]] int y;\n"
            "int g(int *p){ p = 0; return *p; }\n")


def test_sarif_has_no_toolchain_path_from_linemarkers(
    tmp_path, sandbox_spy, _clang_only,
):
    """A linemarker inside an attribute list (here an ``#include``
    expanded inside ``[[ ... ]]``) must not carry the toolchain's
    absolute header path into any SARIF string. Path literals written in
    the scanned source itself are out of scope."""
    import json
    import re
    result = _scan_files(tmp_path, {"leak2.c": _LEAK_TU})
    assert [s["tu"] for s in result.suppressed_tus] == ["leak2.c"], (
        result.summary_line(), result.unvetted_tus)
    tu = tmp_path / "repo" / "leak2.c"
    pp = subprocess.run(
        [compiler_sweep._clang_path(), "-E", "-D__clang_analyzer__=1", str(tu)],
        capture_output=True, text=True, check=True).stdout
    emitted = {ln.split('"')[1] for ln in pp.splitlines()
               if ln.startswith("# ") and ln.count('"') >= 2}
    toolchain = {n for n in emitted if n.startswith("/") and "stdbool.h" in n}
    assert toolchain, emitted
    sarif = _cs.to_sarif(result)
    strings = list(_sarif_strings(sarif))
    fixed = ["/Library", "/usr", "/opt", "/Applications", str(Path.home())]
    for s in strings:
        for bad in toolchain:
            assert bad not in s, s
        for bad in fixed:
            assert bad not in s, (bad, s)
        for rx in _ABS_PATH_RES:
            assert not re.search(rx, s), (rx, s)
    witness = result.suppressed_tus[0]["suppression_witness"]
    assert "clang::suppress" in witness and "stdbool" not in witness, witness
    text = json.dumps(sarif)
    assert str(tmp_path) not in text
    assert str((tmp_path / "repo").resolve()) not in text


def test_resolution_limit_marks_tu_unvetted(tmp_path, sandbox_spy, _clang_only):
    deep = "d/" * 400 + "x.c"
    result = _scan_files(tmp_path, {"deep.c": (
        f'#line 1 "{deep}"\n'
        "int f(int c){ int *p = 0; if (c) return 0; return *p; }\n")})
    assert [u["tu"] for u in result.unvetted_tus] == ["deep.c"], (
        result.summary_line(), result.suppressed_tus)
    reason = result.unvetted_tus[0]["reason"]
    assert "resolution limit" in reason and deep not in reason, reason
    assert "not vetted" in result.summary_line()


def test_limit_reason_under_a_long_root_carries_no_path_text(
    tmp_path, sandbox_spy, _clang_only,
):
    """A repo header 250 directories deep trips the per-name component
    limit; under a target root longer than 120 characters, no SARIF
    string may carry any root component or the include name."""
    root = tmp_path / ("a_very_long_directory_name_" + "x" * 60) / "tgt"
    root.mkdir(parents=True)
    assert len(str(root)) > 120
    deep = "/".join(["a"] * 250) + "/h.h"
    (root / deep).parent.mkdir(parents=True)
    (root / deep).write_text("int h;\n")
    (root / "deep.c").write_text(
        f'#include "{deep}"\n'
        "int f(int c){ int *p = 0; if (c) return 0; return *p; }\n")
    result = _cs.scan_target(root, out_dir=tmp_path / "out")
    assert result.ok is True, result.reason
    assert [u["tu"] for u in result.unvetted_tus] == ["deep.c"], (
        result.summary_line())
    assert "resolution limit" in result.unvetted_tus[0]["reason"]
    frags = [p for p in root.resolve().parts if len(p) > 3]
    frags += [p for p in root.parts if len(p) > 3] + [deep, "a/a/a"]
    for s in _sarif_strings(_cs.to_sarif(result)):
        for frag in frags:
            assert frag not in s, (frag, s)


def test_symlink_chain_marks_tu_unvetted_quickly(tmp_path, sandbox_spy, _clang_only):
    """1,000 chained symlinks, each target ``"d/../"*200 + next``, named by
    20 relative #line markers: the vet must end "not vetted" within 5 s."""
    import time
    repo = tmp_path / "repo"
    (repo / "d").mkdir(parents=True)
    (repo / "real").mkdir()
    for i in range(1000):
        (repo / f"s{i}").symlink_to("d/../" * 200 + (f"s{i + 1}" if i < 999 else "real"))
    lines = "".join(f'#line 1 "s0/f{i}.c"\nint v{i};\n' for i in range(20))
    (repo / "t.c").write_text(
        lines + '#line 100 "t.c"\n'
        "int f(int c){ int *p = 0; if (c) return 0; return *p; }\n")
    t0 = time.perf_counter()
    result = _cs.scan_target(repo, out_dir=tmp_path / "out")
    took = time.perf_counter() - t0
    assert result.ok is True, result.reason
    assert [u["tu"] for u in result.unvetted_tus] == ["t.c"], result.summary_line()
    assert took <= 5.0, took
