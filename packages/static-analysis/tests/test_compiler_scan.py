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
"""

from __future__ import annotations

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

compiler_sweep._reset_probe_cache()
HAVE_ANALYZER = (
    compiler_sweep._gcc_analyzer() is not None
    or compiler_sweep._clang_path() is not None
)
needs_analyzer = pytest.mark.skipif(
    not HAVE_ANALYZER, reason="neither gcc -fanalyzer nor clang installed",
)


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
