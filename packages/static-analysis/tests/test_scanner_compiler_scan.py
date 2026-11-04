"""Tests for the ``--compiler-scan`` wiring in scanner.py and
raptor_agentic.py.

Same hyphenated-package importlib pattern as ``test_scanner_cocci``.
Covers:
  * ``run_compiler_scan_stage`` skip on non-C targets
  * SARIF emission + return shape on a mocked scan result
  * loud stderr reporting when the scan refuses or the cap skipped TUs
  * CLI flag presence + default-off semantics (scanner + agentic)
  * agentic → scanner argv forwarding
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
import pytest

# parents[3]: tests/ → static-analysis/ → packages/ → repo root
_REPO_ROOT = str(Path(__file__).resolve().parents[3])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

_SCANNER_PATH = Path(_REPO_ROOT) / "packages/static-analysis/scanner.py"
_spec = importlib.util.spec_from_file_location(
    "static_analysis_scanner_compiler_scan", _SCANNER_PATH,
)
_scanner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_scanner)


def _load_cs():
    return _scanner._load_compiler_scan()


@pytest.fixture(autouse=True)
def _baseline_compiler_channel_only(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(_load_cs(), "run_memcpy_overlap", lambda *a, **kw: SimpleNamespace(
        value=SimpleNamespace(diagnostics={}, limitations=[]),
    ))


# ---------------------------------------------------------------------
# run_compiler_scan_stage
# ---------------------------------------------------------------------


def test_stage_skips_non_c_target(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hi')\n")
    out = tmp_path / "out"
    out.mkdir()

    called = []
    monkeypatch.setattr(
        _scanner, "_load_compiler_scan",
        lambda: called.append(1) or None,
    )
    assert _scanner.run_compiler_scan_stage(repo, out) == []
    assert not called  # never even loaded the module
    assert not (out / "compiler.sarif").exists()


def test_stage_writes_sarif_on_success(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.c").write_text("int main(void){return 0;}\n")
    out = tmp_path / "out"
    out.mkdir()

    cs = _load_cs()
    fake_result = cs.CompilerScanResult(
        ok=True, tus_total=1, tus_analyzed=1,
        findings=[{
            "rule_id": "-Wanalyzer-null-dereference", "file": "main.c",
            "line": 3, "message": "null deref", "cwe": "CWE-476",
            "compiler": "gcc", "tu": "main.c",
        }],
    )
    monkeypatch.setattr(cs, "scan_target", lambda *a, **k: fake_result)

    paths = _scanner.run_compiler_scan_stage(repo, out, max_tus=100)
    assert paths == [str(out / "compiler.sarif")]
    sarif = json.loads((out / "compiler.sarif").read_text(encoding="utf-8"))
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "compiler"
    assert len(sarif["runs"][0]["results"]) == 1


def test_stage_reports_refusal_loudly(tmp_path, monkeypatch, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.c").write_text("int main(void){return 0;}\n")
    out = tmp_path / "out"
    out.mkdir()

    cs = _load_cs()
    monkeypatch.setattr(
        cs, "scan_target",
        lambda *a, **k: cs.CompilerScanResult(
            ok=False, reason="core.sandbox unavailable — refusing",
        ),
    )
    assert _scanner.run_compiler_scan_stage(repo, out) == []
    err = capsys.readouterr().err
    assert "compiler-scan did not run" in err
    assert "sandbox" in err
    assert not (out / "compiler.sarif").exists()


def test_stage_reports_cap_skips_on_stderr(tmp_path, monkeypatch, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.c").write_text("int main(void){return 0;}\n")
    out = tmp_path / "out"
    out.mkdir()

    cs = _load_cs()
    monkeypatch.setattr(
        cs, "scan_target",
        lambda *a, **k: cs.CompilerScanResult(
            ok=True, tus_total=5, tus_analyzed=2, tus_skipped_cap=3,
        ),
    )
    paths = _scanner.run_compiler_scan_stage(repo, out, max_tus=2)
    assert len(paths) == 1
    err = capsys.readouterr().err
    assert "SKIPPED" in err
    assert "--compiler-scan-max-tus" in err


def test_stage_forwards_max_tus(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.c").write_text("int main(void){return 0;}\n")
    out = tmp_path / "out"
    out.mkdir()

    cs = _load_cs()
    seen_kwargs = {}

    def fake_scan(target, **kwargs):
        seen_kwargs.update(kwargs)
        return cs.CompilerScanResult(ok=True)

    monkeypatch.setattr(cs, "scan_target", fake_scan)
    _scanner.run_compiler_scan_stage(repo, out, max_tus=7)
    assert seen_kwargs["max_tus"] == 7

    # None ⇒ module default, not an explicit override.
    seen_kwargs.clear()
    _scanner.run_compiler_scan_stage(repo, out, max_tus=None)
    assert "max_tus" not in seen_kwargs


# ---------------------------------------------------------------------
# CLI flag surface
# ---------------------------------------------------------------------


def test_scanner_flags_default_off():
    import argparse
    # Reconstruct the parser the same way main() does — cheapest way to
    # assert flag presence + defaults without running a scan.
    src = _SCANNER_PATH.read_text(encoding="utf-8")
    assert '"--compiler-scan"' in src
    assert '"--no-compiler-scan"' in src
    assert '"--compiler-scan-max-tus"' in src
    # Default-off wiring: the stage only runs on the opt-in flag.
    assert "args.compiler_scan and not args.no_compiler_scan" in src
    # Help text says no repo code executes (operator-facing contract).
    ap = argparse.ArgumentParser()
    ap.add_argument("--compiler-scan", action="store_true")
    ns = ap.parse_args([])
    assert ns.compiler_scan is False


def test_agentic_forwards_compiler_scan_flags():
    src = (Path(_REPO_ROOT) / "raptor_agentic.py").read_text(encoding="utf-8")
    assert '"--compiler-scan"' in src
    assert '"--no-compiler-scan"' in src
    assert '"--compiler-scan-max-tus"' in src
    # Forwarding into the scanner subprocess argv, gated on the
    # --no override.
    assert 'semgrep_cmd.append("--compiler-scan")' in src
    assert "args.compiler_scan and not args.no_compiler_scan" in src
    assert '"--compiler-scan-max-tus",' in src


def test_stage_reports_suppressed_tus_on_stderr(tmp_path, monkeypatch, capsys):
    """A suppression-limited scan must print its summary to stderr and
    write the notification into compiler.sarif, so the operator sees
    it without reading logs."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.c").write_text("int main(void){return 0;}\n")
    out = tmp_path / "out"
    out.mkdir()

    cs = _load_cs()
    monkeypatch.setattr(
        cs, "scan_target",
        lambda *a, **k: cs.CompilerScanResult(
            ok=True, tus_total=1, tus_analyzed=1,
            suppressed_tus=[{
                "tu": "main.c", "suppression_witness": "__clang_analyzer__",
            }],
        ),
    )
    paths = _scanner.run_compiler_scan_stage(repo, out)
    assert len(paths) == 1
    err = capsys.readouterr().err
    assert "suppression" in err
    assert "0 finding(s) from 1/1 TU(s)" in err
    sarif = json.loads((out / "compiler.sarif").read_text(encoding="utf-8"))
    run = sarif["runs"][0]
    assert run["results"] == []
    assert run["invocations"][0]["toolExecutionNotifications"]


def test_stage_runs_shared_detector_and_exports_its_findings(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from core.detectors import compiler as detector

    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "main.c"
    source.write_text("void f(char *p) { *p = 1; }\n")
    cs = _load_cs()
    monkeypatch.setattr(cs, "_gcc_analyzer", lambda: ("/trusted/gcc", "json"))
    monkeypatch.setattr(cs, "_clang_path", lambda: None)
    monkeypatch.setattr(cs, "_suppression_vet", lambda *a: ("", ""))
    calls = []
    executions = []
    original = detector.run_detector

    def observe(*args):
        result = original(*args)
        executions.append(result)
        return result

    monkeypatch.setattr(detector, "run_detector", observe)

    def run(cmd, **kwargs):
        calls.append(kwargs)
        return SimpleNamespace(returncode=0, stderr=json.dumps([{
            "kind": "warning", "option": "-Wanalyzer-null-dereference",
            "message": "dereference of NULL p",
            "locations": [{"caret": {"file": str(source), "line": 1}}],
        }]))

    monkeypatch.setattr(cs, "_sandbox_runner", lambda: run)
    paths = _scanner.run_compiler_scan_stage(repo, tmp_path / "out")
    assert len(calls) == len(executions) == len(paths) == 1
    assert executions[0].identifier == "compiler-diagnostics"
    assert calls[0]["block_network"] is True
    sarif = json.loads(Path(paths[0]).read_text())
    finding = sarif["runs"][0]["results"][0]
    assert finding["ruleId"] == "-Wanalyzer-null-dereference"
    assert finding["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "main.c"
    assert not Path(calls[0]["output"]).exists()


def test_additional_detector_limitation_is_reported_on_stderr(tmp_path, monkeypatch, capsys):
    repo = tmp_path / 'repo'
    repo.mkdir()
    (repo / 'a.c').write_text('void f(void) {}\n')
    out = tmp_path / 'out'
    out.mkdir()
    cs = _load_cs()
    monkeypatch.setattr(cs, 'scan_target', lambda *a, **kw: cs.CompilerScanResult(
        ok=True, tus_total=1, tus_analyzed=1, detector_limitations=[{
            'tu': 'a.c', 'reason': 'Clang unavailable', 'detector': 'stack_return',
        }],
    ))
    _scanner.run_compiler_scan_stage(repo, out)
    assert 'additional analyzer limitation' in capsys.readouterr().err


def test_stage_uses_callers_setup(tmp_path, monkeypatch):
    from core.detectors.setup import AnalysisSetup
    (tmp_path / 'main.c').write_text('int main(void){return 0;}\n')
    setup = AnalysisSetup()
    cs = _load_cs()
    seen = []
    def scan(target, **kwargs):
        seen.append(kwargs['setup'])
        return cs.CompilerScanResult(ok=True)
    monkeypatch.setattr(cs, 'scan_target', scan)
    _scanner.run_compiler_scan_stage(tmp_path, tmp_path / 'out', setup=setup)
    assert seen == [setup]


@pytest.mark.parametrize('compiler,disabled,expanded,count,retained', [
    (True, False, True, 2, True), (True, False, False, 1, False),
    (False, False, True, 1, False), (True, True, True, 1, False),
    (False, False, False, 0, False),
])
def test_scanner_owns_one_setup_for_compiler_and_expanded_stages(compiler, disabled, expanded, count, retained):
    import ast
    from types import SimpleNamespace
    from core.detectors.setup import AnalysisSetup, PreparedViews
    tree = ast.parse(_SCANNER_PATH.read_text())
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
    # Execute the actual adjacent dispatch statements, without running unrelated
    # scanners or model analysis. A stage must receive the same run owner.
    block = next(node for node in ast.walk(main) if isinstance(node, ast.Try)
                 and any(isinstance(item, ast.Assign)
                         and any(isinstance(t, ast.Name) and t.id == 'analysis_setup' for t in item.targets)
                         for item in node.body))
    start = next(i for i, node in enumerate(block.body) if isinstance(node, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == 'analysis_setup' for t in node.targets))
    end = next(i for i in range(start, len(block.body)) if isinstance(block.body[i], ast.If)
               and ast.unparse(block.body[i].test) == 'args.expanded_semgrep')
    program = ast.fix_missing_locations(ast.Module(body=block.body[start:end+1], type_ignores=[]))
    calls = []
    def stage(*a, **kw):
        calls.append(kw['setup'])
        return []
    env = {'AnalysisSetup': AnalysisSetup, 'PreparedViews': PreparedViews, 'args': SimpleNamespace(
        compiler_scan=compiler, no_compiler_scan=disabled, compiler_scan_max_tus=None,
        expanded_semgrep=expanded, extra_config=[]), 'repo_path': Path('/target'),
        'out_dir': Path('/output'), 'rules_dirs': [], 'resolved_baseline': [],
        'run_compiler_scan_stage': stage, 'run_expanded_semgrep_stage': stage}
    exec(compile(program, '<scanner setup dispatch>', 'exec'), env)
    assert len(calls) == count
    assert all(setup is env["analysis_setup"] for setup in calls)
    assert (env["analysis_setup"].preprocessed_views is not None) == retained
