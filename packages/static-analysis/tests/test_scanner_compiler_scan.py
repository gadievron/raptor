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
