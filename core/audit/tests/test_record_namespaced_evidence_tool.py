"""`record` G2 gate accepts namespaced evidence tools.

VALID_EVIDENCE_TOOLS stores namespaced tools (dynamic:crash,
frida:runtime, dark_verify:*) under their full colon-qualified names.
The G2 validity check must therefore test the full normalized string
as well as the stripped base name — checking only the base rejected
every namespaced choice the argument parser itself offers, so findings
backed by dynamic/frida/dark_verify evidence could never be recorded.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "libexec" / "raptor-audit"


def _load_cli():
    loader = SourceFileLoader("raptor_audit_cli_g2", str(_SCRIPT))
    spec = importlib.util.spec_from_loader("raptor_audit_cli_g2", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _record_args(out_dir: Path, target: Path, **overrides) -> SimpleNamespace:
    base = dict(
        out=str(out_dir),
        target=str(target),
        file="src/a.c",
        function="foo",
        status="finding",
        body="dynamic crash replay output",
        line_start=None,
        line_end=None,
        cwe=None,
        strategies=None,
        evidence_tool="dynamic:crash",
        hypothesis="if input reaches memcpy without bound check, CWE-787",
        vuln_type="buffer_overflow",
        related_to=None,
        reach_via="exported API",
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _seed_run(tmp_path: Path, *, sweep_tool: str = "dynamic:crash"):
    """Minimal run dir: context breadcrumb + confirmed sweep receipt."""
    from core.audit.record import append_audit_log

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "a.c").write_text(
        "int foo(char *p) { return p[0]; }\n"
    )
    append_audit_log(out_dir, {
        "action": "context", "key": "src/a.c:foo",
        "file": "src/a.c", "function": "foo",
    })
    append_audit_log(out_dir, {
        "action": "sweep", "key": "src/a.c:foo",
        "file": "src/a.c", "function": "foo",
        "tool": sweep_tool, "outcome": "confirmed",
    })
    return out_dir, target


def test_namespaced_evidence_tool_records_finding(tmp_path, capsys):
    mod = _load_cli()
    out_dir, target = _seed_run(tmp_path)
    rc = mod.cmd_record(_record_args(out_dir, target))
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    assert "not a recognised tool" not in captured.err
    assert "recorded: src/a.c:foo" in captured.out


def test_namespaced_evidence_tool_accepted_via_cli(tmp_path):
    """Full argparse surface: choices offer dynamic:crash and the gate
    must not then reject its own choice."""
    out_dir, target = _seed_run(tmp_path)
    cp = subprocess.run(
        [sys.executable, str(_SCRIPT), "record",
         "--out", str(out_dir), "--target", str(target),
         "--file", "src/a.c", "--function", "foo",
         "--status", "finding",
         "--hypothesis", "if input reaches memcpy unchecked, CWE-787",
         "--evidence-tool", "dynamic:crash",
         "--vuln-type", "buffer_overflow",
         "--reach-via", "exported API",
         "--body", "crash replay output"],
        capture_output=True, text=True, check=False, timeout=120,
    )
    assert cp.returncode == 0, cp.stderr
    assert "not a recognised tool" not in cp.stderr


def test_unknown_evidence_tool_still_rejected(tmp_path, capsys):
    mod = _load_cli()
    out_dir, target = _seed_run(tmp_path)
    rc = mod.cmd_record(
        _record_args(out_dir, target, evidence_tool="wizardry"),
    )
    captured = capsys.readouterr()
    assert rc == 1
    assert "not a recognised tool" in captured.err


def test_unknown_namespaced_tool_still_rejected(tmp_path, capsys):
    """A namespaced string whose base AND full form are both unknown
    must not slip through the full-string acceptance."""
    mod = _load_cli()
    out_dir, target = _seed_run(tmp_path)
    rc = mod.cmd_record(
        _record_args(out_dir, target, evidence_tool="wizardry:crash"),
    )
    captured = capsys.readouterr()
    assert rc == 1
    assert "not a recognised tool" in captured.err
