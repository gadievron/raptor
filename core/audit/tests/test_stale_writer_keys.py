"""Stale detection reads the span keys the annotation writer stamps.

raptor-annotate stamps `start_line`/`end_line` into annotation
metadata; the stale readers (raptor-audit `stale` and
core.audit.staleness) used to read the checklist spelling
`line_start`/`line_end`, so both resolved to 0, the hash recompute
was skipped, and drifted annotations kept authority weight against
changed source. Round-trip through the real writer so a future key
rename on either side fails here.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.testing.standalone_cli import run_standalone_cli

_REPO_ROOT = Path(__file__).resolve().parents[3]
_AUDIT_CLI = _REPO_ROOT / "libexec" / "raptor-audit"
_ANNOTATE_CLI = _REPO_ROOT / "libexec" / "raptor-annotate"


def _load_audit_cli():
    loader = SourceFileLoader("raptor_audit_cli_stalekeys", str(_AUDIT_CLI))
    spec = importlib.util.spec_from_loader(
        "raptor_audit_cli_stalekeys", loader,
    )
    mod = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", sys.path.copy()):
        loader.exec_module(mod)
    return mod


def _write_annotation(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Annotate src/auth.c:check_pw via the REAL writer."""
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    src = target / "src" / "auth.c"
    src.write_text("int check_pw() { return 1; }\n")

    ann_dir = tmp_path / "annotations"
    env = dict(os.environ, PYTHONPATH=str(_REPO_ROOT))
    cp = run_standalone_cli(
        [sys.executable, str(_ANNOTATE_CLI), "add",
         "src/auth.c", "check_pw",
         "--base", str(ann_dir), "--target", str(target),
         "--lines", "1-1", "--status", "clean",
         "-m", "constant-time compare"],
        env=env, capture_output=True, text=True, check=False, timeout=120,
    )
    assert cp.returncode == 0, cp.stderr
    return target, src, ann_dir


def test_audit_stale_detects_writer_stamped_drift(tmp_path, capsys):
    target, src, ann_dir = _write_annotation(tmp_path)
    src.write_text("int check_pw() { return validate(); }\n")

    mod = _load_audit_cli()
    rc = mod.cmd_stale(SimpleNamespace(
        annotations_dir=str(ann_dir), target=str(target),
    ))
    captured = capsys.readouterr()
    assert rc == 0
    assert "stale: src/auth.c:check_pw" in captured.out
    assert "1 stale annotation(s)" in captured.out


def test_audit_stale_quiet_when_source_unchanged(tmp_path, capsys):
    target, _src, ann_dir = _write_annotation(tmp_path)

    mod = _load_audit_cli()
    rc = mod.cmd_stale(SimpleNamespace(
        annotations_dir=str(ann_dir), target=str(target),
    ))
    captured = capsys.readouterr()
    assert rc == 0
    assert "0 stale annotation(s)" in captured.out


def test_find_stale_annotations_detects_writer_stamped_drift(tmp_path):
    from core.audit.staleness import find_stale_annotations

    target, src, ann_dir = _write_annotation(tmp_path)
    src.write_text("int check_pw() { return validate(); }\n")

    result = find_stale_annotations(ann_dir, target)
    assert len(result) == 1
    assert result[0].reason == "modified"
    assert result[0].function == "check_pw"
    assert result[0].line_start == 1
