"""`resume` accepts the same target shapes as `run`.

`run` audits binary-file targets (ELF/PE/Mach-O or a Ghidra project)
in addition to source directories, and an interrupted run advertises
`raptor-audit resume <dir>`. Resume must therefore accept a
binary-file target too — a directory-only check made interrupted
binary audits permanently unresumable, with a misleading
"target not found" for a file that exists.
"""

from __future__ import annotations

import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "libexec" / "raptor-audit"


def _load_cli():
    loader = SourceFileLoader("raptor_audit_cli_resume_tgt", str(_SCRIPT))
    spec = importlib.util.spec_from_loader(
        "raptor_audit_cli_resume_tgt", loader,
    )
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _make_run_dir(tmp_path: Path, target: Path) -> Path:
    """Interrupted run dir pointing at *target*, with no checklist —
    resume should get past the target check and stop at the missing
    checklist (a diagnostic later than the target-shape gate)."""
    out_dir = tmp_path / "run"
    out_dir.mkdir()
    (out_dir / ".raptor-run.json").write_text(json.dumps({
        "status": "interrupted",
        "command": "audit",
        "target_path": str(target),
    }))
    (out_dir / "audit-run-config.json").write_text(json.dumps({
        "target_path": str(target),
    }))
    return out_dir


def _resume(mod, out_dir: Path) -> int:
    return mod.cmd_resume(SimpleNamespace(
        out_dir=str(out_dir), reopen=False, allow_drift=False,
    ))


def test_resume_accepts_elf_binary_target(tmp_path, capsys):
    mod = _load_cli()
    binary = tmp_path / "prog"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
    out_dir = _make_run_dir(tmp_path, binary)
    rc = _resume(mod, out_dir)
    captured = capsys.readouterr()
    assert rc == 1
    # Past the target-shape gate: the refusal is the missing checklist,
    # not a bogus "target not found" for a file that exists.
    assert "target not found" not in captured.err
    assert "no checklist.json" in captured.err


def test_resume_accepts_directory_target(tmp_path, capsys):
    mod = _load_cli()
    src = tmp_path / "src"
    src.mkdir()
    out_dir = _make_run_dir(tmp_path, src)
    rc = _resume(mod, out_dir)
    captured = capsys.readouterr()
    assert rc == 1
    assert "target not found" not in captured.err
    assert "no checklist.json" in captured.err


def test_resume_still_rejects_non_binary_file_target(tmp_path, capsys):
    mod = _load_cli()
    stray = tmp_path / "notes.txt"
    stray.write_text("not a binary\n")
    out_dir = _make_run_dir(tmp_path, stray)
    rc = _resume(mod, out_dir)
    captured = capsys.readouterr()
    assert rc == 1
    assert "target not found" in captured.err


def test_resume_still_rejects_missing_target(tmp_path, capsys):
    mod = _load_cli()
    out_dir = _make_run_dir(tmp_path, tmp_path / "gone")
    rc = _resume(mod, out_dir)
    captured = capsys.readouterr()
    assert rc == 1
    assert "target not found" in captured.err
