"""cmd_run target-gate messages tell the truth about existing files.

Pre-fix `raptor-audit run <zip>` printed "target not found" for a
file that plainly exists — the gate only recognises source dirs and
binary artifacts, and collapsed "exists but unsupported" into the
not-found arm, sending operators path-debugging. The two arms are now
distinct, and archives get the canonical extract-or-/scan hint
(/audit does not unpack in this series by design).
"""

from __future__ import annotations

import importlib.util
import zipfile
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace


def _load_cli():
    cli_path = str(
        Path(__file__).resolve().parents[3] / "libexec" / "raptor-audit",
    )
    loader = SourceFileLoader("raptor_audit_cli_test", cli_path)
    spec = importlib.util.spec_from_loader("raptor_audit_cli_test", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_archive_target_named_with_extract_hint(tmp_path, capsys):
    mod = _load_cli()
    zippath = tmp_path / "app.zip"
    with zipfile.ZipFile(zippath, "w") as zf:
        zf.writestr("app/main.py", "print('hi')\n")
    rc = mod.cmd_run(SimpleNamespace(target=str(zippath)))
    assert rc == 1
    err = capsys.readouterr().err
    assert "target not found" not in err
    assert "exists but is not a recognized audit target" in err
    assert "_sources" in err  # the canonical /scan-unpacks route


def test_plain_file_named_without_archive_hint(tmp_path, capsys):
    mod = _load_cli()
    txt = tmp_path / "notes.txt"
    txt.write_text("hello", encoding="utf-8")
    rc = mod.cmd_run(SimpleNamespace(target=str(txt)))
    assert rc == 1
    err = capsys.readouterr().err
    assert "exists but is not a recognized audit target" in err
    assert "_sources" not in err


def test_missing_target_still_not_found(tmp_path, capsys):
    mod = _load_cli()
    rc = mod.cmd_run(SimpleNamespace(target=str(tmp_path / "gone")))
    assert rc == 1
    assert "target not found" in capsys.readouterr().err
