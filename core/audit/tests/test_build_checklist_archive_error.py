"""raptor-build-checklist archive targets error in one line, not a traceback.

Pre-fix a zip target crashed with the builder's raw ValueError
traceback ("Target file has no recognized source extension"). The
shim now catches builder refusals at the entry and, for archives,
names the canonical route (extract, or /scan which unpacks into the
shared _sources cache) — the builder works on trees, never inside
archives.
"""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "libexec" / "raptor-build-checklist"


def _run(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), *argv],
        capture_output=True, text=True, check=False, timeout=120,
    )


def test_zip_target_one_line_archive_error(tmp_path):
    zippath = tmp_path / "app.zip"
    with zipfile.ZipFile(zippath, "w") as zf:
        zf.writestr("app/main.py", "x = 1\n")
    out = tmp_path / "out"
    cp = _run(str(zippath), str(out))
    assert cp.returncode == 1
    assert "Traceback" not in cp.stderr
    assert "target is an archive, not a source tree" in cp.stderr
    assert "_sources" in cp.stderr


def test_unrecognised_plain_file_keeps_builder_message(tmp_path):
    blob = tmp_path / "data.blob"
    blob.write_bytes(b"\x00\x01\x02not source")
    out = tmp_path / "out"
    cp = _run(str(blob), str(out))
    assert cp.returncode == 1
    assert "Traceback" not in cp.stderr
    assert "no recognized source extension" in cp.stderr


def test_source_tree_still_builds(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.py").write_text("def f():\n    return 1\n",
                                 encoding="utf-8")
    out = tmp_path / "out"
    cp = _run(str(src), str(out))
    assert cp.returncode == 0, cp.stderr
    assert (out / "checklist.json").exists()
