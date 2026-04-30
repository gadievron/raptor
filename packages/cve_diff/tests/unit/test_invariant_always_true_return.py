"""
Invariant #9 (plan): forbid `return <expr> or True` / `return <expr> or False`.

These short-circuit the caller's boolean check, turning every False into True.
Bug #9 in the reference project was exactly this. Enforced by
`scripts/check_no_always_true_return.py` in pre-commit; this test pins the
script's semantics so CI catches regressions even without pre-commit installed.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT = ROOT / "scripts" / "check_no_always_true_return.py"


def test_lint_script_passes_on_current_tree() -> None:
    """Baseline: the package is clean right now."""
    result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_lint_script_flags_offender(tmp_path: Path) -> None:
    """Drop an offender into a temp package mirror + re-point the script at it."""
    pkg = tmp_path / "cve_diff"
    pkg.mkdir()
    (pkg / "bad.py").write_text("def f(x):\n    return x or True\n")

    src = SCRIPT.read_text()
    patched = src.replace(
        'PKG = ROOT / "cve_diff"',
        f'PKG = Path({str(pkg)!r})',
    )
    local_script = tmp_path / "lint.py"
    local_script.write_text(patched)
    local_script.chmod(0o755)

    result = subprocess.run(
        [sys.executable, str(local_script)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "bad.py" in result.stdout
