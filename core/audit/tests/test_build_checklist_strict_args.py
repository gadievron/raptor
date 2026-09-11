"""raptor-build-checklist argument contract is strict.

Unknown --flags must be a loud usage error. Tolerating them was worse
than a silent ignore: a value-taking unknown flag shifted its value
into the positional slots (`--out /custom /src /outdir` bound
target='/custom', output_dir='/src'), so the checklist was silently
built for the wrong tree and written into the source root.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "libexec" / "raptor-build-checklist"


def _run(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), *argv],
        capture_output=True, text=True, check=False, timeout=120,
    )


def test_unknown_flag_after_positionals_errors(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    out = tmp_path / "out"
    cp = _run(str(src), "--out", str(out))
    assert cp.returncode == 2
    assert "unrecognized arguments" in cp.stderr
    # The unknown flag's value must NOT have been consumed as a
    # positional and built against.
    assert not (out / "checklist.json").exists()


def test_unknown_flag_cannot_shift_positionals(tmp_path):
    """The positional-shift failure shape: `--out X src out` used to
    bind target=X and output_dir=src."""
    src = tmp_path / "src"
    src.mkdir()
    out = tmp_path / "out"
    custom = tmp_path / "custom"
    cp = _run("--out", str(custom), str(src), str(out))
    assert cp.returncode == 2
    assert "unrecognized arguments" in cp.stderr
    # No stray artifacts written into the source tree or elsewhere.
    assert not (src / "checklist.json").exists()
    assert not custom.exists()


def test_two_positionals_still_parse(tmp_path):
    """Documented surface still works: strict parsing binds the two
    positionals, so a missing target is OUR diagnostic (exit 1), not
    an argparse usage error (exit 2)."""
    cp = _run(str(tmp_path / "missing-target"), str(tmp_path / "out"))
    assert cp.returncode == 1
    assert "target not found" in cp.stderr


def test_scope_flag_still_parses(tmp_path):
    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    (src / "sub" / "a.c").write_text(
        "int add(int a, int b) { return a + b; }\n"
    )
    out = tmp_path / "out"
    cp = _run(str(src), str(out), "--scope", "sub")
    assert cp.returncode == 0, cp.stderr
    assert (out / "checklist.json").exists()
