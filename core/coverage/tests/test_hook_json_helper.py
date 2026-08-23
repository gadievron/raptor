"""The coverage read hook's named python helper (plugins/coverage/
libexec/raptor-hook-json) and the hook's no-jq fallback path.

EDR-coexistence refactor: the hook used to spawn ``python3 -c`` with
embedded source (three JSON extractors) plus a ``python3 -`` heredoc
(manifest append) — on EVERY tracked file read. Those are now a named
on-disk helper executed by path. These tests pin (a) the helper's
behaviour, (b) the hook's end-to-end behaviour when jq is absent so
every JSON parse goes through the helper, and (c) that the inline-code
process shapes never regrow.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
HOOK = REPO_ROOT / "plugins" / "coverage" / "libexec" / "raptor-hook-read"
HELPER = REPO_ROOT / "plugins" / "coverage" / "libexec" / "raptor-hook-json"


def _helper(*args: str, stdin: str = "") -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(HELPER), *args],
        input=stdin, capture_output=True, text=True,
        timeout=30, check=False,
    )


class TestGet:
    def test_top_level_key_from_file(self, tmp_path):
        f = tmp_path / "p.json"
        f.write_text(json.dumps({"output_dir": "/some/dir", "n": 3}))
        proc = _helper("get", str(f), "output_dir")
        assert proc.returncode == 0
        assert proc.stdout.strip() == "/some/dir"

    def test_dotted_key_from_stdin(self):
        payload = json.dumps({"tool_input": {"file_path": "/a/b.py"}})
        proc = _helper("get", "-", "tool_input.file_path", stdin=payload)
        assert proc.returncode == 0
        assert proc.stdout.strip() == "/a/b.py"

    def test_missing_key_prints_nothing(self, tmp_path):
        f = tmp_path / "p.json"
        f.write_text(json.dumps({"other": "x"}))
        proc = _helper("get", str(f), "output_dir")
        assert proc.returncode == 0
        assert proc.stdout == ""

    def test_non_string_value_prints_nothing(self, tmp_path):
        f = tmp_path / "p.json"
        f.write_text(json.dumps({"output_dir": {"nested": 1}}))
        proc = _helper("get", str(f), "output_dir")
        assert proc.returncode == 0
        assert proc.stdout == ""

    def test_malformed_json_silent(self, tmp_path):
        f = tmp_path / "p.json"
        f.write_text("{not json")
        proc = _helper("get", str(f), "output_dir")
        assert proc.returncode == 0
        assert proc.stdout == ""

    def test_missing_file_silent(self, tmp_path):
        proc = _helper("get", str(tmp_path / "absent.json"), "k")
        assert proc.returncode == 0
        assert proc.stdout == ""

    def test_hostile_filename_is_data_not_code(self, tmp_path):
        """The pre-refactor injection surface: a path containing a
        quote must be handled as argv DATA (the file simply gets
        opened), never spliced into python source."""
        f = tmp_path / "run'; import os #.json"
        f.write_text(json.dumps({"status": "running"}))
        proc = _helper("get", str(f), "status")
        assert proc.returncode == 0
        assert proc.stdout.strip() == "running"


class TestAppend:
    def test_appends_line_0600(self, tmp_path):
        manifest = tmp_path / "m"
        proc = _helper("append", str(manifest), "/a/b.py")
        assert proc.returncode == 0
        assert manifest.read_text() == "/a/b.py\n"
        assert (manifest.stat().st_mode & 0o777) == 0o600

    def test_symlinked_manifest_refused(self, tmp_path):
        victim = tmp_path / "victim"
        victim.write_text("original\n")
        manifest = tmp_path / "m"
        manifest.symlink_to(victim)
        proc = _helper("append", str(manifest), "/a/b.py")
        assert proc.returncode == 0
        assert victim.read_text() == "original\n"

    def test_dangling_symlink_not_created_through(self, tmp_path):
        victim = tmp_path / "never-created"
        manifest = tmp_path / "m"
        manifest.symlink_to(victim)
        proc = _helper("append", str(manifest), "/a/b.py")
        assert proc.returncode == 0
        assert not victim.exists()


class TestProcessShapePins:
    def test_hook_has_no_inline_python(self):
        """The EDR-noisy shapes must not regrow: no ``python3 -c``
        blobs and no ``python3 -`` heredocs in the hook."""
        code_lines = [
            line for line in HOOK.read_text(encoding="utf-8").splitlines()
            if not line.lstrip().startswith("#")
        ]
        code = "\n".join(code_lines)
        assert "python3 -c" not in code
        assert "python3 - " not in code
        assert "<<'PY'" not in code and "<<PY" not in code

    def test_helper_is_stdlib_only(self):
        src = HELPER.read_text(encoding="utf-8")
        for forbidden in ("import core", "from core", "RAPTOR_DIR"):
            assert forbidden not in src, (
                "helper must stay standalone — it runs outside any "
                "RAPTOR process"
            )


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
class TestHookWithoutJq:
    """End-to-end through the helper: PATH stripped of jq, so every
    JSON parse takes the fallback path."""

    def test_read_recorded_via_helper_fallback(self, tmp_path):
        home = tmp_path / "home"
        target = tmp_path / "target"
        target.mkdir(parents=True)
        (target / "a.py").write_text("x = 1\n")

        projects = home / ".raptor" / "projects"
        projects.mkdir(parents=True)
        project_dir = tmp_path / "proj-out"
        run_dir = project_dir / "run1"
        run_dir.mkdir(parents=True)
        (run_dir / ".raptor-run.json").write_text(
            json.dumps({"status": "running"}),
        )
        (projects / "myproj").write_text(json.dumps({
            "output_dir": str(project_dir),
            "target": str(target),
        }))
        (projects / ".active").symlink_to("myproj")

        # A bin dir holding everything the hook needs EXCEPT jq.
        bindir = tmp_path / "bin"
        bindir.mkdir()
        for tool in ("dirname", "readlink", "stat", "realpath",
                     "python3", "bash"):
            path = shutil.which(tool)
            if path is None:
                pytest.skip(f"{tool} not on PATH")
            (bindir / tool).symlink_to(path)

        env = dict(os.environ)
        env["HOME"] = str(home)
        env["PATH"] = str(bindir)

        payload = json.dumps(
            {"tool_input": {"file_path": str(target / "a.py")}},
        )
        proc = subprocess.run(
            ["bash", str(HOOK)],
            input=payload, env=env, capture_output=True,
            text=True, timeout=60, check=False,
        )
        assert proc.returncode == 0, proc.stderr
        manifest = run_dir / ".reads-manifest"
        assert manifest.is_file()
        assert manifest.read_text().strip() == str(
            (target / "a.py").resolve(),
        )
