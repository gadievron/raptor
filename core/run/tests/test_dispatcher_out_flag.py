"""Tests for operator --out adoption in raptor.py's lifecycle wrapper.

Covers:
  1. ``raptor._extract_and_strip_out`` — argument-level parsing.
  2. ``raptor._run_with_lifecycle`` — an operator --out becomes THE run
     directory: one dir for the lifecycle records, the OUTPUT_DIR
     sentinel, and the child's --out (resolved), with no stray
     project-attached directory.
"""

from __future__ import annotations

import sys
from pathlib import Path

_RAPTOR_ROOT = Path(__file__).resolve().parents[3]


def _import_raptor():
    if "raptor" not in sys.modules:
        sys.path.insert(0, str(_RAPTOR_ROOT))
    import raptor
    return raptor


class TestExtractAndStripOut:
    def test_returns_none_when_flag_absent(self):
        raptor = _import_raptor()
        out, rest = raptor._extract_and_strip_out(["--repo", "/x"])
        assert out is None
        assert rest == ["--repo", "/x"]

    def test_space_form_extracted_and_stripped(self):
        raptor = _import_raptor()
        out, rest = raptor._extract_and_strip_out(
            ["--out", "/tmp/d", "--repo", "/x"],
        )
        assert out == "/tmp/d"
        assert rest == ["--repo", "/x"]

    def test_equals_form_extracted_and_stripped(self):
        raptor = _import_raptor()
        out, rest = raptor._extract_and_strip_out(["--repo", "/x", "--out=/tmp/d"])
        assert out == "/tmp/d"
        assert rest == ["--repo", "/x"]

    def test_dangling_flag_left_for_child_argparse(self):
        raptor = _import_raptor()
        out, rest = raptor._extract_and_strip_out(["--repo", "/x", "--out"])
        assert out is None
        assert rest == ["--repo", "/x", "--out"]


class _LifecycleHarness:
    """Patch set for exercising _run_with_lifecycle hermetically."""

    def __init__(self, raptor, monkeypatch):
        self.child_args: list | None = None
        self.started_dirs: list[Path] = []

        def _spy_run_script(script_path, args):
            self.child_args = list(args)
            return 0

        def _spy_start_run(out_dir, command, **kw):
            self.started_dirs.append(Path(out_dir))

        monkeypatch.setattr(raptor, "_run_script", _spy_run_script)
        monkeypatch.setattr(raptor, "start_run", _spy_start_run)
        monkeypatch.setattr(raptor, "complete_run", lambda *a, **kw: None)
        monkeypatch.setattr(raptor, "fail_run", lambda *a, **kw: None)
        # No active project unless a test installs one; no default target.
        monkeypatch.setattr(
            "core.run.output._resolve_active_project", lambda: None,
        )
        monkeypatch.setattr(raptor, "resolve_default_target", lambda: None)

    def child_out_values(self):
        vals = []
        i = 0
        args = self.child_args or []
        while i < len(args):
            if args[i] == "--out" and i + 1 < len(args):
                vals.append(args[i + 1])
                i += 2
                continue
            if args[i].startswith("--out="):
                vals.append(args[i][len("--out="):])
            i += 1
        return vals


class TestRunWithLifecycleOut:
    def test_operator_out_adopted_everywhere(self, tmp_path, monkeypatch, capsys):
        raptor = _import_raptor()
        h = _LifecycleHarness(raptor, monkeypatch)
        out_dir = tmp_path / "myrun"
        rc = raptor._run_with_lifecycle(
            "scan", Path("/nonexistent/script.py"),
            ["--out", str(out_dir)], "label",
        )
        assert rc == 0
        resolved = str(out_dir.resolve())
        # One lifecycle dir, and it is the operator's.
        assert h.started_dirs == [Path(resolved)]
        # Sentinel names the same dir.
        assert f"OUTPUT_DIR={resolved}" in capsys.readouterr().out
        # Child receives exactly one --out, the resolved path.
        assert h.child_out_values() == [resolved]
        # The directory exists (lifecycle created it via safe_run_mkdir).
        assert out_dir.is_dir()

    def test_equals_form_adopted(self, tmp_path, monkeypatch, capsys):
        raptor = _import_raptor()
        h = _LifecycleHarness(raptor, monkeypatch)
        out_dir = tmp_path / "eqrun"
        rc = raptor._run_with_lifecycle(
            "scan", Path("/nonexistent/script.py"),
            [f"--out={out_dir}"], "label",
        )
        assert rc == 0
        assert h.child_out_values() == [str(out_dir.resolve())]

    def test_relative_out_resolved_for_child(self, tmp_path, monkeypatch, capsys):
        raptor = _import_raptor()
        h = _LifecycleHarness(raptor, monkeypatch)
        monkeypatch.chdir(tmp_path)
        rc = raptor._run_with_lifecycle(
            "scan", Path("/nonexistent/script.py"),
            ["--out", "relrun"], "label",
        )
        assert rc == 0
        resolved = str((tmp_path / "relrun").resolve())
        assert h.started_dirs == [Path(resolved)]
        assert h.child_out_values() == [resolved]

    def test_out_wins_over_active_project(self, tmp_path, monkeypatch, capsys):
        raptor = _import_raptor()
        h = _LifecycleHarness(raptor, monkeypatch)
        project_dir = tmp_path / "proj"
        project_dir.mkdir()
        monkeypatch.setattr(
            "core.run.output._resolve_active_project",
            lambda: (str(project_dir), "proj", str(tmp_path / "target")),
        )
        out_dir = tmp_path / "explicit"
        rc = raptor._run_with_lifecycle(
            "scan", Path("/nonexistent/script.py"),
            ["--out", str(out_dir)], "label",
        )
        assert rc == 0
        resolved = str(out_dir.resolve())
        assert h.started_dirs == [Path(resolved)]
        # Nothing was created under the project dir.
        assert list(project_dir.iterdir()) == []

    def test_no_out_uses_lifecycle_dir(self, tmp_path, monkeypatch, capsys):
        raptor = _import_raptor()
        h = _LifecycleHarness(raptor, monkeypatch)
        seen = {}

        def _stub_get_output_dir(command, explicit_out=None, target_path=None,
                                 **kw):
            seen["explicit_out"] = explicit_out
            return tmp_path / "lifecycle_run"

        monkeypatch.setattr(raptor, "get_output_dir", _stub_get_output_dir)
        rc = raptor._run_with_lifecycle(
            "scan", Path("/nonexistent/script.py"), [], "label",
        )
        assert rc == 0
        assert seen["explicit_out"] is None
        assert h.child_out_values() == [str(tmp_path / "lifecycle_run")]

    def test_help_short_circuits_before_lifecycle(self, tmp_path, monkeypatch):
        raptor = _import_raptor()
        h = _LifecycleHarness(raptor, monkeypatch)

        def _boom(*a, **kw):
            raise AssertionError("lifecycle must not run for --help")

        monkeypatch.setattr(raptor, "get_output_dir", _boom)
        rc = raptor._run_with_lifecycle(
            "scan", Path("/nonexistent/script.py"),
            ["--help", "--out", str(tmp_path / "x")], "label",
        )
        assert rc == 0
        assert h.started_dirs == []
        # --out passes through untouched on the help path.
        assert "--out" in (h.child_args or [])
