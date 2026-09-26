"""Tests for the ``/project ledger`` CLI verbs (``_handle_ledger``).

The handler is exercised directly with a fake manager (the
``test_cli.py`` idiom) so no global project registry state is touched.
The sandboxed build-id probe is stubbed for hermeticity, matching the
engagement ledger's own battery.
"""

from __future__ import annotations

import argparse
import contextlib
import io
from pathlib import Path

import pytest

from core.binary import elf as elf_mod
from core.project.cli import _handle_ledger


@pytest.fixture(autouse=True)
def _stub_build_id(monkeypatch):
    monkeypatch.setattr(elf_mod, "_read_build_id",
                        lambda p: (None, None))


class _FakeProject:
    def __init__(self, target: Path, output_dir: Path) -> None:
        self.target = str(target)
        self.output_dir = str(output_dir)


class _FakeManager:
    def __init__(self, project: _FakeProject | None) -> None:
        self._project = project

    def load(self, name: str):
        return self._project if name == "demo" else None


def _args(action: str, artifact: str | None = None) -> argparse.Namespace:
    return argparse.Namespace(
        action=action, artifact=artifact, name="demo",
        max_archive_children=None, max_archive_bytes=None,
        max_archive_depth=None, no_expand=False,
    )


def _run(mgr, args) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        _handle_ledger(mgr, args)
    return buf.getvalue()


@pytest.fixture()
def demo(tmp_path):
    target = tmp_path / "install"
    target.mkdir()
    (target / "evil\x1b[31m.dat").write_bytes(b"CHNL data")
    (target / "notes.txt").write_bytes(b"plain")
    out = tmp_path / "out"
    out.mkdir()
    return _FakeManager(_FakeProject(target, out)), target, out


class TestLedgerCli:
    def test_build_then_status_then_show(self, demo):
        mgr, _target, out = demo
        built = _run(mgr, _args("build"))
        assert "Ledger built:" in built
        assert (out / "ledger.json").is_file()

        status = _run(mgr, _args("status"))
        assert "corpus-family" in status
        for line in status.splitlines():
            assert all(c.isprintable() for c in line), repr(line)
        assert "\x1b" not in status          # hostile name stays inert

        from core.engagement.ledger import load_ledger
        artifact_id = load_ledger(out)["rows"][0]["artifact_id"]
        shown = _run(mgr, _args("show", artifact_id))
        assert f"Artifact: {artifact_id}" in shown
        # Prefix match resolves too.
        assert "Artifact:" in _run(mgr, _args("show", artifact_id[:10]))

    def test_status_before_build_hints(self, demo):
        mgr, _target, _out = demo
        assert "no ledger" in _run(mgr, _args("status"))

    def test_show_requires_artifact(self, demo):
        mgr, _target, _out = demo
        _run(mgr, _args("build"))
        assert "Usage:" in _run(mgr, _args("show"))

    def test_show_unknown_artifact_escaped(self, demo):
        mgr, _target, _out = demo
        _run(mgr, _args("build"))
        output = _run(mgr, _args("show", "zz-\x1b[31m-nope"))
        assert "No artifact matches" in output
        assert "\x1b[31m" not in output

    def test_missing_project_is_an_error(self, tmp_path):
        mgr = _FakeManager(None)
        args = _args("build")
        args.name = "absent"
        assert "not found" in _run(mgr, args)

    def test_lone_positional_on_build_is_the_project_name(self, demo,
                                                          monkeypatch):
        """``ledger build <name>`` must NEVER fall through to the
        active project with the name stranded in the artifact slot —
        the exact misbinding that once ran a build against the active
        project (regression pin)."""
        mgr, _target, _out = demo
        import core.project.cli as cli_mod
        monkeypatch.setattr(cli_mod, "_get_active_project",
                            lambda: "demo")
        args = _args("build")
        args.name = None
        args.artifact = "absent-project"
        # The lone positional names a project that does not exist —
        # the handler must report THAT, not build the active project.
        assert "not found" in _run(mgr, args)

    def test_lone_positional_on_show_stays_an_artifact(self, demo,
                                                       monkeypatch):
        mgr, _target, _out = demo
        import core.project.cli as cli_mod
        monkeypatch.setattr(cli_mod, "_get_active_project",
                            lambda: "demo")
        _run(mgr, _args("build"))
        args = _args("show", "zz-not-an-artifact")
        args.name = None
        assert "No artifact matches" in _run(mgr, args)

    def test_negative_cap_refused_before_any_work(self, demo):
        mgr, _target, out = demo
        for flag_attr in ("max_archive_children", "max_archive_bytes",
                          "max_archive_depth"):
            args = _args("build")
            setattr(args, flag_attr, -1)
            output = _run(mgr, args)
            assert "must be >= 0" in output, flag_attr
        assert not (out / "ledger.json").exists()

    def test_target_not_a_directory_refused(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        mgr = _FakeManager(_FakeProject(tmp_path / "gone", out))
        assert "not a directory" in _run(mgr, _args("build"))

    def test_real_project_manager_end_to_end(self, tmp_path):
        """Full stack through a REAL ProjectManager (temp registry —
        the shared per-user registry and the last-activated default
        are never touched)."""
        from core.project.project import ProjectManager
        target = tmp_path / "install"
        target.mkdir()
        (target / "data_a.bin").write_bytes(b"MAGC" + b"a" * 8)
        (target / "data_b.bin").write_bytes(b"MAGC" + b"b" * 8)
        mgr = ProjectManager(projects_dir=tmp_path / "registry")
        mgr.create("demo", str(target),
                   output_dir=str(tmp_path / "out"))
        args = _args("build")
        assert "Ledger built:" in _run(mgr, args)
        status = _run(mgr, _args("status"))
        assert "corpus-family" in status
