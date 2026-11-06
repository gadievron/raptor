"""Native editor notes retain UTF-8 text and scope their temporary file."""

import os
from pathlib import Path
import sys
import tempfile
from types import ModuleType

import pytest

from core.project import cli, project as model
from core.run import scratch
from core.testing.state_isolation import pin_user_state_dirs

pytestmark = [pytest.mark.integration, pytest.mark.skipif(os.name != "posix", reason="POSIX editor fixture")]


@pytest.mark.parametrize("mode", ["success", "nonzero", "cleanup-error", "write-error", "close-error"])
def test_native_editor_notes_lifecycle(tmp_path, monkeypatch, mode):
    pin_user_state_dirs(monkeypatch, tmp_path / "state")
    monkeypatch.setattr(model, "DEFAULT_OUTPUT_BASE", tmp_path / "output")
    manager = model.ProjectManager(projects_dir=tmp_path / "registry")
    manager.create("demo", str(tmp_path / "target"))
    manager.update_notes("demo", "café initial")
    monkeypatch.setattr(cli, "ProjectManager", lambda: manager)
    monkeypatch.setattr(sys, "argv", ["raptor-project", "notes", "demo", "--edit"])
    proxy_os = ModuleType("notes_os")
    proxy_os.__dict__.update(vars(os))
    proxy_os.isatty = lambda fd: True
    monkeypatch.setattr(cli, "os", proxy_os)
    marker = tmp_path / "editor-ran"
    editor = tmp_path / "vi"
    editor.write_text(
        f"#!{sys.executable}\n"
        "from pathlib import Path\nimport sys\n"
        "notes = Path(sys.argv[-1])\n"
        "assert notes.read_text(encoding='utf-8') == 'café initial'\n"
        f"Path({str(marker)!r}).write_text('ran')\n"
        "notes.write_text('edited café', encoding='utf-8')\n"
        f"raise SystemExit({3 if mode == 'nonzero' else 0})\n",
        encoding="utf-8",
    )
    editor.chmod(0o700)
    monkeypatch.setenv("EDITOR", str(editor))
    parent = tmp_path / "inputs"
    parent.mkdir()
    created = []
    original = tempfile.NamedTemporaryFile

    def allocate(**kwargs):
        kwargs["dir"] = parent
        stream = original(**kwargs)
        close, write = stream.close, stream.write
        created.append((stream, close, Path(stream.name)))
        def fail_write(text):
            write(text[:2])
            raise OSError("notes write failed")
        def fail_close():
            close()
            raise OSError("notes close failed")
        if mode == "write-error":
            stream.write = fail_write
        if mode == "close-error":
            stream.close = fail_close
        return stream

    proxy_temp = ModuleType("notes_tempfile")
    proxy_temp.__dict__.update(vars(tempfile))
    proxy_temp.NamedTemporaryFile = allocate
    monkeypatch.setattr(scratch, "tempfile", proxy_temp)
    if mode == "cleanup-error":
        class FaultPath(type(parent)):
            def unlink(self, *args, **kwargs):
                raise OSError("notes cleanup failed")
        monkeypatch.setattr(scratch, "Path", FaultPath)
    try:
        if mode in {"write-error", "close-error"}:
            with pytest.raises(OSError, match="notes .* failed"):
                cli.main()
            assert not marker.exists()
        else:
            cli.main()
            assert marker.read_text() == "ran"
        expected = "edited café" if mode in {"success", "cleanup-error"} else "café initial"
        assert manager.load("demo").notes == expected
        assert created and all(stream.file.closed for stream, _, _ in created)
        if mode != "cleanup-error":
            assert not list(parent.iterdir())
    finally:
        for stream, close, path in created:
            close()
            path.unlink(missing_ok=True)
