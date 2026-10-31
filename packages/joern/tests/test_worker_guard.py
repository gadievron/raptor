"""Worker refusal diagnostics must remain safe even before confinement."""

from pathlib import Path
import subprocess
import sys

from packages.joern import worker_guard


def test_refusal_sanitises_terminal_text(tmp_path, monkeypatch, capsys):
    def refuse(*args, **kwargs):
        raise RuntimeError("\x1b[31mforged\nsecond line\x1b[0m")
    monkeypatch.setattr(worker_guard, "run", refuse)
    monkeypatch.setattr(sys, "argv", ["worker_guard.py", "--write", str(tmp_path), "--", "true"])
    assert worker_guard.main() == 126
    error = capsys.readouterr().err
    assert "forged" in error
    assert "\x1b" not in error
    assert error.count("\n") == 1


def test_early_parent_refusal_can_import_safe_diagnostics(tmp_path):
    reply = subprocess.run(
        [sys.executable, "-I", str(Path(worker_guard.__file__).resolve()),
         "--write", str(tmp_path), "--parent", "0", "--", "true"],
        capture_output=True, text=True, timeout=10)
    assert reply.returncode == 126
    assert "worker controller exited" in reply.stderr
    assert "ModuleNotFoundError" not in reply.stderr
