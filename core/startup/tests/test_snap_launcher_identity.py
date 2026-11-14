"""Version probes retain launcher identity without executing external tools."""

import builtins
import json
import os
import shutil
import subprocess
from types import ModuleType

import pytest

from core.startup import init as startup
from core.testing.module_views import module_function_view


def _launcher(tmp_path, kind="symlink"):
    launcher = tmp_path / "snap" / "bin" / "semgrep"
    launcher.parent.mkdir(parents=True)
    if kind == "regular":
        launcher.write_text("owned launcher metadata; never executed\n")
    else:
        dispatcher = tmp_path / "usr" / "lib" / "snapd" / "snapd"
        dispatcher.parent.mkdir(parents=True)
        dispatcher.write_text("owned dispatcher metadata; never executed\n")
        launcher.symlink_to(dispatcher)
    return launcher


def _probe(selected, callback):
    private_shutil = ModuleType(shutil.__name__)
    vars(private_shutil).update(vars(shutil))
    private_shutil.which = lambda name: selected() if name == "semgrep" else None
    private_subprocess = ModuleType(subprocess.__name__)
    vars(private_subprocess).update(vars(subprocess))
    private_subprocess.run = callback

    def imported(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name == "subprocess":
            return private_subprocess
        return builtins.__import__(name, globals, locals, fromlist, level)

    return module_function_view(startup, bindings={"shutil": private_shutil},
                                import_hook=imported)._cached_cli_version


@pytest.mark.parametrize("kind", ["regular", "symlink"])
def test_selected_launcher_executes_without_resolving_dispatch_name(tmp_path, monkeypatch, kind):
    launcher = _launcher(tmp_path, kind)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        version = "1.56.0" if argv[0] == str(launcher) else "2.72.0"
        return subprocess.CompletedProcess(argv, 0, version + "\n", "")

    assert _probe(lambda: str(launcher), run)("semgrep") == "1.56.0"
    assert len(calls) == 1
    assert calls[0][0] == [str(launcher), "--version"]
    assert calls[0][1]["cwd"] == os.sep


def test_relative_launcher_is_pinned_before_root_working_directory(tmp_path, monkeypatch):
    launcher = _launcher(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        assert kwargs["cwd"] == os.sep
        return subprocess.CompletedProcess(argv, 0, "1.56.0\n", "")

    assert _probe(lambda: str(launcher.relative_to(tmp_path)), run)("semgrep") == "1.56.0"
    assert calls == [[str(launcher), "--version"]]


def test_old_dispatcher_cache_entry_is_reprobed(tmp_path, monkeypatch):
    launcher = _launcher(tmp_path)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    dispatcher = launcher.resolve()
    info = dispatcher.stat()
    cache = tmp_path / "cache" / "raptor" / "tool-versions.json"
    cache.parent.mkdir(parents=True)
    cache.write_text(json.dumps({"semgrep": {
        "key": f"{dispatcher}:{info.st_mtime_ns}:{info.st_size}",
        "version": "2.72.0",
    }}))
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "1.56.0\n", "")

    assert _probe(lambda: str(launcher), run)("semgrep") == "1.56.0"
    assert calls == [[str(launcher), "--version"]]
    assert json.loads(cache.read_text())["semgrep"]["version"] == "1.56.0"


def test_successful_selected_launcher_still_hits_owned_cache(tmp_path, monkeypatch):
    launcher = _launcher(tmp_path)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        assert len(calls) == 1, "unchanged selected launcher should use its cached result"
        return subprocess.CompletedProcess(argv, 0, "1.56.0\n", "")

    probe = _probe(lambda: str(launcher), run)
    assert probe("semgrep") == probe("semgrep") == "1.56.0"
    assert len(calls) == 1


def test_different_launcher_for_same_dispatcher_does_not_borrow_cache(tmp_path, monkeypatch):
    launcher = _launcher(tmp_path)
    other = tmp_path / "other" / "semgrep"
    other.parent.mkdir()
    other.symlink_to(launcher.resolve())
    selected = [str(launcher)]
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        version = "1.56.0" if argv[0] == str(launcher) else "1.57.0"
        return subprocess.CompletedProcess(argv, 0, version + "\n", "")

    probe = _probe(lambda: selected[0], run)
    assert probe("semgrep") == "1.56.0"
    selected[0] = str(other)
    assert probe("semgrep") == "1.57.0"
    assert calls == [[str(launcher), "--version"], [str(other), "--version"]]


@pytest.mark.parametrize("failure", ["exit", "oserror"])
def test_failed_launcher_probe_does_not_populate_cache(tmp_path, monkeypatch, failure):
    launcher = _launcher(tmp_path)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        if failure == "oserror":
            raise OSError("owned version probe refusal")
        return subprocess.CompletedProcess(argv, 1, "", "owned version probe refusal")

    assert _probe(lambda: str(launcher), run)("semgrep") is None
    assert calls == [[str(launcher), "--version"]]
    assert not (tmp_path / "cache" / "raptor" / "tool-versions.json").exists()


def test_missing_launcher_does_not_dispatch(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))

    def forbidden(*args, **kwargs):
        raise AssertionError("missing launcher must not be executed")

    assert _probe(lambda: None, forbidden)("semgrep") is None
