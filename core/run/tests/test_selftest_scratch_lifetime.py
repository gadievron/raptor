"""Scratch lifetime of ``libexec/raptor-self-test``.

The harness docstring promises a reaper-prefixed scratch deleted on
exit — an interrupt (Ctrl-C) must not strand multi-GB fixtures, and
the prefix must be registered with the tmp reaper so a SIGKILL'd
harness's scratch is reclaimed by a later process's sweep.
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest.mock import patch

import pytest


from core.testing.module_bindings import patch_module_attribute


REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_selftest():
    script = str(REPO_ROOT / "libexec" / "raptor-self-test")
    loader = SourceFileLoader("raptor_self_test_mod", script)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    with pytest.MonkeyPatch.context() as mp, patch.object(sys, "path", sys.path.copy()):
        mp.setenv("_RAPTOR_TRUSTED", "1")
        loader.exec_module(mod)
    return mod


class TestScratchLifetime:

    def _run_interrupted(self, mod, monkeypatch, tmp_path,
                         keep: bool = False) -> Path:
        made: list[str] = []
        real_mkdtemp = tempfile.mkdtemp

        def recording_mkdtemp(*a, **kw):
            path = real_mkdtemp(*a, dir=str(tmp_path), **kw)
            made.append(path)
            return path

        patch_module_attribute(monkeypatch, mod, 'tempfile', "mkdtemp", recording_mkdtemp)

        def interrupt(ctx, args, selected):
            raise KeyboardInterrupt

        monkeypatch.setattr(mod, "_run_selected", interrupt)
        argv = ["raptor-self-test", "--only", "doctor"]
        if keep:
            argv.append("--keep")
        monkeypatch.setattr(sys, "argv", argv)
        with pytest.raises(KeyboardInterrupt):
            mod.main()
        assert made, "scratch never created"
        return Path(made[0])

    def test_interrupt_removes_scratch(self, monkeypatch, tmp_path):
        mod = _load_selftest()
        scratch = self._run_interrupted(mod, monkeypatch, tmp_path)
        assert not scratch.exists(), (
            "Ctrl-C stranded the scratch dir with no message"
        )

    def test_interrupt_with_keep_retains_scratch(self, monkeypatch,
                                                 tmp_path, capsys):
        mod = _load_selftest()
        scratch = self._run_interrupted(
            mod, monkeypatch, tmp_path, keep=True)
        assert scratch.exists()
        assert "scratch retained" in capsys.readouterr().out

    def test_prefix_registered_with_reaper(self, monkeypatch, tmp_path):
        mod = _load_selftest()
        from core.run import tmp_reaper
        registered: list[str] = []
        monkeypatch.setattr(
            tmp_reaper, "register_dir_prefix",
            lambda prefix: registered.append(prefix),
        )
        self._run_interrupted(mod, monkeypatch, tmp_path)
        assert "raptor_selftest_" in registered
