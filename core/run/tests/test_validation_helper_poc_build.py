"""Sandbox-invocation seam for the Stage-A standalone-PoC build.

The compile must confine writes to the run-dir build scratch
(``output=``) with the target passed read-only (``target=``), and must
declare its ``get_safe_env()``-derived env as caller-filtered — the
sandbox's "unfiltered caller env" warning otherwise fires once per
compile straight into the stage's stderr, polluting the build evidence
the LLM reads.
"""

import importlib.util
import os
import shutil
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_helper():
    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    script = str(REPO_ROOT / "libexec" / "raptor-validation-helper")
    loader = SourceFileLoader("raptor_validation_helper", script)
    spec = importlib.util.spec_from_loader("raptor_validation_helper", loader)
    mod = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", sys.path.copy()):
        loader.exec_module(mod)
    return mod


@pytest.mark.skipif(
    shutil.which("gcc") is None and shutil.which("cc") is None,
    reason="no C compiler on host (the build probe returns early)",
)
def test_poc_compile_sandbox_invocation_shape(tmp_path, monkeypatch):
    mod = _load_helper()
    target = tmp_path / "target"
    target.mkdir()
    (target / "poc.c").write_text("int main(void){return 0;}\n")
    build_dir = tmp_path / "run" / "build"

    calls: list[dict] = []

    def _recording_run(cmd, **kwargs):
        calls.append({"cmd": list(cmd), **kwargs})
        return CompletedProcess(cmd, 0, stdout="", stderr="")

    import core.sandbox
    monkeypatch.setattr(core.sandbox, "run", _recording_run)

    mod._build_standalone_pocs(str(target), str(build_dir))

    assert calls, "compile never reached the sandbox runner"
    call = calls[0]
    assert call["target"] == str(target.resolve())
    assert call["output"] == str(build_dir.resolve())
    assert call["block_network"] is True
    assert call["env_caller_filtered"] is True
    assert isinstance(call.get("env"), dict)


def test_build_system_target_skips_poc_build(tmp_path, monkeypatch):
    mod = _load_helper()
    target = tmp_path / "target"
    target.mkdir()
    (target / "poc.c").write_text("int main(void){return 0;}\n")
    (target / "Makefile").write_text("all:\n")
    build_dir = tmp_path / "run" / "build"

    def _must_not_run(cmd, **kwargs):
        raise AssertionError("sandbox runner invoked despite build system")

    import core.sandbox
    monkeypatch.setattr(core.sandbox, "run", _must_not_run)

    mod._build_standalone_pocs(str(target), str(build_dir))
    assert not build_dir.exists()
