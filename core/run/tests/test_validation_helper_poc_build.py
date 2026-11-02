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


@pytest.mark.parametrize('optout', [None, '', '0', 'true', ' 1'])
def test_missing_sandbox_refuses_before_any_compiler_call(tmp_path, monkeypatch, optout):
    import builtins
    from core.run.sandbox_policy import SandboxUnavailableError

    mod = _load_helper()
    target = tmp_path / 'target'
    target.mkdir()
    (target / 'poc.c').write_text('int main(void){return 0;}\n')
    monkeypatch.delenv('RAPTOR_ALLOW_UNSANDBOXED_TOOLS', raising=False)
    if optout is not None:
        monkeypatch.setenv('RAPTOR_ALLOW_UNSANDBOXED_TOOLS', optout)
    original_import = builtins.__import__
    failure = ImportError('test-only missing sandbox dependency')
    def unavailable(name, *args, **kwargs):
        if name == 'core.sandbox':
            raise failure
        return original_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', unavailable)
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(args)
        raise AssertionError('compiler must not run without explicit consent')
    import subprocess
    monkeypatch.setattr(subprocess, 'run', forbidden)
    with pytest.raises(SandboxUnavailableError, match='RAPTOR_ALLOW_UNSANDBOXED_TOOLS=1') as caught:
        mod._build_standalone_pocs(str(target), str(tmp_path / 'build'))
    assert caught.value.__cause__ is failure
    assert not calls


def test_missing_sandbox_explicit_optout_logs_and_keeps_filtered_env(tmp_path, monkeypatch, caplog):
    import builtins
    import subprocess
    from core.run import sandbox_policy

    mod = _load_helper()
    target = tmp_path / 'target'
    target.mkdir()
    source = target / 'poc.c'
    source.write_text('int main(void){return 0;}\n')
    monkeypatch.setenv('RAPTOR_ALLOW_UNSANDBOXED_TOOLS', '1')
    monkeypatch.setenv('LD_PRELOAD', '/test-only-hostile-library.so')
    original_import = builtins.__import__
    def unavailable(name, *args, **kwargs):
        if name == 'core.sandbox':
            raise ImportError('test-only missing sandbox dependency')
        return original_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', unavailable)
    calls, events = [], []
    def record(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return CompletedProcess(cmd, 0, stdout='', stderr='')
    monkeypatch.setattr(subprocess, 'run', record)
    monkeypatch.setattr(sandbox_policy, 'log_security_event',
                        lambda *args, **kwargs: events.append((args, kwargs)))
    mod._build_standalone_pocs(str(target), str(tmp_path / 'build'))
    assert len(calls) == 2  # compiler availability probe, then compilation
    assert calls[0][0] == ['gcc', '--version']
    assert str(source) in calls[1][0]
    assert all('LD_PRELOAD' not in kwargs['env'] for _, kwargs in calls)
    assert 'SANDBOX WAIVED' in caplog.text
    assert len(events) == 1
    assert events[0][0][0] == 'unsandboxed_tool_fallback'
    assert 'standalone PoC compilation' in events[0][1]['tool']


def test_sandbox_setup_failure_never_retries_as_bare_compile(tmp_path, monkeypatch):
    import subprocess
    import core.sandbox
    from core.sandbox.errors import SandboxSetupError

    mod = _load_helper()
    target = tmp_path / 'target'
    target.mkdir()
    (target / 'poc.c').write_text('int main(void){return 0;}\n')
    # Import succeeds: even the import-failure opt-out cannot waive a setup
    # failure or turn it into an automatic bare-process retry.
    monkeypatch.setenv('RAPTOR_ALLOW_UNSANDBOXED_TOOLS', '1')
    calls = []
    def probe(cmd, **kwargs):
        calls.append(cmd)
        assert cmd == ['gcc', '--version']
        return CompletedProcess(cmd, 0, stdout='', stderr='')
    monkeypatch.setattr(subprocess, 'run', probe)
    def refused(*args, **kwargs):
        raise SandboxSetupError('test-only setup failure')
    monkeypatch.setattr(core.sandbox, 'run', refused)
    with pytest.raises(SandboxSetupError, match='test-only setup failure'):
        mod._build_standalone_pocs(str(target), str(tmp_path / 'build'))
    assert len(calls) == 1
