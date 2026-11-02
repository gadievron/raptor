"""The skill delegates replay to the shared contained implementation."""
import importlib.util
from pathlib import Path
import subprocess

import pytest

source = Path(__file__).with_name('crash_trace.py')
spec = importlib.util.spec_from_file_location('crash_trace', source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_batch_delegates_without_raw_subprocess(monkeypatch):
    calls = []
    def replay(trace, **kwargs):
        calls.append((trace, kwargs))
        return subprocess.CompletedProcess([], 0, b'output', b'')
    monkeypatch.setattr(module, 'replay', replay)
    module.extract_trace('/selected/recording', steps=1)
    assert calls[0][0] == '/selected/recording'
    assert calls[0][1]['commands'].startswith(b'set auto-load no\n')
    assert b'reverse-next' in calls[0][1]['commands']


def test_interactive_uses_same_entrypoint(monkeypatch):
    calls = []
    def replay(trace, **kwargs):
        calls.append((trace, kwargs))
        return subprocess.CompletedProcess([], 0)
    monkeypatch.setattr(module, 'replay', replay)
    monkeypatch.setattr(module.sys, 'argv', ['crash_trace.py', '/trace', '--interactive'])
    with pytest.raises(SystemExit) as result:
        module.main()
    assert result.value.code == 0
    assert calls == [('/trace', {'timeout': None})]


def test_failed_replay_does_not_exit_successfully(monkeypatch):
    def replay(*args, **kwargs):
        return subprocess.CompletedProcess([], 9, b'', b'rr failed')
    monkeypatch.setattr(module, 'replay', replay)
    monkeypatch.setattr(module.sys, 'argv', ['crash_trace.py', '/trace', '--steps', '1'])
    with pytest.raises(SystemExit) as result:
        module.main()
    assert result.value.code == 9
