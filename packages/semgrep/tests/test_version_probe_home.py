"""Version probes must work without writable operator state, including old CLIs."""
import json
import os
from pathlib import Path
import sys

import pytest

from core.run.toolprobe import ToolInfo
from packages.semgrep import runner


@pytest.mark.parametrize('version,scope_supported', [
    ('1.79.0', False), ('1.95.0', True), ('1.100.0', True),
])
def test_stateful_version_probe_uses_private_home(tmp_path, monkeypatch, version, scope_supported):
    operator = tmp_path / 'operator'
    operator.mkdir()
    monkeypatch.setenv('HOME', str(operator))
    for name in ('XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME'):
        monkeypatch.setenv(name, str(operator))
    monkeypatch.delenv('RAPTOR_SEMGREP_OFFLINE', raising=False)
    record = tmp_path / 'probe.json'
    binary = tmp_path / 'semgrep'
    binary.write_text(f'#!{sys.executable}\n' + f'''
import json, os, sys
from pathlib import Path
assert sys.argv[1:] == ['--version', '--metrics', 'off', '--disable-version-check']
state = Path(os.environ['XDG_CONFIG_HOME']) / '.semgrep'
state.mkdir()
(state / 'settings.yml').write_text('settings: fixture\\n')
(state / 'semgrep.log').write_text('probe\\n')
Path({str(record)!r}).write_text(json.dumps({{
    key: os.environ[key] for key in
    ('HOME', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME')
}}))
print({version!r})
''')
    binary.chmod(0o700)
    monkeypatch.setattr(runner.shutil, 'which', lambda name: str(binary))
    monkeypatch.setattr(runner, '_SCOPE_PROBE_CACHE', None)
    monkeypatch.setattr(runner, '_SCOPE_PROBE_PENDING', None)

    assert runner.version() == version
    assert runner.scope_isolation_available() is scope_supported
    values = json.loads(record.read_text())
    assert values['HOME'] != str(operator)
    assert all(not Path(path).exists() for path in values.values())
    assert list(operator.iterdir()) == []
    assert os.environ['HOME'] == str(operator)


@pytest.mark.parametrize('code', [1, None])
def test_failed_probe_is_not_a_version_string(monkeypatch, code):
    monkeypatch.setattr(runner, '_version_probe', lambda: ToolInfo(
        name='semgrep', path='/fixture/semgrep', returncode=code,
        stderr='Traceback (most recent call last):\nPermissionError: settings.yml',
    ))
    assert runner.version() is None
