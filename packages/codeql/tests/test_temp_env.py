"""CodeQL launcher scratch must remain inside the selected writable directory."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from core.config import RaptorConfig
from packages.codeql.temp_env import temporary_command

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux read-only /tmp steering")


@pytest.fixture
def readonly_tmp(monkeypatch, tmp_path):
    original = os.statvfs
    monkeypatch.setattr(os, 'statvfs', lambda path: (
        SimpleNamespace(f_flag=os.ST_RDONLY) if str(path) == '/tmp' else original(path)))
    monkeypatch.setattr(RaptorConfig, 'get_safe_env', staticmethod(lambda: {'TMPDIR': str(tmp_path)}))
    return tmp_path


def test_writable_system_tmp_keeps_original_command(monkeypatch):
    monkeypatch.setattr(os, 'statvfs', lambda _: SimpleNamespace(f_flag=0))
    command = ['/tools/codeql', 'database', 'analyze', '/database']
    assert temporary_command(command) is command


def test_readonly_system_tmp_steers_shell_and_java_without_shell_evaluation(readonly_tmp):
    command = ['/tools/codeql', 'pack', 'install', 'pack with spaces']
    wrapped = temporary_command(command)
    assert wrapped[:4] == ['/usr/bin/python3', '-I', '-S', '-c']
    assert wrapped[5] == str(readonly_tmp)
    assert wrapped[6:] == command



def test_standalone_caller_uses_python_selected_tmp_without_launcher(readonly_tmp, monkeypatch):
    import tempfile
    monkeypatch.setattr(RaptorConfig, 'get_safe_env', staticmethod(lambda: {}))
    monkeypatch.setattr(tempfile, 'tempdir', str(readonly_tmp))
    assert temporary_command(['/tools/codeql', 'version'])[5] == str(readonly_tmp)


def test_readonly_selected_tmp_refuses_instead_of_using_global_tmp(monkeypatch):
    monkeypatch.setattr(os, 'statvfs', lambda _: SimpleNamespace(f_flag=os.ST_RDONLY))
    monkeypatch.setattr(RaptorConfig, 'get_safe_env', staticmethod(lambda: {'TMPDIR': '/selected'}))
    with pytest.raises(OSError, match='writable TMPDIR'):
        temporary_command(['/tools/codeql', 'version'])


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize('suffix', ['space and quotes\'"', 'back\\slash'])
def test_java_reads_the_exact_selected_tmp_property(readonly_tmp, monkeypatch, suffix):
    java = shutil.which('java')
    if not java:
        pytest.skip('JDK required')
    selected = readonly_tmp / suffix
    selected.mkdir()
    monkeypatch.setattr(RaptorConfig, 'get_safe_env', staticmethod(lambda: {'TMPDIR': str(selected)}))
    command = temporary_command([java, '-XshowSettings:properties', '-version'])
    env = {k: v for k, v in os.environ.items() if k not in {'_JAVA_OPTIONS', 'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS'}}
    env['TMPDIR'] = str(selected)
    result = subprocess.run(command, env=env, text=True, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert 'java.io.tmpdir = ' + str(Path(selected)) in result.stderr


def test_inner_sandbox_temporary_directory_overrides_parent_fallback(readonly_tmp):
    selected = readonly_tmp / 'inner-sandbox'
    selected.mkdir()
    command = temporary_command([sys.executable, '-I', '-c',
                                 'import os; print(os.environ["TMPDIR"]); print(os.environ["_JAVA_OPTIONS"])'])
    result = subprocess.run(command, env={'TMPDIR': str(selected)}, text=True,
                            capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [str(selected), '-Djava.io.tmpdir=' + str(selected)]


def test_steering_uses_current_python_if_system_python_is_absent(readonly_tmp, monkeypatch):
    original = Path.is_file
    monkeypatch.setattr(Path, 'is_file', lambda path: (
        False if str(path) == '/usr/bin/python3' else original(path)))
    command = temporary_command([sys.executable, '-I', '-c', 'print("executed")'])
    assert command[0] == sys.executable
    result = subprocess.run(command, env={'TMPDIR': str(readonly_tmp)},
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'executed'
