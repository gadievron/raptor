"""An outer read-only /tmp must not replace usable operator scratch."""
import json
import os
import sys
import subprocess
import tempfile

import pytest

from core.sandbox import sandbox

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux sandbox temporary routing')


def test_bare_call_keeps_explicit_branded_tmp_without_filesystem_confinement(tmp_path, monkeypatch):
    chosen = tmp_path / 'raptor-operator-temp'
    chosen.mkdir()
    monkeypatch.setenv('TMPDIR', str(chosen))
    with sandbox(block_network=False, restrict_reads=False) as run:
        result = run([sys.executable, '-c', 'import os; print(os.environ["TMPDIR"])'],
                     env={'TMPDIR': str(chosen), 'PATH': os.defpath},
                     env_caller_filtered=True, text=True, capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(chosen)


def test_mountless_call_uses_writable_private_tmp_under_readonly_outer_tmp(tmp_path, monkeypatch):
    from core.sandbox.landlock import check_landlock_available
    if not check_landlock_available():
        pytest.skip('Landlock required for filesystem policy')
    chosen = tmp_path / 'raptor-selected-temp'
    chosen.mkdir()
    output = tmp_path / 'output'
    output.mkdir()
    original = os.statvfs
    def readonly_tmp(path):
        value = original(path)
        if str(path) == '/tmp':
            fields = list(value)
            fields[8] |= os.ST_RDONLY
            return os.statvfs_result(fields)
        return value
    monkeypatch.setattr(os, 'statvfs', readonly_tmp)
    monkeypatch.setattr(tempfile, 'tempdir', str(chosen))
    monkeypatch.setenv('TMPDIR', str(chosen))
    # Exercise policy assembly without claiming kernel engagement: the native
    # backend is replaced, and the received grants are checked explicitly.
    from core.sandbox import context, _spawn, probes
    monkeypatch.setattr(context, 'check_net_available', lambda: True)
    monkeypatch.setattr(context, 'check_mount_available', lambda: True)
    monkeypatch.setattr(probes, 'check_unshare_engages', lambda flags: (True, 'unit backend'))
    received = []
    def execute(command, **kwargs):
        received.append(kwargs)
        result = subprocess.run(command, env=kwargs['env'], cwd=kwargs.get('cwd'),
                                capture_output=True, text=True, timeout=5)
        result._setup_status = None
        return result
    monkeypatch.setattr(_spawn, 'run_sandboxed', execute)
    code = '''
import json,os,pathlib,tempfile,sys
with tempfile.TemporaryFile() as stream: stream.write(b'private scratch works')
pathlib.Path(sys.argv[1]).write_text('caller temporary output works')
print(json.dumps({'tmp':os.environ['TMPDIR']}))
'''
    with sandbox(output=str(output), block_network=False, restrict_reads=False) as run:
        result = run([sys.executable, '-c', code, str(chosen / 'tool-output.json')],
                     text=True, capture_output=True, timeout=5, skip_mount_ns=True)
    assert result.returncode == 0, result.stderr
    assert received
    assert str(chosen) in received[-1]['writable_paths']
    value = json.loads(result.stdout)
    assert value['tmp'] != '/tmp'
    assert value['tmp'].startswith(str(chosen) + os.sep)
    assert (chosen / 'tool-output.json').read_text() == 'caller temporary output works'
