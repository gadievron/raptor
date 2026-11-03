"""Real radare2 protocol and filesystem boundaries under the shared floor."""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[3]
WRAPPER = ROOT / 'libexec/raptor-r2-sandboxed'
pytestmark = [pytest.mark.integration, pytest.mark.slow,
              pytest.mark.linux_native, pytest.mark.darwin_native]


@pytest.fixture
def native(tmp_path):
    if sys.platform == 'linux':
        from core.sandbox.probes import check_mount_available, check_net_available
        if not check_mount_available() or not check_net_available():
            pytest.skip('mount and PID/network namespaces required')
    elif sys.platform == 'darwin':
        from core.sandbox.probes import check_seatbelt_available
        if not check_seatbelt_available():
            pytest.skip('Seatbelt required')
    else:
        pytest.skip('Linux or macOS required')
    tool = shutil.which('r2') or shutil.which('radare2')
    if not tool:
        pytest.skip('radare2 required')
    source, scratch, home = (tmp_path / name for name in ('source', 'scratch', 'home'))
    for directory in (source, scratch, home):
        directory.mkdir()
    binary = source / 'fixture'
    selected = shutil.which('true') or '/bin/ls'
    shutil.copyfile(selected, binary)
    env = dict(os.environ, HOME=str(home), OUTPUT_DIR=str(scratch),
               R2_TARGET_DIR=str(source), _RAPTOR_TRUSTED='1')
    # An owned rc file must not auto-execute; no operator settings are used.
    marker = tmp_path / 'rc-ran'
    (home / '.radare2rc').write_text('!touch ' + shlex.quote(str(marker)) + '\n')
    return binary, scratch, home, env, marker, tool


def _invoke(native, commands, tmp_path):
    binary, _, _, env, _, _ = native
    report = tmp_path / 'tier.json'
    runner = tmp_path / 'observe-wrapper.py'
    runner.write_text('''import json, runpy, sys
from pathlib import Path
sys.path.insert(0, ''' + repr(str(ROOT)) + ''')
from core import sandbox
original = sandbox.run
def observe(command, **options):
    assert options['require_fresh_procfs'] is True
    result = original(command, **options)
    expected = 'mount-ns' if sys.platform == 'linux' else 'seatbelt'
    assert result.sandbox_info['containment_tier'] == expected, result.sandbox_info
    Path(''' + repr(str(report)) + ''').write_text(json.dumps(result.sandbox_info))
    return result
sandbox.run = observe
sys.argv = [''' + repr(str(WRAPPER)) + ", '-2', '-q0', " + repr(str(binary)) + ''']
runpy.run_path(sys.argv[0], run_name='__main__')
''')
    result = subprocess.run([sys.executable, '-I', '-B', str(runner)], env=env,
                            input=(commands + '\nq\n').encode(), capture_output=True, timeout=45)
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    assert report.is_file(), 'wrapper did not reach the observed shared sandbox'
    return result


@pytest.mark.parametrize('location', ['installed', 'home-bin'])
def test_native_radare2_protocol_and_selected_tool(native, tmp_path, location):
    binary, _, home, env, marker, tool = native
    if location == 'home-bin':
        shim = home / 'bin' / 'r2'
        shim.parent.mkdir()
        shim.symlink_to(Path(tool).resolve())
        env['PATH'] = str(shim.parent) + os.pathsep + env.get('PATH', os.defpath)
    result = _invoke(native, 'ij', tmp_path)
    records = [json.loads(line) for line in result.stdout.replace(b'\0', b'\n').splitlines()
               if line.strip().startswith(b'{') and line.strip().endswith(b'}')]
    assert any(record.get('bin') or record.get('core') for record in records), result.stdout
    assert binary.exists() and not marker.exists()


def test_native_radare2_shell_escape_remains_confined(native, tmp_path):
    binary, scratch, _, _, marker, _ = native
    secret = tmp_path / 'secret'
    secret.write_text('owned secret')
    link = binary.parent / 'escape'
    link.symlink_to(secret)
    probe = binary.parent / 'probe.sh'
    probe.write_text('''set -eu
''' + '\n'.join('if cat ' + shlex.quote(str(path)) + ' >/dev/null 2>&1; then exit 8; fi'
                 for path in (secret, link)) + '''
if (printf changed > ''' + shlex.quote(str(binary)) + ''') 2>/dev/null; then exit 9; fi
[ "$HOME" = "$PWD/.home" ]
[ "$TMPDIR" = "$PWD" ]
[ "${_RAPTOR_TRUSTED-unset}" = unset ]
[ "${RAPTOR_INSTALL_PROTECTED-unset}" = unset ]
printf owned > "$TMPDIR/probe-marker"
echo R2_CONTAINED
''')
    before = binary.read_bytes()
    result = _invoke(native, '!/bin/sh ' + shlex.quote(str(probe)), tmp_path)
    assert b'R2_CONTAINED' in result.stdout, (result.stdout, result.stderr)
    assert binary.read_bytes() == before and not marker.exists()
    assert (scratch / 'probe-marker').read_text() == 'owned'


def test_native_real_r2pipe_round_trip(native, monkeypatch):
    pytest.importorskip('r2pipe')
    binary, _, _, env, marker, _ = native
    for key in ('HOME', 'OUTPUT_DIR', 'R2_TARGET_DIR', '_RAPTOR_TRUSTED'):
        monkeypatch.setenv(key, env[key])
    monkeypatch.setenv('R2PIPE_R2', str(WRAPPER))
    from packages.binary_analysis.radare2_understand import BinaryUnderstand
    understand = BinaryUnderstand.__new__(BinaryUnderstand)
    understand.binary = binary
    understand.slice_arch = None
    with understand._sandboxed_session() as session:
        launcher = Path(session.process.args[0])
        assert launcher.resolve() == WRAPPER
        # Removing a test-owned launcher must fail too: a compromised r2
        # must not replace its next restart with an unsandboxed executable.
        session.cmd('!/bin/rm ' + shlex.quote(str(launcher)))
        assert launcher.is_symlink() and launcher.resolve() == WRAPPER
        result = json.loads(session.cmd('ij'))
        assert isinstance(result, dict) and (result.get('bin') or result.get('core'))
    assert not marker.exists()
