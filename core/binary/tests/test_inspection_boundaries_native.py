"""Native parser read boundaries using disposable inputs and owned probes."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]


@pytest.fixture
def native_host():
    if sys.platform == 'linux':
        from core.sandbox.probes import check_mount_available, check_net_available
        if not check_mount_available() or not check_net_available():
            pytest.skip('native mount and PID/network namespaces required')
    elif sys.platform == 'darwin':
        from core.sandbox.probes import check_seatbelt_available
        if not check_seatbelt_available():
            pytest.skip('Seatbelt required')
    else:
        pytest.skip('Linux or macOS required')


_PROBE = r'''
import os, pathlib, socket, sys
binary, secret, outside, owner, marker, owner_ns, adapter = sys.argv[1:]
assert pathlib.Path(binary).read_bytes() == b'owned input'
for path in (secret, str(pathlib.Path(binary).parent / 'escape')):
    try: pathlib.Path(path).read_bytes()
    except OSError: pass
    else: raise AssertionError('outside read allowed: ' + path)
# Numeric PIDs can legitimately repeat in nested namespaces. A readable
# /proc/<outside-pid> entry must never contain the outside process's marker.
if sys.platform == 'linux':
    assert os.readlink('/proc/self/ns/pid') != owner_ns, 'PID namespace was reused'
    try: environment = pathlib.Path('/proc/' + owner + '/environ').read_bytes()
    except OSError: pass
    else: assert marker.encode() not in environment, 'outside environment leaked'
for path in (outside, binary):
    try: pathlib.Path(path).write_text('changed')
    except OSError: pass
    else: raise AssertionError('outside write allowed: ' + path)
assert sys.stdin.read() == ('_Z3foov' if adapter == 'demangle' else '')
assert os.getcwd() == os.environ['TMPDIR'] == os.environ['TEMP'] == os.environ['TMP']
home = pathlib.Path(os.environ['HOME'])
# Mount-ns stages fake HOME in its private tmpfs to avoid revealing the
# output path. Landlock-only and Seatbelt retain the output/.home location.
assert home in (pathlib.Path(os.getcwd()) / '.home', pathlib.Path('/tmp/.home')), str(home)
(home / 'owned-home-write').write_text('private home')
for key, suffix in (('XDG_CONFIG_HOME', '.config'), ('XDG_CACHE_HOME', '.cache'),
                    ('XDG_DATA_HOME', '.local/share'), ('XDG_STATE_HOME', '.local/state')):
    directory = pathlib.Path(os.environ[key])
    assert directory == home / suffix, (key, str(directory), str(home))
    (directory / 'owned-write').write_text('private XDG')
assert all(name not in os.environ for name in ('_RAPTOR_TRUSTED', 'RAPTOR_INSTALL_PROTECTED'))
pathlib.Path(os.environ['TMPDIR'], 'owned-written').write_text('scratch')
try: socket.create_connection(('127.0.0.1', 9), timeout=1)
except OSError: pass
else: raise AssertionError('network connect allowed')
print('owned stdout')
'''


@pytest.fixture
def outside_owner(tmp_path):
    # The kernel records this marker in an owned process's initial environment;
    # changing os.environ in pytest would not reliably update /proc/environ.
    marker = 'RAPTOR_OWNED_ENV_' + uuid.uuid4().hex
    environment = dict(PATH=os.defpath, HOME=str(tmp_path), **{marker: 'owned'})
    process = subprocess.Popen(
        [sys.executable, '-I', '-S', '-c', 'import sys; sys.stdin.buffer.read()'],
        env=environment, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        assert process.poll() is None, 'owned environment probe exited before inspection'
        namespace = os.readlink('/proc/self/ns/pid') if sys.platform == 'linux' else ''
        if sys.platform == 'linux':
            assert (marker + '=owned').encode() in Path(f'/proc/{process.pid}/environ').read_bytes()
        yield process.pid, marker, namespace
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


@pytest.mark.parametrize('adapter', ['inspect', 'capture', 'stream', 'demangle'])
def test_native_parser_cannot_read_or_modify_outside_scope(tmp_path, monkeypatch, native_host, outside_owner, adapter):
    from core import sandbox
    from core.analysis import binary_oracle as oracle
    from core.binary.inspect import readelf
    from core.sandbox.python_paths import python_runtime_tool_paths
    source = tmp_path / 'source'
    source.mkdir()
    binary = source / 'binary'
    binary.write_bytes(b'owned input')
    secret = tmp_path / 'outside-secret'
    secret.write_text('owned secret')
    outside = tmp_path / 'outside-written'
    (source / 'escape').symlink_to(secret)
    original = sandbox.run
    seen = []
    def observe(command, **options):
        # Replace only the parser with our fixed owned probe. It receives the
        # exact adapter policy; Python runtime grants are fixture-only.
        options['tool_paths'] = python_runtime_tool_paths()
        options['readable_paths'] = list(dict.fromkeys([*options['readable_paths'], str(source)]))
        probe = [sys.executable, '-I', '-S', '-c', _PROBE, str(binary),
                 str(secret), str(outside), str(outside_owner[0]), *outside_owner[1:], adapter]
        command = [*command[:14 if adapter == 'stream' else 9], *probe]
        result = original(command, **options)
        seen.append(result)
        return result
    monkeypatch.setattr(sandbox, 'run', observe)
    if adapter == 'inspect':
        result = readelf(binary, '-h')
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == 'owned stdout'
    elif adapter == 'capture':
        assert oracle._run_status(['nm', str(binary)], binary=binary) == ('owned stdout\n', True)
    elif adapter == 'stream':
        assert list(oracle._stream(['objdump', str(binary)], 30, binary)) == ['owned stdout']
    else:
        monkeypatch.setattr(oracle.shutil, 'which', lambda tool: '/usr/bin/c++filt')
        assert oracle._demangle_linkage_names(['_Z3foov']) == {'_Z3foov': 'owned stdout'}
    expected = 'mount-ns' if sys.platform == 'linux' else 'seatbelt'
    assert seen and seen[-1].sandbox_info['containment_tier'] == expected
    assert secret.read_text() == 'owned secret'
    assert not outside.exists()


def test_native_binutils_preserve_real_binary_evidence(tmp_path, native_host):
    if sys.platform != 'linux':
        pytest.skip('ELF evidence fixture requires Linux; boundary probes also run on macOS')
    for tool in ('cc', 'readelf', 'nm', 'objdump', 'c++filt'):
        if not shutil.which(tool):
            pytest.skip(tool + ' required')
    from core.analysis import binary_oracle as oracle
    from core.binary.inspect import readelf, addr2line
    source = tmp_path / 'source'
    source.mkdir()
    fixture = source / 'fixture.c'
    fixture.write_text('int kept(void) { return 7; }\nint main(void) { return kept(); }\n')
    binary = source / 'fixture'
    subprocess.run(['cc', '-g', '-O0', '-o', str(binary), str(fixture)],
                   capture_output=True, check=True, timeout=30)
    header = readelf(binary, '-h')
    assert header.returncode == 0 and 'ELF' in header.stdout, header.stderr
    assert oracle.read_build_id(binary)
    evidence = oracle.classify_binary_evidence(['kept', 'not_in_fixture'], binary)
    assert evidence['kept'].classification == 'symbol_present'
    assert evidence['not_in_fixture'].classification == 'absent'
    assert evidence['not_in_fixture'].tier == 'full'
    assert oracle._demangle_linkage_names(['_Z3foov']) == {'_Z3foov': 'foo()'}
    assert addr2line(binary, '0x0').returncode == 0
