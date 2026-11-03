"""Native ELF-worker facts, transport refusal and hard resource boundaries."""
import json
import shutil
import struct
import subprocess
import sys
import time

import pytest

from core.binary import elf_worker as worker

pytestmark = [pytest.mark.integration, pytest.mark.slow,
              pytest.mark.linux_native, pytest.mark.darwin_native]


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


@pytest.fixture(autouse=True)
def delivered_tier(monkeypatch, native_host):
    from core import sandbox
    original = sandbox.run
    def observe(command, **options):
        assert options['require_fresh_procfs'] is True
        result = original(command, **options)
        expected = 'mount-ns' if sys.platform == 'linux' else 'seatbelt'
        assert result.sandbox_info['containment_tier'] == expected
        return result
    monkeypatch.setattr(sandbox, 'run', observe)


@pytest.fixture
def source(tmp_path, native_host):
    directory = tmp_path / 'source'
    directory.mkdir()
    return directory


def _fixture(source, *, no_plt=False):
    binary = source / 'fixture'
    if sys.platform != 'linux':
        # Valid minimal ELF64: no native execution or host linker required.
        ident = b'\x7fELF' + bytes([2, 1, 1]) + b'\0' * 9
        binary.write_bytes(ident + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1,
                           0, 0, 0, 0, 64, 56, 0, 64, 0, 0))
        return binary
    cc = shutil.which('cc')
    if not cc:
        pytest.skip('C compiler required')
    code = source / 'fixture.c'
    code.write_text('#include <string.h>\nint guarded(char*s){char b[64];strcpy(b,s);return b[0];}\n'
                    'int main(int n,char**v){return n>1?guarded(v[1]):0;}\n')
    flags = ['-fno-plt'] if no_plt else []
    subprocess.run([cc, '-g', '-O2', '-D_FORTIFY_SOURCE=2', '-fstack-protector-all',
                    '-fPIE', '-pie', '-Wl,-z,relro,-z,now', *flags, '-o', str(binary), str(code)],
                   capture_output=True, check=True, timeout=30)
    return binary


def _replacement(source, monkeypatch, program):
    script = source.parent / 'owned-worker.py'
    script.write_text(program)
    monkeypatch.setattr(worker, '_WORKER', script)


def _payload():
    return dict(arch='amd64', bits=64, endian='little', os_abi='SYSV', relro='Full',
                pie=True, nx=True, canary=True, fortify=True, has_gnu_stack=True, checksec='owned facts')


@pytest.mark.parametrize('mode', ['plt', 'no_plt'])
def test_native_worker_preserves_mitigation_facts(source, mode):
    if mode == 'no_plt' and sys.platform != 'linux':
        pytest.skip('Linux ELF linking case')
    facts = worker.inspect_elf(_fixture(source, no_plt=mode == 'no_plt'))
    assert facts is not None, 'pwntools worker unavailable or failed'
    assert facts.bits in (32, 64) and facts.endian == 'little'
    if sys.platform == 'linux':
        assert facts.relro == 'Full' and facts.pie and facts.canary and facts.fortify
        assert 'FORTIFY:' in facts.checksec


def test_native_data_import_named_chk_is_not_fortify(source):
    if sys.platform != 'linux':
        pytest.skip('Linux ELF linking case')
    cc = shutil.which('cc')
    if not cc:
        pytest.skip('C compiler required')
    library = source / 'data.c'
    library.write_text('int arbitrary_chk = 1;\n')
    code = source / 'fixture.c'
    code.write_text('extern int arbitrary_chk; int main(void){return arbitrary_chk;}\n')
    shared, binary = source / 'libowned.so', source / 'fixture'
    subprocess.run([cc, '-shared', '-fPIC', '-o', str(shared), str(library)],
                   capture_output=True, check=True, timeout=30)
    subprocess.run([cc, '-o', str(binary), str(code), '-L' + str(source), '-lowned'],
                   capture_output=True, check=True, timeout=30)
    facts = worker.inspect_elf(binary)
    assert facts is not None and facts.fortify is False


def test_native_malformed_elf_returns_no_partial_facts(source):
    binary = source / 'malformed'
    binary.write_bytes(b'\x7fELF' + b'\0' * 64)
    assert worker.inspect_elf(binary) is None


def test_native_wall_timeout_reclaims_worker(source, monkeypatch):
    binary = source / 'input'
    binary.write_bytes(b'owned')
    _replacement(source, monkeypatch, 'import time\ntime.sleep(60)\n')
    monkeypatch.setattr(worker, '_TIMEOUT_SECONDS', 2)
    started = time.monotonic()
    assert worker.inspect_elf(binary) is None
    assert time.monotonic() - started < 12


def test_native_memory_limit_is_enforced(source, monkeypatch):
    if sys.platform != 'linux':
        pytest.skip('macOS RLIMIT_AS is best effort, not a hard guarantee')
    binary = source / 'input'
    binary.write_bytes(b'owned')
    payload = json.dumps(_payload())
    _replacement(source, monkeypatch, """import resource, sys
assert 0 <= resource.getrlimit(resource.RLIMIT_AS)[1] <= 2048 * 1024 * 1024
assert 0 <= resource.getrlimit(resource.RLIMIT_CPU)[0] <= 10
assert 0 <= resource.getrlimit(resource.RLIMIT_CPU)[1] <= 11
try:
    data = bytearray(3 * 1024 * 1024 * 1024)
except MemoryError:
    sys.stdout.write(""" + repr(payload) + """)
else:
    raise AssertionError('allocation beyond the configured cap succeeded')
""")
    assert worker.inspect_elf(binary) is not None


def test_native_worker_cannot_read_or_write_outside_scope(source, monkeypatch):
    binary = source / 'input'
    binary.write_bytes(b'owned')
    secret, outside = source.parent / 'secret', source.parent / 'outside-write'
    secret.write_text('owned secret')
    (source / 'escape').symlink_to(secret)
    program = """import os, pathlib, sys
binary = pathlib.Path(sys.argv[1])
assert binary.read_bytes() == b'owned'
for path in (""" + repr(str(secret)) + ', ' + repr(str(source / 'escape')) + """):
    try: pathlib.Path(path).read_bytes()
    except OSError: pass
    else: raise AssertionError('outside read allowed')
for path in (str(binary), """ + repr(str(outside)) + """):
    try: pathlib.Path(path).write_text('changed')
    except OSError: pass
    else: raise AssertionError('outside write allowed')
assert pathlib.Path(os.environ['HOME']) == pathlib.Path(os.getcwd()) / '.home'
assert os.environ['TMPDIR'] == os.getcwd()
assert '_RAPTOR_TRUSTED' not in os.environ and 'RAPTOR_INSTALL_PROTECTED' not in os.environ
sys.stdout.write(""" + repr(json.dumps(_payload())) + ')\n'
    _replacement(source, monkeypatch, program)
    assert worker.inspect_elf(binary) is not None
    assert secret.read_text() == 'owned secret' and not outside.exists()


def test_native_oversized_complete_prefix_is_refused(source, monkeypatch):
    binary = source / 'input'
    binary.write_bytes(b'owned')
    program = 'import sys\nsys.stdout.write(' + repr(json.dumps(_payload())) + ' + " " * (1024 * 1024))\n'
    _replacement(source, monkeypatch, program)
    assert worker.inspect_elf(binary) is None
