"""Slow owned-fixture checks for record -> pack -> replay, never host attachment."""
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile

import pytest

from core.config import RaptorConfig
from packages.binary_analysis import rr_record, rr_replay

pytestmark = [pytest.mark.slow, pytest.mark.integration,
              pytest.mark.skipif(sys.platform != 'linux', reason='rr requires Linux')]


def _owned_run(command, *, timeout=60, input=None, **kwargs):
    if kwargs.get('stdin') is None:
        kwargs['stdin'] = subprocess.PIPE if input is not None else subprocess.DEVNULL
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          start_new_session=True, **kwargs) as process:
        try:
            stdout, stderr = process.communicate(input=input, timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=10)
            raise
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


@pytest.fixture
def fixture(tmp_path, monkeypatch, request):
    if not shutil.which('rr') or not shutil.which('cc') or not shutil.which('gdb'):
        pytest.skip('rr, C compiler and GDB required')
    home = tmp_path/'home'
    home.mkdir()
    root = tmp_path/'workspace'
    repo = root/'repo'
    repo.mkdir(parents=True)
    attachments = root/'attachments'
    attachments.mkdir()
    (attachments/'input').write_bytes(b'input witness')
    private = tmp_path/'private'
    private.mkdir()
    secret = private/'secret'
    secret.write_text('private witness')
    forbidden = private/'write'
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    request.addfinalizer(listener.close)
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('TMPDIR', str(tmp_path))
    monkeypatch.delenv('RAPTOR_ALLOW_DEGRADED_UNTRUSTED', raising=False)
    from core.sandbox import state, context
    monkeypatch.setattr(state, '_cli_sandbox_profile', None)
    monkeypatch.setattr(state, '_cli_sandbox_disabled', False)
    monkeypatch.setattr(state, '_cli_sandbox_floor', None)
    monkeypatch.setattr(state, '_project_sandbox_floor', None)
    monkeypatch.setattr(context, '_host_consented_floor', lambda: None)
    source = repo/'owned.c'
    source.write_text(r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/capability.h>
#include <sys/syscall.h>
#include <errno.h>
int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--denied-syscall") == 0) {
        errno = 0;
        if (syscall(SYS_bpf, 0, 0, 0) != -1 || errno != EPERM) return 87;
        puts("DENIED_BPF");
        return 0;
    }
    if (getenv("RUNNING_UNDER_RR")) {
        struct __user_cap_header_struct h = {_LINUX_CAPABILITY_VERSION_3, 0};
        struct __user_cap_data_struct caps[2] = {{0}};
        if (syscall(SYS_capget, &h, caps)) return 85;
        for (int i = 0; i < 2; ++i)
            if (caps[i].effective || caps[i].permitted || caps[i].inheritable) return 86;
    }
    char input[64] = {0};
    if (fread(input, 1, 63, stdin) != 13 || strcmp(input, "input witness")) return 80;
    FILE *f = fopen(SECRET, "r");
    if (f) { fclose(f); puts("PRIVATE_READ_ALLOWED"); return 81; }
    if (link(SECRET, "secret-link") == 0) { puts("PRIVATE_LINK_ALLOWED"); return 82; }
    if (getenv("_RAPTOR_TRUSTED") || getenv("RAPTOR_DIR")) return 83;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(PORT);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd >= 0 && connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0) {
        puts("HOST_NETWORK_ALLOWED"); return 84;
    }
    if (fd >= 0) close(fd);
    f = fopen(FORBIDDEN, "w");
    if (f) { fputs("shadow", f); fclose(f); }
    puts("RR_RECORD_SCOPE_OK");
    fflush(stdout);
    if (argc > 1 && strcmp(argv[1], "--crash") == 0) raise(SIGSEGV);
    return 0;
}
''')
    binary = repo/'owned'
    result = _owned_run(['cc', '-g', '-O0', '-DSECRET='+json.dumps(str(secret)),
                         '-DFORBIDDEN='+json.dumps(str(forbidden)),
                         '-DPORT='+str(listener.getsockname()[1]), str(source), '-o', str(binary)])
    assert result.returncode == 0, result.stderr
    return root, secret, forbidden, listener.getsockname()[1]


@pytest.mark.parametrize('native', [False, True])
@pytest.mark.parametrize('crash', [False, True])
def test_record_pack_replay_boundaries(fixture, monkeypatch, native, crash):
    root, secret, forbidden, port = fixture
    if native:
        from core.sandbox.probes import check_mount_available
        if not check_mount_available():
            pytest.skip('native mount namespaces required')
    else:
        from core.sandbox.landlock import _make_landlock_preexec, check_landlock_available, _get_landlock_abi
        from core.sandbox.seccomp import _make_seccomp_preexec, check_seccomp_available
        if not check_landlock_available() or _get_landlock_abi() < 4 or not check_seccomp_available():
            pytest.skip('Landlock ABI 4+ and seccomp required')
        # Exercise real rr + filesystem policies when the test environment
        # cannot create namespaces. Only this owned fixture uses the adapter;
        # production still requires the complete recorder/replay rr contract.
        def projected(command, **kwargs):
            output = kwargs['output']
            reads = [p for p in ('/usr', '/lib', '/lib64', '/bin', '/sbin', '/etc', '/proc', '/sys') if Path(p).exists()]
            reads += kwargs.get('tool_paths') or []
            reads += kwargs.get('readable_paths') or []
            if kwargs.get('target'):
                reads.append(kwargs['target'])
            with tempfile.TemporaryDirectory(prefix='owned-rr-', dir=output) as temp:
                home = Path(temp)/'home'
                home.mkdir()
                temporary = Path(temp)/'tmp'
                temporary.mkdir()
                env = RaptorConfig.strip_target_exec_markers(dict(kwargs['env']))
                env.update(HOME=str(home), TMPDIR=str(temporary))
                for name in ('XDG_DATA_HOME', 'XDG_CACHE_HOME', 'XDG_CONFIG_HOME'):
                    env[name] = str(home/name.lower())
                landlock = _make_landlock_preexec([output], readable_paths=reads,
                                                 deny_all_tcp_connect=not (Path(command[0]).name == 'rr' and command[1] == 'replay'))
                seccomp = _make_seccomp_preexec(kwargs.get('profile', 'full'),
                    deny_fd_exec=True, allow_unix_sockets=Path(command[0]).name == 'rr' and command[1] != 'pack')
                def preexec():
                    landlock()
                    seccomp()
                return _owned_run(command, env=env, cwd=kwargs['cwd'],
                    stdin=kwargs.get('stdin'), input=kwargs.get('input'),
                    timeout=kwargs['timeout'], preexec_fn=preexec)
        monkeypatch.setattr(rr_record, 'run', projected)
        monkeypatch.setattr(rr_record, 'run_untrusted', projected)
        monkeypatch.setattr(rr_replay, 'run', projected)
    command = ['./owned'] + (['--crash'] if crash else [])
    plain = rr_record.run_target(root, command, cwd='repo',
                                 input_file='attachments/input', timeout=60)
    assert b'RR_RECORD_SCOPE_OK' in plain.stdout+plain.stderr
    assert plain.returncode in ((139, -11) if crash else (0,))
    assert secret.read_text() == 'private witness'
    assert not forbidden.exists()
    if not crash:
        # A real leak must remain a leak report, rather than becoming a
        # seccomp/ptrace tooling error or being hidden by detect_leaks=0.
        source = root/'repo'/'leak.c'
        source.write_text('#include <stdlib.h>\nint main(void) { void *p = malloc(123); *(char *)p = 1; return 0; }\n')
        binary = root/'repo'/'leak'
        build = _owned_run(['cc', '-g', '-O0', '-fsanitize=address', str(source), '-o', str(binary)])
        assert build.returncode == 0, build.stderr
        leak = rr_record.run_target(root, ['./leak'], cwd='repo', sanitizer=True, timeout=60)
        assert leak.returncode != 0
        assert b'LeakSanitizer: detected memory leaks' in leak.stderr, leak.stdout+leak.stderr
        assert b'123 byte' in leak.stderr
        assert b'LeakSanitizer does not work' not in leak.stderr
        recorded_leak = rr_record.record(root, 'leak-trace', ['./leak'], cwd='repo', timeout=60)
        assert recorded_leak.returncode != 0
        assert b'LeakSanitizer: detected memory leaks' in recorded_leak.stderr, recorded_leak.stderr
        packed_leak = rr_record.pack(root, 'leak-trace', timeout=60)
        assert packed_leak.returncode == 0, packed_leak.stdout+packed_leak.stderr
        replayed_leak = rr_replay.replay(root/'leak-trace', commands=b'set confirm off\ncontinue\nquit\n', timeout=60)
        assert replayed_leak.returncode == 0, replayed_leak.stderr
        assert b'LeakSanitizer: detected memory leaks' in replayed_leak.stdout+replayed_leak.stderr
    result = rr_record.record(root, 'trace', command, cwd='repo',
                              input_file='attachments/input', timeout=60)
    output = result.stdout+result.stderr
    assert b'RR_RECORD_SCOPE_OK' in output, output
    assert result.returncode in ((139, -11) if crash else (0,)), output
    assert result.recording_verified is True
    assert secret.read_text() == 'private witness'
    assert not forbidden.exists()
    assert not (root/'repo'/'secret-link').exists()
    packed = rr_record.pack(root, 'trace', timeout=60)
    assert packed.returncode == 0, packed.stdout+packed.stderr
    # Independently probe the pack consumer's actual kernel policy, using
    # an owned executable in place of rr. Trace paths never add read roots.
    tools = root.parent/'pack-probe-tools'
    tools.mkdir()
    shim = tools/'rr'
    immutable = root/'pack-read-only-witness'
    immutable.write_text('unchanged')
    shim.write_text('#!/usr/bin/python3 -I\n'+f'''
import pathlib, socket, sys
assert pathlib.Path({str(immutable)!r}).read_text() == 'unchanged'
try:
    pathlib.Path({str(immutable)!r}).write_text('modified')
except OSError:
    pass
else:
    raise AssertionError('pack wrote outside the trace')
try:
    pathlib.Path({str(secret)!r}).read_text()
except OSError:
    pass
else:
    raise AssertionError('pack read private host data')
try:
    socket.create_connection(('127.0.0.1', {port}), timeout=1)
except OSError:
    pass
else:
    raise AssertionError('pack reached host networking')
(pathlib.Path(sys.argv[2])/'pack-write-proof').write_text('persisted')
print('PACK_BOUNDARY_OK')
''')
    shim.chmod(0o700)
    with monkeypatch.context() as patch:
        patch.setattr(rr_record, '_runtime', lambda *args, **kwargs:
                      (shim, None, [str(tools)]))
        proof = rr_record.pack(root, 'trace', timeout=30)
    assert proof.returncode == 0, proof.stdout+proof.stderr
    assert b'PACK_BOUNDARY_OK' in proof.stdout
    assert (root/'trace'/'pack-write-proof').read_text() == 'persisted'
    assert immutable.read_text() == 'unchanged'
    commands = b'set confirm off\ncontinue\nbt\nquit\n'
    replayed = rr_replay.replay(root/'trace', commands=commands, timeout=60)
    (root.parent/'replay.stdout').write_bytes(replayed.stdout)
    (root.parent/'replay.stderr').write_bytes(replayed.stderr)
    assert replayed.returncode == 0, (replayed.stdout+replayed.stderr).decode(errors='replace')
    if crash:
        assert b'SIGSEGV' in replayed.stdout+replayed.stderr
    if native:
        for stage in (plain, result, packed, replayed):
            assert stage.sandbox_info['mount_ns_active'], stage.sandbox_info
            assert stage.sandbox_info['restrict_reads'], stage.sandbox_info

    if not crash:
        # A direct seccomp denial can be hidden from stock rr's TRACE
        # optimization. Its original zero exit must not publish usable
        # evidence when the full replay cannot reproduce the execution.
        rejected = rr_record.record(root, 'denied-trace', ['./owned', '--denied-syscall'],
                                    cwd='repo', timeout=60)
        (root.parent/'denied-record.stdout').write_bytes(rejected.stdout)
        (root.parent/'denied-record.stderr').write_bytes(rejected.stderr)
        assert b'DENIED_BPF' in rejected.stdout, rejected.stdout+rejected.stderr
        assert rejected.returncode == 1, rejected.stderr
        assert rejected.recording_verified is False
        assert b'recording verification failed' in rejected.stderr
        assert (root/'denied-trace'/'version').exists()
