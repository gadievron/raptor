"""Opt-in real debugger/inferior checks; never attach to existing processes."""
import json
import shutil
import socket
import subprocess
import sys

import pytest

from packages.binary_analysis.crash_analyser import CrashAnalyser
from packages.binary_analysis.debugger import GDBDebugger

pytestmark = [pytest.mark.integration, pytest.mark.slow,
              pytest.mark.skipif(sys.platform != 'linux', reason='native Linux debugger check')]


@pytest.fixture
def fixture(tmp_path, monkeypatch, request):
    from core.sandbox.probes import check_mount_available
    if not check_mount_available():
        pytest.skip('native mount namespaces required')
    compiler, gdb = shutil.which('cc'), shutil.which('gdb')
    if not compiler or not gdb:
        pytest.skip('C compiler and GDB required')
    work = tmp_path/'work'
    work.mkdir()
    private = tmp_path/'private'
    private.mkdir()
    secret = private/'secret'
    secret.write_text('original private data')
    forbidden = private/'forbidden'
    home = tmp_path/'home'
    home.mkdir()
    init_marker = work/'init-executed'
    init_script = 'shell touch ' + str(init_marker) + '\n'
    (home/'.gdbinit').write_text(init_script)
    (work/'.gdbinit').write_text(init_script)
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('_RAPTOR_TRUSTED', '1')
    monkeypatch.setenv('RAPTOR_DIR', '/must-not-reach-inferior')
    monkeypatch.chdir(work)
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    request.addfinalizer(listener.close)
    source = work/'fixture.c'
    source.write_text(r'''
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(PORT);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd >= 0 && connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0) {
        puts("HOST_NETWORK_REACHED"); return 93;
    }
    if (fd >= 0) close(fd);
    FILE *f = fopen(SECRET, "r");
    if (f) { fclose(f); puts("PRIVATE_READ_ALLOWED"); return 91; }
    if (getenv("_RAPTOR_TRUSTED") || getenv("RAPTOR_DIR")) {
        puts("TRUST_MARKER_LEAKED"); return 92;
    }
    f = fopen(FORBIDDEN, "w");
    if (f) { fputs("shadow", f); fclose(f); }
    puts("RAPTOR_INFERIOR_PROBE_OK");
    fflush(stdout);
    raise(TEST_SIGNAL);
    return 0;
}
''')
    binary = work/'fixture'
    # Debuggers own the SIGSEGV stop. The direct replay branch only tests
    # containment boundaries and output, so a quiet signal suffices there.
    replay_signal = ('SIGTERM' if request.node.callspec.params['consumer'] == 'asan'
                     else 'SIGSEGV')
    build = subprocess.run([compiler, '-g', '-O0', '-DTEST_SIGNAL=' + replay_signal,
        '-DPORT='+str(listener.getsockname()[1]),
        '-DSECRET='+json.dumps(str(secret)), '-DFORBIDDEN='+json.dumps(str(forbidden)),
        str(source), '-o', str(binary)], capture_output=True, text=True, timeout=30)
    assert build.returncode == 0, build.stderr
    return binary, secret, forbidden, init_marker


@pytest.mark.parametrize('consumer', ['wrapper', 'gdb', 'asan'])
def test_real_crash_target_keeps_private_files_and_init_scripts_out(fixture, tmp_path, consumer):
    binary, secret, forbidden, init_marker = fixture
    source = tmp_path/'input'
    source.write_bytes(b'fixture input')
    if consumer == 'wrapper':
        output = GDBDebugger(binary).get_backtrace(source)
    else:
        analyser = CrashAnalyser.__new__(CrashAnalyser)
        analyser.binary = binary
        if consumer == 'gdb':
            output = analyser._run_gdb_analysis_internal(source)
        else:
            # This exercises the direct sanitizer-replay execution path with
            # an owned target. Observe the actual sandbox result because this
            # fixture deliberately has no sanitizer report for its parser.
            import packages.binary_analysis.crash_analyser as module
            original = module._sandbox_run
            replies = []
            from unittest.mock import patch
            def observe(*args, **kwargs):
                reply = original(*args, **kwargs)
                replies.append(reply)
                return reply
            with patch.object(module, '_sandbox_run', observe):
                analyser._run_asan_analysis(source)
            assert len(replies) == 1
            output = replies[0].stdout + replies[0].stderr
    assert 'RAPTOR_INFERIOR_PROBE_OK' in output, output
    assert 'PRIVATE_READ_ALLOWED' not in output, output
    assert 'HOST_NETWORK_REACHED' not in output, output
    assert 'TRUST_MARKER_LEAKED' not in output, output
    assert secret.read_text() == 'original private data'
    assert not forbidden.exists(), 'inferior modified the host private directory'
    assert not init_marker.exists(), 'debugger sourced an implicit init file'
    if consumer != 'asan':
        assert 'SIGSEGV' in output and 'main' in output, output
    assert not list(binary.parent.glob('.raptor_*')), 'debugger scratch leaked'
