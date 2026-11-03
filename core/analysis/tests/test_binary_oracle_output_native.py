"""Real stdout descriptor handoff using fixed Python fixtures only."""
import sys

import pytest

from core.analysis import binary_oracle as oracle

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
        pytest.skip('Linux or macOS sandbox required')


@pytest.fixture
def runner(tmp_path, monkeypatch, native_host):
    from core import sandbox
    from core.sandbox.python_paths import python_runtime_tool_paths
    source = tmp_path / 'source'
    source.mkdir()
    binary = source / 'owned-data'
    binary.write_bytes(b'owned fixture')
    secret = tmp_path / "secret with $quotes'"
    secret.write_text('owned secret marker\n')
    original = sandbox.run
    seen = []
    def observe(command, **kwargs):
        # Python is just the test-owned producer; production invokes binutils.
        kwargs['tool_paths'] = python_runtime_tool_paths()
        command = [*command, kwargs['output'], str(secret)]
        result = original(command, **kwargs)
        seen.append(result)
        return result
    monkeypatch.setattr(sandbox, 'run', observe)
    def invoke(program):
        lines = list(oracle._stream([sys.executable, '-I', '-S', '-c', program],
                                    timeout=30, binary=binary))
        assert seen
        expected = 'mount-ns' if sys.platform == 'linux' else 'seatbelt'
        assert seen[-1].sandbox_info['containment_tier'] == expected
        assert secret.read_text() == 'owned secret marker\n'
        return lines
    return invoke


def test_native_descriptor_preserves_large_output_and_neutral_stdin(runner):
    program = r'''
import sys
assert sys.stdin.buffer.read(1) == b''
for n in range(10000):
    sys.stdout.buffer.write(b'owned line\r\n')
sys.stdout.buffer.write(b'invalid:\xff\n')
'''
    lines = runner(program)
    assert len(lines) == 10001
    assert lines[:-1] == ['owned line'] * 10000
    assert lines[-1] == 'invalid:\ufffd'


def test_native_output_path_replacement_cannot_redirect_parent(runner):
    program = r'''
import os, sys
name = next(name for name in os.listdir(sys.argv[1]) if name.startswith('stdout'))
path = os.path.join(sys.argv[1], name)
sys.stdout.write('owned stdout\n')
sys.stdout.flush()
if os.path.lexists(path): os.unlink(path)
os.symlink(sys.argv[2], path)
'''
    assert runner(program) == ['owned stdout']


def test_native_nonzero_discards_stdout_and_escapes_stderr(runner, caplog):
    program = r'''
import sys
sys.stdout.write('partial evidence\n')
sys.stderr.buffer.write(b'owned error \x1b]0;unsafe\x07\n')
sys.exit(7)
'''
    assert runner(program) == []
    messages = ' '.join(record.getMessage() for record in caplog.records)
    assert 'owned error' in messages
    assert '\x1b' not in messages and '\\x1b' in messages
