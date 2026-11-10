"""Explicit parent codecs must survive Landlock audit dispatch."""

from contextlib import contextmanager
import sys

import pytest

from core.sandbox import context
from core.sandbox.tests.capability import requires_landlock
from core.testing.module_views import module_function_view


pytestmark = [pytest.mark.slow, pytest.mark.linux_native, requires_landlock,
              pytest.mark.skipif(sys.platform != 'linux', reason='Linux audit backend')]


@pytest.fixture
def audit_run(tmp_path):
    from core.sandbox.ptrace_probe import check_ptrace_available
    from core.sandbox.seccomp import check_seccomp_available

    if not (check_ptrace_available() and check_seccomp_available()):
        pytest.skip('requires actual ptrace and seccomp audit support')
    target, output = tmp_path / 'target', tmp_path / 'output'
    target.mkdir()
    output.mkdir()
    private = module_function_view(context, bindings={
        'sandbox': context.sandbox.__wrapped__,
        'check_net_available': lambda: False,
        'check_mount_available': lambda: False,
    })
    with contextmanager(private.sandbox)(
        profile='full', target=str(target), output=str(output),
        block_network=False, audit=True, audit_required=True,
    ) as run:
        yield run


@pytest.mark.parametrize('errors,expected', [
    ('replace', '\ufffd\n'), ('ignore', '\n'), ('backslashreplace', '\\xff\n'),
], ids=['replace', 'ignore', 'backslashreplace'])
def test_explicit_output_codec_and_newlines(audit_run, errors, expected):
    result = audit_run(['/bin/cat'], input=b'\xff\r\n', capture_output=True,
                       encoding='utf-8', errors=errors, timeout=15)
    assert result.returncode == 0, result.stderr
    assert result.sandbox_info['audit_engaged'] is True
    assert result.stdout == expected


def test_explicit_strict_output_refuses_invalid_bytes(audit_run):
    with pytest.raises(UnicodeDecodeError):
        audit_run(['/bin/cat'], input=b'\xff', capture_output=True,
                  encoding='utf-8', errors='strict', timeout=15)
