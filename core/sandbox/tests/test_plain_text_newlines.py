"""Successful native text capture normalises CRLF and standalone CR."""

import sys

import pytest

from core.sandbox.tests.capability import requires_landlock
from core.sandbox.tests.test_timeout_output_bytes import execution as execution


pytestmark = [
    pytest.mark.slow, pytest.mark.linux_native, requires_landlock,
    pytest.mark.skipif(sys.platform != 'linux', reason='Linux native text capture'),
]


@pytest.mark.parametrize('options', [
    {'text': True}, {'universal_newlines': True}, {'text': False}, {'encoding': 'utf-8'},
], ids=['text', 'legacy-alias', 'bytes', 'explicit-codec'])
def test_native_successful_capture_preserves_newline_contract(execution, options):
    run, backend = execution
    positive = run(['/bin/sh', '-c', 'printf ready'], capture_output=True, timeout=15)
    assert positive.returncode == 0 and positive.stdout == b'ready'
    stamp = 'mount_ns_active' if backend == 'namespace' else 'audit_engaged'
    assert positive.sandbox_info[stamp] is True
    actual = run(['/bin/sh', '-c', "printf 'out\\r\\nrow\\rtail\\n'; printf 'err\\r\\nrow\\rtail\\n' >&2"],
                 capture_output=True, check=True, timeout=15, **options)
    assert actual.sandbox_info[stamp] is True
    if options == {'text': False}:
        assert actual.stdout == b'out\r\nrow\rtail\n'
        assert actual.stderr == b'err\r\nrow\rtail\n'
    else:
        assert actual.stdout == 'out\nrow\ntail\n'
        assert actual.stderr == 'err\nrow\ntail\n'


def test_plain_text_keeps_existing_invalid_utf8_replacement(execution):
    run, backend = execution
    actual = run(['/bin/sh', '-c', "printf '\\377'; printf '\\376' >&2"],
                 text=True, capture_output=True, check=True, timeout=15)
    assert actual.stdout == actual.stderr == '\ufffd'
    assert actual.sandbox_info['mount_ns_active' if backend == 'namespace' else 'audit_engaged'] is True
