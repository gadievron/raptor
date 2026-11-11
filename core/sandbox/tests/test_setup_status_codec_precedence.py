"""Backend setup status takes precedence over target-output text decoding."""

import subprocess
import sys

import pytest

from core.sandbox import context
from core.sandbox.errors import SandboxSetupError
from core.sandbox.tests.test_context_decision_pins import _Driver
from core.testing.module_bindings import patch_module_attribute
from core.testing.state_isolation import pin_user_state_dirs


pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux dispatch decision')


def _execute(monkeypatch, tmp_path, *, status, stdout, stderr, encoding):
    calls = []

    def backend(cmd, **kwargs):
        calls.append(kwargs)
        assert kwargs['text'] is False
        result = subprocess.CompletedProcess(cmd, 99 if status else 0, stdout, stderr)
        result._setup_status = status
        return result

    def forbid_process(*args, **kwargs):
        pytest.fail('the setup-status contract control must not launch a process')

    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    _Driver(monkeypatch, backend)
    monkeypatch.setattr(context, '_run_teardown_first_timeout', forbid_process)
    patch_module_attribute(monkeypatch, context, 'subprocess', 'Popen', forbid_process)
    with context.sandbox(profile='full', target=str(tmp_path)) as run:
        try:
            return run(['/bin/true'], encoding=encoding, capture_output=True, timeout=1)
        finally:
            assert len(calls) == 1


@pytest.mark.parametrize('category', ['L', 'S', 'Z'], ids=['landlock', 'seccomp', 'unknown'])
@pytest.mark.parametrize('encoding', ['ascii', 'utf-8'])
def test_setup_refusal_survives_nonascii_diagnostics(monkeypatch, tmp_path, category, encoding):
    with pytest.raises(SandboxSetupError) as refused:
        _execute(monkeypatch, tmp_path, status=(category, 'owned setup refusal'),
                 stdout=b'', stderr='owned \u03bb diagnostic'.encode(), encoding=encoding)
    assert refused.value.setup_category == category


@pytest.mark.parametrize('encoding,payload,expected', [
    ('ascii', b'owned\r\n', 'owned\n'),
    ('utf-8', 'owned \u03bb\r\n'.encode(), 'owned \u03bb\n'),
], ids=['ascii', 'utf-8'])
def test_successful_result_keeps_selected_codec(monkeypatch, tmp_path, encoding, payload, expected):
    result = _execute(monkeypatch, tmp_path, status=None,
                      stdout=payload, stderr=b'', encoding=encoding)
    assert result.stdout == expected
    assert result.stderr == ''


def test_successful_result_still_rejects_invalid_selected_codec_bytes(monkeypatch, tmp_path):
    with pytest.raises(UnicodeDecodeError):
        _execute(monkeypatch, tmp_path, status=None,
                 stdout=b'\xff', stderr=b'', encoding='utf-8')
