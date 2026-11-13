"""Selected codecs decode retained bytes before trusted loss annotations."""

import ast
from pathlib import Path
import subprocess
import sys

import pytest

from core.sandbox import _capture, context
from core.sandbox.errors import SandboxSetupError
from core.sandbox.tests.test_context_decision_pins import _Driver
from core.testing.module_bindings import patch_module_attribute
from core.testing.state_isolation import pin_user_state_dirs


def _marker(label, cap):
    return f"\n[sandbox: {label} capture truncated at {cap} bytes]\n"


def _execute(monkeypatch, tmp_path, *, encoding, cap, stdout=None, stderr=None, status=None):
    if sys.platform != 'linux':
        pytest.skip('Linux dispatch adapter; no native backend is executed')
    calls = []

    def backend(cmd, **kwargs):
        calls.append(kwargs)
        assert kwargs['text'] is False and kwargs['max_capture_bytes'] == cap
        streams, truncated = [], []
        values = (stdout, b'' if stdout is not None and stderr is None else stderr)
        for label, value in zip(('stdout', 'stderr'), values):
            loss = value is not None and len(value) > cap
            truncated.append(loss)
            raw = None if value is None else value[:cap]
            streams.append(raw + _marker(label, cap).encode() if loss else raw)
        result = subprocess.CompletedProcess(cmd, 99 if status else 0, *streams)
        result._setup_status = status
        result._capture_encoding_limits = (cap, *truncated)
        return result

    def forbidden(*args, **kwargs):
        raise AssertionError('codec control reached actual process execution')

    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    _Driver(monkeypatch, backend)
    monkeypatch.setattr(context, '_run_teardown_first_timeout', forbidden)
    patch_module_attribute(monkeypatch, context, 'subprocess', 'Popen', forbidden)
    capture = {'capture_output': True} if stdout is not None else {'stderr': subprocess.PIPE}
    with context.sandbox(profile='full', target=str(tmp_path)) as run:
        try:
            return run(['/bin/true'], encoding=encoding, timeout=1,
                       max_capture_bytes=cap, **capture)
        finally:
            assert len(calls) == 1


@pytest.mark.parametrize('encoding,payload,cap,expected', [
    pytest.param('utf-16', 'ABtail'.encode('utf-16'), 6, 'AB', id='utf16-ascii'),
    pytest.param('utf-16', '🦕tail'.encode('utf-16'), 3, '', id='utf16-split'),
    pytest.param('utf-16-be', 'ABtail'.encode('utf-16-be'), 3, 'A', id='utf16be-split'),
    pytest.param('utf-8', 'éx'.encode(), 1, '', id='utf8-split'),
    pytest.param('utf-8', 'é🦕tail'.encode(), 3, 'é', id='utf8-complete-prefix'),
    pytest.param('utf-8', b'tail', 0, '', id='zero-cap'),
    pytest.param('latin-1', b'\xe9\xe9', 2, 'é', id='utf8-presentation-bound'),
])
def test_truncated_capture_decodes_prefix_before_marker(monkeypatch, tmp_path, encoding, payload, cap, expected):
    result = _execute(monkeypatch, tmp_path, encoding=encoding, cap=cap, stdout=payload)
    assert result.stdout == expected + _marker('stdout', cap)
    before = result.stdout, result.stderr
    context._apply_capture_ceiling(result, cap)
    assert (result.stdout, result.stderr) == before
    assert result.stdout.count('capture truncated') == 1


def test_stderr_only_capture_preserves_stdout_none(monkeypatch, tmp_path):
    result = _execute(monkeypatch, tmp_path, encoding='utf-16', cap=6,
                      stderr='ABtail'.encode('utf-16'))
    assert result.stdout is None
    assert result.stderr == 'AB' + _marker('stderr', 6)


@pytest.mark.parametrize('payload,cap', [(b'\xff', 10), (b'\xffx', 1)])
def test_malformed_retained_bytes_still_refuse(monkeypatch, tmp_path, payload, cap):
    with pytest.raises(UnicodeDecodeError):
        _execute(monkeypatch, tmp_path, encoding='utf-8', cap=cap, stdout=payload)


def test_marker_looking_target_text_is_not_metadata(monkeypatch, tmp_path):
    text = _marker('stdout', 1)
    result = _execute(monkeypatch, tmp_path, encoding='utf-8', cap=100, stdout=text.encode())
    assert result.stdout == text


def test_setup_status_remains_prior_to_codec(monkeypatch, tmp_path):
    with pytest.raises(SandboxSetupError):
        _execute(monkeypatch, tmp_path, encoding='utf-8', cap=1, stdout=b'\xffx',
                 status=('L', 'owned setup refusal'))


def test_nontext_codec_still_refuses(monkeypatch, tmp_path):
    with pytest.raises(LookupError):
        _execute(monkeypatch, tmp_path, encoding='hex_codec', cap=10, stdout=b'41')


def test_native_metadata_uses_effective_cap_and_parent_loss_flags():
    source = Path(__file__).parents[1] / '_spawn.py'
    tree = ast.parse(source.read_text())
    writes = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Attribute) and target.attr == '_capture_encoding_limits'
                      for target in node.targets)]
    assert len(writes) == 1
    expected = ast.parse('(_capture_cap, _truncated[1], _truncated[2])', mode='eval').body
    assert ast.dump(writes[0].value) == ast.dump(expected)


@pytest.mark.parametrize('cap', [10, 1], ids=['complete', 'truncated'])
def test_nontext_codec_refuses_before_incremental_decoder(monkeypatch, tmp_path, cap):
    def forbidden(encoding):
        raise AssertionError('nontext codec reached payload decoder construction')
    patch_module_attribute(monkeypatch, _capture, 'codecs', 'getincrementaldecoder', forbidden)
    with pytest.raises(LookupError, match='not a text encoding'):
        _execute(monkeypatch, tmp_path, encoding='hex_codec', cap=cap, stdout=b'41')


def test_complete_text_capture_does_not_require_incremental_decoder(monkeypatch, tmp_path):
    def forbidden(encoding):
        raise AssertionError('complete capture unnecessarily requested incremental decoder')
    patch_module_attribute(monkeypatch, _capture, 'codecs', 'getincrementaldecoder', forbidden)
    result = _execute(monkeypatch, tmp_path, encoding='utf-8', cap=20, stdout=b'owned')
    assert result.stdout == 'owned' and result.stderr == ''
