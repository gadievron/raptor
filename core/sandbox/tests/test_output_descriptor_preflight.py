"""Output descriptor validity is checked before internal descriptor setup."""
import os
import subprocess
import sys

import pytest

from core.sandbox import context
from core.sandbox.tests.test_capture_limit_preflight import prepared as prepared

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux dispatcher preparation')


@pytest.mark.parametrize('stream', ['stdout', 'stderr'])
@pytest.mark.parametrize('shape', ['integer', 'file'])
def test_closed_output_refuses_before_dispatch(prepared, tmp_path, stream, shape):
    with context.sandbox(profile='full', target=str(tmp_path)) as run:
        handle = (tmp_path / 'closed-output').open('w+b')
        number = handle.fileno()
        handle.close()
        with pytest.raises(OSError):
            os.fstat(number)
        supplied = number if shape == 'integer' else handle
        expected = TypeError if shape == 'integer' else ValueError
        with pytest.raises(expected):
            run(['/bin/true'], **{stream: supplied}, capture_output=False, timeout=1)
    assert prepared.calls == []


@pytest.mark.parametrize('stream', ['stdout', 'stderr'])
@pytest.mark.parametrize('shape', ['integer', 'file'])
def test_valid_output_reaches_same_dispatch(prepared, tmp_path, stream, shape):
    with (tmp_path / 'output').open('w+b') as handle:
        supplied = handle.fileno() if shape == 'integer' else handle
        with context.sandbox(profile='full', target=str(tmp_path)) as run:
            result = run(['/bin/true'], **{stream: supplied}, capture_output=False, timeout=1)
        assert result.returncode == 0
        assert len(prepared.calls) == 1 and prepared.calls[0][stream] == supplied


@pytest.mark.parametrize('stream,value', [
    ('stdout', None), ('stdout', subprocess.PIPE), ('stdout', subprocess.DEVNULL),
    ('stderr', None), ('stderr', subprocess.PIPE), ('stderr', subprocess.DEVNULL),
    ('stderr', subprocess.STDOUT),
])
def test_output_sentinels_retain_dispatch(prepared, tmp_path, stream, value):
    with context.sandbox(profile='full', target=str(tmp_path)) as run:
        result = run(['/bin/true'], **{stream: value}, capture_output=False, timeout=1)
    assert result.returncode == 0 and len(prepared.calls) == 1


@pytest.mark.parametrize('entry', ['one-shot', 'untrusted-stdio'])
def test_invalid_output_refuses_before_wrapper_acquisition(tmp_path, monkeypatch, entry):
    handle = (tmp_path / 'closed-wrapper-output').open('w+b')
    number = handle.fileno()
    handle.close()

    def forbidden(*args, **kwargs):
        pytest.fail('invalid output must refuse before context or stdio acquisition')

    monkeypatch.setattr(context, 'sandbox', forbidden)
    monkeypatch.setattr(context, '_reopen_write_only', forbidden)
    with pytest.raises(TypeError):
        if entry == 'one-shot':
            context.run(['/bin/true'], stdout=number)
        else:
            context._untrusted_stdio_write_only({'stdout': number}, 'owned')
