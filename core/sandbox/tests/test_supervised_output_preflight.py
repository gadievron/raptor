"""Supervised outputs are validated before probes or backend acquisition."""
from types import SimpleNamespace
import os
import subprocess
import sys

import pytest

from core.sandbox import supervised as sup
from core.testing.module_views import module_function_view

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux supervision selection')


@pytest.mark.parametrize('stream', ['stdout', 'stderr'])
@pytest.mark.parametrize('shape', ['integer', 'file'])
@pytest.mark.parametrize('tier', ['off', 'auto', 'require'])
def test_closed_output_refuses_before_probe_or_backend(tmp_path, stream, shape, tier):
    handle = (tmp_path / 'closed-output').open('wb')
    descriptor = handle.fileno()
    handle.close()
    with pytest.raises(OSError):
        os.fstat(descriptor)
    supplied = descriptor if shape == 'integer' else handle
    events = []

    def forbidden(*args, **kwargs):
        events.append('unexpected execution boundary')
        pytest.fail('closed output must refuse before probe/backend')

    private = module_function_view(sup, bindings={
        'probes': SimpleNamespace(check_pidns_supervision_available=forbidden),
        '_spawn_pidns_tier': forbidden, '_spawn_group_tier': forbidden,
    })
    with pytest.raises(ValueError):
        private.spawn_supervised(['/bin/true'], on_parent_death='kill',
                                 pid_ns=tier, env={'PATH': os.defpath}, **{stream: supplied})
    assert events == []


@pytest.mark.parametrize('stream', ['stdout', 'stderr'])
@pytest.mark.parametrize('shape', ['integer', 'file'])
@pytest.mark.parametrize('tier', ['off', 'require'])
def test_valid_output_reaches_selected_inert_backend(tmp_path, stream, shape, tier):
    events = []
    sentinel = object()

    def probe():
        events.append('probe')
        return True, 'owned verdict'

    def backend(*args):
        events.append('backend')
        assert args[3 if stream == 'stdout' else 4] == supplied
        return sentinel

    private = module_function_view(sup, bindings={
        'probes': SimpleNamespace(check_pidns_supervision_available=probe),
        '_spawn_pidns_tier': backend, '_spawn_group_tier': backend,
    })
    with (tmp_path / 'output').open('wb') as handle:
        supplied = handle.fileno() if shape == 'integer' else handle
        result = private.spawn_supervised(['/bin/true'], on_parent_death='kill',
                                          pid_ns=tier, env={'PATH': os.defpath}, **{stream: supplied})
        assert result is sentinel
    assert events == (['backend'] if tier == 'off' else ['probe', 'backend'])


@pytest.mark.parametrize('stream', ['stdout', 'stderr'])
@pytest.mark.parametrize('value', [None, subprocess.DEVNULL])
def test_supported_sentinels_need_no_validation_allocation(stream, value):
    sentinel = object()
    private = module_function_view(sup, bindings={
        '_spawn_group_tier': lambda *args: sentinel,
        '_resolve_stdio_fd': lambda *args: pytest.fail('sentinel validation must not allocate'),
    })
    assert private.spawn_supervised(['/bin/true'], on_parent_death='kill', pid_ns='off',
                                    env={'PATH': os.defpath}, **{stream: value}) is sentinel
