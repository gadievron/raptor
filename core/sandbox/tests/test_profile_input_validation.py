"""Invalid profile names retain the documented validation error."""

from contextlib import contextmanager

import pytest

from core.sandbox import context, state, landlock, seccomp
from core.testing.module_views import module_function_view
from core.testing.state_isolation import pin_user_state_dirs


@pytest.mark.parametrize('paths', ['none', 'target', 'output', 'both'])
def test_unknown_profile_with_paths_raises_value_error(tmp_path, monkeypatch, paths):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))

    def forbidden(*args, **kwargs):
        pytest.fail('invalid profile reached capability or dispatch setup')

    private = module_function_view(context, bindings={
        'sandbox': context.sandbox.__wrapped__,
        'state': module_function_view(state, bindings={
            '_cli_sandbox_profile': None, '_cli_sandbox_disabled': False,
        }),
        'check_net_available': forbidden, 'check_mount_available': forbidden,
        'check_seatbelt_available': forbidden, 'check_landlock_available': forbidden,
        'check_seccomp_available': forbidden, '_make_preexec_fn': forbidden,
        '_load_user_limits': forbidden,
    })
    kwargs = {'profile': 'unknown-owned-profile'}
    if paths in ('target', 'both'):
        kwargs['target'] = str(tmp_path)
    if paths in ('output', 'both'):
        kwargs['output'] = str(tmp_path)
    with pytest.raises(ValueError, match='Unknown sandbox profile'):
        with contextmanager(private.sandbox)(**kwargs):
            pytest.fail('invalid profile yielded a context')


@pytest.mark.parametrize('selected', ['full', 'network-only', 'none'])
def test_cli_profile_overrides_unknown_caller_profile(tmp_path, monkeypatch, selected):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))

    def forbidden(*args, **kwargs):
        pytest.fail('constructor-only control reached execution')

    private = module_function_view(context, bindings={
        'sandbox': context.sandbox.__wrapped__,
        'state': module_function_view(state, bindings={
            '_cli_sandbox_profile': selected, '_cli_sandbox_disabled': False,
            'warn_once': lambda *args: False,
        }),
        '_landlock': module_function_view(landlock, bindings={
            'check_landlock_available': lambda: True, '_get_landlock_abi': lambda: 6,
        }),
        '_seccomp': module_function_view(seccomp, bindings={
            'check_seccomp_available': lambda: True,
        }),
        'check_net_available': lambda: False, 'check_mount_available': lambda: False,
        'check_seatbelt_available': lambda: False, 'check_landlock_available': lambda: True,
        'check_seccomp_available': lambda: True, '_make_preexec_fn': lambda *a, **kw: None,
        '_load_user_limits': lambda: {}, '_run_teardown_first_timeout': forbidden,
    })
    with contextmanager(private.sandbox)(
            profile='unknown-owned-profile', output=str(tmp_path), block_network=False) as run:
        assert callable(run)
