"""Invalid profile names retain the documented validation error."""

from contextlib import contextmanager

import pytest

from core.sandbox import context, state
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
