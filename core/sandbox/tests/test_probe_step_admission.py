"""Static malformed probe plans are refused before starting their target."""

from contextlib import ExitStack
import sys

import pytest

from core.sandbox import _daemon as daemon
from core.sandbox._pipe_poll import readable_fds
from core.testing.module_views import module_function_view
from core.testing.processes import reap_on_exit


pytestmark = [pytest.mark.slow, pytest.mark.linux_native,
              pytest.mark.skipif(sys.platform != 'linux', reason='Linux request ownership')]


def test_malformed_step_cannot_start_an_owned_target(tmp_path):
    marker = tmp_path / 'must-not-run'
    launches = []
    with ExitStack() as owners:
        def launch(argv):
            proc = daemon._spawn_request_target(argv)
            owners.enter_context(reap_on_exit(proc, process_group=True))
            launches.append(proc)
            # Select target-first scheduling without sleeps or a weakened
            # deadline. The real owned child acknowledges its marker write.
            assert readable_fds([proc.stdout.fileno()], 5)
            assert proc.stdout.read(1) == b'R'
            return proc

        private = module_function_view(daemon, bindings={'_spawn_request_target': launch})
        result = private._handle_probe({
            'target_argv': [sys.executable, '-I', '-S', '-B', '-c',
                            'import os,sys; from pathlib import Path; '
                            'Path(sys.argv[1]).write_bytes(b"x"); '
                            'os.write(1,b"R"); os.read(0,1)', str(marker)],
            'steps': [None], 'per_recv_timeout': 1, 'total_wait_seconds': 1,
        })
        assert result['ok'] is False and result['error'] == 'step 0 not an object'
        assert not marker.exists(), 'malformed probe request executed its target'
        assert launches == []


@pytest.mark.parametrize('steps', [[0], ['bad'], [[]], 'bad', {'bad': 1}],
                         ids=['number', 'text-step', 'list-step', 'text-plan', 'object-plan'])
def test_invalid_static_shape_never_reaches_launch(steps):
    calls = []

    def launch(argv):
        calls.append(argv)
        raise AssertionError('malformed plan reached target launch')

    private = module_function_view(daemon, bindings={'_spawn_request_target': launch})
    result = private._handle_probe({'target_argv': ['unused'], 'steps': steps})
    assert result['ok'] is False
    assert calls == []


@pytest.mark.parametrize('steps', [[], [{}], [{'recv_until': 8}]],
                         ids=['empty', 'empty-step', 'receive'])
def test_valid_probe_plans_keep_native_execution(steps):
    processes = []
    with ExitStack() as owners:
        def launch(argv):
            proc = daemon._spawn_request_target(argv)
            owners.enter_context(reap_on_exit(proc, process_group=True))
            processes.append(proc)
            return proc

        private = module_function_view(daemon, bindings={'_spawn_request_target': launch})
        result = private._handle_probe({
            'target_argv': [sys.executable, '-I', '-S', '-B', '-c',
                            'import os; os.write(1,b"admitted")'],
            'steps': steps, 'per_recv_timeout': 2, 'total_wait_seconds': 2,
        })
        assert result['ok'] is True and result['target_exit'] == 'clean'
        assert result['steps_completed'] == len(steps)
        assert result['target_stdout_tail'] == 'admitted'
        assert len(processes) == 1 and processes[0].returncode == 0
        assert all(s.closed for s in (processes[0].stdin, processes[0].stdout, processes[0].stderr))
