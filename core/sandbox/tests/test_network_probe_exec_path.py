"""The actual namespace probe does not depend on inherited PATH contents."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from core.sandbox.tests.capability import requires_userns
from core.testing.standalone_cli import run_standalone_cli
from core.testing.module_views import module_function_view


@pytest.mark.slow
@pytest.mark.linux_native
@requires_userns
@pytest.mark.skipif(sys.platform != 'linux', reason='actual Linux user/network namespace probe')
def test_uncached_network_probe_survives_empty_parent_path(tmp_path):
    empty = tmp_path / 'empty-path'
    empty.mkdir()
    driver = r'''
import io, logging, os, shutil, sys
sys.path.insert(0, sys.argv[1])
from core.sandbox import probes
assert probes._probe_net_available() is True
print('NORMAL_NATIVE_OK', flush=True)
captured = io.StringIO()
handler = logging.StreamHandler(captured)
probes.logger.addHandler(handler)
probes.logger.setLevel(logging.DEBUG)
os.environ['PATH'] = sys.argv[2]
assert shutil.which('true') is None
assert probes._probe_net_available() is True, captured.getvalue()
print('NARROWED_NATIVE_OK', flush=True)
'''
    root = Path(__file__).resolve().parents[3]
    result = run_standalone_cli(
        [sys.executable, '-I', '-c', driver, str(root), str(empty)],
        env=dict(os.environ), cwd=tmp_path, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines() == ['NORMAL_NATIVE_OK', 'NARROWED_NATIVE_OK']


def test_missing_trusted_noop_refuses_before_any_probe_execution():
    from core.sandbox import probes
    lookups = []

    def resolve(name):
        assert name == 'unshare'
        return '/trusted/unshare'

    def which(name, *, path):
        lookups.append((name, path))
        return None

    def no_execution(*args, **kwargs):
        pytest.fail('missing trusted no-op must refuse before execution')

    private = module_function_view(probes, bindings={
        '_resolve_sandbox_binary': resolve,
        'shutil': module_function_view(shutil, bindings={'which': which}),
        'subprocess': module_function_view(subprocess, bindings={'run': no_execution}),
        '_staged_pidns_selftest': no_execution,
    })
    assert private._probe_net_available() is False
    assert lookups == [('true', os.pathsep.join(probes._SAFE_BIN_DIRS))]
