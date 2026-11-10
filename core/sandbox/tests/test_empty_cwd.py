"""Explicit empty working directories refuse before the native target execs."""
import sys

import pytest

from core.sandbox import SandboxSetupError, sandbox
from core.sandbox.tests.capability import requires_landlock, requires_mount, requires_userns


pytestmark = [pytest.mark.slow, pytest.mark.linux_native, requires_landlock,
              requires_mount, requires_userns,
              pytest.mark.skipif(sys.platform != 'linux', reason='Linux namespace cwd handling')]


@pytest.mark.parametrize('empty', ['', b''], ids=['text', 'bytes'])
def test_explicit_empty_cwd_refuses_before_execution(tmp_path, empty):
    target, output = tmp_path / 'target', tmp_path / 'output'
    target.mkdir()
    output.mkdir()
    marker = output / 'must-not-run'
    with sandbox(profile='strict', target=str(target), output=str(output)) as run:
        positive = run(['/bin/sh', '-c', 'pwd'], cwd=str(target),
                       capture_output=True, text=True, timeout=15)
        assert positive.returncode == 0, positive.stderr
        assert positive.stdout.strip() == str(target)
        assert positive.sandbox_info['mount_ns_active'] is True
        caught = None
        result = None
        try:
            result = run(['/bin/sh', '-c', 'printf reached > "$1"', 'owned', str(marker)],
                         cwd=empty, capture_output=True, text=True, timeout=15)
        except SandboxSetupError as error:
            caught = error
    assert not marker.exists(), 'explicit empty cwd executed the native target'
    assert result is None, 'invalid cwd returned a target result'
    assert isinstance(caught, SandboxSetupError)
    assert caught.setup_category == 'C'
    assert 'cwd' in str(caught)
