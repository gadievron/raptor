"""Explicit child environments without PATH retain the default exec search."""
import os
from pathlib import Path
import sys

import pytest

from core.sandbox.tests.capability import requires_landlock, requires_mount, requires_userns
from core.testing.standalone_cli import run_standalone_cli


pytestmark = [pytest.mark.slow, pytest.mark.linux_native, requires_landlock,
              requires_mount, requires_userns,
              pytest.mark.skipif(sys.platform != 'linux', reason='Linux namespace exec search')]


def test_child_without_path_uses_default_search_under_restricted_parent(tmp_path):
    target, output, empty = (tmp_path / name for name in ('target', 'output', 'empty-path'))
    for directory in (target, output, empty):
        directory.mkdir()
    driver = r'''
import os, shutil, sys
sys.path.insert(0, sys.argv[1])
from core.sandbox import sandbox
with sandbox(profile='strict', target=sys.argv[2], output=sys.argv[3]) as run:
    positive = run(['/bin/sh', '-c', 'printf absolute'], env={},
                   capture_output=True, text=True, timeout=15)
    assert positive.returncode == 0, positive.stderr
    assert positive.stdout == 'absolute'
    assert positive.sandbox_info['mount_ns_active'] is True
    print('ABSOLUTE_NATIVE_OK', flush=True)
    os.environ['PATH'] = sys.argv[4]
    assert shutil.which('sh') is None
    actual = run(['sh', '-c', 'printf default'], env={},
                 capture_output=True, text=True, timeout=15)
    assert actual.returncode == 0, actual.stderr
    assert actual.stdout == 'default'
    assert actual.sandbox_info['mount_ns_active'] is True
    print('DEFAULT_NATIVE_OK', flush=True)
'''
    environment = dict(os.environ)
    root = Path(__file__).resolve().parents[3]
    result = run_standalone_cli(
        [sys.executable, '-I', '-c', driver, str(root), str(target), str(output), str(empty)],
        env=environment, cwd=tmp_path, capture_output=True, text=True, timeout=40,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines() == ['ABSOLUTE_NATIVE_OK', 'DEFAULT_NATIVE_OK']
