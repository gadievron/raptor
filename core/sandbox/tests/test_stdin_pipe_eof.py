"""Synchronous PIPE without input supplies EOF without contaminating stderr."""
import subprocess
import sys

import pytest

from core.sandbox import sandbox
from core.sandbox.tests.capability import requires_landlock, requires_mount, requires_userns


@pytest.mark.slow
@pytest.mark.linux_native
@pytest.mark.skipif(sys.platform != 'linux', reason='Linux native stdin delivery')
@requires_landlock
@requires_mount
@requires_userns
@pytest.mark.parametrize('explicit_none', [False, True], ids=['omitted-input', 'none-input'])
def test_stdin_pipe_without_payload_delivers_clean_eof(tmp_path, explicit_none):
    target, output = tmp_path / 'target', tmp_path / 'output'
    target.mkdir()
    output.mkdir()
    command = ['/bin/sh', '-c',
               'if IFS= read -r value; then printf unexpected-input; else printf owned-eof; fi']
    with sandbox(profile='strict', target=str(target), output=str(output)) as run:
        positive = run(command, stdin=subprocess.DEVNULL, capture_output=True,
                       text=True, timeout=15)
        assert positive.returncode == 0 and positive.stdout == 'owned-eof', positive.stderr
        assert positive.stderr == '' and positive.sandbox_info['mount_ns_active'] is True
        options = {'input': None} if explicit_none else {}
        actual = run(command, stdin=subprocess.PIPE, capture_output=True,
                     text=True, timeout=15, **options)
    assert actual.returncode == 0 and actual.stdout == 'owned-eof', actual.stderr
    assert actual.sandbox_info['mount_ns_active'] is True
    assert actual.stderr == '', 'valid synchronous stdin=PIPE must not inject an unsupported warning'

