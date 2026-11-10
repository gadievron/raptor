"""Parent-side Darwin dispatch and codec plumbing, without seatbelt claims."""

import builtins
import os
from contextlib import contextmanager
import subprocess
import sys

import pytest

from core.sandbox import context, _macos_spawn as mac
import core.sandbox as package
from core.testing.module_views import module_function_view


def test_darwin_dispatch_keeps_explicit_codecs(tmp_path):
    target, output = tmp_path / 'target', tmp_path / 'output'
    target.mkdir()
    output.mkdir()
    received = []

    def execute(cmd, **kwargs):
        received.append(kwargs)
        assert kwargs.get('encoding') == 'ascii', 'Darwin dispatch dropped caller encoding'
        assert kwargs.get('errors') == 'replace', 'Darwin dispatch dropped caller error handler'
        assert kwargs['input'] == 'owned \u03bb'
        result = subprocess.CompletedProcess(cmd, 0, 'owned ?', '')
        result._setup_status = None
        return result

    backend = module_function_view(mac, bindings={'run_sandboxed': execute})
    parent = module_function_view(package, bindings={'_macos_spawn': backend})

    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and not name and '_macos_spawn' in fromlist:
            return parent
        return builtins.__import__(name, globals, locals, fromlist, level)

    private = module_function_view(context, bindings={
        'sandbox': context.sandbox.__wrapped__,
        'sys': module_function_view(sys, bindings={'platform': 'darwin'}),
        'check_seatbelt_available': lambda: True,
        'check_mount_available': lambda: False,
        'check_net_available': lambda: False,
    }, import_hook=imports)
    with contextmanager(private.sandbox)(profile='full', target=str(target), output=str(output)) as run:
        result = run(['/bin/cat'], input='owned \u03bb', encoding='ascii', errors='replace',
                     capture_output=True, timeout=5)
    assert result.stdout == 'owned ?'
    assert len(received) == 1


@pytest.mark.slow
@pytest.mark.skipif(os.name != 'posix', reason='owned POSIX Popen transport')
@pytest.mark.parametrize('errors,expected', [('replace', 'owned ?'), ('ignore', 'owned '),
                                            ('backslashreplace', 'owned \\u03bb')],
                         ids=['replace', 'ignore', 'backslashreplace'])
def test_seatbelt_parent_uses_explicit_input_and_output_codecs(tmp_path, errors, expected):
    output = tmp_path / 'output'
    output.mkdir()
    processes = []
    popen = subprocess.Popen

    def launch(sandbox_cmd, **kwargs):
        # Only the launch boundary is emulated. This checks the original
        # command still carries seatbelt, then exercises real owned Popen I/O.
        assert mac.SANDBOX_EXEC in sandbox_cmd
        assert kwargs['encoding'] == 'ascii'
        assert kwargs['errors'] == errors
        os.write(int(kwargs['env']['_RAPTOR_STATUS_FD']), b'K')
        process = popen(['/bin/cat'], **kwargs)
        processes.append(process)
        return process

    private = module_function_view(mac, bindings={
        'subprocess': module_function_view(subprocess, bindings={'Popen': launch}),
        '_grant_pin_mismatch': lambda *args: None,
        '_ps_snapshot': lambda: [],
        '_sweep_descendants': lambda *args, **kwargs: set(),
    })
    try:
        result = private.run_sandboxed(['/bin/cat'], env={}, nproc_limit=0,
                                      output=str(output), capture_output=True, text=False,
                                      encoding='ascii', errors=errors, input='owned \u03bb', timeout=5)
        assert result.returncode == 0, result.stderr
        assert result.stdout == expected
        assert result._setup_status is None  # synthetic readiness, not Darwin enforcement
        assert len(processes) == 1
        assert processes[0].returncode == 0
        assert all(stream is None or stream.closed for stream in
                   (processes[0].stdin, processes[0].stdout, processes[0].stderr))
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
