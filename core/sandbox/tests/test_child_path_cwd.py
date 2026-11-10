"""Native executable search resolves relative PATH entries after child chdir."""
import os
import shutil
import sys
import uuid

import pytest

from core.sandbox import SandboxSetupError, context, sandbox
from core.sandbox.tests.capability import requires_landlock, requires_mount, requires_userns
from core.testing.module_views import module_function_view


@pytest.mark.slow
@pytest.mark.linux_native
@requires_landlock
@requires_mount
@requires_userns
@pytest.mark.skipif(sys.platform != 'linux', reason='Linux namespace executable search')
@pytest.mark.parametrize('entry', ['bin', ''], ids=['relative-bin', 'empty-current-directory'])
def test_child_path_search_uses_explicit_child_cwd(tmp_path, entry):
    target, output = tmp_path / 'target', tmp_path / 'output'
    target.mkdir()
    output.mkdir()
    directory = target / entry if entry else target
    directory.mkdir(exist_ok=True)
    name = 'raptor-owned-path-' + uuid.uuid4().hex
    tool = directory / name
    tool.write_text('#!/bin/sh\nprintf owned-path\n')
    tool.chmod(0o755)
    assert shutil.which(name) is None
    assert shutil.which(name, path=entry) is None
    with sandbox(profile='strict', target=str(target), output=str(output)) as run:
        positive = run([str(tool)], cwd=str(target), env={'PATH': entry},
                       capture_output=True, text=True, timeout=15)
        assert positive.returncode == 0, positive.stderr
        assert positive.stdout == 'owned-path'
        assert positive.sandbox_info['mount_ns_active'] is True
        actual = run([name], cwd=str(target), env={'PATH': entry},
                     capture_output=True, text=True, timeout=15)
    assert actual.returncode == 0, actual.stderr
    assert actual.stdout == 'owned-path'
    assert actual.sandbox_info['mount_ns_active'] is True


@pytest.mark.parametrize('kind', ['str', 'bytes', 'path'])
def test_lookup_keeps_symlink_parent_traversal(tmp_path, kind):
    real = tmp_path / 'real'
    child = real / 'child'
    binary = real / 'bin'
    child.mkdir(parents=True)
    binary.mkdir()
    alias = tmp_path / 'alias'
    alias.symlink_to(child, target_is_directory=True)
    name = 'raptor-owned-path-' + uuid.uuid4().hex
    tool = binary / name
    tool.write_text('owned lookup only')
    tool.chmod(0o755)
    cwd = alias / '..'
    value = str(cwd) if kind == 'str' else os.fsencode(cwd) if kind == 'bytes' else cwd
    assert shutil.which(name) is None
    assert context._cmd_resolves_nowhere([name], 'bin', cwd=value) is False


def test_missing_tool_in_valid_child_cwd_still_refuses(tmp_path):
    (tmp_path / 'bin').mkdir()
    name = 'raptor-owned-missing-' + uuid.uuid4().hex
    assert context._cmd_resolves_nowhere([name], 'bin', cwd=tmp_path) is True


@pytest.mark.parametrize('empty', [True, False], ids=['empty', 'missing'])
def test_invalid_child_cwd_is_left_to_lane_validation(tmp_path, empty):
    cwd = '' if empty else str(tmp_path / 'absent')
    name = 'raptor-owned-missing-' + uuid.uuid4().hex
    assert context._cmd_resolves_nowhere([name], 'bin', cwd=cwd) is False


@pytest.mark.parametrize('exists', [True, False], ids=['child-tool-exists', 'child-tool-missing'])
def test_refusing_context_uses_output_as_default_resolution_cwd(tmp_path, exists):
    binary = tmp_path / 'bin'
    binary.mkdir()
    name = 'raptor-owned-path-' + uuid.uuid4().hex
    if exists:
        tool = binary / name
        tool.write_text('owned lookup only')
        tool.chmod(0o755)
    refusal = SandboxSetupError('owned construction refusal')
    calls = []

    class Refusing:
        def __enter__(self):
            raise refusal

        def __exit__(self, *args):
            pytest.fail('a refusing context was never entered')

    def construct(**configuration):
        calls.append(configuration)
        return Refusing()

    private = module_function_view(context, bindings={'sandbox': construct})
    if exists:
        with pytest.raises(SandboxSetupError) as caught:
            private.run([name], output=str(tmp_path), profile='strict', env={'PATH': 'bin'})
        assert caught.value is refusal
    else:
        with pytest.raises(FileNotFoundError) as caught:
            private.run([name], output=str(tmp_path), profile='strict', env={'PATH': 'bin'})
        assert caught.value.__cause__ is refusal
    assert len(calls) == 1 and calls[0]['output'] == str(tmp_path)
