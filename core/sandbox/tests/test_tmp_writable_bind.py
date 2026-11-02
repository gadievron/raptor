"""Explicit host grants under /tmp need binds, not the private tmpfs view."""
from pathlib import Path
import sys
import tempfile

import pytest

from core.sandbox._spawn import _anchor_grants_to_bind_view, _drop_host_tmpdir_grants
from core.sandbox._pathpin import ViewAnchoredPath

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux mount-tree grant planning')


@pytest.fixture
def paths():
    # This is specifically a /tmp-vs-private-tmpfs contract, independent of
    # the operator's selected scratch base. Only this owned fixture is removed.
    with tempfile.TemporaryDirectory(prefix='bind-grant-', dir='/tmp') as base:
        root = Path(base)
        source, output = root/'source', root/'database'
        source.mkdir()
        output.mkdir()
        yield root, source, output


def plan(paths, grants, **overrides):
    _, _, output = paths
    args = dict(target=None, output=str(output), rootfs=None,
                readable_paths=None, kind='writable')
    args.update(overrides)
    return _anchor_grants_to_bind_view(grants, **args)


@pytest.mark.parametrize('file_grant', [False, True])
def test_only_explicit_host_grant_is_carried(paths, file_grant):
    root, source, _ = paths
    grant = source
    if file_grant:
        grant = source/'input'
        grant.write_text('fixture')
    rules, carry = plan(paths, ['/tmp', str(grant)])
    assert rules[0] == '/tmp'
    assert not isinstance(rules[0], ViewAnchoredPath)
    assert isinstance(rules[1], ViewAnchoredPath)
    assert carry == [str(grant)]
    assert str(root) not in carry


def test_read_only_target_subpath_is_not_overridden(paths):
    _, source, _ = paths
    sub = source/'build'
    sub.mkdir()
    rules, carry = plan(paths, [str(sub)], target=str(source))
    assert carry == []
    assert rules == [str(sub)]


def test_readable_bind_remains_read_only(paths):
    _, source, _ = paths
    rules, carry = plan(paths, [str(source)], readable_paths=[str(source)], kind='readable')
    assert carry == []
    assert isinstance(rules[0], ViewAnchoredPath)


def test_namespace_local_nonexistent_path_is_not_a_host_bind(paths):
    root, _, _ = paths
    path = str(root/'missing')
    rules, carry = plan(paths, [path])
    assert rules == [path]
    assert carry == []


def test_host_tmpdir_baseline_is_not_reintroduced(paths, monkeypatch):
    root, source, output = paths
    monkeypatch.setattr(tempfile, 'tempdir', str(root))
    grants = _drop_host_tmpdir_grants([str(root), '/tmp', str(source)],
                                    target=None, output=str(output), rootfs=None)
    assert str(root) not in grants
    _, carry = plan(paths, grants)
    assert carry == [str(source)]


def test_image_rootfs_keeps_existing_grant_semantics(paths):
    root, source, _ = paths
    rules, carry = plan(paths, [str(source)], rootfs=str(root))
    assert rules == [str(source)]
    assert carry == []
