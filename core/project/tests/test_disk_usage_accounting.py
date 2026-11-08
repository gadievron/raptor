"""Project footprint and reclamation estimates reflect real inode allocation."""
import os
import sys

import pytest

from core.project import disk_usage as disk
from core.project import cli
from core.project.project import Project
from core.testing.module_bindings import patch_module_attribute
from core.testing.standalone_cli import run_standalone_cli


BACKENDS = [
    pytest.param(False, id='anchored', marks=pytest.mark.skipif(
        not callable(getattr(os, 'fwalk', None)), reason='requires fwalk')),
    pytest.param(True, id='portable'),
]


def allocated(path):
    info = path.lstat()
    return info.st_blocks * 512 if hasattr(info, 'st_blocks') else info.st_size


@pytest.mark.parametrize('portable', BACKENDS)
@pytest.mark.parametrize('layout', ['flat', 'nested', 'spread'])
@pytest.mark.parametrize('payload', [0, 1, 8193, 'sparse'], ids=['empty', 'small', 'blocks', 'sparse'])
@pytest.mark.parametrize('count', [1, 3], ids=['single', 'linked'])
@pytest.mark.parametrize('retained', [False, True], ids=['all-selected', 'outside-link'])
def test_unique_allocation_and_reclaimable_space(tmp_path, monkeypatch, portable, layout, payload, count, retained):
    root = tmp_path / 'project'
    root.mkdir()
    directories = [root]
    parents = [root]
    if layout == 'nested':
        (root / 'a/b').mkdir(parents=True)
        directories += [root / 'a', root / 'a/b']
        parents = [root / 'a/b']
    elif layout == 'spread':
        for name in ('a', 'b'):
            (root / name).mkdir()
        directories += [root / 'a', root / 'b']
        parents = directories[1:]
    first = parents[0] / 'data-0'
    if payload == 'sparse':
        with first.open('wb') as output:
            output.truncate(32 * 1024 * 1024)
    else:
        first.write_bytes(b'x' * payload)
    for index in range(1, count):
        os.link(first, parents[index % len(parents)] / f'data-{index}')
    if retained:
        os.link(first, tmp_path / 'retained')
    if portable:
        patch_module_attribute(monkeypatch, disk, 'os', 'fwalk', None, raising=False)
    usage = disk.scan_usage(root)
    directory_bytes = sum(allocated(path) for path in directories)
    assert not usage.incomplete
    assert usage.allocated_bytes == directory_bytes + allocated(first)
    assert usage.reclaimable_bytes == directory_bytes + (0 if retained else allocated(first))


@pytest.mark.parametrize('portable', BACKENDS)
def test_joint_roots_credit_shared_data_once_and_duplicates_add_nothing(tmp_path, monkeypatch, portable):
    first, second = tmp_path / 'first', tmp_path / 'second'
    first.mkdir()
    second.mkdir()
    (first / 'data').write_bytes(b'x' * 8193)
    os.link(first / 'data', second / 'same')
    if portable:
        patch_module_attribute(monkeypatch, disk, 'os', 'fwalk', None, raising=False)
    sizes, incomplete = disk.estimate_removals([first, second, first])
    assert not incomplete
    assert sizes[first] == allocated(first)
    assert sizes[second] == allocated(second) + allocated(first / 'data')


@pytest.mark.parametrize('portable', BACKENDS)
def test_overlapping_roots_do_not_double_count_inode_allocation(tmp_path, monkeypatch, portable):
    root = tmp_path / 'project'
    child = root / 'child'
    child.mkdir(parents=True)
    (child / 'data').write_text('payload')
    if portable:
        patch_module_attribute(monkeypatch, disk, 'os', 'fwalk', None, raising=False)
    sizes, incomplete = disk.estimate_removals([root, child])
    assert not incomplete
    assert sum(sizes.values()) == allocated(root) + allocated(child) + allocated(child / 'data')


@pytest.mark.parametrize('kind', ['file-link', 'directory-link', 'loop', 'fifo'])
def test_special_entries_do_not_follow_targets_or_block(tmp_path, kind):
    root = tmp_path / 'project'
    root.mkdir()
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'data').write_bytes(b'x' * 16384)
    node = root / 'special'
    if kind == 'fifo':
        if not hasattr(os, 'mkfifo'):
            pytest.skip('requires FIFO support')
        os.mkfifo(node)
    else:
        node.symlink_to(root if kind == 'loop' else outside / 'data' if kind == 'file-link' else outside)
    output = run_standalone_cli([sys.executable, '-c', '''
import sys
from pathlib import Path
from core.project.disk_usage import scan_usage
root = Path(sys.argv[1])
usage = scan_usage(root)
assert len(usage.entries) == 2, usage
assert not usage.incomplete, usage
''', str(root)], capture_output=True, text=True, timeout=20)
    assert output.returncode == 0, output.stdout + output.stderr
    assert (outside / 'data').stat().st_size == 16384


@pytest.mark.parametrize('portable', BACKENDS)
def test_root_symlink_is_a_link_inode_not_a_traversal(tmp_path, monkeypatch, portable):
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'data').write_bytes(b'x' * 8193)
    root = tmp_path / 'project'
    root.symlink_to(outside)
    if portable:
        patch_module_attribute(monkeypatch, disk, 'os', 'fwalk', None, raising=False)
    usage = disk.scan_usage(root)
    assert len(usage.entries) == 1
    assert usage.allocated_bytes == allocated(root)


@pytest.mark.parametrize('runs', [False, True], ids=['no-runs', 'with-run'])
@pytest.mark.parametrize('alias', [False, True], ids=['direct', 'explicit-output-alias'])
def test_status_includes_caches_and_generated_files_even_without_runs(tmp_path, capsys, runs, alias):
    root = tmp_path / 'project'
    root.mkdir()
    cache = root / '_sources/cache'
    cache.mkdir(parents=True)
    (cache / 'data').write_bytes(b'x' * 8193)
    findings = root / 'findings'
    findings.mkdir()
    (findings / 'report').write_text('report')
    if runs:
        run = root / 'scan-one'
        run.mkdir()
        (run / '.raptor-run.json').write_text('{"command":"scan","status":"completed"}')
        os.link(cache / 'data', run / 'linked')
    chosen = root
    if alias:
        chosen = tmp_path / 'chosen'
        chosen.symlink_to(root)
    expected = disk.scan_usage(root).allocated_bytes
    project = Project(name='demo', target=str(tmp_path / 'target'), output_dir=str(chosen))
    cli._print_status(project)
    text = capsys.readouterr().out
    amount = f'{expected / 1024 / 1024:.1f}MB' if expected >= 1024 * 1024 else f'{expected / 1024:.1f}KB' if expected >= 1024 else f'{expected}B'
    assert f'Disk usage: {amount} (estimate)' in text
    assert ('Runs:' if runs else 'No runs.') in text


def test_metadata_errors_are_partial_and_status_says_so(tmp_path, monkeypatch, capsys):
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'good').write_text('good')
    (root / 'unreadable').write_text('bad')
    original = os.stat
    class LocalPath(type(root)):
        def lstat(self):
            if self.name == 'unreadable':
                raise PermissionError('metadata unavailable')
            return super().lstat()
    monkeypatch.setattr(disk, 'Path', LocalPath)
    def unavailable(path, *args, **kwargs):
        if path == 'unreadable':
            raise PermissionError('metadata unavailable')
        return original(path, *args, **kwargs)
    patch_module_attribute(monkeypatch, disk, 'os', 'stat', unavailable)
    usage = disk.scan_usage(root)
    assert usage.incomplete
    assert usage.allocated_bytes == allocated(root) + allocated(root / 'good')
    cli._print_disk_usage(Project(name='demo', target='', output_dir=str(root)))
    assert '(partial estimate)' in capsys.readouterr().out


@pytest.mark.parametrize('portable', BACKENDS)
def test_metadata_budget_stops_scanning_and_marks_incomplete(tmp_path, monkeypatch, portable):
    root = tmp_path / 'project'
    root.mkdir()
    for index in range(20):
        (root / f'file-{index}').write_text('data')
    monkeypatch.setattr(disk, '_MAX_USAGE_RECORDS', 12)
    if portable:
        patch_module_attribute(monkeypatch, disk, 'os', 'fwalk', None, raising=False)
    usage = disk.scan_usage(root)
    assert usage.incomplete and usage.truncated
    assert usage._records <= 12
    assert len(usage.entries) <= 4


def test_forest_budget_does_not_restart_for_every_root(tmp_path, monkeypatch):
    roots = []
    for index in range(10):
        root = tmp_path / f'root-{index}'
        root.mkdir()
        (root / 'data').write_text('data')
        roots.append(root)
    monkeypatch.setattr(disk, '_MAX_USAGE_RECORDS', 9)
    scanned = []
    original = disk.scan_usage
    def scan(path):
        scanned.append(path)
        return original(path)
    monkeypatch.setattr(disk, 'scan_usage', scan)
    sizes, incomplete = disk.estimate_removals(roots)
    assert incomplete
    assert len(scanned) < len(roots)
    assert all(sizes[root] == 0 for root in roots[len(scanned):])


@pytest.mark.parametrize('fallback', ['missing', 'negative'])
def test_missing_allocation_support_uses_logical_size(tmp_path, fallback):
    path = tmp_path / 'data'
    path.write_text('payload')
    actual = path.stat()
    class Info:
        def __getattr__(self, name):
            if name == 'st_blocks':
                if fallback == 'missing':
                    raise AttributeError(name)
                return -1
            return getattr(actual, name)
    assert disk._allocated(Info()) == actual.st_size


@pytest.mark.skipif(not callable(getattr(os, 'fwalk', None)), reason='requires fwalk')
@pytest.mark.parametrize('primary', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('close_failure', [OSError, KeyboardInterrupt, SystemExit])
def test_walker_close_failure_never_hides_primary(tmp_path, monkeypatch, primary, close_failure):
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'data').write_text('payload')
    original = disk.os.fwalk
    descriptors = []
    def walk(*args, **kwargs):
        iterator = original(*args, **kwargs)
        try:
            for row in iterator:
                descriptors.append(row[3])
                yield row
                raise primary('primary scan failure')
        finally:
            iterator.close()
            raise close_failure('secondary close failure')
    # Raise in the consumer after receiving the first real descriptor: close()
    # then runs the wrapper's finally while that original exception is active.
    original_stat = disk.os.stat
    def fail(path, *args, **kwargs):
        if path == 'data':
            raise primary('primary scan failure')
        return original_stat(path, *args, **kwargs)
    patch_module_attribute(monkeypatch, disk, 'os', 'fwalk', walk)
    patch_module_attribute(monkeypatch, disk, 'os', 'stat', fail)
    if primary is OSError:
        # Ordinary metadata errors are handled as incomplete observations, so
        # a later cancellation during teardown remains a new cancellation.
        if close_failure is OSError:
            assert disk.scan_usage(root).incomplete
        else:
            with pytest.raises(close_failure):
                disk.scan_usage(root)
    else:
        with pytest.raises(primary, match='primary scan failure'):
            disk.scan_usage(root)
    assert descriptors
    for fd in descriptors:
        with pytest.raises(OSError):
            os.fstat(fd)



def test_link_observations_share_the_metadata_budget(tmp_path, monkeypatch):
    root = tmp_path / 'project'
    root.mkdir()
    data = root / 'data'
    data.write_text('payload')
    for index in range(20):
        os.link(data, root / f'link-{index}')
    monkeypatch.setattr(disk, '_MAX_USAGE_RECORDS', 12)
    usage = disk.scan_usage(root)
    assert usage.truncated and usage.incomplete
    assert usage._records <= 12
    assert len(usage.entries) == 2
    assert usage.reclaimable_bytes == allocated(root)


def test_unknown_inode_numbers_do_not_collapse_distinct_files(tmp_path):
    first, second = tmp_path / 'first', tmp_path / 'second'
    first.write_text('first')
    second.write_text('second')
    class Info:
        st_ino = 0
        def __init__(self, actual):
            self.actual = actual
        def __getattr__(self, name):
            return getattr(self.actual, name)
    usage = disk.Usage()
    for path in (first, second):
        usage.add(Info(path.stat()), path, ('parent', path.name), tmp_path)
    assert len(usage.entries) == 2
    assert usage.allocated_bytes == allocated(first) + allocated(second)
    assert usage.incomplete


@pytest.mark.parametrize('portable', BACKENDS)
def test_directory_replacement_never_counts_an_outside_target(tmp_path, monkeypatch, portable):
    root = tmp_path / 'project'
    child = root / 'child'
    child.mkdir(parents=True)
    (child / 'data').write_text('owned data')
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'large').write_bytes(b'x' * 65536)
    expected = allocated(root) + allocated(child) + allocated(child / 'data')
    saved = tmp_path / 'original-child'
    binding = 'walk' if portable else 'fwalk'
    original = getattr(disk.os, binding)
    def walk(*args, **kwargs):
        iterator = original(*args, **kwargs)
        try:
            for row in iterator:
                if row[0] == str(child):
                    child.rename(saved)
                    child.symlink_to(outside)
                yield row
        finally:
            iterator.close()
    if portable:
        patch_module_attribute(monkeypatch, disk, 'os', 'fwalk', None, raising=False)
    patch_module_attribute(monkeypatch, disk, 'os', binding, walk)
    usage = disk.scan_usage(root)
    assert usage.allocated_bytes <= expected
    assert all(key != (outside.stat().st_dev, outside.stat().st_ino) for key in usage.entries)
    assert (saved / 'data').read_text() == 'owned data'
    if portable:
        assert usage.incomplete



def test_invalid_root_path_is_an_incomplete_observation(tmp_path):
    usage = disk.scan_usage(tmp_path / 'invalid\x00root')
    assert usage.incomplete and not usage.entries
    assert usage.allocated_bytes == 0


def test_invalid_stored_output_path_does_not_break_disk_status(tmp_path, capsys):
    project = Project(name='demo', target='', output_dir=str(tmp_path / 'invalid\x00root'))
    cli._print_disk_usage(project)
    assert 'Disk usage: unavailable' in capsys.readouterr().out
