"""Count-based GC preserves fresh generations and keeps quota accounting honest."""
import errno
import os

import pytest
from core.atomic_fs.cache_eviction import evict_oldest_files


def entries(root, count=4):
    paths = []
    for index in range(count):
        path = root / f'{index}.json'
        path.write_bytes(b'cached')
        os.utime(path, (1000 + index,) * 2)
        paths.append(path)
    return paths


@pytest.mark.parametrize('cap', [0, 1, 2, 4, 5])
def test_count_limits_keep_newest_entries(tmp_path, cap):
    paths = entries(tmp_path)
    evict_oldest_files(paths, cap)
    assert [p.exists() for p in paths] == [i >= max(4 - cap, 0) for i in range(4)]


@pytest.mark.parametrize('cap', [-1, True, 1.5, '2', None, float('nan'), float('inf')],
                         ids=['negative', 'bool', 'fraction', 'text', 'none', 'nan', 'infinite'])
def test_invalid_limit_refuses_before_listing(cap):
    def listing():
        pytest.fail('invalid policy must not inspect files')
        yield
    with pytest.raises(ValueError):
        evict_oldest_files(listing(), cap)


@pytest.mark.parametrize('kind', ['directory', 'fifo'])
def test_other_nodes_never_consume_file_quota(tmp_path, kind):
    paths = entries(tmp_path, 2)
    other = tmp_path / 'other.json'
    if kind == 'directory':
        other.mkdir()
    else:
        os.mkfifo(other)
    evict_oldest_files([other, *paths], 2)
    assert all(p.exists() for p in paths) and other.exists()


@pytest.mark.parametrize('change', ['refresh', 'rewrite', 'replace', 'symlink', 'directory', 'fifo'])
@pytest.mark.parametrize('cap', [1, 2])
def test_changes_between_listing_and_removal_are_retained(tmp_path, change, cap):
    paths = entries(tmp_path)
    target = paths[0]
    before = target.stat()
    preserved = tmp_path / 'preserved'
    class ChangingPath(type(target)):
        calls = 0
        def lstat(self):
            type(self).calls += 1
            if type(self).calls == 2:
                if change == 'refresh':
                    os.utime(target, (9000, 9000))
                elif change == 'rewrite':
                    target.write_bytes(b'latest')
                    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
                else:
                    target.rename(preserved)
                    if change == 'replace':
                        target.write_bytes(b'latest')
                        os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
                    elif change == 'symlink':
                        target.symlink_to(preserved)
                    elif change == 'directory':
                        target.mkdir()
                    else:
                        os.mkfifo(target)
            return super().lstat()
    evict_oldest_files([ChangingPath(target), *paths[1:]], cap)
    assert target.exists()
    consumes_slot = change not in ('directory', 'fifo')
    expected_survivors = cap - int(consumes_slot)
    assert sum(path.exists() for path in paths[1:]) == expected_survivors
    if change in ('rewrite', 'replace'):
        assert target.read_bytes() == b'latest'
    if change == 'symlink':
        assert target.is_symlink() and preserved.read_bytes() == b'cached'


@pytest.mark.parametrize('replacement', ['file', 'dangling-link', 'directory'])
def test_post_unlink_replacements_are_counted_by_their_actual_type(tmp_path, replacement):
    paths = entries(tmp_path)
    target = paths[0]
    class ReplacingPath(type(target)):
        def unlink(self):
            super().unlink()
            if replacement == 'file':
                target.write_bytes(b'new')
            elif replacement == 'directory':
                target.mkdir()
            else:
                target.symlink_to('missing')
    evict_oldest_files([ReplacingPath(target), *paths[1:]], 2)
    assert target.exists() or target.is_symlink()
    assert sum(p.exists() for p in paths[1:]) == (2 if replacement == 'directory' else 1)


@pytest.mark.parametrize('stage', ['revalidate', 'unlink', 'confirm'])
def test_per_entry_io_error_does_not_stop_later_candidates(tmp_path, stage):
    paths = entries(tmp_path)
    target = paths[0]
    class FailingPath(type(target)):
        calls = 0
        def lstat(self):
            type(self).calls += 1
            if (stage == 'revalidate' and self.calls == 2
                    or stage == 'confirm' and self.calls == 3):
                raise PermissionError('fixture inspection refused')
            return super().lstat()
        def unlink(self):
            if stage == 'unlink':
                raise OSError(errno.EBUSY, 'fixture removal refused')
            return super().unlink()
    evict_oldest_files([FailingPath(target), *paths[1:]], 2)
    assert not paths[1].exists() and not paths[2].exists() and paths[3].exists()
    assert target.exists() == (stage != 'confirm')


def test_duplicate_paths_are_not_double_counted(tmp_path):
    paths = entries(tmp_path, 2)
    evict_oldest_files([paths[0], paths[0], paths[1]], 2)
    assert all(p.exists() for p in paths)


def test_incomplete_listing_permits_no_deletion(tmp_path):
    paths = entries(tmp_path)
    def listing():
        yield paths[0]
        raise PermissionError('listing interrupted')
    evict_oldest_files(listing(), 0)
    assert all(p.exists() for p in paths)


@pytest.mark.parametrize('failure', [KeyboardInterrupt, SystemExit])
def test_cancellation_is_not_swallowed(tmp_path, failure):
    path = entries(tmp_path, 1)[0]
    class InterruptedPath(type(path)):
        def unlink(self):
            raise failure('stop cleanup')
    with pytest.raises(failure, match='stop cleanup'):
        evict_oldest_files([InterruptedPath(path)], 0)
    assert path.exists()
