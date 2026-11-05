"""Strict correlation indexes paths without changing lexical match rules."""
import pytest

from core.sandbox import observe_context_merge as merge
from core.sandbox.observe_profile import ObserveProfile


@pytest.mark.parametrize('root', ['/repo', '/repo/', '/', 'relative'])
def test_index_matches_reference_predicate(root):
    paths = ['/repo/src/file', '/repo-other/src/file', '/outside/file',
             'src/file', '/src/file', '/repo//src/file', None]
    rows = [{'file': path} for path in ['', 'src/file', '/src/file', '/repo/src/file',
                                      '/outside/file', 'file', '//src/file', None, []]]
    rows += [{'location': 'src/file'}]
    matcher = merge._path_matcher(paths, root)
    for row in rows:
        assert matcher(row) == any(merge._matches_path(path, row, root) for path in paths)


@pytest.mark.parametrize('kind', ['entry', 'sink'])
def test_strict_path_scan_is_linear(kind):
    class CountedPath(str):
        scans = 0

        def startswith(self, *args):
            type(self).scans += 1
            return super().startswith(*args)

    paths = [CountedPath(f'/repo/file-{i}') for i in range(1000)]
    rows = [{'id': i + 1, 'file': f'file-{i}'} for i in range(500)]
    profile = ObserveProfile(paths_read=paths, paths_written=paths)
    correlate = merge._correlate_entry_points if kind == 'entry' else merge._correlate_sinks
    assert correlate(profile, rows, '/repo') == list(range(1, 501))
    assert CountedPath.scans == len(paths)


def test_index_is_rebuilt_after_profile_edits():
    profile = ObserveProfile(paths_read=['/repo/first'])
    rows = [{'id': 'first', 'file': 'first'}, {'id': 'second', 'file': 'second'}]
    assert merge._correlate_entry_points(profile, rows, '/repo') == ['first']
    profile.paths_read[:] = ['/repo/second']
    assert merge._correlate_entry_points(profile, rows, '/repo') == ['second']
