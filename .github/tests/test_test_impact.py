"""Tests for .github/scripts/test_impact.py — cached graphs and timing inputs."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

with patch.object(sys, "path", [str(Path(__file__).resolve().parents[1] / "scripts"), *sys.path]):
    import test_impact


class TestCachePath:
    def test_cache_lives_in_per_uid_private_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(test_impact, "tempfile", SimpleNamespace(gettempdir=lambda: str(tmp_path)))
        p = test_impact._cache_path(Path("/some/repo"))
        assert p is not None
        d = p.parent
        assert d.name == f"raptor-test-impact-{os.getuid()}"
        assert stat.S_IMODE(d.stat().st_mode) == 0o700
        assert d.stat().st_uid == os.getuid()

    def test_same_repo_same_path(self, tmp_path, monkeypatch):
        monkeypatch.setattr(test_impact, "tempfile", SimpleNamespace(gettempdir=lambda: str(tmp_path)))
        a = test_impact._cache_path(Path("/some/repo"))
        b = test_impact._cache_path(Path("/some/repo"))
        c = test_impact._cache_path(Path("/other/repo"))
        assert a == b
        assert a != c

    def test_symlinked_dir_disables_cache(self, tmp_path, monkeypatch):
        # A pre-positioned symlink where the cache dir should be is a
        # squat — run uncached rather than follow it.
        monkeypatch.setattr(test_impact, "tempfile", SimpleNamespace(gettempdir=lambda: str(tmp_path)))
        target = tmp_path / "elsewhere"
        target.mkdir()
        (tmp_path / f"raptor-test-impact-{os.getuid()}").symlink_to(target)
        assert test_impact._cache_path(Path("/some/repo")) is None


def test_graph_cache_detects_same_mtime_content_changes(tmp_path):
    source = tmp_path / 'owned.py'
    source.write_text('import before\n')
    stamp = source.stat()
    before = test_impact._files_fingerprint([Path('owned.py')], tmp_path)
    source.write_text('import after_\n')
    os.utime(source, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    assert source.stat().st_mtime_ns == stamp.st_mtime_ns
    assert test_impact._files_fingerprint([Path('owned.py')], tmp_path) != before


def test_graph_builder_changes_invalidate_unmodified_sources(tmp_path):
    source = tmp_path / 'owned.py'
    source.write_text('import owned\n')
    rules = tmp_path / '.github/scripts/codeql_scope.py'
    rules.parent.mkdir(parents=True)
    rules.write_text('BEFORE = 1\n')
    before = test_impact._files_fingerprint([Path('owned.py')], tmp_path)
    rules.write_text('AFTER_ = 1\n')
    assert test_impact._files_fingerprint([Path('owned.py')], tmp_path) != before


@pytest.mark.skipif(sys.platform != 'linux', reason='exercise POSIX undecodable path bytes')
def test_graph_fingerprint_accepts_non_utf8_filenames(tmp_path):
    name = Path(os.fsdecode(b'owned-\xff.py'))
    (tmp_path / name).write_text('import owned\n')
    assert test_impact._files_fingerprint([name], tmp_path)


@pytest.mark.parametrize("diff_spec", [None, "HEAD"])
def test_diff_preserves_changed_filename_bytes(tmp_path, monkeypatch, diff_spec):
    from core.testing.gitrepo import git_run, init_scratch_repo

    repo = init_scratch_repo(tmp_path)
    names = ["space name.py", "café.py", "line\nname.py", "tab\tname.py",
             'quote"name.py', "trailing-space "]
    if os.name == "posix":
        names.append(os.fsdecode(b"raw-\xff.py"))
    for name in names:
        (repo / name).write_text("before = 1\n")
    git_run(repo, "add", "-A")
    git_run(repo, "commit", "-qm", "base")
    for name in names:
        (repo / name).write_text("after = 2\n")
    # Include staged and unstaged edits in the same diff.
    git_run(repo, "add", "--", names[0])
    monkeypatch.chdir(repo)
    for quote_path in ("true", "false"):
        git_run(repo, "config", "core.quotePath", quote_path)
        actual = test_impact.get_changed_files_from_diff(diff_spec)
        assert set(actual) == set(names)
        assert len(actual) == len(names)


def test_diff_failure_remains_fatal(tmp_path, monkeypatch, capsys):
    from core.testing.gitrepo import init_scratch_repo

    monkeypatch.chdir(init_scratch_repo(tmp_path))
    with pytest.raises(SystemExit) as exc:
        test_impact.get_changed_files_from_diff("missing-revision")
    assert exc.value.code == 1
    error = capsys.readouterr().err
    assert "git diff failed:" in error
    assert "missing-revision" in error
    assert "b'" not in error


@pytest.mark.parametrize('mode', [0o755, 0o770, 0o777], ids=['world-readable', 'group-writable', 'world-writable'])
def test_existing_nonprivate_cache_directory_disables_cache(tmp_path, monkeypatch, mode):
    monkeypatch.setattr(test_impact, 'tempfile', SimpleNamespace(gettempdir=lambda: str(tmp_path)))
    directory = tmp_path / f'raptor-test-impact-{os.getuid()}'
    directory.mkdir()
    directory.chmod(mode)
    assert test_impact._cache_path(Path('/owned/repo')) is None


def _graph_payload():
    return dict(version=1, fingerprint='current', parse_failures=0,
                reverse_graph={'core/helper.py': ['core/tests/test_helper.py']})


@pytest.mark.parametrize('payload', [None, [], 'cache', 1], ids=['null', 'array', 'string', 'number'])
def test_nonobject_graph_cache_is_a_miss(tmp_path, payload):
    cache = tmp_path / 'graph.json'
    cache.write_text(json.dumps(payload))
    assert test_impact._load_cached_graph(cache, 'current') is None


@pytest.mark.parametrize('field,value', [
    ('reverse_graph', None),
    ('reverse_graph', {'core/helper.py': 'core/tests/test_helper.py'}),
    ('reverse_graph', {'core/helper.py': [1]}),
    ('reverse_graph', {'../helper.py': []}),
    ('reverse_graph', {'core/helper.py': ['/outside.py']}),
    ('reverse_graph', {'core/helper.py': ['core/../outside.py']}),
    ('reverse_graph', {'core/helper.py': ['core/bad\0.py']}),
    ('reverse_graph', {'core/helper.py': ['core//test.py']}),
    ('version', True), ('version', 1.0), ('version', 2),
    ('parse_failures', None), ('parse_failures', -1), ('parse_failures', True),
    ('fingerprint', 'stale'),
], ids=['missing-graph', 'string-edges', 'nonpath-edge', 'parent-source',
        'absolute-edge', 'parent-edge', 'nul-edge', 'noncanonical-edge',
        'boolean-version', 'float-version', 'old-version', 'missing-failures',
        'negative-failures', 'boolean-failures', 'stale-fingerprint'])
def test_malformed_graph_cache_is_a_miss(tmp_path, field, value):
    payload = _graph_payload()
    payload[field] = value
    cache = tmp_path / 'graph.json'
    cache.write_text(json.dumps(payload))
    assert test_impact._load_cached_graph(cache, 'current') is None


@pytest.mark.parametrize('field', ['reverse_graph', 'parse_failures'])
def test_incomplete_graph_cache_is_a_miss(tmp_path, field):
    payload = _graph_payload()
    del payload[field]
    cache = tmp_path / 'graph.json'
    cache.write_text(json.dumps(payload))
    assert test_impact._load_cached_graph(cache, 'current') is None


@pytest.mark.parametrize('raw', [b'\xff', b'{"version":'], ids=['invalid-utf8', 'truncated-json'])
def test_unreadable_graph_cache_is_a_miss(tmp_path, raw):
    cache = tmp_path / 'graph.json'
    cache.write_bytes(raw)
    assert test_impact._load_cached_graph(cache, 'current') is None


def test_valid_graph_cache_roundtrips_empty_and_unusual_paths(tmp_path):
    cache = tmp_path / 'graph.json'
    for graph in ({}, {Path('core/café.py'): {Path('core/line\nname.py')}}):
        test_impact._save_graph_cache(cache, 'current', graph, 2)
        assert test_impact._load_cached_graph(cache, 'current') == (graph, 2)


def test_malformed_cache_rebuilds_and_preserves_affected_tests(tmp_path, monkeypatch, capsys):
    helper = tmp_path / 'core/pkg/helper.py'
    helper.parent.mkdir(parents=True)
    helper.write_text('VALUE = 1\n')
    test = tmp_path / 'core/pkg/tests/test_helper.py'
    test.parent.mkdir()
    test.write_text('from core.pkg import helper\ndef test_value():\n    assert helper.VALUE == 1\n')
    files = test_impact.discover_py_files(tmp_path, extra_roots=test_impact._EXTRA_ROOTS)
    payload = _graph_payload()
    payload.update(fingerprint=test_impact._files_fingerprint(files, tmp_path), reverse_graph=[])
    cache = tmp_path / 'graph.json'
    cache.write_text(json.dumps(payload))
    monkeypatch.setattr(test_impact, '_cache_path', lambda repo: cache)
    monkeypatch.setattr(sys, 'argv', ['test_impact.py', '--repo', str(tmp_path), '--json', 'core/pkg/helper.py'])
    for status in ['miss', 'hit']:
        assert test_impact.main() == 0
        result = json.loads(capsys.readouterr().out)
        assert result['graph_cache'] == status
        assert result['affected_tests'] == ['core/pkg/tests/test_helper.py']


def test_duration_estimates_ignore_invalid_values(tmp_path):
    payload = {'core/test_a.py::one': 1.25, 'core/test_a.py::two': 2,
               'core/test_b.py::zero': 0, '::missing-file': 1,
               'bad.py::nan': float('nan'), 'bad.py::infinity': float('inf'),
               'bad.py::negative': -2, 'bad.py::bool': True,
               'bad.py::huge-int': 10 ** 400, 'bad.py::string': '2'}
    (tmp_path / '.test_durations').write_text(json.dumps(payload))
    assert test_impact._load_test_durations(tmp_path) == {'core/test_a.py': 3.25, 'core/test_b.py': 0.0}


@pytest.mark.parametrize('second', ['a.py::two', 'b.py::one'], ids=['within-file', 'across-files'])
def test_overflowing_duration_total_disables_estimates(tmp_path, second):
    (tmp_path / '.test_durations').write_text(json.dumps({'a.py::one': 1e308, second: 1e308}))
    assert test_impact._load_test_durations(tmp_path) is None


def test_invalid_utf8_duration_data_disables_estimates(tmp_path):
    (tmp_path / '.test_durations').write_bytes(b'\xff')
    assert test_impact._load_test_durations(tmp_path) is None
