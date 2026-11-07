"""Portable archives stream regular files within import-compatible limits."""
import calendar
import json
import os
from pathlib import Path
import sys
import zipfile

import pytest
from core.testing.standalone_cli import run_standalone_cli
from core.project import export as archives
from core.source.gated import open_regular_gated


@pytest.fixture
def source(tmp_path):
    root = tmp_path / 'demo'
    root.mkdir()
    (root / 'data').write_bytes(b'content')
    return root


@pytest.mark.parametrize('kind', ['fifo', 'symlink', 'dangling-link'])
def test_special_nodes_are_skipped_without_blocking(source, tmp_path, kind):
    node = source / 'special'
    outside = tmp_path / 'borrowed'
    outside.write_bytes(b'operator data')
    if kind == 'fifo':
        os.mkfifo(node)
    else:
        node.symlink_to(outside if kind == 'symlink' else tmp_path / 'absent')
    destination = tmp_path / 'export.zip'
    script = '''
import sys
from pathlib import Path
from core.project.export import export_project
export_project(Path(sys.argv[1]), Path(sys.argv[2]))
'''
    result = run_standalone_cli([sys.executable, '-c', script, str(source), str(destination)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    with zipfile.ZipFile(destination) as output:
        assert output.namelist() == ['demo/data']
    assert outside.read_bytes() == b'operator data'


@pytest.mark.parametrize('year', [1970, 1979, 1980, 2000, 2107, 2108, 2200])
def test_timestamps_outside_zip_range_are_clamped_without_changing_source(source, tmp_path, year):
    path = source / 'data'
    stamp = calendar.timegm((year, 7, 1, 12, 0, 0))
    os.utime(path, (stamp, stamp))
    before = path.stat().st_mtime_ns
    destination = tmp_path / 'dated.zip'
    archives.export_project(source, destination)
    with zipfile.ZipFile(destination) as output:
        assert output.getinfo('demo/data').date_time[0] == min(max(year, 1980), 2107)
        assert output.read('demo/data') == b'content'
    assert path.stat().st_mtime_ns == before


@pytest.mark.parametrize('force', [False, True])
@pytest.mark.parametrize('budget', ['bytes', 'entries', 'metadata'])
def test_failed_budget_checks_never_publish_partial_or_truncate_previous_archive(source, tmp_path, monkeypatch, force, budget):
    destination = tmp_path / 'limited.zip'
    if force:
        destination.write_bytes(b'previous archive')
    metadata = tmp_path / 'metadata.json'
    metadata.write_text('{"name":"demo"}')
    if budget == 'bytes':
        monkeypatch.setattr(archives, '_MAX_PROJECT_ARCHIVE_BYTES', 2)
    elif budget == 'entries':
        monkeypatch.setattr(archives, '_MAX_ENTRIES', 1)
    else:
        monkeypatch.setattr(archives, '_MAX_PROJECT_META_BYTES', 2)
    with pytest.raises(ValueError, match='limit'):
        archives.export_project(source, destination, project_json_path=metadata, force=force)
    assert destination.read_bytes() == b'previous archive' if force else not destination.exists()
    assert not list(tmp_path.glob('.export-*'))


@pytest.mark.parametrize('metadata_growth', [False, True], ids=['payload-growth', 'metadata-growth'])
def test_growth_after_fstat_is_bounded_before_writing_excess(source, tmp_path, monkeypatch, metadata_growth):
    destination = tmp_path / 'previous.zip'
    destination.write_bytes(b'previous archive')
    metadata = tmp_path / 'metadata.json'
    metadata.write_text('{}')
    growing = metadata if metadata_growth else source / 'data'
    monkeypatch.setattr(archives, '_MAX_PROJECT_ARCHIVE_BYTES', 1000 if metadata_growth else 10)
    monkeypatch.setattr(archives, '_MAX_PROJECT_META_BYTES', 8)
    def opened(path, **kwargs):
        real = open_regular_gated(path, **kwargs)
        class Growing:
            changed = False
            def __enter__(self):
                return self
            def __exit__(self, *exc):
                return real.__exit__(*exc)
            def fileno(self):
                return real.fileno()
            def read(self, size):
                if path == growing and not self.changed:
                    with growing.open('ab') as writer:
                        writer.write(b' ' * 20)
                    self.changed = True
                return real.read(size)
        return Growing()
    monkeypatch.setattr(archives, 'open_regular_gated', opened)
    with pytest.raises(ValueError, match='byte limit'):
        archives.export_project(source, destination, project_json_path=metadata, force=True)
    assert destination.read_bytes() == b'previous archive'
    assert not list(tmp_path.glob('.export-*'))


def test_explicit_metadata_replaces_root_copy_without_duplicate_members(source, tmp_path):
    (source / '.project.json').write_text('{"name":"outdated"}')
    metadata = tmp_path / 'registry.json'
    metadata.write_text('{"name":"demo"}')
    destination = tmp_path / 'export.zip'
    archives.export_project(source, destination, project_json_path=metadata)
    with zipfile.ZipFile(destination) as output:
        assert output.namelist().count('demo/.project.json') == 1
        assert json.loads(output.read('demo/.project.json'))['name'] == 'demo'
    archives.import_project(destination, tmp_path / 'registry', output_base=tmp_path / 'restored')


@pytest.mark.parametrize('common_root', [False, True], ids=['flat', 'rooted'])
def test_nested_project_metadata_is_ordinary_data_on_import(tmp_path, common_root):
    path = tmp_path / 'input.zip'
    prefix = 'demo/' if common_root else ''
    with zipfile.ZipFile(path, 'w') as output:
        output.writestr(prefix + '.project.json', '{"name":"demo"}')
        output.writestr(prefix + 'nested/.project.json', '{"nested":true}')
    result = archives.import_project(path, tmp_path / 'registry', output_base=tmp_path / 'restored')
    assert (Path(result['output_dir']) / 'nested/.project.json').read_text() == '{"nested":true}'


@pytest.mark.parametrize('force', [False, True])
def test_failed_subtree_walk_never_publishes_an_incomplete_archive(source, tmp_path, monkeypatch, force):
    from core.testing.module_bindings import patch_module_attribute
    original = archives.os.walk
    destination = tmp_path / 'walk.zip'
    if force:
        destination.write_bytes(b'previous archive')
    def walk(*args, **kwargs):
        iterator = original(*args, **kwargs)
        try:
            yield next(iterator)
            kwargs['onerror'](PermissionError('subtree unavailable'))
        finally:
            iterator.close()
    patch_module_attribute(monkeypatch, archives, 'os', 'walk', walk)
    with pytest.raises(PermissionError, match='subtree unavailable'):
        archives.export_project(source, destination, force=force)
    if force:
        assert destination.read_bytes() == b'previous archive'
    else:
        assert not destination.exists()
    assert not list(tmp_path.glob('.export-*'))
