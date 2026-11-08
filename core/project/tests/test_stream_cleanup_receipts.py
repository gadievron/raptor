"""Copies and ZIP publication retain primary failures and reclaim staging."""
import zipfile

import pytest

from core.project import export as archives, merge, relocate
from core.project.tests.test_directory_relocation import cross_device
from core.testing.module_bindings import patch_module_attribute
from core.testing.state_isolation import pin_user_state_dirs
from core.testing.stream_faults import FaultingStream

FAILURES = [OSError, KeyboardInterrupt, SystemExit]


@pytest.fixture(autouse=True)
def own_user_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'user')


@pytest.mark.parametrize('operation', ['merge', 'move'])
@pytest.mark.parametrize('phase', ['read', 'write', 'signature'])
@pytest.mark.parametrize('primary_type', FAILURES)
@pytest.mark.parametrize('cleanup_type', FAILURES)
def test_copy_failure_survives_reader_and_writer_cleanup(tmp_path, monkeypatch, operation, phase, primary_type, cleanup_type):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'data.bin').write_bytes(b'original data')
    destination = tmp_path / 'destination'
    primary = primary_type('primary copy failure')
    streams = []
    original_reader = relocate.open_regular_gated
    original_signature = relocate._copy_signature
    original_open = open
    signatures = []
    def reader(*args, **kwargs):
        result = FaultingStream(original_reader(*args, **kwargs),
                                primary=primary if phase == 'read' else None,
                                cleanup=cleanup_type('reader close failure'))
        streams.append(result)
        return result
    def writer(*args, **kwargs):
        result = FaultingStream(original_open(*args, **kwargs),
                                primary=primary if phase == 'write' else None,
                                cleanup=None if phase == 'signature' else cleanup_type('writer close failure'),
                                operation='write')
        streams.append(result)
        return result
    def signature(info):
        signatures.append(True)
        if phase == 'signature' and len(signatures) == 2:
            raise primary
        return original_signature(info)
    monkeypatch.setattr(relocate, 'open_regular_gated', reader)
    monkeypatch.setattr(relocate, 'open', writer, raising=False)
    monkeypatch.setattr(relocate, '_copy_signature', signature)
    if operation == 'move':
        cross_device(monkeypatch)
    with pytest.raises(primary_type) as caught:
        if operation == 'merge':
            merge.merge_runs([source], destination)
        else:
            relocate.move_directory(source, destination)
    # copytree aggregates OSError into shutil.Error, retaining the original
    # error's text. Cancellation must keep the exact exception object.
    assert 'primary copy failure' in str(caught.value)
    if primary_type is not OSError or operation == 'merge':
        assert caught.value is primary
    assert (source / 'data.bin').read_bytes() == b'original data'
    assert not destination.exists()
    assert all(stream.closed and len(stream.exits) == 1 for stream in streams)
    assert not list(tmp_path.glob('.move-*'))
    assert not list(tmp_path.glob('.merge-stage-*'))


@pytest.mark.parametrize('phase', ['read', 'write'])
@pytest.mark.parametrize('primary_type', FAILURES)
@pytest.mark.parametrize('cleanup_type', FAILURES)
def test_export_primary_failure_survives_nested_zip_teardown(tmp_path, monkeypatch, phase, primary_type, cleanup_type):
    source = tmp_path / 'project'
    source.mkdir()
    (source / 'data.bin').write_bytes(b'original data')
    destination = tmp_path / 'previous.zip'
    destination.write_bytes(b'previous archive')
    primary = primary_type('primary export failure')
    streams, containers = [], []
    original_reader = archives.open_regular_gated
    class Zip(zipfile.ZipFile):
        def open(self, *args, **kwargs):
            result = FaultingStream(super().open(*args, **kwargs),
                                    primary=primary if phase == 'write' else None,
                                    cleanup=cleanup_type('member close failure'), operation='write')
            streams.append(result)
            return result
        def close(self):
            armed = self.fp is not None
            super().close()
            if armed:
                containers.append(self)
                raise cleanup_type('container close failure')
    def reader(*args, **kwargs):
        result = FaultingStream(original_reader(*args, **kwargs),
                                primary=primary if phase == 'read' else None,
                                cleanup=cleanup_type('reader close failure'))
        streams.append(result)
        return result
    patch_module_attribute(monkeypatch, archives, 'zipfile', 'ZipFile', Zip)
    monkeypatch.setattr(archives, 'open_regular_gated', reader)
    with pytest.raises(primary_type) as caught:
        archives.export_project(source, destination, force=True)
    assert caught.value is primary
    assert destination.read_bytes() == b'previous archive'
    assert (source / 'data.bin').read_bytes() == b'original data'
    assert streams and all(stream.closed and len(stream.exits) == 1 for stream in streams)
    assert len(containers) == 1 and containers[0].fp is None
    assert not list(tmp_path.glob('.export-*'))


@pytest.mark.parametrize('phase', ['member', 'reader', 'container'])
@pytest.mark.parametrize('cleanup_type', FAILURES)
def test_close_only_failure_refuses_export_publication(tmp_path, monkeypatch, phase, cleanup_type):
    source = tmp_path / 'project'
    source.mkdir()
    (source / 'data.bin').write_bytes(b'original data')
    destination = tmp_path / 'previous.zip'
    destination.write_bytes(b'previous archive')
    cleanup = cleanup_type('primary close failure')
    original_reader = archives.open_regular_gated
    class Zip(zipfile.ZipFile):
        def open(self, *args, **kwargs):
            return FaultingStream(super().open(*args, **kwargs), cleanup=cleanup if phase == 'member' else None)
        def close(self):
            armed = self.fp is not None
            super().close()
            if armed and phase == 'container':
                raise cleanup
    def reader(*args, **kwargs):
        return FaultingStream(original_reader(*args, **kwargs), cleanup=cleanup if phase == 'reader' else None)
    patch_module_attribute(monkeypatch, archives, 'zipfile', 'ZipFile', Zip)
    monkeypatch.setattr(archives, 'open_regular_gated', reader)
    with pytest.raises(cleanup_type) as caught:
        archives.export_project(source, destination, force=True)
    assert caught.value is cleanup
    assert destination.read_bytes() == b'previous archive'
    assert not list(tmp_path.glob('.export-*'))


@pytest.mark.parametrize('primary_type', FAILURES)
@pytest.mark.parametrize('cleanup_type', FAILURES)
def test_import_read_failure_preserves_sources_and_primary(tmp_path, monkeypatch, primary_type, cleanup_type):
    archive = tmp_path / 'input.zip'
    with zipfile.ZipFile(archive, 'w') as output:
        output.writestr('demo/.project.json', '{"version":1,"name":"demo","target":"(imported)"}')
        output.writestr('demo/data.bin', b'original data')
    original = archive.read_bytes()
    primary = primary_type('primary import failure')
    opened = []
    class Zip(zipfile.ZipFile):
        def open(self, name, *args, **kwargs):
            stream = super().open(name, *args, **kwargs)
            filename = name.filename if isinstance(name, zipfile.ZipInfo) else name
            # Metadata and initial archive validation remain real. Inject only
            # when the member payload is extracted into owned staging.
            result = FaultingStream(stream, primary=primary if filename.endswith('data.bin') else None,
                                    cleanup=cleanup_type('member close failure') if filename.endswith('data.bin') else None)
            opened.append(result)
            return result
        def close(self):
            armed = self.fp is not None
            super().close()
            if armed:
                raise cleanup_type('container close failure')
    patch_module_attribute(monkeypatch, archives, 'zipfile', 'ZipFile', Zip)
    with pytest.raises((primary_type, ValueError)) as caught:
        archives.import_project(archive, tmp_path / 'registry', output_base=tmp_path / 'output')
    assert 'primary import failure' in str(caught.value)
    if primary_type is not OSError:
        assert caught.value is primary
    assert archive.read_bytes() == original
    assert not (tmp_path / 'output/demo').exists()
    assert not (tmp_path / 'registry/demo.json').exists()
    assert all(stream.closed and len(stream.exits) == 1 for stream in opened)
    assert not list(tmp_path.rglob('.import-*'))
