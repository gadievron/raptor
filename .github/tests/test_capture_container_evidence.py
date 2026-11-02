"""Offline evidence CLI stays usable in the pytest-only CI tier."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('capture_container_evidence', ROOT / '.github/scripts/capture_container_evidence.py')
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def test_cli_import_and_help_without_http_dependencies():
    with pytest.raises(SystemExit) as error:
        mod.main(['--help'])
    assert error.value.code == 0


def test_offline_layout_refuses_symlink(tmp_path):
    from core.oci.manifest import LayerDescriptor
    layer = LayerDescriptor('sha256:' + 'a' * 64, 5, 'application/vnd.oci.image.layer.v1.tar')
    blobs = tmp_path / 'blobs'
    blobs.mkdir()
    store = tmp_path / 'store'
    store.mkdir()
    (store / ('a' * 64)).write_bytes(b'hello')
    (blobs / 'sha256').symlink_to(store, target_is_directory=True)
    with pytest.raises(OSError):
        list(mod.layout_reader(tmp_path)(layer))


def test_offline_layout_reads_regular_blob(tmp_path):
    from core.oci.manifest import LayerDescriptor
    layer = LayerDescriptor('sha256:' + 'a' * 64, 5, 'application/vnd.oci.image.layer.v1.tar')
    store = tmp_path / 'blobs' / 'sha256'
    store.mkdir(parents=True)
    (store / ('a' * 64)).write_bytes(b'hello')
    assert b''.join(mod.layout_reader(tmp_path)(layer)) == b'hello'


def test_existing_output_refused_before_processing(tmp_path):
    with pytest.raises(SystemExit):
        mod.main(['--syft', str(tmp_path / 'absent'), '--oci-layout', str(tmp_path), '--out', str(tmp_path)])


def test_offline_layout_refuses_fifo_without_blocking(tmp_path):
    import os
    from core.oci.manifest import LayerDescriptor
    layer = LayerDescriptor('sha256:' + 'a' * 64, 5, 'application/vnd.oci.image.layer.v1.tar')
    store = tmp_path / 'blobs' / 'sha256'
    store.mkdir(parents=True)
    os.mkfifo(store / ('a' * 64))
    with pytest.raises(ValueError, match='regular'):
        list(mod.layout_reader(tmp_path)(layer))
