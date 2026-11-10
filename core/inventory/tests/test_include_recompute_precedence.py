"""Legacy edge recomputation retains read cancellation and source controls."""

from pathlib import Path

import pytest

from core.hash import sha256_bytes
from core.inventory import include_graph


def _case(tmp_path, monkeypatch, primary=None, close_fails=True):
    source = tmp_path / 'owned.php'
    raw = b'<?php\nfunction fixture_entry() { return 1; }\n'
    source.write_bytes(raw)
    record = {'path': source.name, 'language': 'php', 'sha256': sha256_bytes(raw),
              'items': [], 'call_graph': {}}
    inventory = {'files': [record], 'target_path': str(tmp_path)}
    native_open = open
    streams = []

    class Reader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()
            if close_fails:
                raise OSError('secondary close failure')

        def read(self, size):
            if primary is not None:
                raise primary
            return self.stream.read(size)

    def open_reader(path, *args, **kwargs):
        assert Path(path) == source
        stream = native_open(path, *args, **kwargs)
        streams.append(stream)
        return Reader(stream)

    # The consumer gets a local opener; builtins and pathlib stay native.
    monkeypatch.setattr(include_graph, 'open', open_reader, raising=False)
    return source, inventory, streams


@pytest.mark.parametrize('failure', [KeyboardInterrupt, SystemExit])
def test_recompute_cancellation_survives_close_error(tmp_path, monkeypatch, failure):
    primary = failure('cancelled read')
    _, inventory, streams = _case(tmp_path, monkeypatch, primary)
    try:
        with pytest.raises(failure) as caught:
            include_graph.build_include_graph(inventory, target_root=tmp_path)
        assert caught.value is primary
    finally:
        assert len(streams) == 1 and streams[0].closed


@pytest.mark.parametrize('read_fails', [False, True])
def test_read_or_close_io_error_keeps_unavailable_census(tmp_path, monkeypatch, read_fails):
    primary = OSError('read unavailable') if read_fails else None
    _, inventory, streams = _case(tmp_path, monkeypatch, primary)
    graph = include_graph.build_include_graph(inventory, target_root=tmp_path)
    assert graph['tier'] == 'hint'
    assert graph['php_files_without_edges'] == 1
    assert graph.get('recomputed_files', 0) == 0
    assert len(streams) == 1 and streams[0].closed


def test_matching_native_source_recomputes_missing_edges(tmp_path, monkeypatch):
    _, inventory, streams = _case(tmp_path, monkeypatch, close_fails=False)
    graph = include_graph.build_include_graph(inventory, target_root=tmp_path)
    assert graph['tier'] == 'hint'
    assert graph['recomputed_files'] == 1
    assert graph.get('php_files_without_edges', 0) == 0
    assert len(streams) == 1 and streams[0].closed


def test_source_drift_keeps_edges_unavailable(tmp_path, monkeypatch):
    source, inventory, streams = _case(tmp_path, monkeypatch, close_fails=False)
    source.write_text('<?php\n$x = 2;\n')
    graph = include_graph.build_include_graph(inventory, target_root=tmp_path)
    assert graph['php_files_without_edges'] == 1
    assert graph.get('recomputed_files', 0) == 0
    assert len(streams) == 1 and streams[0].closed


@pytest.mark.parametrize('mode', ['complete', 'disabled'])
def test_source_is_not_reopened_when_recomputation_is_unneeded(tmp_path, monkeypatch, mode):
    _, inventory, streams = _case(tmp_path, monkeypatch)
    if mode == 'complete':
        inventory['files'][0]['call_graph']['includes'] = []
    graph = include_graph.build_include_graph(
        inventory, target_root=tmp_path, recompute_missing=mode != 'disabled',
    )
    assert graph['tier'] == 'hint'
    assert graph.get('recomputed_files', 0) == 0
    assert streams == []
