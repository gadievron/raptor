"""Whole-content fingerprint equivalence with bounded owned-file reads."""

import hashlib
from types import ModuleType

import pytest

from core.audit import codeql_backend as backend
from core.audit.prep_cache import content_fingerprint
from core.testing.module_views import scoped_function_imports


@pytest.mark.parametrize("size", [0, 1, 65_536, 65_537, 262_144])
def test_sink_fingerprint_reads_bounded_chunks_without_key_change(tmp_path, monkeypatch, size):
    path = tmp_path / "owned.c"
    content = b"x" * size
    path.write_bytes(content)
    reads = []
    opened = []
    real_open = backend.open_regular

    class Observed:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def read(self, size=-1):
            data = self.stream.read(size)
            reads.append((size, len(data)))
            return data

    def observe(*args, **kwargs):
        stream = real_open(*args, **kwargs)
        assert stream is not None
        opened.append(stream)
        return Observed(stream)

    supplied = ModuleType("core.inventory.sink_discovery")
    supplied._PER_FILE_CAP = 2_000_000
    supplied._AGGREGATE_CAP = 2 * 1024 * 1024 * 1024
    supplied.iter_discovery_source_files = lambda root, **kwargs: iter([(path, path.name, "c")])
    monkeypatch.setattr(backend, "open_regular", observe)
    with scoped_function_imports(backend, ("_sink_discovery_fingerprint",),
                                {"core.inventory.sink_discovery": supplied}):
        result = backend._sink_discovery_fingerprint(tmp_path, None)
    base = content_fingerprint([(path.name, content)])
    policy = f"sink-read-admission-v1:{supplied._PER_FILE_CAP}:{supplied._AGGREGATE_CAP}\0".encode("ascii")
    assert result == hashlib.sha256(policy + bytes.fromhex(base)).hexdigest()
    assert reads and all(request == 65_536 and returned <= 65_536 for request, returned in reads)
    assert sum(returned for _, returned in reads) == len(content)
    assert all(stream.closed for stream in opened)
