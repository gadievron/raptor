"""Owned query-header reader/cache control with no CLI discovery."""
import builtins
import errno
import os

import pytest
from core.audit import codeql_query_resolver as source
from core.testing.module_state import isolated_module_state


@pytest.mark.parametrize("body_kind", ["healthy", "cancel", "io", "unexpected"])
@pytest.mark.parametrize("close_kind", ["healthy", "io", "cancel"])
def test_query_index_reader_precedence(tmp_path, monkeypatch, body_kind, close_kind):
    path = tmp_path / "owned.ql"
    content = "/**\n * @id cpp/owned-query\n */\n"
    path.write_text(content)
    primary = {"healthy": None, "cancel": KeyboardInterrupt("owned header read interruption"),
               "io": OSError("owned read failure"),
               "unexpected": TypeError("owned unexpected read error")}[body_kind]
    cleanup = {"healthy": None, "io": OSError("owned close aftereffect"),
               "cancel": KeyboardInterrupt("owned close cancellation")}[close_kind]
    streams, roots = [], []

    class Observed:
        def __init__(self, stream):
            self.stream = stream
            self.fd = stream.fileno()
            self.closes = 0

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            self.closes += 1
            self.stream.__exit__(*args)
            if cleanup is not None:
                raise cleanup

        def read(self, size):
            assert size == source._HEADER_READ_BYTES
            assert self.stream.read(size) == content
            if primary is not None:
                raise primary
            return content

    def observe(*args, **kwargs):
        stream = builtins.open(*args, **kwargs)
        wrapped = Observed(stream)
        streams.append(wrapped)
        return wrapped

    def owned_roots(pack):
        roots.append(pack)
        return [tmp_path]

    monkeypatch.setattr(source, "_pack_roots", owned_roots)
    monkeypatch.setattr(source, "open", observe, raising=False)
    original_index, original_locks = source._PACK_INDEX_CACHE, source._PACK_LOCKS
    with isolated_module_state(source, {"_PACK_INDEX_CACHE": {}, "_PACK_LOCKS": {}},
                               lock=source._CACHE_LOCK):
        observed = None
        result = None
        try:
            try:
                result = source.resolve_query_id("cpp/owned-query")
            except BaseException as error:
                observed = error
            assert len(roots) == 1 and len(streams) == 1
            assert streams[0].closes == 1 and streams[0].stream.closed
            try:
                os.fstat(streams[0].fd)
            except OSError as error:
                assert error.errno == errno.EBADF
            else:
                raise AssertionError("owned descriptor remained live")
            assert path.read_text() == content
            expected = primary if primary is not None else cleanup
            if isinstance(expected, OSError):
                assert observed is None and result is None
                assert source._PACK_INDEX_CACHE == {roots[0]: {}}
            elif expected is not None:
                assert observed is expected and result is None
                assert source._PACK_INDEX_CACHE == {}
            else:
                assert observed is None and result == str(path)
                assert source._PACK_INDEX_CACHE == {roots[0]: {"cpp/owned-query": str(path)}}
                assert source.resolve_query_id("cpp/owned-query") == result
                assert len(roots) == 1 and len(streams) == 1
        finally:
            for wrapped in streams:
                if not wrapped.stream.closed:
                    wrapped.stream.close()

    assert source._PACK_INDEX_CACHE is original_index
    assert source._PACK_LOCKS is original_locks
