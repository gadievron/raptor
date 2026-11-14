"""Direct snippet-reader cleanup precedence with an owned native stream."""
import errno
import io
import os

import pytest

from core.sarif import import_normalizer as mod


@pytest.fixture
def owned_reader(tmp_path, monkeypatch):
    source = tmp_path / "marker.c"
    content = b"owned first line\nowned second line\n"
    source.write_bytes(content)
    state = {"primary": None, "cleanup": None, "closes": 0, "reads": []}

    class Reader(io.BufferedReader):
        def read(self, size=-1):
            state["reads"].append(size)
            data = super().read(size)
            if state["primary"] is not None:
                raise state["primary"]
            return data

        def close(self):
            if self.closed:
                return
            state["closes"] += 1
            super().close()
            if state["cleanup"] is not None:
                raise state["cleanup"]

    def open_owned(root, relative, mode):
        assert root == tmp_path.resolve()
        assert relative == source.relative_to(tmp_path)
        assert mode == "rb"
        stream = Reader(io.FileIO(source, "rb"))
        state["stream"] = stream
        state["fd"] = stream.fileno()
        return stream

    def forbidden(*args, **kwargs):
        pytest.fail("full import or source resolution is outside this direct-reader test")

    monkeypatch.setattr(mod, "open_regular_beneath", open_owned)
    for name in ("normalize_imported_findings", "_resolve_uri", "_build_file_index", "_infer_cwe"):
        monkeypatch.setattr(mod, name, forbidden)
    yield tmp_path, state
    if "stream" in state:
        assert state["stream"].closed
        assert state["closes"] == 1
        with pytest.raises(OSError) as exc:
            os.fstat(state["fd"])
        assert exc.value.errno == errno.EBADF
    assert source.read_bytes() == content


@pytest.mark.parametrize("primary_type", [KeyboardInterrupt, SystemExit], ids=["interrupt", "exit"])
@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt, SystemExit], ids=["oserror", "interrupt", "exit"])
def test_active_cancellation_keeps_identity(owned_reader, primary_type, cleanup_type):
    root, state = owned_reader
    primary = state["primary"] = primary_type("owned primary")
    state["cleanup"] = cleanup_type("owned cleanup")
    with pytest.raises(primary_type) as exc:
        mod._read_snippet_lines(root, "marker.c")
    assert exc.value is primary
    assert state["reads"] == [mod._SNIPPET_SOURCE_MAX_BYTES + 1]


@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt], ids=["oserror", "interrupt"])
def test_active_oserror_keeps_unavailable_fallback(owned_reader, cleanup_type):
    root, state = owned_reader
    state["primary"] = OSError("owned read failure")
    state["cleanup"] = cleanup_type("owned cleanup")
    assert mod._read_snippet_lines(root, "marker.c") is None


def test_fresh_cleanup_oserror_keeps_unavailable_fallback(owned_reader):
    root, state = owned_reader
    state["cleanup"] = OSError("owned close failure")
    assert mod._read_snippet_lines(root, "marker.c") is None


def test_fresh_cleanup_cancellation_propagates(owned_reader):
    root, state = owned_reader
    primary = state["cleanup"] = KeyboardInterrupt("owned close cancellation")
    with pytest.raises(KeyboardInterrupt) as exc:
        mod._read_snippet_lines(root, "marker.c")
    assert exc.value is primary


def test_healthy_owned_reader_keeps_lines(owned_reader):
    root, state = owned_reader
    assert mod._read_snippet_lines(root, "marker.c") == ["owned first line", "owned second line"]
    assert state["reads"] == [mod._SNIPPET_SOURCE_MAX_BYTES + 1]
