"""Owned CSV reads preserve operation errors across actual stream retirement."""
import errno
import io
import os

import pytest

from core.audit.corpus import corpus_metrics as metrics


@pytest.fixture
def owned_csv(tmp_path, monkeypatch):
    source = tmp_path / "owned.csv"
    payload = "marker,note\nowned,reader-only\n"
    source.write_text(payload, encoding="utf-8")
    state = {"primary": None, "cleanup": None, "reads": [], "streams": [],
             "fds": [], "closes": 0}

    class Reader(io.TextIOWrapper):
        def __next__(self):
            line = super().__next__()
            state["reads"].append(line)
            if len(state["reads"]) == 2 and state["primary"] is not None:
                raise state["primary"]
            return line

        def close(self):
            if self.closed:
                return
            super().close()
            state["closes"] += 1
            if state["cleanup"] is not None:
                raise state["cleanup"]

    class OwnedPath(type(source)):
        def open(self, *args, **kwargs):
            assert self == source and not args
            assert kwargs == {}
            stream = Reader(source.open("rb"))
            state["streams"].append(stream)
            state["fds"].append(stream.fileno())
            return stream

    def forbidden(*args, **kwargs):
        raise AssertionError("reader-only qualification")

    monkeypatch.setattr(metrics, "Path", OwnedPath)
    for name in ("compute_metrics", "compute_attribution", "_enrich_from_labels", "load_json"):
        monkeypatch.setattr(metrics, name, forbidden)
    yield OwnedPath(source), state
    assert state["reads"] == payload.splitlines(keepends=True)
    assert state["closes"] == len(state["streams"]) == 1
    assert all(stream.closed for stream in state["streams"])
    for fd in state["fds"]:
        with pytest.raises(OSError) as caught:
            os.fstat(fd)
        assert caught.value.errno == errno.EBADF
    assert source.read_text(encoding="utf-8") == payload


@pytest.mark.parametrize("primary_type", [ValueError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt, SystemExit])
def test_active_read_error_keeps_identity(owned_csv, primary_type, cleanup_type):
    source, state = owned_csv
    primary = state["primary"] = primary_type("owned read failure")
    state["cleanup"] = cleanup_type("owned cleanup failure")
    with pytest.raises(primary_type) as caught:
        metrics._read_results(source)
    assert caught.value is primary


@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_close_error_keeps_identity(owned_csv, cleanup_type):
    source, state = owned_csv
    cleanup = state["cleanup"] = cleanup_type("owned cleanup failure")
    with pytest.raises(cleanup_type) as caught:
        metrics._read_results(source)
    assert caught.value is cleanup


def test_healthy_read_preserves_marker_row(owned_csv):
    source, _ = owned_csv
    result = metrics._read_results(source)
    assert result == [{"marker": "owned", "note": "reader-only"}]
