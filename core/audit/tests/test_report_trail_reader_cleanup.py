"""Direct owned trail readers preserve errors through actual file closure."""
import errno
import io
import json
import os

import pytest

from core.audit import report


@pytest.fixture(params=[("_load_vendored_triage", {"skipped": 1, "glanced": 1}, {}),
                        ("_load_toolchain_screen", 1, 0)], ids=["vendored", "toolchain"])
def owned_reader(tmp_path, monkeypatch, request):
    name, expected, fallback = request.param
    source = tmp_path / "suppressions.jsonl"
    rows = [{"rule_id": "audit:vendored-triage", "tier": "skip"},
            {"rule_id": "audit:vendored-triage", "tier": "glance"},
            {"rule_id": "audit:toolchain-screen"}]
    payload = "".join(json.dumps(row) + "\n" for row in rows)
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
            assert self == source and not args and kwargs == {"encoding": "utf-8"}
            stream = Reader(source.open("rb"), **kwargs)
            state["streams"].append(stream)
            state["fds"].append(stream.fileno())
            return stream

    def forbidden(*args, **kwargs):
        raise AssertionError("direct reader only; no report or metadata calls")

    for name_to_block in ("load_json", "_load_findings", "_run_meta_target", "_compute_stats"):
        monkeypatch.setattr(report, name_to_block, forbidden)
    monkeypatch.setattr(report, "Path", OwnedPath)
    yield lambda: getattr(report, name)(tmp_path), state, expected, fallback
    assert state["reads"] == payload.splitlines(keepends=True)[:2 if state["primary"] else 3]
    assert state["closes"] == len(state["streams"]) == 1
    assert all(stream.closed for stream in state["streams"])
    for fd in state["fds"]:
        with pytest.raises(OSError) as caught:
            os.fstat(fd)
        assert caught.value.errno == errno.EBADF
    assert source.read_text(encoding="utf-8") == payload


@pytest.mark.parametrize("primary_type", [ValueError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt, SystemExit])
def test_active_read_error_keeps_identity(owned_reader, primary_type, cleanup_type):
    read, state, _, _ = owned_reader
    primary = state["primary"] = primary_type("owned read failure")
    state["cleanup"] = cleanup_type("owned cleanup failure")
    with pytest.raises(primary_type) as caught:
        read()
    assert caught.value is primary


@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt, SystemExit])
def test_active_oserror_keeps_reader_fallback(owned_reader, cleanup_type):
    read, state, _, fallback = owned_reader
    state["primary"] = OSError("owned read refusal")
    state["cleanup"] = cleanup_type("owned cleanup failure")
    assert read() == fallback


@pytest.mark.parametrize("cleanup_type", [KeyboardInterrupt, SystemExit])
def test_fresh_non_oserror_keeps_identity(owned_reader, cleanup_type):
    read, state, _, _ = owned_reader
    cleanup = state["cleanup"] = cleanup_type("owned cleanup failure")
    with pytest.raises(cleanup_type) as caught:
        read()
    assert caught.value is cleanup


def test_fresh_oserror_keeps_reader_fallback(owned_reader):
    read, state, _, fallback = owned_reader
    state["cleanup"] = OSError("owned cleanup refusal")
    assert read() == fallback


def test_healthy_reader_keeps_counts(owned_reader):
    read, _, expected, _ = owned_reader
    assert read() == expected
