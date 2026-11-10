"""Direct one-file collection cleanup, without profiling or decoder execution."""
import os
from types import SimpleNamespace

import pytest

from packages.binary_analysis import corpus_profile as module


@pytest.fixture
def collector_io(tmp_path, monkeypatch):
    path = tmp_path / "plain.txt"
    path.write_bytes(b"plain text\n")
    options = module.CorpusProfileOptions(samples_dir=tmp_path, out_dir=tmp_path / "unused",
                                          max_bytes_per_sample=8, total_byte_budget=8, header_window=4)
    state = {"path": path, "options": options, "primary": None, "cleanup": None,
             "site": "metadata", "live": set(), "closes": 0}
    original = module._open_regular_nofollow

    def opened(path):
        fd = original(path)
        assert fd is not None
        state["live"].add(fd)
        return fd

    def fstat(fd):
        result = os.fstat(fd)
        if fd in state["live"] and state["site"] == "metadata" and state["primary"] is not None:
            raise state["primary"]
        return result

    def read(fd, size):
        result = os.read(fd, size)
        if state["site"] == "read" and state["primary"] is not None:
            raise state["primary"]
        return result

    def close(fd):
        os.close(fd)
        state["live"].remove(fd)
        state["closes"] += 1
        if state["cleanup"] is not None:
            raise state["cleanup"]

    monkeypatch.setattr(module, "_open_regular_nofollow", opened)
    monkeypatch.setattr(module, "_iter_sample_paths", lambda _: iter([("plain.txt", path, False)]))
    monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "fstat": fstat, "read": read, "close": close}))
    try:
        yield state
    finally:
        for fd in state["live"]:
            os.close(fd)


def test_metadata_primary_survives_consumed_close(collector_io):
    primary = KeyboardInterrupt("after native metadata")
    collector_io["primary"] = primary
    collector_io["cleanup"] = OSError("after native close")
    with pytest.raises(KeyboardInterrupt) as raised:
        module._collect_samples(collector_io["options"])
    assert raised.value is primary
    assert collector_io["closes"] == 1
    assert not collector_io["live"]


@pytest.mark.parametrize("site", ["metadata", "read"])
@pytest.mark.parametrize("primary_type", [MemoryError, SystemExit])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
def test_active_error_keeps_identity(collector_io, site, primary_type, close_type):
    primary = primary_type("after native operation")
    collector_io.update(site=site, primary=primary, cleanup=close_type("after native close"))
    with pytest.raises(primary_type) as raised:
        module._collect_samples(collector_io["options"])
    assert raised.value is primary
    assert collector_io["closes"] == 1
    assert not collector_io["live"]


def test_read_io_still_records_skip(collector_io):
    collector_io.update(site="read", primary=OSError("after native read"))
    assert module._collect_samples(collector_io["options"]) == (
        [], 1, [{"name": "plain.txt", "reason": "read error"}], [], 1)
    assert collector_io["closes"] == 1
    assert not collector_io["live"]


def test_metadata_io_still_propagates(collector_io):
    primary = OSError("after native metadata")
    collector_io["primary"] = primary
    collector_io["cleanup"] = KeyboardInterrupt("after native close")
    with pytest.raises(OSError) as raised:
        module._collect_samples(collector_io["options"])
    assert raised.value is primary
    assert collector_io["closes"] == 1
    assert not collector_io["live"]


@pytest.mark.parametrize("handled_io", [False, True])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_close_failure_stays_visible(collector_io, handled_io, close_type):
    if handled_io:
        collector_io.update(site="read", primary=OSError("after native read"))
    cleanup = close_type("after native close")
    collector_io["cleanup"] = cleanup
    with pytest.raises(close_type) as raised:
        module._collect_samples(collector_io["options"])
    assert raised.value is cleanup
    assert collector_io["closes"] == 1
    assert not collector_io["live"]


def test_native_collection_retains_header_and_read_caps(collector_io):
    samples, skipped, examples, caps, seen = module._collect_samples(collector_io["options"])
    assert (skipped, examples, caps, seen) == (0, [], [], 1)
    assert len(samples) == 1
    sample = samples[0]
    assert (sample.rel_name, sample.path, sample.size, sample.header, sample.truncated_read) == (
        "plain.txt", collector_io["path"], 11, b"plai", True)
    assert collector_io["closes"] == 1
    assert not collector_io["live"]
