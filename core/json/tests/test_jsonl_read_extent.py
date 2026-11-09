"""Bounded trail reads stop at their initially admitted byte extent."""
import os

import pytest

from core.json import jsonl
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def bounded_trail(tmp_path, monkeypatch):
    path = tmp_path / "trail.jsonl"
    requests = []
    transferred = []
    snapshots = []
    streams = []
    original_stat, original_fdopen = os.fstat, os.fdopen
    growth = []

    def snapshot(fd):
        info = original_stat(fd)
        snapshots.append(info.st_size)
        if growth:
            with path.open("ab") as writer:
                writer.write(growth.pop())
        return info

    class Stream:
        def __init__(self, stream):
            self.stream = stream
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return self.stream.__exit__(*args)
        def readline(self, size=-1):
            requests.append(size)
            data = self.stream.readline(size)
            transferred.append(len(data))
            return data
        def __iter__(self):
            return self
        def __next__(self):
            line = self.readline()
            if not line:
                raise StopIteration
            return line

    def adopt(*args, **kwargs):
        stream = Stream(original_fdopen(*args, **kwargs))
        streams.append(stream)
        return stream

    patch_module_attribute(monkeypatch, jsonl, "os", "fstat", snapshot)
    patch_module_attribute(monkeypatch, jsonl, "os", "fdopen", adopt)
    yield path, growth, requests, transferred, snapshots
    assert all(stream.stream.closed for stream in streams)


@pytest.mark.parametrize("initial,budget,tail,expected", [
    (b"0\n", 2, False, [0]),
    (b"8\n9\n0\n", 4, True, [0]),
    (b"", 4, False, []),
    (b"", 0, False, []),
    (b"12", 2, False, [12]),
    (b"0\r1\r2\n", 6, False, [0, 1, 2]),
], ids=["under-budget", "oversize-tail", "initially-empty", "zero-budget", "unterminated-final", "bare-cr"])
def test_concurrent_append_cannot_extend_admitted_read(bounded_trail, initial, budget, tail, expected):
    path, growth, requests, transferred, snapshots = bounded_trail
    path.write_bytes(initial)
    growth.append(b"1\n")
    assert jsonl.load_jsonl(path, max_total_bytes=budget, oversize_tail=tail) == expected
    assert snapshots == [len(initial)]
    assert sum(transferred) <= min(len(initial), budget)
    assert all(0 < size <= budget for size in requests)
    assert path.read_bytes() == initial + b"1\n"


def test_tail_discard_uses_the_same_remaining_budget(bounded_trail):
    path, growth, requests, transferred, _ = bounded_trail
    path.write_bytes(b"0\n" + b"1" * 64)
    growth.append(b"\n2\n")
    assert jsonl.load_jsonl(path, max_total_bytes=4, oversize_tail=True) == []
    assert sum(transferred) == 4
    assert requests == [4]


def test_record_eviction_only_uses_admitted_rows(bounded_trail):
    path, growth, requests, transferred, _ = bounded_trail
    initial = b"0\n1\n2\n3\n4\n"
    path.write_bytes(initial)
    growth.append(b"5\n")
    assert jsonl.load_jsonl(path, max_total_bytes=len(initial), max_records=2) == [3, 4]
    assert sum(transferred) == len(initial)
    assert all(size > 0 for size in requests)


def test_no_byte_budget_preserves_historical_growing_read(bounded_trail):
    path, growth, _, _, _ = bounded_trail
    path.write_bytes(b"0\n")
    growth.append(b"1\n")
    assert jsonl.load_jsonl(path) == [0, 1]


def test_stable_multibyte_and_unterminated_rows_are_unchanged(bounded_trail):
    path, _, requests, transferred, _ = bounded_trail
    raw = '\"é\"\n{\"k\": 2}'.encode()
    path.write_bytes(raw)
    assert jsonl.load_jsonl(path, max_total_bytes=len(raw)) == ["é", {"k": 2}]
    assert sum(transferred) == len(raw)
    assert all(size > 0 for size in requests)
