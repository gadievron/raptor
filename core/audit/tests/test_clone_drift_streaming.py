"""Winnowing retains short inputs and bounds its temporary hash storage."""

import tracemalloc
from types import SimpleNamespace

import pytest

from core.audit import clone_drift as cd


@pytest.mark.parametrize(('values', 'expected'), [
    pytest.param([9, 7, 5, 3], {9, 7, 5, 3}, id='short-input-keeps-all-hashes'),
    pytest.param([9, 7, 5, 3, 8], {3}, id='overlapping-windows-keep-minima'),
])
def test_window_boundary(monkeypatch, values, expected):
    hashes = iter(values)
    monkeypatch.setattr(cd, 'zlib', SimpleNamespace(crc32=lambda data: next(hashes)))
    tokens = ['I'] * (cd.K_GRAM + len(values) - 1)
    assert cd._fingerprints(tokens) == frozenset(expected)


def test_repetitive_input_does_not_retain_every_shingle_hash():
    if tracemalloc.is_tracing():
        pytest.skip('Requires an independently owned allocation tracer')
    tokens = ['I'] * 50000
    try:
        tracemalloc.start()
        result = cd._fingerprints(tokens)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(result) == 1
    assert peak < 128 * 1024, f'Winnowing retained {peak} bytes for repetitive input'
