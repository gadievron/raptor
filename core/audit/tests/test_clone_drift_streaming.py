"""Winnowing retains short inputs and bounds its temporary hash storage."""

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


def test_repetitive_input_does_not_retain_every_shingle_hash(monkeypatch):
    # Count only the hashes owned by this invocation. A process-wide allocation
    # peak also includes unrelated background threads in a full test worker.
    live = peak = generated = 0
    real_crc32 = cd.zlib.crc32

    class TrackedHash(int):
        def __new__(cls, value):
            nonlocal live, peak, generated
            instance = super().__new__(cls, value)
            live += 1
            generated += 1
            peak = max(peak, live)
            return instance

        def __del__(self):
            nonlocal live
            live -= 1

    monkeypatch.setattr(cd, 'zlib', SimpleNamespace(
        crc32=lambda data: TrackedHash(real_crc32(data))))
    tokens = ['I'] * 50000
    result = cd._fingerprints(tokens)
    assert len(result) == 1
    assert generated == len(tokens) - cd.K_GRAM + 1
    assert peak <= cd.WINNOW_WINDOW + 4, f'Winnowing retained {peak} shingle hashes'
