"""The binary hash byte budget also applies after descriptor admission."""

import contextlib
import hashlib
import os

import pytest

from core.testing.module_state import isolated_module_state
from core.witness import matching


def test_growth_after_admission_is_refused(tmp_path):
    binary = tmp_path / 'binary'
    binary.write_bytes(b'small')
    opened = []
    reads = []

    class GrowingOS:
        def __getattr__(self, name):
            return getattr(os, name)

        def fstat(self, fd):
            admitted = os.fstat(fd)
            opened.append(fd)
            binary.write_bytes(b'x' * 64)
            return admitted

        @contextlib.contextmanager
        def fdopen(self, *args, **kwargs):
            with os.fdopen(*args, **kwargs) as stream:
                class Reader:
                    def read(self, size):
                        data = stream.read(size)
                        reads.append(len(data))
                        return data

                yield Reader()

    with isolated_module_state(matching, {
        'os': GrowingOS(), '_MAX_BINARY_HASH_BYTES': 8, '_binary_hash_memo': {},
    }):
        assert matching._on_disk_binary_hash(str(binary)) is None
        assert not matching._binary_hash_memo
    assert 8 < sum(reads) <= 9
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])


@pytest.mark.parametrize('size', [0, 7, 8])
def test_admitted_static_binary_hash_is_unchanged(tmp_path, size):
    binary = tmp_path / 'binary'
    data = b'x' * size
    binary.write_bytes(data)
    with isolated_module_state(matching, {
        '_MAX_BINARY_HASH_BYTES': 8, '_binary_hash_memo': {},
    }):
        assert matching._on_disk_binary_hash(str(binary)) == hashlib.sha256(data).hexdigest()
        assert len(matching._binary_hash_memo) == 1


def test_initial_oversize_is_refused_before_stream_creation(tmp_path):
    binary = tmp_path / 'binary'
    binary.write_bytes(b'x' * 9)

    class NoStreamOS:
        def __getattr__(self, name):
            return getattr(os, name)

        def fdopen(self, *args, **kwargs):
            pytest.fail('initial oversize must be refused before reading')

    with isolated_module_state(matching, {
        'os': NoStreamOS(), '_MAX_BINARY_HASH_BYTES': 8, '_binary_hash_memo': {},
    }):
        assert matching._on_disk_binary_hash(str(binary)) is None
        assert not matching._binary_hash_memo


@pytest.mark.parametrize('size', [7, 8])
def test_growth_within_budget_remains_hashable(tmp_path, size):
    binary = tmp_path / 'binary'
    binary.write_bytes(b'small')
    data = b'x' * size

    class GrowingOS:
        def __getattr__(self, name):
            return getattr(os, name)

        def fstat(self, fd):
            admitted = os.fstat(fd)
            binary.write_bytes(data)
            return admitted

    with isolated_module_state(matching, {
        'os': GrowingOS(), '_MAX_BINARY_HASH_BYTES': 8, '_binary_hash_memo': {},
    }):
        assert matching._on_disk_binary_hash(str(binary)) == hashlib.sha256(data).hexdigest()
