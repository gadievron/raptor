"""Owned-byte identity controls for binary-cache lookup, with no binary tools.

The tiny target files are not executable artefacts. Minimal JSON databases
exercise the actual cache identity consumer; no parser backend, decompiler,
compiler, provider, or target process runs.
"""
from __future__ import annotations

import hashlib
import json
import os

from core.audit.binary_context import find_redb

_ORIGINAL = b"owned-target-A"
_REPLACEMENT = b"owned-target-B"


def _fixture(tmp_path, monkeypatch):
    # Prevent a test from consulting another run's stem-keyed cache.
    monkeypatch.setenv("RAPTOR_DIR", str(tmp_path / "private-raptor"))
    target = tmp_path / "target.bin"
    target.write_bytes(_ORIGINAL)
    run = tmp_path / "run"
    run.mkdir()
    candidate = run / "re-database.json"
    candidate.write_text(json.dumps({
        "source_tool": "r2", "binary_path": str(target), "functions": [],
        "metadata": {"binary_sha256": hashlib.sha256(_ORIGINAL).hexdigest()},
    }))
    return target, run, candidate


def _rewrite_preserving_mtime(target, before):
    target.write_bytes(_REPLACEMENT)
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
    after = target.stat()
    assert after.st_size == before.st_size
    assert after.st_mtime_ns == before.st_mtime_ns
    assert after.st_ctime_ns != before.st_ctime_ns
    return after


def test_same_size_rewrite_with_restored_mtime_cannot_reuse_old_content_identity(tmp_path, monkeypatch):
    target, run, candidate = _fixture(tmp_path, monkeypatch)
    assert find_redb(run, target) == candidate
    before = target.stat()
    _rewrite_preserving_mtime(target, before)

    assert target.read_bytes() == _REPLACEMENT
    assert find_redb(run, target) is None


def test_replaced_inode_with_same_size_and_mtime_cannot_reuse_old_content_identity(tmp_path, monkeypatch):
    target, run, candidate = _fixture(tmp_path, monkeypatch)
    assert find_redb(run, target) == candidate
    before = target.stat()
    replacement = tmp_path / "replacement.bin"
    replacement.write_bytes(_REPLACEMENT)
    os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
    os.replace(replacement, target)
    after = target.stat()
    assert after.st_ino != before.st_ino
    assert (after.st_size, after.st_mtime_ns) == (before.st_size, before.st_mtime_ns)

    assert target.read_bytes() == _REPLACEMENT
    assert find_redb(run, target) is None


def test_declared_content_identity_unavailable_cannot_fall_back_to_matching_path(tmp_path, monkeypatch):
    import core.hash as core_hash

    target, run, _candidate = _fixture(tmp_path, monkeypatch)
    calls = []

    def unavailable(*args, **kwargs):
        calls.append(True)
        raise OSError("owned content read unavailable")

    # Both established streaming entry points are faulted: the control does
    # not depend on whether the consumer opens by name or owns its file fd.
    monkeypatch.setattr(core_hash, "sha256_file", unavailable)
    monkeypatch.setattr(core_hash, "sha256_fileobj", unavailable)
    assert find_redb(run, target) is None
    assert calls
    assert target.read_bytes() == _ORIGINAL


def test_mutation_during_hash_refuses_candidate_and_retries_the_content_read(tmp_path, monkeypatch):
    import core.hash as core_hash

    target, run, _candidate = _fixture(tmp_path, monkeypatch)
    before = target.stat()
    real_file, real_stream = core_hash.sha256_file, core_hash.sha256_fileobj
    calls = []
    changed = False

    def mutate_once():
        nonlocal changed
        if not changed:
            changed = True
            _rewrite_preserving_mtime(target, before)

    def file_hash(*args, **kwargs):
        calls.append("file")
        digest = real_file(*args, **kwargs)
        mutate_once()
        return digest

    def stream_hash(*args, **kwargs):
        calls.append("stream")
        digest = real_stream(*args, **kwargs)
        mutate_once()
        return digest

    monkeypatch.setattr(core_hash, "sha256_file", file_hash)
    monkeypatch.setattr(core_hash, "sha256_fileobj", stream_hash)
    assert find_redb(run, target) is None
    assert changed and target.read_bytes() == _REPLACEMENT
    first_read_calls = len(calls)
    assert first_read_calls
    # The failed/unstable read cannot become a reusable identity. A later
    # call reads the now-stable replacement and still rejects the old stamp.
    assert find_redb(run, target) is None
    assert len(calls) > first_read_calls


def test_target_identity_is_rechecked_between_database_candidates(tmp_path, monkeypatch):
    import core.audit.binary_context as context
    target, run, local = _fixture(tmp_path, monkeypatch)
    before = target.stat()
    parent = tmp_path / "re-database.json"
    parent.write_text(local.read_text())
    local_doc = json.loads(local.read_text())
    local_doc["metadata"]["binary_sha256"] = "f" * 64
    local.write_text(json.dumps(local_doc))
    real_load = context.load_redb
    changed = False

    def load_then_change(candidate):
        nonlocal changed
        database = real_load(candidate)
        if candidate == parent:
            _rewrite_preserving_mtime(target, before)
            changed = True
        return database

    monkeypatch.setattr(context, "load_redb", load_then_change)
    assert find_redb(run, target) is None
    assert changed and target.read_bytes() == _REPLACEMENT
