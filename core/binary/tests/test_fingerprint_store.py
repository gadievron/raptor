"""Tests for ``core.binary.fingerprint_store``.

Substrate for drift detection: persist fingerprints keyed by
ref, load them back, enumerate the store, handle corrupt /
missing / schema-skew gracefully.
"""

from __future__ import annotations

import json

from core.binary.fingerprint import (
    FINGERPRINT_SCHEMA_VERSION,
    CapabilityFingerprint,
)
from core.binary.fingerprint_store import (
    STORE_SCHEMA_VERSION,
    delete_fingerprint,
    iter_refs,
    load_fingerprint,
    save_fingerprint,
)


def _fp(*, sha="abc", arch="x86", bits=64,
        buckets=None) -> CapabilityFingerprint:
    return CapabilityFingerprint(
        schema_version=FINGERPRINT_SCHEMA_VERSION,
        binary_path="/test",
        binary_sha256=sha, arch=arch, bits=bits,
        binary_format="elf",
        capability_buckets=buckets or {},
    )


# ---------------------------------------------------------------------------
# Roundtrip — save + load
# ---------------------------------------------------------------------------


class TestSaveLoad:
    def test_save_then_load_returns_same_fingerprint(self, tmp_path):
        fp = _fp(sha="A", buckets={"exec": ["execve"]})
        ref = "docker.io/library/alpine:3.18"
        written = save_fingerprint(tmp_path, ref, fp)
        assert written is not None
        assert written.is_file()
        loaded = load_fingerprint(tmp_path, ref)
        assert loaded is not None
        # canonical_json is the comparable representation
        assert loaded.canonical_json() == fp.canonical_json()

    def test_load_missing_ref_returns_none(self, tmp_path):
        assert load_fingerprint(tmp_path, "never-seen") is None

    def test_load_from_empty_store_returns_none(self, tmp_path):
        # Don't even create the store dir
        empty = tmp_path / "nonexistent"
        assert load_fingerprint(empty, "ref") is None

    def test_save_creates_store_dir(self, tmp_path):
        """First save creates the store directory; operators
        shouldn't need to mkdir up-front."""
        store = tmp_path / "fingerprints"
        assert not store.exists()
        save_fingerprint(store, "ref", _fp())
        assert store.is_dir()

    def test_overwrite_existing_entry(self, tmp_path):
        """Re-saving the same ref replaces the previous entry."""
        ref = "x"
        save_fingerprint(tmp_path, ref, _fp(sha="A"))
        save_fingerprint(tmp_path, ref, _fp(sha="B"))
        loaded = load_fingerprint(tmp_path, ref)
        assert loaded.binary_sha256 == "B"

    def test_empty_ref_skipped(self, tmp_path):
        """Empty ref is rejected — defends against accidental
        writes to a wildcard slot."""
        assert save_fingerprint(tmp_path, "", _fp()) is None
        assert load_fingerprint(tmp_path, "") is None


# ---------------------------------------------------------------------------
# Atomic write
# ---------------------------------------------------------------------------


class TestAtomicWrite:
    def test_no_partial_state_after_save(self, tmp_path):
        """After save_fingerprint returns, the file is either
        fully-formed or absent. No half-written JSON visible."""
        save_fingerprint(tmp_path, "ref", _fp())
        files = list(tmp_path.iterdir())
        assert len(files) == 1
        assert files[0].name.endswith(".json")
        # File is parseable JSON
        with open(files[0]) as f:
            data = json.load(f)
        assert data["ref"] == "ref"

    def test_tmp_files_filtered_from_iter_refs(self, tmp_path):
        """A leftover ``.tmp-*.json`` file (process killed
        mid-write) doesn't pollute iter_refs."""
        # Simulate the leftover
        leftover = tmp_path / ".tmp-abc.json"
        leftover.write_text('{"some": "data"}')
        save_fingerprint(tmp_path, "real", _fp())
        refs = list(iter_refs(tmp_path))
        assert len(refs) == 1
        assert refs[0][0] == "real"


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------


class TestIterRefs:
    def test_empty_store(self, tmp_path):
        assert list(iter_refs(tmp_path)) == []

    def test_missing_store_dir(self, tmp_path):
        assert list(iter_refs(tmp_path / "nope")) == []

    def test_multiple_refs(self, tmp_path):
        save_fingerprint(tmp_path, "ref-a", _fp(sha="A"))
        save_fingerprint(tmp_path, "ref-b", _fp(sha="B"))
        save_fingerprint(tmp_path, "ref-c", _fp(sha="C"))
        refs = dict(iter_refs(tmp_path))
        assert set(refs.keys()) == {"ref-a", "ref-b", "ref-c"}

    def test_iter_skips_corrupt_entries(self, tmp_path):
        """Corrupt JSON / missing fields / wrong schema_version
        → skipped silently. Doesn't crash the iteration; doesn't
        emit a bogus ref."""
        save_fingerprint(tmp_path, "good", _fp(sha="A"))
        # Write corrupt entry
        (tmp_path / "deadbeef.json").write_text("not json")
        # Write wrong-schema entry
        (tmp_path / "cafebabe.json").write_text(json.dumps({
            "schema_version": 999,
            "ref": "wrong-schema",
            "fingerprint": {},
        }))
        refs = dict(iter_refs(tmp_path))
        assert "good" in refs
        assert "wrong-schema" not in refs
        assert len(refs) == 1


# ---------------------------------------------------------------------------
# Schema versioning
# ---------------------------------------------------------------------------


class TestSchemaVersioning:
    def test_mismatched_schema_load_returns_none(self, tmp_path):
        """A future-schema entry is treated as "no baseline" —
        better to recompute than misinterpret across version
        skew."""
        save_fingerprint(tmp_path, "ref", _fp())
        # Tamper: bump schema version to a future value
        file_path = next(tmp_path.glob("*.json"))
        with open(file_path) as f:
            data = json.load(f)
        data["schema_version"] = STORE_SCHEMA_VERSION + 100
        with open(file_path, "w") as f:
            json.dump(data, f)
        assert load_fingerprint(tmp_path, "ref") is None

    def test_mismatched_fingerprint_shape_load_returns_none(
            self, tmp_path):
        """Wrapper version OK, embedded fingerprint shape stale —
        treat as no baseline. Regression for the silent-false-
        positive-drift bug: a stored fingerprint with an old
        FINGERPRINT_SCHEMA_VERSION must not be diffed against a
        fresh one with a newer shape (new buckets would all show
        as drift)."""
        save_fingerprint(tmp_path, "ref", _fp())
        file_path = next(tmp_path.glob("*.json"))
        with open(file_path) as f:
            data = json.load(f)
        # Wrapper stays current; tamper only with embedded shape.
        data["fingerprint"]["schema_version"] = \
            FINGERPRINT_SCHEMA_VERSION - 1
        with open(file_path, "w") as f:
            json.dump(data, f)
        assert load_fingerprint(tmp_path, "ref") is None

    def test_iter_refs_skips_mismatched_fingerprint_shape(
            self, tmp_path):
        """Same regression as above, applied to iter_refs() —
        stale-shape entries must be skipped by the enumeration
        path too (drift detectors that scan the whole store
        depend on this)."""
        save_fingerprint(tmp_path, "good", _fp(sha="A"))
        # Write a stale-shape entry directly (correct wrapper,
        # stale embedded schema_version).
        (tmp_path / "deadbeef.json").write_text(json.dumps({
            "schema_version": STORE_SCHEMA_VERSION,
            "ref": "stale-shape",
            "fingerprint": {
                "schema_version": FINGERPRINT_SCHEMA_VERSION - 1,
                "binary_path": "/test",
                "binary_sha256": "B",
                "arch": "x86",
                "bits": 64,
                "binary_format": "elf",
                "capability_buckets": {},
            },
        }))
        refs = dict(iter_refs(tmp_path))
        assert "good" in refs
        assert "stale-shape" not in refs
        assert len(refs) == 1


# ---------------------------------------------------------------------------
# Deletion
# ---------------------------------------------------------------------------


class TestDelete:
    def test_delete_existing(self, tmp_path):
        save_fingerprint(tmp_path, "ref", _fp())
        assert delete_fingerprint(tmp_path, "ref") is True
        assert load_fingerprint(tmp_path, "ref") is None

    def test_delete_missing(self, tmp_path):
        assert delete_fingerprint(tmp_path, "ref") is False

    def test_delete_empty_ref(self, tmp_path):
        """Empty ref → no-op (defends against accidentally
        deleting the wrong slot)."""
        save_fingerprint(tmp_path, "real-ref", _fp())
        assert delete_fingerprint(tmp_path, "") is False
        assert load_fingerprint(tmp_path, "real-ref") is not None


# ---------------------------------------------------------------------------
# Filename safety
# ---------------------------------------------------------------------------


class TestFilenameSafety:
    def test_ref_with_slashes_and_colons(self, tmp_path):
        """Image refs contain ``/`` and ``:``. The filename
        scheme hashes the ref to avoid filesystem escaping."""
        ref = "docker.io/library/alpine:3.18@sha256:abcdef"
        save_fingerprint(tmp_path, ref, _fp())
        loaded = load_fingerprint(tmp_path, ref)
        assert loaded is not None
        # No subdirs created — filename is flat
        files = list(tmp_path.iterdir())
        assert len(files) == 1
        # No problematic chars in the filename
        assert "/" not in files[0].name
        assert ":" not in files[0].name

    def test_ref_with_traversal_pathologies(self, tmp_path):
        """Refs with ``..`` / ``/`` can't escape the store
        directory — the hash scheme makes path-traversal
        impossible."""
        ref = "../../../etc/passwd"
        save_fingerprint(tmp_path, ref, _fp())
        # File is INSIDE tmp_path
        files = list(tmp_path.iterdir())
        assert len(files) == 1
        assert files[0].parent == tmp_path
        # And loadable
        assert load_fingerprint(tmp_path, ref) is not None
