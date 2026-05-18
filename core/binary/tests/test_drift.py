"""Tests for ``core.binary.drift``.

The drift primitive compares two fingerprints bidirectionally
— additions + removals + metadata shifts. Distinct from
``capability_diff`` (which is unidirectional: target-over-current
additions only) because the consumer questions differ:

  * Bump capability-delta: "what does the proposed bump ADD"
  * Drift detection: "what CHANGED since we last saw this image"
"""

from __future__ import annotations

from core.binary.drift import FingerprintDrift, detect_drift
from core.binary.fingerprint import CapabilityFingerprint


def _fp(*, sha="abc", arch="x86", bits=64,
        binary_format="elf", buckets=None) -> CapabilityFingerprint:
    """Build a minimal fingerprint with sensible defaults."""
    return CapabilityFingerprint(
        schema_version=1,
        binary_path="/test",
        binary_sha256=sha,
        arch=arch, bits=bits, binary_format=binary_format,
        capability_buckets=buckets or {},
    )


# ---------------------------------------------------------------------------
# Identity case
# ---------------------------------------------------------------------------


class TestNoChange:
    def test_same_fingerprint_no_drift(self):
        a = _fp(sha="abc", buckets={"exec": ["execve"]})
        b = _fp(sha="abc", buckets={"exec": ["execve"]})
        drift = detect_drift(a, b)
        assert drift.is_empty()
        assert not drift.hash_changed
        assert drift.new_buckets == {}
        assert drift.removed_buckets == {}

    def test_same_bytes_different_capability_short_circuits(self):
        """If binary_sha256 matches, drift is empty by definition
        regardless of bucket differences (which would only happen
        if the fingerprint primitive itself was inconsistent —
        the short-circuit defends against that)."""
        a = _fp(sha="abc", buckets={"exec": ["execve"]})
        b = _fp(sha="abc", buckets={})  # would be weird, but
        drift = detect_drift(a, b)
        assert drift.is_empty()
        assert not drift.hash_changed


# ---------------------------------------------------------------------------
# Capability additions
# ---------------------------------------------------------------------------


class TestAdditions:
    def test_new_bucket_added(self):
        prev = _fp(sha="A", buckets={"alloc": ["calloc"]})
        cur = _fp(sha="B", buckets={
            "alloc": ["calloc"], "exec": ["execve"],
        })
        drift = detect_drift(prev, cur)
        assert not drift.is_empty()
        assert drift.hash_changed
        assert drift.new_buckets == {"exec": ["execve"]}
        assert drift.removed_buckets == {}
        assert drift.high_severity()
        assert drift.added_buckets() == ["exec"]

    def test_bucket_expanded(self):
        """Bucket already present in previous; new entries added.
        Should still surface as a 'new' addition (per-entry, not
        per-bucket)."""
        prev = _fp(sha="A", buckets={"exec": ["execve"]})
        cur = _fp(sha="B", buckets={"exec": ["execve", "popen"]})
        drift = detect_drift(prev, cur)
        assert drift.new_buckets == {"exec": ["popen"]}
        assert drift.high_severity()

    def test_high_severity_only_for_exec_or_network(self):
        """Adding string_overflow alone isn't high severity —
        the ladder reserves high for exec/network adds."""
        prev = _fp(sha="A", buckets={})
        cur = _fp(sha="B", buckets={"string_overflow": ["strcpy"]})
        drift = detect_drift(prev, cur)
        assert not drift.is_empty()
        assert not drift.high_severity()


# ---------------------------------------------------------------------------
# Capability removals
# ---------------------------------------------------------------------------


class TestRemovals:
    def test_bucket_dropped(self):
        prev = _fp(sha="A", buckets={"exec": ["execve"]})
        cur = _fp(sha="B", buckets={})
        drift = detect_drift(prev, cur)
        assert not drift.is_empty()
        assert drift.removed_buckets == {"exec": ["execve"]}
        # Drops don't trigger high severity
        assert not drift.high_severity()
        assert drift.removed_bucket_names() == ["exec"]

    def test_bucket_partially_shrunk(self):
        """Some entries kept, others dropped — only the dropped
        ones surface."""
        prev = _fp(sha="A", buckets={"exec": ["execve", "popen"]})
        cur = _fp(sha="B", buckets={"exec": ["execve"]})
        drift = detect_drift(prev, cur)
        assert drift.removed_buckets == {"exec": ["popen"]}
        assert drift.new_buckets == {}


# ---------------------------------------------------------------------------
# Simultaneous add + remove
# ---------------------------------------------------------------------------


class TestSimultaneous:
    def test_add_and_remove(self):
        """Real bumps often add AND drop — e.g. a rebuild that
        switches between two libraries that provide different
        capability surfaces."""
        prev = _fp(sha="A", buckets={
            "string_overflow": ["strcpy"],
            "alloc": ["calloc"],
        })
        cur = _fp(sha="B", buckets={
            "alloc": ["calloc"],
            "exec": ["execve"],
            "network": ["recv"],
        })
        drift = detect_drift(prev, cur)
        assert drift.added_buckets() == ["exec", "network"]
        assert drift.removed_bucket_names() == ["string_overflow"]
        assert drift.high_severity()


# ---------------------------------------------------------------------------
# Metadata-level changes
# ---------------------------------------------------------------------------


class TestMetadataChanges:
    def test_arch_change_surfaced(self):
        """A re-tagged image that switches arch is a strong
        signal — operators likely didn't expect cross-arch
        substitution."""
        prev = _fp(sha="A", arch="x86", bits=64)
        cur = _fp(sha="B", arch="arm", bits=64)
        drift = detect_drift(prev, cur)
        assert drift.arch_changed
        assert not drift.is_empty()

    def test_bits_change_surfaced(self):
        prev = _fp(sha="A", arch="x86", bits=64)
        cur = _fp(sha="B", arch="x86", bits=32)
        drift = detect_drift(prev, cur)
        assert drift.bits_changed
        assert not drift.is_empty()

    def test_format_change_surfaced(self):
        """ELF → Mach-O on the same ref would be a deep red flag
        (someone repackaged the artifact)."""
        prev = _fp(sha="A", binary_format="elf")
        cur = _fp(sha="B", binary_format="mach-o")
        drift = detect_drift(prev, cur)
        assert drift.format_changed
        assert not drift.is_empty()

    def test_unchanged_metadata_not_flagged(self):
        prev = _fp(sha="A", arch="x86", bits=64, binary_format="elf")
        cur = _fp(sha="B", arch="x86", bits=64, binary_format="elf")
        drift = detect_drift(prev, cur)
        assert not drift.arch_changed
        assert not drift.bits_changed
        assert not drift.format_changed


# ---------------------------------------------------------------------------
# Empty-state semantics
# ---------------------------------------------------------------------------


class TestEmptyState:
    def test_empty_drift_object(self):
        d = FingerprintDrift()
        assert d.is_empty()
        assert not d.high_severity()
        assert d.added_buckets() == []
        assert d.removed_bucket_names() == []

    def test_hash_changed_alone_not_empty(self):
        """Bytes-different but capabilities-equivalent IS empty
        drift — the hash change is implicit in any meaningful
        drift, but bytes-only changes (legitimate rebuilds) are
        deliberately suppressed."""
        prev = _fp(sha="A", buckets={"exec": ["execve"]})
        cur = _fp(sha="B", buckets={"exec": ["execve"]})
        drift = detect_drift(prev, cur)
        # hash_changed is True, but no buckets / metadata
        # changed → is_empty() True
        assert drift.hash_changed
        assert drift.is_empty()
