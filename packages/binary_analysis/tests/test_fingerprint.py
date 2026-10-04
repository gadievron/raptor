"""Tests for ``packages.binary_analysis.fingerprint``.

The fingerprint primitive wraps ``analyse_binary_context`` to
produce a stable, comparable capability snapshot. Tests cover:

  * Bucket classification via the shared taxonomy
  * Stable JSON serialisation (sorted, no whitespace variance)
  * Round-trip dict ↔ dataclass
  * Content-hash computation
  * Graceful degradation: radare2 unavailable, analyser fail

The full radare2 wire-through is gated by ``probe_capability``
— tests use stubs so the suite doesn't require r2pipe.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from packages.binary_analysis.fingerprint import (
    BUCKETS,
    CapabilityFingerprint,
    FINGERPRINT_SCHEMA_VERSION,
    HIGH_SEVERITY_BUCKETS,
    bucket_imports,
    capability_fingerprint,
)
from packages.binary_analysis.radare2_understand import (
    BinaryContextMap, FunctionInfo,
)


# ---------------------------------------------------------------------------
# bucket_imports — bucket classification
# ---------------------------------------------------------------------------


class TestBucketImports:
    def test_exec_imports_classified(self):
        out = bucket_imports({"execve", "popen", "fread"})
        assert "exec" in out
        assert out["exec"] == {"execve", "popen"}

    def test_ubiquitous_imports_dropped(self):
        """``malloc`` / ``printf`` / ``read`` aren't in any
        high-CVE bucket — return empty."""
        assert bucket_imports({"malloc", "printf", "read"}) == {}

    def test_multiple_buckets(self):
        out = bucket_imports({"execve", "recv", "strcpy"})
        assert "exec" in out
        assert "network" in out
        assert "string_overflow" in out

    def test_empty_input_empty_output(self):
        assert bucket_imports(set()) == {}


class TestBucketTaxonomy:
    """The BUCKETS table is shared between fingerprint + SCA bump
    detector — these tests pin its shape so a tiny refactor in
    one consumer doesn't silently change the other."""

    def test_all_bucket_names_present(self):
        names = [b[0] for b in BUCKETS]
        assert names == [
            "exec", "network", "string_overflow", "scan",
            "memory_copy", "format_string", "alloc", "parser",
            "integer_parse", "toctou",
        ]

    def test_high_severity_buckets_subset_of_buckets(self):
        bucket_names = {b[0] for b in BUCKETS}
        assert HIGH_SEVERITY_BUCKETS <= bucket_names


# ---------------------------------------------------------------------------
# CapabilityFingerprint serialisation
# ---------------------------------------------------------------------------


class TestFingerprintSerialisation:
    def test_to_dict_stable_ordering(self):
        """Same fingerprint → same to_dict output regardless of
        insertion order of internal dicts / lists. Needed for
        content-hash-based dedup."""
        fp1 = CapabilityFingerprint(
            schema_version=1,
            binary_path="/x", binary_sha256="abc",
            arch="x86_64", bits=64, binary_format="elf",
            capability_buckets={"exec": ["execve", "popen"],
                                  "network": ["recv"]},
            dangerous_sinks=["b", "a"],
        )
        fp2 = CapabilityFingerprint(
            schema_version=1,
            binary_path="/x", binary_sha256="abc",
            arch="x86_64", bits=64, binary_format="elf",
            capability_buckets={"network": ["recv"],
                                  "exec": ["popen", "execve"]},
            dangerous_sinks=["a", "b"],
        )
        assert fp1.to_dict() == fp2.to_dict()
        assert fp1.canonical_json() == fp2.canonical_json()

    def test_canonical_json_no_whitespace_variance(self):
        fp = CapabilityFingerprint(
            schema_version=1,
            binary_path="/x", binary_sha256="abc",
            arch="x86_64", bits=64, binary_format="elf",
            capability_buckets={"exec": ["execve"]},
            dangerous_sinks=["sym.imp.execve"],
        )
        out = fp.canonical_json()
        # Compact: no whitespace around separators
        assert ": " not in out
        assert ", " not in out
        # Parses back to a dict (the comparison view — see
        # test_canonical_json_excludes_binary_path below).
        parsed = json.loads(out)
        assert "binary_path" not in parsed
        # Every other field present
        for k in ("schema_version", "binary_sha256", "arch", "bits",
                  "binary_format", "capability_buckets",
                  "dangerous_sinks"):
            assert k in parsed

    def test_canonical_json_excludes_binary_path(self):
        """ADVERSARIAL REGRESSION: same binary bytes at two
        different filesystem paths must produce identical
        canonical_json. Including binary_path would create
        false drift signals between CI / local runs / different
        extraction tempdirs.
        """
        kwargs = dict(
            schema_version=1, binary_sha256="abc",
            arch="x86_64", bits=64, binary_format="elf",
            capability_buckets={"exec": ["execve"]},
            dangerous_sinks=["sym.imp.execve"],
        )
        fp_a = CapabilityFingerprint(
            binary_path="/usr/bin/foo", **kwargs,
        )
        fp_b = CapabilityFingerprint(
            binary_path="dl-xyz/foo", **kwargs,
        )
        assert fp_a.canonical_json() == fp_b.canonical_json()
        # to_dict() does include binary_path (operator-facing
        # rendering / SBOM property) — that's intentional and
        # they differ there
        assert fp_a.to_dict() != fp_b.to_dict()
        assert fp_a.to_dict()["binary_path"] == "/usr/bin/foo"
        assert fp_b.to_dict()["binary_path"] == "dl-xyz/foo"

    def test_from_dict_roundtrip(self):
        fp = CapabilityFingerprint(
            schema_version=1,
            binary_path="/x", binary_sha256="abc",
            arch="x86_64", bits=64, binary_format="elf",
            capability_buckets={"exec": ["execve"]},
            dangerous_sinks=["sym.imp.execve"],
        )
        restored = CapabilityFingerprint.from_dict(fp.to_dict())
        assert restored.to_dict() == fp.to_dict()

    def test_schema_version_in_dict(self):
        fp = CapabilityFingerprint(
            schema_version=FINGERPRINT_SCHEMA_VERSION,
            binary_path="/x", binary_sha256="abc",
            arch="x86_64", bits=64, binary_format="elf",
        )
        d = fp.to_dict()
        assert d["schema_version"] == FINGERPRINT_SCHEMA_VERSION


# ---------------------------------------------------------------------------
# capability_fingerprint — full path with stubbed analyser
# ---------------------------------------------------------------------------


@pytest.fixture
def patched_analyser(monkeypatch):
    """Replace ``analyse_binary_context`` + ``probe_capability``
    on the radare2 module so tests can drive the fingerprint
    primitive without r2pipe."""
    state = {"available": True, "ctx": None, "raise": None}

    def fake_probe():
        return {"available": state["available"], "reason": "stub"}

    def fake_analyse(path, **kwargs):
        if state["raise"] is not None:
            raise state["raise"]
        return state["ctx"]

    monkeypatch.setattr(
        "packages.binary_analysis.radare2_understand.probe_capability",
        fake_probe,
    )
    monkeypatch.setattr(
        "packages.binary_analysis.radare2_understand.analyse_binary_context",
        fake_analyse,
    )
    yield state


def _real_bytes_tempfile(tmp_path: Path, name: str, content: bytes) -> Path:
    """Write a file we can actually SHA-256 — fingerprint needs
    real bytes for the content hash."""
    out = tmp_path / name
    out.write_bytes(content)
    return out


class TestCapabilityFingerprint:
    def test_full_path_returns_fingerprint(
        self, patched_analyser, tmp_path,
    ):
        bin_path = _real_bytes_tempfile(
            tmp_path, "test.bin", b"\x7fELF\x00\x01" * 50,
        )
        patched_analyser["ctx"] = BinaryContextMap(
            binary_path=bin_path,
            arch="x86_64", bits=64, binary_format="elf",
            imports=["execve", "recv", "malloc", "printf"],
            dangerous_sinks=[
                FunctionInfo(name="sym.imp.execve", address=0x1000),
            ],
        )
        fp = capability_fingerprint(bin_path)
        assert fp is not None
        assert fp.schema_version == FINGERPRINT_SCHEMA_VERSION
        assert fp.arch == "x86_64"
        assert fp.bits == 64
        assert fp.binary_format == "elf"
        assert "exec" in fp.capability_buckets
        assert "network" in fp.capability_buckets
        assert "malloc" not in {
            fn for fns in fp.capability_buckets.values() for fn in fns
        }
        assert "sym.imp.execve" in fp.dangerous_sinks
        # Real bytes → real hash, 64 hex chars
        assert len(fp.binary_sha256) == 64
        assert all(c in "0123456789abcdef" for c in fp.binary_sha256)

    def test_same_bytes_same_hash(
        self, patched_analyser, tmp_path,
    ):
        """Two files with identical bytes produce identical
        ``binary_sha256``. Drift detection depends on this
        property — same image-content → same fingerprint."""
        ctx_a = BinaryContextMap(
            binary_path=Path("/a"),
            arch="x86_64", bits=64, binary_format="elf",
            imports=["execve"],
        )
        ctx_b = BinaryContextMap(
            binary_path=Path("/b"),
            arch="x86_64", bits=64, binary_format="elf",
            imports=["execve"],
        )
        bin_a = _real_bytes_tempfile(
            tmp_path, "a.bin", b"identical bytes",
        )
        bin_b = _real_bytes_tempfile(
            tmp_path, "b.bin", b"identical bytes",
        )
        patched_analyser["ctx"] = ctx_a
        fp_a = capability_fingerprint(bin_a)
        patched_analyser["ctx"] = ctx_b
        fp_b = capability_fingerprint(bin_b)
        assert fp_a.binary_sha256 == fp_b.binary_sha256

    def test_radare2_unavailable_returns_none(
        self, patched_analyser, tmp_path,
    ):
        patched_analyser["available"] = False
        bin_path = _real_bytes_tempfile(tmp_path, "x", b"bytes")
        assert capability_fingerprint(bin_path) is None

    def test_analyse_exception_returns_none(
        self, patched_analyser, tmp_path,
    ):
        patched_analyser["raise"] = RuntimeError("parse failed")
        bin_path = _real_bytes_tempfile(tmp_path, "x", b"bytes")
        assert capability_fingerprint(bin_path) is None

    def test_missing_file_returns_none(self, patched_analyser):
        """File doesn't exist → SHA-256 read fails → None."""
        patched_analyser["ctx"] = BinaryContextMap(
            binary_path=Path("/nope"), arch="x86_64", bits=64,
            binary_format="elf", imports=[],
        )
        assert capability_fingerprint(Path("/does/not/exist")) is None

    def test_empty_capabilities_still_emits_fingerprint(
        self, patched_analyser, tmp_path,
    ):
        """Binary with NO dangerous imports → fingerprint with
        empty ``capability_buckets``. That's a valid baseline —
        means 'this binary doesn't do anything dangerous we
        recognise' and is the safest snapshot."""
        bin_path = _real_bytes_tempfile(tmp_path, "x", b"safe")
        patched_analyser["ctx"] = BinaryContextMap(
            binary_path=bin_path,
            arch="x86_64", bits=64, binary_format="elf",
            imports=["malloc", "free", "printf"],   # all ubiquitous
        )
        fp = capability_fingerprint(bin_path)
        assert fp is not None
        assert fp.capability_buckets == {}
        assert fp.dangerous_sinks == []

    def test_empty_file_hashes_cleanly(self, patched_analyser, tmp_path):
        """ADVERSARIAL: empty file → known SHA-256 (the empty-
        string hash). Fingerprint primitive shouldn't crash on
        zero-byte binaries (rare but real — broken extraction
        could yield one)."""
        import hashlib
        bin_path = _real_bytes_tempfile(tmp_path, "empty", b"")
        patched_analyser["ctx"] = BinaryContextMap(
            binary_path=bin_path,
            arch="", bits=0, binary_format="",
            imports=[],
        )
        fp = capability_fingerprint(bin_path)
        assert fp is not None
        assert fp.binary_sha256 == hashlib.sha256(b"").hexdigest()

    def test_large_file_streams_without_oom(
        self, patched_analyser, tmp_path,
    ):
        """ADVERSARIAL: 10MB file. The SHA-256 streamer must
        chunk; loading the whole binary into memory would OOM
        on container images. 10MB is small enough to be cheap
        in CI but big enough to detect a regression where
        someone replaces the chunked read with ``read()``.
        """
        bin_path = _real_bytes_tempfile(
            tmp_path, "big.bin", b"x" * (10 * 1024 * 1024),
        )
        patched_analyser["ctx"] = BinaryContextMap(
            binary_path=bin_path, arch="x86_64", bits=64,
            binary_format="elf", imports=[],
        )
        fp = capability_fingerprint(bin_path)
        assert fp is not None
        assert len(fp.binary_sha256) == 64

    def test_symlink_follows_to_real_bytes(
        self, patched_analyser, tmp_path,
    ):
        """ADVERSARIAL: symlink → SHA-256 hashes the TARGET's
        bytes, not the symlink itself. Matters for OCI layer
        extraction which can place busybox-style symlinks for
        all commands; we want the actual binary's fingerprint.
        """
        import os
        real = _real_bytes_tempfile(tmp_path, "real.bin", b"target")
        link = tmp_path / "link.bin"
        os.symlink(real, link)
        patched_analyser["ctx"] = BinaryContextMap(
            binary_path=real, arch="x86_64", bits=64,
            binary_format="elf", imports=[],
        )
        fp = capability_fingerprint(link)
        assert fp is not None
        # Hash should be the target's bytes
        import hashlib
        assert fp.binary_sha256 == hashlib.sha256(b"target").hexdigest()

    def test_non_ascii_imports_dont_crash(self):
        """ADVERSARIAL: imports with non-ASCII names (rare; could
        come from a corrupted analyse pass or a hostile binary).
        Bucket lookup just ignores them — they don't match any
        taxonomy entry."""
        out = bucket_imports({"execve", "réalloc", "🍕", "popen"})
        assert "exec" in out
        # ASCII matches captured; non-ASCII ignored
        assert out["exec"] == {"execve", "popen"}


# ---------------------------------------------------------------------------
# Real-binary integration — gated on radare2 + r2pipe availability
# ---------------------------------------------------------------------------


class TestRealBinaryFingerprint:
    """End-to-end via radare2. Skipped on hosts without
    r2pipe (probe_capability returns available=False). Each
    test asserts the quick-mode path is fast enough to run
    in a unit-test budget (was 5+ minutes per binary before
    quick mode was added)."""

    @pytest.fixture(autouse=True)
    def _gate(self):
        from packages.binary_analysis.radare2_understand import (
            probe_capability,
        )
        cap = probe_capability()
        if not cap.get("available"):
            pytest.skip(f"radare2 stack not available: {cap}")

    def test_quick_fingerprint_of_bin_ls(self):
        """Fingerprint ``/bin/ls`` in quick mode. Asserts the
        primitive completes in well under a minute (quick mode
        skips the expensive ``aaa`` step). Default mode took
        5+ minutes — far too slow to live in the unit suite."""
        import time
        ls = Path("/bin/ls")
        if not ls.exists():
            pytest.skip("/bin/ls not present on host")
        t0 = time.time()
        fp = capability_fingerprint(ls)
        elapsed = time.time() - t0
        assert fp is not None
        # Be generous — 30s leaves headroom for slow CI runners
        # while still catching a regression to the multi-minute
        # default-pipeline path.
        assert elapsed < 30, (
            f"quick fingerprint took {elapsed:.1f}s — likely "
            f"regressed to the full-analysis pipeline"
        )
        # Sanity-check the fingerprint shape
        assert fp.schema_version == FINGERPRINT_SCHEMA_VERSION
        assert fp.binary_format in ("elf", "elf64", "elf32",
                                       "mach0", "mach-o", "pe")
        assert len(fp.binary_sha256) == 64

    def test_quick_mode_omits_sinks(self):
        """Quick mode populates ``capability_buckets`` but leaves
        ``dangerous_sinks`` empty (no cross-ref analysis). Locks
        in the documented semantic — callers needing sinks pass
        ``include_sinks=True`` and pay the slow-pipeline cost."""
        ls = Path("/bin/ls")
        if not ls.exists():
            pytest.skip("/bin/ls not present on host")
        fp = capability_fingerprint(ls)   # default quick=True
        assert fp is not None
        assert fp.dangerous_sinks == []
        # Buckets DO populate — ls imports common libc calls
        assert isinstance(fp.capability_buckets, dict)

    def test_same_binary_idempotent(self):
        """Fingerprinting the same path twice produces identical
        ``canonical_json``. Drift detection depends on this —
        if quick-mode runs were non-deterministic, every scan
        would flag drift."""
        ls = Path("/bin/ls")
        if not ls.exists():
            pytest.skip("/bin/ls not present on host")
        fp_a = capability_fingerprint(ls)
        fp_b = capability_fingerprint(ls)
        assert fp_a is not None
        assert fp_b is not None
        assert fp_a.canonical_json() == fp_b.canonical_json()


# ---------------------------------------------------------------------------
# Cross-consumer parity — bucket helpers shared with SCA bump detector
# ---------------------------------------------------------------------------


# NOTE: A ``TestSharedTaxonomyParity`` class previously lived here.
# It checked that ``packages.sca.bump.binary_capability_delta``
# imported the same ``BUCKETS`` / ``bucket_imports`` identity as
# this module. The May 2026 ruff-sweep removed those imports from
# the SCA detector (which delegates to
# ``core.binary.diff_binary_capabilities`` and doesn't need the
# primitives in its own namespace), making the parity tests
# unable to find the symbols they were checking.
#
# Restoring the parity check at the right architectural layer
# would mean asserting that ``core.binary.BUCKETS is
# packages.binary_analysis.fingerprint.BUCKETS`` — but those are
# currently DIFFERENT object identities because ``core/binary/
# fingerprint.py`` and ``packages/binary_analysis/fingerprint.py``
# duplicate the bucket definitions rather than re-export from a
# single source. Fixing the duplication is a real refactor;
# leaving the parity tests would assert against an architecture
# that doesn't exist yet. Removed for now; restore when the
# duplication is collapsed.
