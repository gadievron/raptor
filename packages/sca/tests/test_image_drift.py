"""Tests for ``packages.sca.image_drift``.

The drift detector wires the substrate (``core.binary``) into
the SCA scan pipeline: enumerate image refs, fingerprint each,
diff vs baseline, emit findings. Tests stub the OCI binary
extraction + ELF parsing so the suite doesn't require radare2 /
r2pipe / actual image registries.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.binary import CapabilityFingerprint, save_fingerprint
from core.binary.fingerprint import FINGERPRINT_SCHEMA_VERSION
from packages.sca.image_drift import detect_image_drift


def _fp(*, sha="abc", buckets=None) -> CapabilityFingerprint:
    return CapabilityFingerprint(
        schema_version=FINGERPRINT_SCHEMA_VERSION,
        binary_path="/extracted",
        binary_sha256=sha,
        arch="x86", bits=64, binary_format="elf",
        capability_buckets=buckets or {},
    )


class _StubImageRefSource:
    """Mimic ``dockerfile_from.ImageRefSource``."""

    def __init__(self, image: str, declared_in: Path):
        self.image = image
        self.declared_in = declared_in
        self.source_kind = "dockerfile_from"
        self.stage_name = None


@pytest.fixture
def stub_pipeline(monkeypatch, tmp_path):
    """Patch the three external calls the drift detector makes:
    ``find_all_image_refs``, ``fetch_image_binary``,
    ``capability_fingerprint``. Returns a state dict with helpers
    to register refs + their fingerprints."""
    state = {
        "refs": [],
        "fingerprints": {},     # image_ref → CapabilityFingerprint
        "extract_failures": set(),
    }

    def fake_find_refs(target):
        return state["refs"]

    def fake_fetch_binary(ref, *, client, **kwargs):
        if ref in state["extract_failures"]:
            return None
        # Write a tempfile to mimic the real extraction. The
        # drift detector uses this only for fingerprint input
        # and then unlinks it; we just need ANY existing file
        # to pass the unlink + read steps.
        p = tmp_path / f"extracted-{ref.replace('/', '_').replace(':', '-')}"
        p.write_bytes(b"stub-bytes")
        return p

    def fake_fingerprint(path):
        # Look up by the path the fetch fixture wrote — we
        # encoded the ref into the filename.
        for ref, fp in state["fingerprints"].items():
            encoded = ref.replace("/", "_").replace(":", "-")
            if encoded in path.name:
                return fp
        return None

    monkeypatch.setattr(
        "packages.sca.image_drift.find_all_image_refs",
        fake_find_refs,
    )
    monkeypatch.setattr(
        "packages.sca.image_drift.fetch_image_binary",
        fake_fetch_binary,
    )
    monkeypatch.setattr(
        "packages.sca.image_drift.capability_fingerprint",
        fake_fingerprint,
    )
    yield state


class TestFirstScanNoFinding:
    """First-ever scan: no baseline. Detector stores the
    fingerprint but emits no drift signal (nothing to compare
    against)."""

    def test_no_finding_on_first_scan(
        self, stub_pipeline, tmp_path,
    ):
        ref = "docker.io/library/alpine:3.18"
        stub_pipeline["refs"] = [
            _StubImageRefSource(ref, tmp_path / "Dockerfile"),
        ]
        stub_pipeline["fingerprints"][ref] = _fp(
            sha="A", buckets={"alloc": ["calloc"]},
        )
        store_dir = tmp_path / "fp_store"
        findings = detect_image_drift(
            tmp_path,
            oci_client=object(),
            fingerprint_store_dir=store_dir,
        )
        assert findings == []
        # Baseline was saved
        from core.binary import load_fingerprint
        baseline = load_fingerprint(store_dir, ref)
        assert baseline is not None
        assert baseline.binary_sha256 == "A"


class TestSecondScanDriftDetected:
    def test_high_severity_drift_on_exec_add(
        self, stub_pipeline, tmp_path,
    ):
        """Baseline shows alloc only; new scan adds exec capability
        → high-severity image_capability_drift finding."""
        ref = "docker.io/library/alpine:3.18"
        store_dir = tmp_path / "fp_store"

        baseline = _fp(sha="A", buckets={"alloc": ["calloc"]})
        save_fingerprint(store_dir, ref, baseline)

        new_fp = _fp(
            sha="B",
            buckets={"alloc": ["calloc"], "exec": ["execve"]},
        )
        stub_pipeline["refs"] = [
            _StubImageRefSource(ref, tmp_path / "Dockerfile"),
        ]
        stub_pipeline["fingerprints"][ref] = new_fp

        findings = detect_image_drift(
            tmp_path,
            oci_client=object(),
            fingerprint_store_dir=store_dir,
        )
        assert len(findings) == 1
        f = findings[0]
        assert f.kind == "image_capability_drift"
        assert f.severity == "high"
        assert f.evidence["new_dangerous_imports"] == {
            "exec": ["execve"],
        }
        assert f.evidence["added_buckets"] == ["exec"]
        # Baseline updated
        from core.binary import load_fingerprint
        baseline2 = load_fingerprint(store_dir, ref)
        assert baseline2.binary_sha256 == "B"

    def test_medium_severity_drift_on_string_overflow_add(
        self, stub_pipeline, tmp_path,
    ):
        ref = "docker.io/library/x:1"
        store_dir = tmp_path / "fp_store"
        save_fingerprint(
            store_dir, ref, _fp(sha="A", buckets={}),
        )
        stub_pipeline["refs"] = [
            _StubImageRefSource(ref, tmp_path / "Dockerfile"),
        ]
        stub_pipeline["fingerprints"][ref] = _fp(
            sha="B", buckets={"string_overflow": ["strcpy"]},
        )
        findings = detect_image_drift(
            tmp_path, oci_client=object(),
            fingerprint_store_dir=store_dir,
        )
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_no_finding_when_bytes_unchanged(
        self, stub_pipeline, tmp_path,
    ):
        """Same SHA → no drift signal even if (impossibly) the
        bucket dict differs. Defends against legitimate-rebuild
        noise."""
        ref = "x"
        store_dir = tmp_path / "fp_store"
        save_fingerprint(
            store_dir, ref, _fp(sha="A", buckets={"alloc": ["calloc"]}),
        )
        stub_pipeline["refs"] = [
            _StubImageRefSource(ref, tmp_path / "Dockerfile"),
        ]
        stub_pipeline["fingerprints"][ref] = _fp(
            sha="A", buckets={"exec": ["execve"]},
        )
        findings = detect_image_drift(
            tmp_path, oci_client=object(),
            fingerprint_store_dir=store_dir,
        )
        assert findings == []


class TestFailureModes:
    def test_extract_failure_no_finding(self, stub_pipeline, tmp_path):
        """OCI extraction fails (image deleted / private /
        unreachable) → no finding for that ref, scan continues."""
        ref = "docker.io/missing:1"
        stub_pipeline["refs"] = [
            _StubImageRefSource(ref, tmp_path / "Dockerfile"),
        ]
        stub_pipeline["extract_failures"].add(ref)
        findings = detect_image_drift(
            tmp_path, oci_client=object(),
            fingerprint_store_dir=tmp_path / "store",
        )
        assert findings == []

    def test_fingerprint_failure_no_finding(
        self, stub_pipeline, tmp_path,
    ):
        """Binary extracts but fingerprint returns None (corrupt
        binary, unsupported format)."""
        ref = "x"
        stub_pipeline["refs"] = [
            _StubImageRefSource(ref, tmp_path / "Dockerfile"),
        ]
        # No entry in fingerprints → fake_fingerprint returns None
        findings = detect_image_drift(
            tmp_path, oci_client=object(),
            fingerprint_store_dir=tmp_path / "store",
        )
        assert findings == []

    def test_find_refs_failure_returns_empty(
        self, monkeypatch, tmp_path,
    ):
        """``find_all_image_refs`` raising → empty result, no
        crash."""
        def boom(target):
            raise RuntimeError("walker crashed")
        monkeypatch.setattr(
            "packages.sca.image_drift.find_all_image_refs",
            boom,
        )
        findings = detect_image_drift(
            tmp_path, oci_client=object(),
            fingerprint_store_dir=tmp_path / "store",
        )
        assert findings == []


class TestDeduplication:
    def test_same_ref_in_multiple_sources_processed_once(
        self, stub_pipeline, tmp_path,
    ):
        """Image ref appears in Dockerfile + compose + helm → drift
        check runs once. Otherwise we'd emit duplicate findings
        and the baseline would be saved 3×."""
        ref = "x"
        stub_pipeline["refs"] = [
            _StubImageRefSource(ref, tmp_path / "Dockerfile"),
            _StubImageRefSource(ref, tmp_path / "docker-compose.yml"),
            _StubImageRefSource(ref, tmp_path / "helm/Chart.yaml"),
        ]
        store_dir = tmp_path / "store"
        save_fingerprint(
            store_dir, ref, _fp(sha="A", buckets={}),
        )
        stub_pipeline["fingerprints"][ref] = _fp(
            sha="B", buckets={"exec": ["execve"]},
        )
        findings = detect_image_drift(
            tmp_path, oci_client=object(),
            fingerprint_store_dir=store_dir,
        )
        # ONE finding despite three sources
        assert len(findings) == 1


class TestMultipleRefs:
    def test_multiple_refs_independent_baselines(
        self, stub_pipeline, tmp_path,
    ):
        ref_a = "alpine:3.18"
        ref_b = "debian:12"
        store_dir = tmp_path / "store"
        # Both have baselines
        save_fingerprint(store_dir, ref_a, _fp(sha="A1", buckets={}))
        save_fingerprint(store_dir, ref_b, _fp(sha="B1", buckets={}))
        # alpine drifts, debian doesn't
        stub_pipeline["refs"] = [
            _StubImageRefSource(ref_a, tmp_path / "Dockerfile.a"),
            _StubImageRefSource(ref_b, tmp_path / "Dockerfile.b"),
        ]
        stub_pipeline["fingerprints"][ref_a] = _fp(
            sha="A2", buckets={"exec": ["execve"]},
        )
        stub_pipeline["fingerprints"][ref_b] = _fp(
            sha="B1", buckets={},   # same bytes
        )
        findings = detect_image_drift(
            tmp_path, oci_client=object(),
            fingerprint_store_dir=store_dir,
        )
        # Only alpine drifted
        assert len(findings) == 1
        assert findings[0].evidence["ref"] == ref_a
