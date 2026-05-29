"""Tests for packages.zkpox.disclosure — the Tier 2/3 CBOR schema and
the ZKPoXBundle → DisclosureBundle projection.

Covers the review-driven invariants: the projection reads the manifest
(it does not rebuild from flags), the Tier 1.5 reproduction evidence
reaches the disclosure bundle's provenance, the target hash is derived
from the manifest (normalised to sha256:HEX), and the target
reconciliation helper rejects a mismatched artifact.
"""

from __future__ import annotations

import pytest

pytest.importorskip("cbor2")

from packages.zkpox.bundle import ZKPoXBundle
from packages.zkpox.disclosure import (
    BUNDLE_VERSION,
    DisclosureBundle,
    HarnessRef,
    Proof,
    VendorEnvelope,
    disclosure_from_manifest,
    from_cbor,
    manifest_target_bare_hex,
    target_hash_matches,
    to_cbor,
)


def _manifest(**overrides) -> ZKPoXBundle:
    base = dict(
        witness_hash="b" * 64,
        witness_len=42,
        source="fuzz",
        observed_outcome="exit_signal",
        outcome_detail={"finding_id": "F1"},
        target_binary_hash="a" * 64,  # bare hex (the form core.hash emits)
        target_source_hash=None,
        produced_by="raptor",
        timestamp=None,
        attestation={"claim": "input X makes Y crash"},
        tier="0/1",
        reproduction=None,
    )
    base.update(overrides)
    return ZKPoXBundle(**base)


def _empty_envelope() -> VendorEnvelope:
    return VendorEnvelope(
        scheme="zkpox-none/v1", aes_blob=b"", ct_K_age=b"", ct_K_tlock=b"",
        drand_round_min=None, vendor_pubkey="", vendor_pubkey_fingerprint="sha256:",
    )


def _project(manifest: ZKPoXBundle) -> DisclosureBundle:
    return disclosure_from_manifest(
        manifest,
        proof=Proof(system="sp1-groth16/v6.1.0", bytes=b"\x01\x02",
                    verifier_key_hash="sha256:dead"),
        vendor_envelope=_empty_envelope(),
        harness=HarnessRef(git_url=None, rev=None, hash="sha256:beef"),
        vuln_class="memory-safety",
        gadget_id="memory-safety::oob-write@0.1.0",
        gadget_id_hash="sha256:abc",
        leaked_fields=[],
        target_kind="elf",
    )


# ---------------------------------------------------------------------------
# Projection derives from the manifest (not from flags)
# ---------------------------------------------------------------------------

def test_projection_normalises_bare_hex_target():
    """Manifest stores bare hex; the CBOR Target.hash must be the
    proposal's sha256:HEX form."""
    db = _project(_manifest(target_binary_hash="a" * 64))
    assert db.target.hash == "sha256:" + "a" * 64
    assert db.version == BUNDLE_VERSION


def test_projection_tolerates_already_prefixed_hash():
    db = _project(_manifest(target_binary_hash="sha256:" + "c" * 64))
    assert db.target.hash == "sha256:" + "c" * 64


def test_projection_carries_tier15_reproduction_into_provenance():
    """The core review point: reproduction evidence must reach the
    disclosure bundle, not be dropped."""
    repro = {"reproduced": True, "runs": 5, "deterministic": True}
    db = _project(_manifest(tier="1.5", reproduction=repro))
    assert db.provenance is not None
    assert db.provenance["reproduction"] == repro
    assert db.provenance["tier"] == "1.5"
    assert db.provenance["observed_outcome"] == "exit_signal"
    assert db.provenance["attestation"]["claim"] == "input X makes Y crash"


def test_projection_provenance_omits_reproduction_when_absent():
    db = _project(_manifest(reproduction=None))
    assert db.provenance is not None
    assert "reproduction" not in db.provenance


def test_projection_binary_hash_wins_over_source():
    db = _project(_manifest(
        target_binary_hash="a" * 64, target_source_hash="d" * 64,
    ))
    assert db.target.hash == "sha256:" + "a" * 64
    assert db.target.metadata["target_artefact_kind"] == "binary"


def test_projection_uses_source_hash_when_no_binary():
    db = _project(_manifest(
        target_binary_hash=None, target_source_hash="d" * 64,
    ))
    assert db.target.hash == "sha256:" + "d" * 64
    assert db.target.metadata["target_artefact_kind"] == "source"


def test_projection_errors_without_any_target_hash():
    with pytest.raises(ValueError, match="neither target_binary_hash"):
        _project(_manifest(target_binary_hash=None, target_source_hash=None))


# ---------------------------------------------------------------------------
# CBOR round-trip preserves the new provenance field
# ---------------------------------------------------------------------------

def test_provenance_survives_cbor_round_trip():
    repro = {"reproduced": True, "runs": 3}
    db = _project(_manifest(tier="1.5", reproduction=repro))
    restored = from_cbor(to_cbor(db))
    assert restored.provenance["reproduction"] == repro
    assert restored.target.hash == db.target.hash
    assert restored.version == db.version


def test_bundle_without_provenance_round_trips():
    """A hand-built DisclosureBundle with provenance=None must still
    encode/decode (provenance omitted from CBOR like timestamp)."""
    db = DisclosureBundle(
        version=BUNDLE_VERSION,
        target=_project(_manifest()).target,
        vulnerability=_project(_manifest()).vulnerability,
        proof=Proof(system="s", bytes=b"\x00", verifier_key_hash="sha256:x"),
        harness=HarnessRef(git_url=None, rev=None, hash="sha256:y"),
        vendor_envelope=_empty_envelope(),
    )
    assert db.provenance is None
    assert from_cbor(to_cbor(db)).provenance is None


# ---------------------------------------------------------------------------
# Target reconciliation (anti re-keying)
# ---------------------------------------------------------------------------

def test_target_hash_matches_accepts_same_artifact():
    m = _manifest(target_binary_hash="a" * 64)
    assert target_hash_matches(m, "a" * 64) is True


def test_target_hash_matches_rejects_different_artifact():
    m = _manifest(target_binary_hash="a" * 64)
    assert target_hash_matches(m, "f" * 64) is False


def test_target_hash_matches_tolerates_prefixed_manifest_hash():
    m = _manifest(target_binary_hash="sha256:" + "a" * 64)
    assert manifest_target_bare_hex(m) == "a" * 64
    assert target_hash_matches(m, "a" * 64) is True


def test_target_hash_matches_when_manifest_has_no_hash():
    """Nothing to reconcile against → vacuously matches (the projection
    is what rejects a hash-less manifest)."""
    m = _manifest(target_binary_hash=None, target_source_hash=None)
    assert manifest_target_bare_hex(m) is None
    assert target_hash_matches(m, "a" * 64) is True
