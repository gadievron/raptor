"""Tests for ``packages.zkpox.bundle`` — Tier 0/1 prover-ready
bundle assembly + persistence."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


# packages/zkpox/tests/test_bundle.py → parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from core.witness.store import WitnessStore  # noqa: E402
from core.witness.types import (  # noqa: E402
    Witness,
    WitnessOutcome,
    WitnessSource,
    compute_bytes_hash,
)
from packages.zkpox.bundle import (  # noqa: E402
    ZKPoXBundleError,
    assemble_bundle,
    render_bundle,
    write_bundle,
)


def _store_with_witness(
    tmp_path: Path,
    *,
    outcome: WitnessOutcome = WitnessOutcome.EXIT_SIGNAL,
    target_binary_hash="a" * 64,
    target_source_hash=None,
    data: bytes = b"crash-input",
    source: WitnessSource = WitnessSource.FUZZ,
):
    store = WitnessStore(tmp_path / "witnesses")
    w = Witness(
        bytes_hash=compute_bytes_hash(data),
        bytes_len=len(data),
        source=source,
        observed_outcome=outcome,
        outcome_detail={"finding_id": "FIND-1", "signal": "SIGSEGV"},
        target_binary_hash=target_binary_hash,
        target_source_hash=target_source_hash,
        produced_by="afl++",
    )
    store.put(w, data)
    return store, w


# ----------------------------------------------------------------------
# Assembly
# ----------------------------------------------------------------------


def test_assemble_eligible_witness(tmp_path):
    store, w = _store_with_witness(tmp_path)
    bundle = assemble_bundle(w, store)
    assert bundle.witness_hash == w.bytes_hash
    assert bundle.tier == "0/1"
    assert bundle.observed_outcome == "exit_signal"
    assert bundle.target_binary_hash == "a" * 64
    assert bundle.reproduction is None
    # Attestation carries the plain claim
    assert "exhibit outcome exit_signal" in bundle.attestation["claim"]
    assert bundle.attestation["attestation_only"] is True
    assert bundle.attestation["target_artefact_kind"] == "binary"


def test_assemble_source_target(tmp_path):
    store, w = _store_with_witness(
        tmp_path, target_binary_hash=None, target_source_hash="b" * 64,
    )
    bundle = assemble_bundle(w, store)
    assert bundle.target_source_hash == "b" * 64
    assert bundle.attestation["target_artefact_kind"] == "source"


def test_assemble_ineligible_raises(tmp_path):
    """A NOT_RUN witness can't be bundled."""
    store, w = _store_with_witness(
        tmp_path, outcome=WitnessOutcome.NOT_RUN,
    )
    with pytest.raises(ZKPoXBundleError) as e:
        assemble_bundle(w, store)
    assert "ineligible" in str(e.value)


def test_assemble_missing_blob_raises(tmp_path):
    """Witness manifest exists but blob is gone → can't assemble."""
    store, w = _store_with_witness(tmp_path)
    # Delete the blob
    blob = store.blob_path(w.bytes_hash)
    blob.unlink()
    with pytest.raises(ZKPoXBundleError) as e:
        assemble_bundle(w, store)
    assert "bytes blob missing" in str(e.value)


# ----------------------------------------------------------------------
# Persistence
# ----------------------------------------------------------------------


def test_write_bundle_layout(tmp_path):
    store, w = _store_with_witness(tmp_path, data=b"the-crash-bytes")
    bundle = assemble_bundle(w, store)
    out = tmp_path / "out"
    bundle_dir = write_bundle(bundle, store, out)

    assert bundle_dir == out / "zkpox" / w.bytes_hash
    assert (bundle_dir / "manifest.json").is_file()
    assert (bundle_dir / "witness.bin").is_file()

    # Bytes copied verbatim (self-contained bundle)
    assert (bundle_dir / "witness.bin").read_bytes() == b"the-crash-bytes"

    # Manifest round-trips
    manifest = json.loads((bundle_dir / "manifest.json").read_text())
    assert manifest["witness_hash"] == w.bytes_hash
    assert manifest["tier"] == "0/1"
    assert manifest["observed_outcome"] == "exit_signal"
    assert manifest["attestation"]["attestation_only"] is True


def test_write_bundle_self_contained_bytes_match_hash(tmp_path):
    """The copied witness.bin must hash to the manifest's
    witness_hash — a prover handed just the bundle dir can verify
    integrity without the original store."""
    store, w = _store_with_witness(tmp_path, data=b"xyz" * 100)
    bundle = assemble_bundle(w, store)
    bundle_dir = write_bundle(bundle, store, tmp_path / "out")
    copied = (bundle_dir / "witness.bin").read_bytes()
    assert compute_bytes_hash(copied) == bundle.witness_hash


# ----------------------------------------------------------------------
# Render
# ----------------------------------------------------------------------


def test_render_bundle_includes_claim(tmp_path):
    store, w = _store_with_witness(tmp_path)
    bundle = assemble_bundle(w, store)
    out = render_bundle(bundle)
    assert "tier 0/1" in out
    assert "exit_signal" in out
    assert "claim:" in out


def test_render_bundle_shows_reproduction_when_present(tmp_path):
    store, w = _store_with_witness(tmp_path)
    bundle = assemble_bundle(w, store)
    bundle.reproduction = {"reproduced": True, "runs": 3}
    out = render_bundle(bundle)
    assert "reproduced: True" in out


# ----------------------------------------------------------------------
# Path-traversal defense
# ----------------------------------------------------------------------


def test_write_bundle_rejects_traversal_hash(tmp_path):
    """A mutated/corrupt witness_hash containing path-traversal
    segments must NOT cause write_bundle to mkdir outside the
    output tree. Pre-fix the mkdir(parents=True) ran on the
    escaped path before the blob lookup raised — creating a dir
    in the wrong place. Post-fix _require_clean_hash rejects any
    non-sha256-hex value before any path is touched."""
    store, w = _store_with_witness(tmp_path)
    bundle = assemble_bundle(w, store)
    bundle.witness_hash = "../../../../tmp/zkpox_traversal_probe"
    out = tmp_path / "out"
    with pytest.raises(ZKPoXBundleError) as e:
        write_bundle(bundle, store, out)
    assert "not a sha256 hex digest" in str(e.value)
    assert not Path("/tmp/zkpox_traversal_probe").exists()


def test_assemble_rejects_non_hex_hash(tmp_path):
    """assemble_bundle validates the hash up-front too — a witness
    whose bytes_hash isn't a clean digest is refused."""
    store, w = _store_with_witness(tmp_path)
    # Forge a bad hash on the witness object
    object.__setattr__(w, "bytes_hash", "not-a-real-hash")
    with pytest.raises(ZKPoXBundleError) as e:
        assemble_bundle(w, store)
    assert "not a sha256 hex digest" in str(e.value)
