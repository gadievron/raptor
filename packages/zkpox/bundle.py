"""ZKPoX Tier 0/1 — prover-ready bundle assembly.

Once a witness is eligible (see :mod:`packages.zkpox.eligibility`),
the bundle is the stable hand-off shape that every higher tier
(1.5 reproduction, 2 RISC-V, 3 SP1) consumes. Assembly is **on
request** in the design's trigger model — it produces a persistent
artifact on disk, so the operator asks for it rather than getting
it automatically.

A bundle gathers everything a prover needs *about* the claim:

  * the witness bytes (the secret the ZK tiers will hide; held in
    the clear at Tier 0/1),
  * the target artefact hashes (binary / source),
  * the observed outcome + detail,
  * provenance (source pipeline, produced_by, timestamp),
  * a Tier-1 attestation: the structured claim itself.

A bundle is NOT a proof. Tier 0/1 is attestation-only — "I assert
this". The cryptographic strength comes at Tier 3. The bundle is
the substrate the prover reads.

The full tier model lives in the package docstring
(``packages/zkpox/__init__.py``).
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from core.witness.store import WitnessStore
from core.witness.types import Witness

from packages.zkpox.eligibility import is_zkpox_eligible


# A witness identity is always a sha256 hex digest. We use it as a
# path component (bundle dir name), so anything that isn't a clean
# 64-char lowercase hex string is rejected — a corrupt / malicious
# value containing ``/`` or ``..`` must never reach ``Path(...)``
# where it could escape the output tree. Honest data always matches.
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


class ZKPoXBundleError(Exception):
    """Raised when a bundle can't be assembled (ineligible witness,
    missing bytes, etc.)."""


def _require_clean_hash(witness_hash: str) -> None:
    """Reject a witness_hash that isn't a bare sha256 hex digest.

    Defends the path construction in :func:`write_bundle` against
    traversal: the hash is used as a directory name, so a value
    with ``..`` / ``/`` segments could otherwise ``mkdir`` outside
    the intended output tree.
    """
    if not isinstance(witness_hash, str) or not _SHA256_HEX.match(witness_hash):
        raise ZKPoXBundleError(
            f"witness_hash {witness_hash!r} is not a sha256 hex "
            f"digest; refusing to use it as a path component"
        )


@dataclass
class ZKPoXBundle:
    """A Tier 0/1 prover-ready bundle for one witness.

    ``tier`` starts at ``"0/1"`` (attestation). The reproduction
    step (Tier 1.5) upgrades a persisted bundle by attaching a
    ``reproduction`` block and bumping ``tier`` — this dataclass
    carries the slot but leaves it ``None`` at assembly time.
    """
    witness_hash: str
    witness_len: int
    source: str               # WitnessSource value
    observed_outcome: str     # WitnessOutcome value
    outcome_detail: Dict[str, Any]
    target_binary_hash: Optional[str]
    target_source_hash: Optional[str]
    produced_by: Optional[str]
    timestamp: Optional[str]
    attestation: Dict[str, Any]
    tier: str = "0/1"
    reproduction: Optional[Dict[str, Any]] = None

    def as_dict(self) -> dict:
        return asdict(self)


def _build_attestation(witness: Witness) -> Dict[str, Any]:
    """The Tier-1 claim, stated plainly. No crypto — this is the
    assertion a Tier-3 proof would later make zero-knowledge."""
    target = witness.target_binary_hash or witness.target_source_hash
    target_kind = (
        "binary" if witness.target_binary_hash else "source"
    )
    return {
        "claim": (
            f"input with sha256 {witness.bytes_hash} makes the "
            f"{target_kind} artefact (sha256 {target}) exhibit "
            f"outcome {witness.observed_outcome.value}"
        ),
        "witness_bytes_sha256": witness.bytes_hash,
        "target_artefact_sha256": target,
        "target_artefact_kind": target_kind,
        "observed_outcome": witness.observed_outcome.value,
        "attestation_only": True,
        "note": (
            "Tier 0/1 attestation — asserted, not proven. "
            "Cryptographic proof requires Tier 3 (SP1)."
        ),
    }


def assemble_bundle(
    witness: Witness,
    store: WitnessStore,
) -> ZKPoXBundle:
    """Assemble a Tier 0/1 bundle for ``witness``.

    Raises :class:`ZKPoXBundleError` if the witness is ineligible
    or its bytes blob is missing from ``store`` (can't assemble a
    bundle whose subject bytes we can't retrieve).

    The bytes themselves are NOT inlined into the returned bundle
    object (they may be large); :func:`write_bundle` copies the
    blob alongside the manifest on persist.
    """
    _require_clean_hash(witness.bytes_hash)

    verdict = is_zkpox_eligible(witness)
    if not verdict.eligible:
        raise ZKPoXBundleError(
            f"witness {witness.bytes_hash[:16]} ineligible: "
            f"{verdict.reason}"
        )

    # Confirm the bytes are retrievable — a bundle for bytes we
    # can't produce is useless to a prover.
    if store.blob_path(witness.bytes_hash) is None:
        raise ZKPoXBundleError(
            f"witness {witness.bytes_hash[:16]} bytes blob missing "
            f"from store; cannot assemble bundle"
        )

    return ZKPoXBundle(
        witness_hash=witness.bytes_hash,
        witness_len=witness.bytes_len,
        source=witness.source.value,
        observed_outcome=witness.observed_outcome.value,
        outcome_detail=(
            dict(witness.outcome_detail)
            if isinstance(witness.outcome_detail, dict) else {}
        ),
        target_binary_hash=witness.target_binary_hash,
        target_source_hash=witness.target_source_hash,
        produced_by=witness.produced_by,
        timestamp=(
            witness.timestamp.isoformat()
            if witness.timestamp is not None else None
        ),
        attestation=_build_attestation(witness),
    )


def write_bundle(
    bundle: ZKPoXBundle,
    store: WitnessStore,
    out_dir: Path,
) -> Path:
    """Persist a bundle under ``out_dir/zkpox/<witness_hash>/``.

    Layout mirrors the WitnessStore convention:

        <out_dir>/zkpox/<witness_hash>/
            manifest.json      # the ZKPoXBundle
            witness.bin        # the raw witness bytes (copied from store)

    Returns the bundle directory path. The bytes are copied so the
    bundle is self-contained — a prover (or an operator handing the
    bundle off) doesn't need the original WitnessStore.
    """
    # Re-validate before using the hash as a path component — a
    # caller could have mutated bundle.witness_hash after assembly.
    _require_clean_hash(bundle.witness_hash)
    bundle_dir = Path(out_dir) / "zkpox" / bundle.witness_hash
    bundle_dir.mkdir(parents=True, exist_ok=True)

    # Copy the witness bytes into the bundle (self-contained).
    data = store.get_bytes(bundle.witness_hash)
    (bundle_dir / "witness.bin").write_bytes(data)

    manifest_path = bundle_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(bundle.as_dict(), indent=2),
        encoding="utf-8",
    )
    return bundle_dir


def render_bundle(bundle: ZKPoXBundle) -> str:
    """Console-friendly one-block view of a bundle."""
    lines = [
        f"ZKPoX bundle (tier {bundle.tier}):",
        f"   witness:  {bundle.witness_hash[:16]}... "
        f"({bundle.witness_len}B, source={bundle.source})",
        f"   outcome:  {bundle.observed_outcome}",
        "   target:   "
        + (
            f"binary {bundle.target_binary_hash[:16]}..."
            if bundle.target_binary_hash
            else f"source {bundle.target_source_hash[:16]}..."
            if bundle.target_source_hash else "none"
        ),
        f"   claim:    {bundle.attestation['claim']}",
    ]
    if bundle.reproduction is not None:
        rep = bundle.reproduction
        lines.append(
            f"   reproduced: {rep.get('reproduced')} "
            f"({rep.get('runs')} runs)"
        )
    return "\n".join(lines)
