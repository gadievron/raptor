"""Image capability-drift detector — SCA scan integration.

Substrate lives in :mod:`core.binary`:
  - :func:`core.binary.capability_fingerprint` — extract the
    fingerprint
  - :func:`core.binary.detect_drift` — diff two fingerprints
  - :func:`core.binary.save_fingerprint` / ``load_fingerprint``
    — persistent baseline store

This module wires those primitives into the SCA scan pipeline:
walks every image ref in the target, fingerprints its main
binary, compares against the stored baseline (if any), emits a
``SupplyChainFinding`` of kind ``image_capability_drift`` when
drift is detected, and updates the baseline.

Drift = re-tagged image whose digest moved to bytes with
different capabilities. The bumper can't catch this (no version
change in the manifest), but operators relying on mutable tags
like ``alpine:3.18`` get a warning when the bytes silently
change.

Co-Authored-By: Natalie Somersall <natalie.somersall@gmail.com>
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.binary import (
    CapabilityFingerprint,
    FingerprintDrift,
    capability_fingerprint,
    detect_drift,
    load_fingerprint,
    save_fingerprint,
)
from .bump.image_binary_extract import fetch_image_binary
from .dockerfile_from import find_all_image_refs
from .models import (
    Confidence,
    Dependency,
    PinStyle,
    Severity,
    SupplyChainFinding,
)

logger = logging.getLogger(__name__)


def detect_image_drift(
    target: Path,
    *,
    oci_client,
    fingerprint_store_dir: Path,
    out_fingerprints: Optional[Dict[str, CapabilityFingerprint]] = None,
) -> List[SupplyChainFinding]:
    """Walk every image ref in ``target``, fingerprint each,
    compare against ``fingerprint_store_dir``'s baseline, return
    one finding per drifted ref.

    First scan of a given ref: no baseline exists → no finding
    emitted, the fingerprint is stored as the new baseline.

    Subsequent scans: baseline loaded, current fingerprint
    computed, drift compared. If drift is non-empty (bucket
    additions / removals / metadata change), emit a
    ``image_capability_drift`` finding. Either way, store the
    current fingerprint as the new baseline so the next scan
    compares against it.

    Returns ``[]`` on any infrastructure failure (extract /
    fingerprint / store I/O) — drift is best-effort enrichment,
    not load-bearing, and a partial result is more useful than
    a hard failure that drops the whole scan.

    ``out_fingerprints`` — optional dict the caller can pass to
    capture the (ref → CapabilityFingerprint) mapping computed
    during the walk. Used by the SBOM emitter so consumers see
    the fingerprint on each container component. Refs that fail
    to extract / fingerprint are not added.
    """
    findings: List[SupplyChainFinding] = []
    try:
        ref_sources = find_all_image_refs(target)
    except Exception as e:                            # noqa: BLE001
        logger.warning(
            "sca.image_drift: image-ref enumeration failed: %s", e,
        )
        return findings

    # De-dup refs across multiple source files (the same image can
    # appear in Dockerfile + compose + helm chart).
    seen: set = set()
    for source in ref_sources:
        ref = source.image
        if not ref or ref in seen:
            continue
        seen.add(ref)
        try:
            finding, fp = _drift_for_ref(
                ref, oci_client=oci_client,
                fingerprint_store_dir=fingerprint_store_dir,
                declared_in=source.declared_in,
            )
        except Exception as e:                        # noqa: BLE001
            logger.warning(
                "sca.image_drift: drift check failed for %s: %s",
                ref, e,
            )
            continue
        if fp is not None and out_fingerprints is not None:
            out_fingerprints[ref] = fp
        if finding is not None:
            findings.append(finding)
    return findings


def _drift_for_ref(
    ref: str,
    *,
    oci_client,
    fingerprint_store_dir: Path,
    declared_in: Path,
) -> "tuple[Optional[SupplyChainFinding], Optional[CapabilityFingerprint]]":
    """Run the full drift check for one image ref. Returns a
    tuple ``(finding, fingerprint)`` so the caller can surface
    the fingerprint to the SBOM regardless of drift outcome.

    Outcomes:
      * (None, fp)      — first-ever scan; baseline saved
      * (None, fp)      — no drift; baseline refreshed
      * (Finding, fp)   — drift detected; baseline replaced
      * (None, None)    — extract / fingerprint failed
    """
    binary = fetch_image_binary(ref, client=oci_client)
    if binary is None:
        logger.debug(
            "sca.image_drift: could not extract binary from %s", ref,
        )
        return None, None
    try:
        current = capability_fingerprint(binary)
    finally:
        # The extracted binary is in a tempdir; clean up so a
        # full scan doesn't accumulate gigabytes.
        try:
            binary.unlink()
        except OSError:
            pass
    if current is None:
        logger.debug(
            "sca.image_drift: could not fingerprint %s", ref,
        )
        return None, None

    baseline = load_fingerprint(fingerprint_store_dir, ref)
    # Always save the new fingerprint AFTER computing the drift
    # — the previous baseline is what we compare against, then
    # the current fingerprint becomes the next-scan baseline.
    save_fingerprint(fingerprint_store_dir, ref, current)
    if baseline is None:
        # First scan of this ref — no baseline, no signal yet.
        logger.debug(
            "sca.image_drift: first baseline for %s; no drift signal",
            ref,
        )
        return None, current

    drift = detect_drift(baseline, current)
    if drift.is_empty():
        return None, current

    finding = _drift_finding(
        ref=ref, drift=drift, declared_in=declared_in,
    )
    return finding, current


def _drift_finding(
    *, ref: str, drift: FingerprintDrift, declared_in: Path,
) -> SupplyChainFinding:
    """Wrap a :class:`FingerprintDrift` in the SCA-specific
    finding shape. Severity ``high`` for exec / network adds;
    ``medium`` for anything else (other-bucket adds, removals,
    metadata changes)."""
    severity: Severity = "high" if drift.high_severity() else "medium"

    detail_parts: List[str] = []
    if drift.new_buckets:
        detail_parts.append(
            "new dangerous-import buckets: "
            + ", ".join(drift.added_buckets())
        )
    if drift.removed_buckets:
        detail_parts.append(
            "removed buckets: "
            + ", ".join(drift.removed_bucket_names())
        )
    if drift.arch_changed:
        detail_parts.append("arch changed")
    if drift.bits_changed:
        detail_parts.append("bits changed")
    if drift.format_changed:
        detail_parts.append("binary format changed")
    detail = "; ".join(detail_parts) or "image capabilities drifted"

    placeholder_dep = Dependency(
        ecosystem="Container",
        name=ref,
        version="<drift>",
        declared_in=declared_in,
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:container/{ref}",
        parser_confidence=Confidence(
            "high",
            reason="image-drift synthetic dep",
        ),
    )

    evidence: Dict[str, Any] = {
        "ref": ref,
        "new_dangerous_imports": drift.new_buckets,
        "removed_buckets": drift.removed_buckets,
        "added_buckets": drift.added_buckets(),
        "removed_bucket_names": drift.removed_bucket_names(),
        "arch_changed": drift.arch_changed,
        "bits_changed": drift.bits_changed,
        "format_changed": drift.format_changed,
    }

    # Encode the ref hash in the finding_id rather than the ref
    # itself (refs contain ``/`` and ``:`` that downstream
    # consumers' deduping doesn't tolerate uniformly).
    import hashlib
    ref_hash = hashlib.sha256(ref.encode("utf-8")).hexdigest()[:16]
    return SupplyChainFinding(
        finding_id=f"sca:scan:image_capability_drift:{ref_hash}",
        kind="image_capability_drift",
        dependency=placeholder_dep,
        detail=detail,
        evidence=evidence,
        severity=severity,
        confidence=Confidence(
            "medium",
            reason=(
                "radare2 / native ELF capability surface diff "
                "vs stored baseline; static signal only"
            ),
        ),
    )


__all__ = [
    "detect_image_drift",
]
