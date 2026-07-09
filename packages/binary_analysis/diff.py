"""Evidence-backed diffing between compiled targets."""

from __future__ import annotations

from typing import Any

from .manifest import BinaryManifest


def diff_manifests(base: BinaryManifest, head: BinaryManifest) -> dict[str, Any]:
    base_imports = set(base.imports)
    head_imports = set(head.imports)
    base_signals = {(item.family, item.marker) for item in base.runtime_signals}
    head_signals = {(item.family, item.marker) for item in head.runtime_signals}
    return {
        "base": {
            "binary_path": base.binary_path,
            "binary_sha256": base.binary_sha256,
            "target_kind": base.target_kind,
            "arch": base.arch,
            "bits": base.bits,
            "binary_format": base.binary_format,
        },
        "head": {
            "binary_path": head.binary_path,
            "binary_sha256": head.binary_sha256,
            "target_kind": head.target_kind,
            "arch": head.arch,
            "bits": head.bits,
            "binary_format": head.binary_format,
        },
        "bytes_changed": base.binary_sha256 != head.binary_sha256,
        "metadata_changed": {
            "target_kind": base.target_kind != head.target_kind,
            "arch": base.arch != head.arch,
            "bits": base.bits != head.bits,
            "binary_format": base.binary_format != head.binary_format,
        },
        "imports": {
            "added": sorted(head_imports - base_imports),
            "removed": sorted(base_imports - head_imports),
        },
        "capability_buckets": {
            "added": {
                bucket: sorted(set(values) - set(base.capability_buckets.get(bucket, [])))
                for bucket, values in head.capability_buckets.items()
                if set(values) - set(base.capability_buckets.get(bucket, []))
            },
            "removed": {
                bucket: sorted(set(values) - set(head.capability_buckets.get(bucket, [])))
                for bucket, values in base.capability_buckets.items()
                if set(values) - set(head.capability_buckets.get(bucket, []))
            },
        },
        "runtime_signals": {
            "added": [
                {"family": family, "marker": marker}
                for family, marker in sorted(head_signals - base_signals)
            ],
            "removed": [
                {"family": family, "marker": marker}
                for family, marker in sorted(base_signals - head_signals)
            ],
        },
        "interpretation": (
            "This is a byte/import/runtime-marker diff only. "
            "It does not claim a new path is reachable or exploitable."
        ),
    }


__all__ = ["diff_manifests"]
