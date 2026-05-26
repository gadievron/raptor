"""Capability fingerprint for a single binary.

A *fingerprint* is a small, stable, comparable JSON shape that
summarises what a binary is capable of doing — its dangerous
imports bucketed by capability family (exec / network / parser /
etc.), its reachable dangerous sinks, plus binary metadata
(arch / bits / format) and a content hash for the bytes.

Two binaries with the same fingerprint shape are interchangeable
from a capability-surface perspective; two with different
fingerprints have different attack surfaces. The fingerprint is
the primitive every higher-level capability-aware feature builds
on:

  * **Drift detection**: store last-seen fingerprint per image
    ref; diff against fresh extraction on each scan.
  * **CI gate**: assert "all images' fingerprints have
    capability_buckets ⊆ allowed set".
  * **SBOM property**: embed alongside the image component for
    audit / VEX context.
  * **Bump finding evidence**: structured payload inside
    ``SupplyChainFinding.evidence``.

The schema is stable across builds — sort everything, no
volatile fields like absolute paths or timestamps inside the
hash-relevant parts. The ``binary_path`` field is informational
(operator-facing) and isn't load-bearing for comparison.

Schema is versioned (``schema_version`` field). Bumps when
adding fields that change diff semantics; consumers reject
mismatched versions.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from core.function_taxonomy import (
    ALLOC_FUNCS,
    EXEC_FUNCS,
    FORMAT_STRING_FUNCS,
    INTEGER_PARSE_FUNCS,
    MEMORY_COPY_FUNCS,
    NETWORK_INGEST_FUNCS,
    PARSER_FUNCS,
    SCAN_FAMILY_FUNCS,
    STRING_OVERFLOW_FUNCS,
    TOCTOU_FUNCS,
)

logger = logging.getLogger(__name__)


# Schema version. Bump when changing the meaning of any
# fingerprint field. Consumers check this on read and refuse to
# diff across versions (better to recompute than mis-attribute).
FINGERPRINT_SCHEMA_VERSION = 1


# Per-bucket capability classification. Single source of truth —
# the SCA bump detector and any future capability-aware consumer
# imports from here so the bucket names stay consistent across
# fingerprints + findings + drift records.
BUCKETS: Tuple[Tuple[str, FrozenSet[str]], ...] = (
    ("exec", EXEC_FUNCS),
    ("network", NETWORK_INGEST_FUNCS),
    ("string_overflow", STRING_OVERFLOW_FUNCS),
    ("scan", SCAN_FAMILY_FUNCS),
    ("memory_copy", MEMORY_COPY_FUNCS),
    ("format_string", FORMAT_STRING_FUNCS),
    ("alloc", ALLOC_FUNCS),
    ("parser", PARSER_FUNCS),
    ("integer_parse", INTEGER_PARSE_FUNCS),
    ("toctou", TOCTOU_FUNCS),
)

# Buckets that warrant high-severity treatment when they appear
# as a NEW addition (drift detection, bump capability-delta).
# ``exec`` is RCE-flavoured; ``network`` is exfil-flavoured.
HIGH_SEVERITY_BUCKETS: FrozenSet[str] = frozenset({"exec", "network"})


def bucket_imports(imports: Set[str]) -> Dict[str, Set[str]]:
    """Classify an import set by capability bucket.

    Returns ``{bucket_name: {fn1, fn2, ...}}`` for each bucket
    with at least one matching entry. Imports outside the
    high-CVE-density taxonomy buckets are intentionally dropped
    — ubiquitous functions like ``malloc`` / ``printf`` /
    ``read`` aren't signal at fingerprint scale either.
    """
    out: Dict[str, Set[str]] = {}
    for bucket_name, fn_set in BUCKETS:
        matched = imports & fn_set
        if matched:
            out[bucket_name] = matched
    return out


@dataclass
class CapabilityFingerprint:
    """Stable snapshot of one binary's capability surface.

    Serialised via :meth:`to_dict`; the dict is suitable for
    direct JSON storage / SBOM property / diff comparison. Two
    fingerprints with equal ``to_dict()`` outputs are
    capability-equivalent.

    ``binary_sha256`` is the SHA-256 of the binary bytes — the
    cryptographically strong content key. Two different bytes
    with the same fingerprint *capability shape* will still
    have different ``binary_sha256``, which is the signal "this
    rebuild changed bytes but didn't change capabilities"
    (acceptable noise; suppressible in consumers).
    """

    schema_version: int
    binary_path: str          # operator-facing only; not hashed
    binary_sha256: str
    arch: str
    bits: int
    binary_format: str        # 'elf' / 'mach-o' / 'pe'
    capability_buckets: Dict[str, List[str]] = field(default_factory=dict)
    dangerous_sinks: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Full JSON-ready representation INCLUDING the
        informational ``binary_path``. For storage / operator-
        facing rendering / SBOM property. Use
        :meth:`canonical_json` (which drops binary_path) for
        comparison / hashing — two fingerprints of the same
        bytes from different filesystem paths should compare
        equal, and they will via canonical_json but won't via
        to_dict."""
        return {
            "schema_version": self.schema_version,
            "binary_path": self.binary_path,
            "binary_sha256": self.binary_sha256,
            "arch": self.arch,
            "bits": self.bits,
            "binary_format": self.binary_format,
            "capability_buckets": {
                k: sorted(v) for k, v in sorted(
                    self.capability_buckets.items(),
                )
            },
            "dangerous_sinks": sorted(self.dangerous_sinks),
        }

    def _comparison_dict(self) -> Dict[str, Any]:
        """The fields that DEFINE this fingerprint's identity for
        comparison / drift detection. Excludes ``binary_path``
        (an operator-facing breadcrumb that legitimately varies
        across machines / tempdirs for the same binary bytes —
        including it would create false drift signals)."""
        d = self.to_dict()
        d.pop("binary_path", None)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CapabilityFingerprint":
        return cls(
            schema_version=int(data.get("schema_version", 0)),
            binary_path=str(data.get("binary_path", "")),
            binary_sha256=str(data.get("binary_sha256", "")),
            arch=str(data.get("arch", "")),
            bits=int(data.get("bits", 0)),
            binary_format=str(data.get("binary_format", "")),
            capability_buckets={
                str(k): list(v) for k, v in (
                    data.get("capability_buckets") or {}
                ).items()
            },
            dangerous_sinks=list(data.get("dangerous_sinks") or []),
        )

    def canonical_json(self) -> str:
        """Stable bytes for content-hashing or eq-comparison
        between fingerprints. Sorted keys, compact whitespace,
        and EXCLUDES the informational ``binary_path`` so the
        same binary bytes at two different filesystem paths
        produce identical canonical_json (drift detection
        depends on this — without it, comparing
        ``/tmp/dl-abc/foo`` to ``/tmp/dl-xyz/foo`` for the same
        image would always look like drift)."""
        return json.dumps(
            self._comparison_dict(),
            sort_keys=True, separators=(",", ":"),
        )


def capability_fingerprint(
    binary_path: Path,
    *,
    include_sinks: bool = False,
) -> Optional[CapabilityFingerprint]:
    """Compute the capability fingerprint of ``binary_path``.

    Returns ``None`` when:
      * radare2 is unavailable on the host
      * the binary can't be analysed (corrupt / unsupported
        format / read failure)

    By default runs in *quick* mode — skips radare2's ``aaa``
    (full auto-analysis) step, populating only metadata +
    imports. Order of magnitude faster on typical binaries
    (seconds vs minutes for ``/bin/ls``). The bucketed-imports
    signal is the load-bearing piece of the fingerprint;
    ``dangerous_sinks`` is a nice-to-have that requires
    cross-reference analysis.

    Pass ``include_sinks=True`` to run the full pipeline and
    populate the ``dangerous_sinks`` field. Use for
    deeper-analysis paths (e.g. forensic / pre-merge gates)
    where the extra signal justifies the cost.
    """
    try:
        from packages.binary_analysis.radare2_understand import (
            analyse_binary_context,
            probe_capability,
        )
    except ImportError:
        logger.debug(
            "binary_analysis.fingerprint: radare2_understand not "
            "importable; cannot fingerprint",
        )
        return None

    cap = probe_capability()
    if not cap.get("available"):
        logger.debug(
            "binary_analysis.fingerprint: radare2 stack not "
            "available (%s); cannot fingerprint",
            cap.get("reason", "<no reason>"),
        )
        return None

    try:
        ctx = analyse_binary_context(
            binary_path,
            max_strings=0,
            max_decompile=0,
            quick=not include_sinks,
        )
    except Exception as e:                            # noqa: BLE001
        logger.warning(
            "binary_analysis.fingerprint: analyse failed for %s: %s",
            binary_path, e,
        )
        return None

    try:
        content_hash = _sha256_of_file(binary_path)
    except OSError as e:
        logger.warning(
            "binary_analysis.fingerprint: could not hash %s: %s",
            binary_path, e,
        )
        return None

    buckets = bucket_imports(set(ctx.imports))
    return CapabilityFingerprint(
        schema_version=FINGERPRINT_SCHEMA_VERSION,
        binary_path=str(binary_path),
        binary_sha256=content_hash,
        arch=ctx.arch,
        bits=ctx.bits,
        binary_format=ctx.binary_format,
        capability_buckets={k: list(v) for k, v in buckets.items()},
        dangerous_sinks=[f.name for f in ctx.dangerous_sinks],
    )


def _sha256_of_file(path: Path, *, chunk_size: int = 64 * 1024) -> str:
    """Stream-hash a file. ``64KB`` chunks balance throughput vs
    memory across small (binaries) + large (containers) inputs.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


__all__ = [
    "BUCKETS",
    "CapabilityFingerprint",
    "FINGERPRINT_SCHEMA_VERSION",
    "HIGH_SEVERITY_BUCKETS",
    "bucket_imports",
    "capability_fingerprint",
]
