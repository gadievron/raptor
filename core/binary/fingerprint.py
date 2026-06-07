"""Capability fingerprint for a single binary.

A *fingerprint* is a small, stable, comparable JSON shape that
summarises what a binary is capable of doing — its dangerous
imports bucketed by capability family (exec / network / parser /
etc.), plus binary metadata (arch / bits / format) and a content
hash for the bytes.

Two fingerprints with the same shape have the same capability
surface; two with different shapes have different attack surfaces.
The fingerprint is the primitive every higher-level capability-
aware feature builds on:

  * **Drift detection**: store last-seen fingerprint per image
    ref; diff against fresh extraction on each scan.
  * **CI gate**: assert all images' capability_buckets ⊆ allowed.
  * **SBOM property**: embed alongside the image component for
    audit / VEX context.
  * **Bump finding evidence**: structured payload inside
    ``SupplyChainFinding.evidence``.

Scope boundary
- The fingerprint is import-table-based only — it surfaces "what
  is this binary capable of calling into" via the dynamic symbol
  table. Cross-reference-aware analysis ("which of this binary's
  own functions actually call into execve") requires
  ``BinaryUnderstand`` from :mod:`packages.binary_analysis.
  radare2_understand` and its expensive ``aaa`` step. That signal
  has a different output shape and lives in a different
  abstraction; the fingerprint primitive deliberately stays
  cheap-to-compute substrate.

The schema is versioned (``schema_version``). Bumps when adding
fields that change diff semantics; consumers reject mismatched
versions.
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
    IPC_FUNCS,
    KERNEL_TRACE_FUNCS,
    MEMORY_COPY_FUNCS,
    NETWORK_INGEST_FUNCS,
    PARSER_FUNCS,
    PROCESS_BOUNDARY_FUNCS,
    RUNTIME_PRIVILEGE_FUNCS,
    SCAN_FAMILY_FUNCS,
    STREAM_INPUT_FUNCS,
    STRING_OVERFLOW_FUNCS,
    TOCTOU_FUNCS,
)

logger = logging.getLogger(__name__)


# Schema version. Bump when changing the meaning of any
# fingerprint field. Consumers check this on read and refuse to
# diff across versions (better to recompute than mis-attribute).
#
# v2: added stream_input / process_boundary / ipc buckets. A binary
# fingerprinted under v1 may legitimately have these capabilities
# but they were not surfaced — re-fingerprint rather than diff across
# the bump.
# v3: added runtime_privilege / kernel_trace buckets — supply-chain
# forensic surface (setuid / bpf / ptrace / perf_event_open et al.).
# Same re-fingerprint guidance as v1→v2.
#
# Migration is operator-transparent: ``fingerprint_store._load_fingerprint``
# treats any stored fingerprint whose ``schema_version`` doesn't equal
# the current ``FINGERPRINT_SCHEMA_VERSION`` as "no baseline" and
# the next scan re-fingerprints from bytes.  No manual cache flush
# needed; the first scan after the bump pays the re-fingerprint cost
# (sub-millisecond per binary via :mod:`core.binary.elf`).
FINGERPRINT_SCHEMA_VERSION = 3


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
    ("stream_input", STREAM_INPUT_FUNCS),
    ("process_boundary", PROCESS_BOUNDARY_FUNCS),
    ("ipc", IPC_FUNCS),
    # Added in v3 — supply-chain forensic surface.
    ("runtime_privilege", RUNTIME_PRIVILEGE_FUNCS),
    ("kernel_trace", KERNEL_TRACE_FUNCS),
)

# Buckets that warrant high-severity treatment when they appear
# as a NEW addition (drift detection, bump capability-delta).
# ``exec`` is RCE-flavoured; ``network`` is exfil-flavoured.
# ``runtime_privilege`` and ``kernel_trace`` are the supply-chain
# forensic flavour — their presence in a package's native binary
# is rare and high-signal regardless of the host being a delta.
HIGH_SEVERITY_BUCKETS: FrozenSet[str] = frozenset({
    "exec", "network", "runtime_privilege", "kernel_trace",
})


def bucket_imports(imports: Set[str]) -> Dict[str, Set[str]]:
    """Classify an import set by capability bucket.

    Returns ``{bucket_name: {fn1, fn2, ...}}`` for each bucket
    with at least one matching entry. Imports outside the
    high-CVE-density taxonomy buckets are intentionally dropped —
    ubiquitous functions like ``malloc`` / ``printf`` / ``read``
    aren't signal at fingerprint scale either.
    """
    out: Dict[str, Set[str]] = {}
    for bucket_name, fn_set in BUCKETS:
        matched = imports & fn_set
        if matched:
            out[bucket_name] = matched
    return out


@dataclass
class CapabilityFingerprint:
    """Stable snapshot of one binary's capability surface,
    derived from its dynamic import table.

    Serialised via :meth:`to_dict`; the dict is suitable for
    direct JSON storage / SBOM property / diff comparison. Two
    fingerprints with equal ``canonical_json()`` outputs are
    capability-equivalent.

    ``binary_sha256`` is the SHA-256 of the binary bytes — the
    cryptographically strong content key. Two different bytes
    with the same capability *shape* will still have different
    ``binary_sha256``, which is the signal "this rebuild
    changed bytes but didn't change capabilities" (acceptable
    noise; suppressible in consumers).
    """

    schema_version: int
    binary_path: str          # operator-facing only; not hashed
    binary_sha256: str
    arch: str
    bits: int
    binary_format: str        # 'elf' / 'mach-o' / 'pe'
    capability_buckets: Dict[str, List[str]] = field(default_factory=dict)

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
        }

    def _comparison_dict(self) -> Dict[str, Any]:
        """The fields that define identity for comparison / drift
        detection. Excludes ``binary_path`` (legitimately varies
        across machines / tempdirs for the same bytes)."""
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
        )

    def canonical_json(self) -> str:
        """Stable bytes for content-hashing or eq-comparison
        between fingerprints. Sorted keys, compact whitespace,
        and EXCLUDES the informational ``binary_path`` so the
        same binary bytes at two different filesystem paths
        produce identical canonical_json (drift detection
        depends on this — without it, comparing
        ``/tmp/dl-abc/foo`` to ``/tmp/dl-xyz/foo`` for the
        same image would always look like drift).
        """
        return json.dumps(
            self._comparison_dict(),
            sort_keys=True, separators=(",", ":"),
        )


def capability_fingerprint(
    binary_path: Path,
) -> Optional[CapabilityFingerprint]:
    """Compute the capability fingerprint of ``binary_path``.

    Tier dispatch:
      1. Try :func:`core.binary.elf.parse_elf` — stdlib-only ELF
         parser, sub-millisecond on typical binaries, no
         external deps. Covers the operationally-common case
         (Linux container binaries).
      2. Fall back to ``analyse_binary_context`` (radare2,
         quick mode) for PE / Mach-O / anything tier 0 can't
         identify as ELF.
      3. If neither tier works, return ``None``.

    The fingerprint shape is tier-agnostic — fingerprints
    produced by either tier compare bit-for-bit (the arch
    taxonomy is aligned to radare2's family convention).

    Returns ``None`` when:
      * The binary can't be read (OSError)
      * It's neither ELF nor analysable by radare2
      * Radare2 is unavailable AND the binary isn't ELF

    Operational consequence: on hosts WITHOUT r2pipe installed,
    Linux ELF binaries still fingerprint successfully via
    tier 0. Only PE / Mach-O require tier 1.
    """
    try:
        content_hash = _sha256_of_file(binary_path)
    except OSError as e:
        logger.warning(
            "core.binary.fingerprint: could not hash %s: %s",
            binary_path, e,
        )
        return None

    # Tier 0: native ELF parser.
    fp = _fingerprint_via_elf(binary_path, content_hash)
    if fp is not None:
        return fp

    # Tier 1: radare2 (covers PE / Mach-O + corrupted ELF
    # the native parser couldn't handle).
    return _fingerprint_via_radare2(binary_path, content_hash)


def _fingerprint_via_elf(
    binary_path: Path, content_hash: str,
) -> Optional[CapabilityFingerprint]:
    """Try the stdlib ELF parser. Returns ``None`` for non-ELF
    inputs or unrecoverable parse failures — caller falls
    through to tier 1."""
    from core.binary.elf import parse_elf

    meta = parse_elf(binary_path)
    if meta is None:
        return None
    buckets = bucket_imports(meta.imports)
    return CapabilityFingerprint(
        schema_version=FINGERPRINT_SCHEMA_VERSION,
        binary_path=str(binary_path),
        binary_sha256=content_hash,
        arch=meta.arch,
        bits=meta.bits,
        binary_format=meta.binary_format,
        capability_buckets={k: list(v) for k, v in buckets.items()},
    )


def _fingerprint_via_radare2(
    binary_path: Path, content_hash: str,
) -> Optional[CapabilityFingerprint]:
    """Tier 1 fallback. Used for PE / Mach-O and any input the
    ELF parser couldn't identify. Returns ``None`` if radare2
    isn't installed, or if the analyser couldn't extract any
    meaningful signal from the file (empty bytes, unrecognised
    format, etc.)."""
    try:
        from packages.binary_analysis.radare2_understand import (
            analyse_binary_context,
            probe_capability,
        )
    except ImportError:
        logger.debug(
            "core.binary.fingerprint: tier 0 didn't match and "
            "radare2_understand not importable — no fingerprint",
        )
        return None

    cap = probe_capability()
    if not cap.get("available"):
        logger.debug(
            "core.binary.fingerprint: tier 0 didn't match and "
            "radare2 stack unavailable (%s) — no fingerprint",
            cap.get("reason", "<no reason>"),
        )
        return None

    try:
        ctx = analyse_binary_context(
            binary_path,
            max_strings=0,
            max_decompile=0,
            quick=True,
        )
    except Exception as e:                            # noqa: BLE001
        logger.warning(
            "core.binary.fingerprint: radare2 fallback failed "
            "for %s: %s",
            binary_path, e,
        )
        return None

    # Empty file, unrecognised format, or anything radare2 opened
    # but couldn't classify yields a fully-empty context. Reject
    # — a fingerprint of "I have nothing to say about this file"
    # only pollutes the fingerprint store (drift detection would
    # match every unparseable file to every other one via the
    # empty-string SHA isn't even unique once the file is empty).
    if (not ctx.binary_format and not ctx.arch
            and not ctx.imports):
        logger.debug(
            "core.binary.fingerprint: radare2 returned empty "
            "context for %s — no fingerprint",
            binary_path,
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
