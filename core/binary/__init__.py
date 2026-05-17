"""Binary substrate: fingerprinting + capability diff.

Tool-substrate-level primitives for analysing binaries. The
high-level analyser (``BinaryUnderstand``) lives in
:mod:`packages.binary_analysis.radare2_understand`; this package
contains the lightweight primitives every binary-aware consumer
shares:

  * :func:`capability_fingerprint` — stable JSON snapshot of one
    binary's capability surface (bucketed dangerous imports +
    metadata + content hash).
  * :func:`diff_binary_capabilities` — diff two binaries'
    capability surfaces. Returns a :class:`CapabilityDelta` with
    newly-added dangerous-import buckets.
  * :data:`BUCKETS` + :func:`bucket_imports` — shared taxonomy
    for classifying imports into high-CVE-density buckets.

The fingerprint and diff primitives are cross-reference-blind by
design — they answer "what is this binary capable of calling"
based on the dynamic symbol table. The expensive cross-reference
analysis (which functions in the binary actually USE the
dangerous imports) requires ``BinaryUnderstand`` and is a
different output shape.
"""

from core.binary.capability_diff import (
    CapabilityDelta,
    diff_binary_capabilities,
)
from core.binary.drift import (
    FingerprintDrift,
    detect_drift,
)
from core.binary.fingerprint import (
    BUCKETS,
    CapabilityFingerprint,
    FINGERPRINT_SCHEMA_VERSION,
    HIGH_SEVERITY_BUCKETS,
    bucket_imports,
    capability_fingerprint,
)
from core.binary.fingerprint_store import (
    STORE_SCHEMA_VERSION,
    delete_fingerprint,
    iter_refs,
    load_fingerprint,
    save_fingerprint,
)

__all__ = [
    "BUCKETS",
    "CapabilityDelta",
    "CapabilityFingerprint",
    "FINGERPRINT_SCHEMA_VERSION",
    "FingerprintDrift",
    "HIGH_SEVERITY_BUCKETS",
    "STORE_SCHEMA_VERSION",
    "bucket_imports",
    "capability_fingerprint",
    "delete_fingerprint",
    "detect_drift",
    "diff_binary_capabilities",
    "iter_refs",
    "load_fingerprint",
    "save_fingerprint",
]
