"""First-class type for "the input bytes that triggered a bug."

A ``Witness`` is the canonical artefact that captures *what was
fed to a target* and *what was observed* when it ran. Produced by
multiple pipelines (``/fuzz`` crashes, ``/crash-analysis`` replays,
``/validate`` PoC executions, future ``/agentic`` exploit runs)
and consumed by downstream features (reporting, future
calibrated IntentMatchJudge, future ZKPoX bundle assembly).

The data model has two pieces:

  * :class:`Witness` — the metadata record (bytes-hash + provenance
    + observed outcome). Carries a *reference* to the bytes via
    sha256 hash rather than inlining them, so large witnesses
    (fuzz inputs can be megabytes) don't bloat the in-memory
    representation.
  * :class:`WitnessStore` — hash-addressed blob storage at
    ``{out_dir}/witnesses/``. Bytes are written once per unique
    hash (dedup across pipelines is automatic); the manifest sits
    alongside.

Pipeline adapters live close to their producer (e.g.
``packages/fuzzing/witness_adapter.py``) rather than in ``core/``
to avoid the layering inversion of ``core/`` importing
``packages/``.
"""

from core.witness.discovery import (
    discover_witness_stores,
    iter_visible_witnesses,
)
from core.witness.matching import (
    WitnessMatch,
    best_match_for_finding,
    score_witness_for_finding,
)
from core.witness.sandbox_outcome import outcome_from_sandbox_info
from core.witness.store import WitnessStore, WitnessStoreError
from core.witness.types import (
    Witness,
    WitnessOutcome,
    WitnessSource,
    compute_bytes_hash,
)

__all__ = [
    "Witness",
    "WitnessOutcome",
    "WitnessSource",
    "WitnessStore",
    "WitnessStoreError",
    "compute_bytes_hash",
    "outcome_from_sandbox_info",
    "discover_witness_stores",
    "iter_visible_witnesses",
    "WitnessMatch",
    "best_match_for_finding",
    "score_witness_for_finding",
]
