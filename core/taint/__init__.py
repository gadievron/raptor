"""Taint spec packs — sources, sinks, sanitizers, propagators as data.

One JSON pack format feeding two backends: a native cross-file
propagator and models-as-data emission through
:mod:`core.dataflow.extension_pack`. The packs are configuration, not
code: adding a sink class is a data-only change (see
``core/taint/data/packs/README.md``), which is the whole point of the
format — downstream lanes (secrets egress, stored-taint pairing,
template sinks) arrive as pack files with zero engine changes.

Module map:

* :mod:`core.taint.packs` — schema, fail-closed loader, curated
  sanitizer merge, the in-tree-only trust posture.
* :mod:`core.taint.learned_intake` — the bounded intake through which
  project-learned specs (:mod:`core.iris`) enter the same in-memory
  model, tier-tagged ``learned``.

Nothing here renders verdicts: packs and learned specs configure an
origination lane whose findings are candidates for the existing
classifier / validation pipeline.
"""

from core.taint.learned_intake import (
    LearnedIntake,
    LearnedSpec,
    intake_learned_specs,
)
from core.taint.packs import (
    DEFAULT_PACKS_DIR,
    SCHEMA_VERSION,
    FlowEdge,
    PackLoadError,
    PackSet,
    PropagatorSpec,
    SanitizerSpec,
    SinkSpec,
    SourceSpec,
    TaintPack,
    curated_sanitizers,
    load_packs,
)

__all__ = [
    "DEFAULT_PACKS_DIR",
    "SCHEMA_VERSION",
    "FlowEdge",
    "LearnedIntake",
    "LearnedSpec",
    "PackLoadError",
    "PackSet",
    "PropagatorSpec",
    "SanitizerSpec",
    "SinkSpec",
    "SourceSpec",
    "TaintPack",
    "curated_sanitizers",
    "intake_learned_specs",
    "load_packs",
]
