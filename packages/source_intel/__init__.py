"""Source intelligence — cocci-based structural evidence for
memory-corruption CWEs in C/C++ targets.

Public API:
  * :class:`SourceIntelResult` — frozen per-target evidence record
  * :func:`analyze` — run shipped cocci rules against a target
  * :class:`WurEvidence` — single observation of warn_unused_result
  * :func:`derive_evidence_strings` — render evidence for prompts
  * :class:`SourceIntelCache` — in-memory content-addressed cache
  * :class:`SourceIntelValidator` — corpus-runner Validator adapter

See ``~/design/dataflow-sanitizer-bypass.md`` ("Mechanism #4 —
source_intel") for the design + axis roadmap.
"""

from packages.source_intel.analyze import (
    ALL_KINDS,
    KIND_ACCESS,
    KIND_ALLOC_SIZE,
    KIND_MALLOC,
    KIND_NO_STACK_PROTECTOR,
    KIND_NONNULL,
    KIND_NORETURN,
    KIND_RETURNS_NONNULL,
    KIND_WUR,
    SCHEMA_VERSION,
    AttributeEvidence,
    SourceIntelResult,
    WurEvidence,
    analyze,
)
from packages.source_intel.cache import SourceIntelCache
from packages.source_intel.conditional import enclosing_condition
from packages.source_intel.discovery import (
    DiscoveryResult,
    discover_aliases,
)
from packages.source_intel.render import derive_evidence_strings

__all__ = [
    "ALL_KINDS",
    "AttributeEvidence",
    "DiscoveryResult",
    "KIND_ACCESS",
    "KIND_ALLOC_SIZE",
    "KIND_MALLOC",
    "KIND_NO_STACK_PROTECTOR",
    "KIND_NONNULL",
    "KIND_NORETURN",
    "KIND_RETURNS_NONNULL",
    "KIND_WUR",
    "SCHEMA_VERSION",
    "SourceIntelCache",
    "SourceIntelResult",
    "WurEvidence",
    "analyze",
    "derive_evidence_strings",
    "discover_aliases",
    "enclosing_condition",
]
