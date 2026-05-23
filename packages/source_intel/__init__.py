"""Source intelligence — cocci-based structural evidence for
memory-corruption CWEs in C/C++ targets.

Public API:
  * :class:`SourceIntelResult` — frozen per-target evidence record
  * :func:`analyze` — run shipped cocci rules against a target
  * :class:`WurEvidence` — single observation of warn_unused_result
  * :func:`derive_evidence_strings` — render evidence for prompts
  * :class:`SourceIntelCache` — in-memory content-addressed cache
  * :class:`SourceIntelValidator` — corpus-runner Validator adapter
  * :func:`make_source_intel_collector` — evidence-collector factory
    for ``DataflowValidator(evidence_collector=...)``
  * :func:`make_cwe_dispatched_collector` — composes source_intel
    with the PR1 V2 sanitizer-extraction collector via rule_id-prefix
    dispatch

source_intel") for the design + axis roadmap.
"""

from packages.source_intel.analyze import (
    ALL_GRADES,
    ALL_KINDS,
    GRADE_DOMINATES,
    GRADE_SAME_FUNCTION,
    GRADE_SAME_PATH,
    KIND_ACCESS,
    KIND_ALLOC_SIZE,
    KIND_MALLOC,
    KIND_NO_STACK_PROTECTOR,
    KIND_NONNULL,
    KIND_NORETURN,
    KIND_RETURNS_NONNULL,
    KIND_WUR,
    SCHEMA_VERSION,
    AbortEvidence,
    AllocationEvidence,
    AttributeEvidence,
    SourceIntelResult,
    WurEvidence,
    analyze,
    clear_inventory_cache,
)
from packages.source_intel.cache import SourceIntelCache
from packages.source_intel.conditional import enclosing_condition
from packages.source_intel.discovery import (
    DiscoveryResult,
    discover_aliases,
)
from packages.source_intel.llm_bridge import (
    DEFAULT_SOURCE_INTEL_RULE_PREFIXES,
    make_cwe_dispatched_collector,
    make_source_intel_collector,
)
from packages.source_intel.render import derive_evidence_strings

__all__ = [
    "ALL_GRADES",
    "ALL_KINDS",
    "AbortEvidence",
    "AllocationEvidence",
    "AttributeEvidence",
    "DEFAULT_SOURCE_INTEL_RULE_PREFIXES",
    "DiscoveryResult",
    "GRADE_DOMINATES",
    "GRADE_SAME_FUNCTION",
    "GRADE_SAME_PATH",
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
    "clear_all_source_intel_caches",
    "clear_inventory_cache",
    "discover_aliases",
    "enclosing_condition",
    "make_cwe_dispatched_collector",
    "make_source_intel_collector",
]


def clear_all_source_intel_caches() -> None:
    """Drop every source_intel process-level cache.

    Single entry point for orchestrators that want a clean slate
    between consecutive runs in the same Python process. Clears
    both the inventory cache (``packages.source_intel.analyze``)
    and the result cache (``packages.llm_analysis.source_intel_inject``).

    Signature-based auto-invalidation already covers correctness
    when the target tree changes; this is the explicit reset for
    callers that don't want to rely on the implicit path. Safe to
    call when ``packages.llm_analysis.source_intel_inject`` isn't
    importable (the inject module is the LLM-side consumer; tests
    that exercise source_intel in isolation may not import it).
    """
    clear_inventory_cache()
    try:
        from packages.llm_analysis.source_intel_inject import clear_si_result_cache
    except ImportError:
        return
    clear_si_result_cache()
