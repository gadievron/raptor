"""SharedState dataclass for the /audit orchestrator.

Collects all prep outputs computed during the setup phase of _run_audit_body
(lines ~263-912) so they can be passed cleanly to per-function review workers
and post-loop passes without threading individual variables through every
call site.

Fields are grouped into two sections:
  - Read-only after prep: set once during the prep phase; workers only read.
  - Mutable during loop: updated across loop iterations as reviews complete.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from packages.checker_synthesis.library import RuleLibrary as CheckerLibrary
    from .demand_explore import ExpansionBudget
    from core.evidence import EvidenceRecord
    from .exploit_feedback import FeedbackState
    from .live_classifications import LiveClassifications
    from .propagation import PropagationConfig
    from .summary_cache import SummaryCache
    from .sweep import SarifCache


@dataclass
class SharedState:
    """All prep outputs that the main review loop reads from.

    Create via ``SharedState.from_prep(...)`` at the end of the setup phase;
    then pass the single object to any helper that currently receives a long
    list of individual prep-output arguments.
    """

    # ------------------------------------------------------------------
    # Read-only after prep
    # ------------------------------------------------------------------

    # Core function inventory and call-graph maps.
    checklist: dict[str, Any] = field(default_factory=dict)
    context_map: dict[str, Any] = field(default_factory=dict)

    # Per-function evidence from static analysis passes.
    evidence_index: dict[str, EvidenceRecord] = field(default_factory=dict)  # type: ignore[type-arg]

    # Mechanical-gate support: data-flow provenance and security-role sets.
    provenance_map: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    security_decision_keys: frozenset[str] = field(default_factory=frozenset)
    feeds_security_keys: frozenset[str] = field(default_factory=frozenset)

    # Taint analysis results from the approximation and summary passes.
    taint_approx_results: dict[str, Any] = field(default_factory=dict)

    # SARIF cache holding pre-loaded CodeQL / Semgrep alerts.
    sarif_cache: SarifCache | None = None  # type: ignore[type-arg]

    # /understand flow traces imported from a prior run.
    flow_traces: list[Any] | dict[str, Any] = field(default_factory=list)

    # Functions that matched a variant-hunt result; used to annotate context.
    variant_targets: set[str] = field(default_factory=set)

    # Entry points and sinks extracted from context_map; used for triage and
    # reachability gates throughout the loop.
    entry_points: set[str] = field(default_factory=set)
    sinks_set: set[str] = field(default_factory=set)

    # Functions deemed widely-used by the priority scorer; surfaced in context.
    widely_used_keys: set[str] = field(default_factory=set)

    # Security conventions discovered by negative-space analysis.
    conventions: list[Any] = field(default_factory=list)

    # Cross-sibling negative-space and postcondition findings computed once
    # over all gaps; injected per-function during the loop.
    sibling_ns_findings: list[Any] = field(default_factory=list)
    sibling_postcond_violations: list[Any] = field(default_factory=list)

    # Capability displacement findings (dispatch-table analysis).
    capability_displacements: list[Any] = field(default_factory=list)

    # Struct-field co-accessor index: field_name → [AccessorRecord, ...].
    struct_accessor_index: dict[str, list[Any]] = field(default_factory=dict)

    # Sibling peer groups for semantic-consistency and paired-operation checks.
    peer_groups: list[Any] = field(default_factory=list)

    # Semantic consistency outlier findings across peer groups.
    semantic_findings: list[Any] = field(default_factory=list)

    # Cross-function / cross-file mechanical detector results; keyed by
    # "file:function".
    mechanical_findings: dict[str, list[Any]] = field(default_factory=dict)

    # Lazy inject-mode detector resolver (check_lock_domain, uninit_leak).
    inject_resolver: Any = None

    # Fuzz coverage data merged from sibling runs.
    fuzz_coverage: dict[str, Any] = field(default_factory=dict)

    # Test-discovery results; keyed by function name.
    discovered_tests: dict[str, Any] | None = None

    # Typestate lifecycle models extracted from the checklist.
    typestate_models: dict[str, Any] | None = None

    # In-memory summary cache for stdlib / third-party callee summaries.
    summary_cache: SummaryCache | None = None  # type: ignore[type-arg]

    # Checker library loaded from the on-disk checker directory.
    checker_library: CheckerLibrary | None = None  # type: ignore[type-arg]

    # Triage classification results; keyed by "file:function".
    triage_results: dict[str, Any] = field(default_factory=dict)

    # Per-project learnings from prior audit runs.
    project_learnings: list[dict[str, Any]] = field(default_factory=list)

    # Exploit-feedback state loaded from prior /validate runs.
    feedback_state: FeedbackState | None = None  # type: ignore[type-arg]

    # False-positive patterns mined from manual annotations.
    fp_patterns: list[Any] = field(default_factory=list)

    # Constraint propagation configuration (max depth, db path, etc.).
    prop_config: PropagationConfig | None = None  # type: ignore[type-arg]

    # IRIS taint specs synthesised before the loop starts.
    iris_taint_specs: list[Any] = field(default_factory=list)

    # Call-graph edges extracted from context_map["call_edges"]; stored here
    # so callers don't need to re-extract from context_map every time.
    call_edges: list[dict[str, Any]] = field(default_factory=list)

    # Adjacency index over call_edges: maps "file:function" → list of edges
    # involving that function (as caller or callee).  Built once at loop
    # setup; eliminates per-function linear scans during chain collection
    # and injection.
    call_edge_index: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    # Checklist lookup: maps (file, function_name) → gap dict for O(1)
    # lookups during chain injection.
    checklist_index: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)

    # Domain model (concepts + invariants) loaded from the journal.
    domain_model: dict[str, Any] | None = None

    # ------------------------------------------------------------------
    # Mutable during loop
    # ------------------------------------------------------------------

    # Callee taint summaries; new entries are added after each function
    # review so that callers later in the topological order can use them.
    taint_summary_results: dict[str, Any] = field(default_factory=dict)
    _taint_lock: threading.Lock = field(default_factory=threading.Lock)

    # Running list of per-review observations used to build session context
    # for subsequent reviews.
    session_observations: list[dict[str, str]] = field(default_factory=list)
    _observations_lock: threading.Lock = field(default_factory=threading.Lock)

    # Evidence discovered at runtime by proactive tool dispatching; keyed by
    # "file:function".
    discovered_evidence: dict[str, Any] = field(default_factory=dict)

    _evidence_lock: threading.Lock = field(default_factory=threading.Lock)

    # Constraint set; updated via propagation after each finding review.
    constraints: Any = None
    _constraints_lock: threading.Lock = field(default_factory=threading.Lock)

    # Functions reviewed before Joern finished; eligible for re-review once
    # Joern flows are available.
    reviewed_before_joern: list[dict[str, Any]] = field(default_factory=list)

    # Budget tracker for on-demand callee expansion during the loop.
    expansion_budget: ExpansionBudget | None = None  # type: ignore[type-arg]

    # Synthesis hits discovered mid-loop; drained into a second executor pass.
    synthesis_queue: list[dict[str, Any]] = field(default_factory=list)

    # Incremental study consumer queue; set at runtime when C/C++ files
    # are present.  Typed as Any to avoid circular import.
    study_queue: Any = None

    # Live-discovered sinks, sanitizers, and entry points accumulated
    # from LLM review outcomes during the loop.
    live_classifications: LiveClassifications | None = None  # type: ignore[type-arg]
    _live_lock: threading.Lock = field(default_factory=threading.Lock)

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_prep(
        cls,
        *,
        checklist: dict[str, Any],
        context_map: dict[str, Any],
        evidence_index: dict[str, Any],
        provenance_map: dict[str, list[dict[str, str]]],
        security_decision_keys: frozenset[str],
        feeds_security_keys: frozenset[str],
        taint_approx_results: dict[str, Any],
        sarif_cache: SarifCache | None,
        flow_traces: list[Any] | dict[str, Any],
        variant_targets: set[str],
        entry_points: set[str],
        sinks_set: set[str],
        widely_used_keys: set[str],
        conventions: list[Any],
        sibling_ns_findings: list[Any],
        sibling_postcond_violations: list[Any],
        peer_groups: list[Any],
        semantic_findings: list[Any],
        mechanical_findings: dict[str, list[Any]],
        fuzz_coverage: dict[str, Any],
        discovered_tests: dict[str, Any] | None,
        typestate_models: dict[str, Any] | None,
        summary_cache: SummaryCache | None,
        checker_library: CheckerLibrary | None,
        triage_results: dict[str, Any],
        project_learnings: list[dict[str, Any]],
        feedback_state: FeedbackState | None,
        fp_patterns: list[Any],
        prop_config: PropagationConfig | None,
        iris_taint_specs: list[Any],
        call_edges: list[dict[str, Any]],
        domain_model: dict[str, Any] | None = None,
        capability_displacements: list[Any] | None = None,
        struct_accessor_index: dict[str, list[Any]] | None = None,
        # Mutable fields initialised at the start of the loop; callers pass
        # the seed values so that the state object owns them from day one.
        taint_summary_results: dict[str, Any] | None = None,
        constraints: Any = None,
        expansion_budget: ExpansionBudget | None = None,
    ) -> SharedState:
        """Package prep outputs into a SharedState instance.

        All positional keyword arguments correspond to variables computed
        during the prep phase of ``_run_audit_body``.  Mutable loop fields
        (``taint_summary_results``, ``constraints``, ``expansion_budget``)
        are optional so callers can pass ``None`` and rely on the dataclass
        defaults when the seed value is unknown at prep time.
        """
        edge_index: dict[str, list[dict[str, Any]]] = {}
        for edge in call_edges:
            caller_bare = f"{edge.get('caller_file', '')}:{edge.get('caller', '')}"
            callee_file = edge.get("callee_file") or edge.get("caller_file", "")
            callee_bare = f"{callee_file}:{edge.get('callee', '')}"
            edge_index.setdefault(caller_bare, []).append(edge)
            if callee_bare != caller_bare:
                edge_index.setdefault(callee_bare, []).append(edge)

        cl_index: dict[tuple[str, str], dict[str, Any]] = {}
        for file_info in checklist.get("files", []):
            fpath = file_info.get("path", "")
            for item in file_info.get("items", file_info.get("functions", [])):
                name = item.get("name", "")
                if fpath and name:
                    cl_index[(fpath, name)] = {
                        "file": fpath,
                        "name": name,
                        "line_start": item.get("line_start", 0),
                        "line_end": item.get("line_end"),
                    }

        return cls(
            checklist=checklist,
            context_map=context_map,
            evidence_index=evidence_index,
            provenance_map=provenance_map,
            security_decision_keys=security_decision_keys,
            feeds_security_keys=feeds_security_keys,
            taint_approx_results=taint_approx_results,
            sarif_cache=sarif_cache,
            flow_traces=flow_traces,
            variant_targets=variant_targets,
            entry_points=entry_points,
            sinks_set=sinks_set,
            widely_used_keys=widely_used_keys,
            conventions=conventions,
            sibling_ns_findings=sibling_ns_findings,
            sibling_postcond_violations=sibling_postcond_violations,
            peer_groups=peer_groups,
            semantic_findings=semantic_findings,
            mechanical_findings=mechanical_findings,
            fuzz_coverage=fuzz_coverage,
            discovered_tests=discovered_tests,
            typestate_models=typestate_models,
            summary_cache=summary_cache,
            checker_library=checker_library,
            triage_results=triage_results,
            project_learnings=project_learnings,
            feedback_state=feedback_state,
            fp_patterns=fp_patterns,
            prop_config=prop_config,
            iris_taint_specs=iris_taint_specs,
            call_edges=call_edges,
            call_edge_index=edge_index,
            checklist_index=cl_index,
            domain_model=domain_model,
            capability_displacements=capability_displacements if capability_displacements is not None else [],
            struct_accessor_index=struct_accessor_index if struct_accessor_index is not None else {},
            taint_summary_results=taint_summary_results if taint_summary_results is not None else {},
            constraints=constraints,
            expansion_budget=expansion_budget,
        )
