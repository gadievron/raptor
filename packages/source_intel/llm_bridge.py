"""Production wiring: source_intel → ``DataflowValidator(evidence_collector=...)``.

Mirrors :mod:`core.dataflow.llm_bridge` (which wires the PR1 V2 LLM
extractor). Source_intel's evidence is structurally different — it's
mechanically-derived rather than LLM-extracted — but it plugs into
the same ``evidence_collector=`` channel via the generalised
:class:`~packages.codeql.dataflow_validator.EvidenceCollector` type,
which now accepts an :class:`~core.security.prompt_envelope.UntrustedBlock`
return as a sibling of :class:`SanitizerEvidence`.

Typical use (operator wiring for memory-corruption findings)::

    from packages.source_intel.llm_bridge import (
        make_source_intel_collector,
        make_cwe_dispatched_collector,
    )
    from core.dataflow.llm_bridge import make_evidence_collector
    from packages.codeql.dataflow_validator import DataflowValidator

    sanitizer = make_evidence_collector(llm_client)          # PR1 V2
    source_intel = make_source_intel_collector()             # this module
    dispatched = make_cwe_dispatched_collector(
        sanitizer_collector=sanitizer,
        source_intel_collector=source_intel,
    )
    validator = DataflowValidator(llm_client, evidence_collector=dispatched)

("Mechanism #4 — source_intel"), source_intel plugs into the same
``evidence_collector=`` channel PR1 V2 shipped — but evidence is
pre-computed cocci output, not LLM extraction. CWE-class dispatch
picks the right collector per finding: injection-class → sanitizer
extractor (V2); memory-corruption-class → source_intel.

This module performs NO verdict gating. Source_intel is a SIDECAR
(evidence, not verdict) — the renderer hands prose to the LLM, the
LLM consumes it alongside the dataflow path, no early return.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable, Optional, Set

from core.security.prompt_envelope import UntrustedBlock

logger = logging.getLogger(__name__)


# CWE rule_id prefixes that source_intel's evidence axes are most
# relevant to. Curated from design (CWE-120/122/190/415/416/476/787)
# crossed with CodeQL's actual rule_id naming. When a finding's
# rule_id matches one of these, the dispatched collector routes to
# source_intel; otherwise the sanitizer-extraction collector runs.
#
# Conservative on the source_intel side: the goal is to avoid burning
# the LLM budget on findings where source_intel has no relevant axis.
# The default set covers the memory-corruption family RAPTOR's cocci
# rules target; operators can extend via the ``source_intel_rule_prefixes``
# parameter on :func:`make_cwe_dispatched_collector`.
DEFAULT_SOURCE_INTEL_RULE_PREFIXES: frozenset = frozenset({
    # CWE-120 / CWE-122 — buffer / heap overflows
    "cpp/unbounded-write",
    "cpp/badly-bounded-write",
    "cpp/uncontrolled-allocation-size",
    "cpp/very-likely-overrunning-write",
    "cpp/overrunning-write",
    # CWE-190 — integer overflow into alloc / index
    "cpp/uncontrolled-arithmetic",
    "cpp/integer-multiplication-cast-to-long",
    "cpp/signed-overflow-check",
    "cpp/tainted-arithmetic",
    # CWE-415 / CWE-416 — double-free / use-after-free
    "cpp/use-after-free",
    "cpp/double-free",
    # CWE-476 — null deref
    "cpp/null-dereference",
    "c/null-dereference",
    # CWE-787 — out-of-bounds write
    "cpp/out-of-bounds-write",
    "cpp/incorrect-allocation-error-handling",
    # CWE-252 — unchecked return (paired with WUR/nodiscard axis 1)
    "cpp/unchecked-return-value",
    "c/unchecked-return",
})


# Maximum lines of source_intel evidence rendered into the prompt.
# Keeps the prompt budget bounded when many axes fire on one finding.
# 12 ≈ one screen of context for the LLM; larger settings risk
# crowding out the dataflow path itself.
DEFAULT_MAX_EVIDENCE_LINES = 12


def make_source_intel_collector(
    *,
    cache: Optional[Any] = None,
    repo_path_resolver: Optional[Callable[[Any, Path], Path]] = None,
    binary_verdict_resolver: Optional[Callable[[Any, Path], Optional[str]]] = None,
    style: str = "stage_d",
    max_lines: int = DEFAULT_MAX_EVIDENCE_LINES,
):
    """Build a source_intel evidence collector for ``DataflowValidator``.

    The returned callable matches the generalised
    :data:`~packages.codeql.dataflow_validator.EvidenceCollector`
    signature ``(DataflowPath, Path) -> Optional[UntrustedBlock]``.
    It:

    1. Resolves the source_intel scan target (``repo_path`` by default;
       operator-supplied ``repo_path_resolver`` may narrow to a
       sub-tree for kernel-scale targets).
    2. Runs :func:`packages.source_intel.analyze.analyze` (uses
       ``cache`` when provided to amortise across findings).
    3. Extracts build-flag context for the same target.
    4. Determines the sink's enclosing function (best-effort scan).
    5. Optionally consults ``binary_verdict_resolver`` for the
       per-finding Stage E binary verdict (see
       :mod:`packages.exploit_feasibility`). When the resolver
       returns a "blocked" / "requires_environment" verdict, the
       rendered evidence is prefixed with a SUPERSEDED marker per
       design Stage E ("binary observation supersedes source intent").
    6. Renders evidence via
       :func:`packages.source_intel.render.derive_evidence_strings`
       and wraps as
       ``UntrustedBlock(kind="source-intel-evidence", origin="cocci-structural-evidence")``.

    Returns ``None`` (no block) when:
      * source_intel skipped AND no observations exist (genuine no-data);
      * the renderer produced no lines (no relevant evidence for the
        sink function);
      * any unexpected exception (logged at warning level — never fail
        the validate_path call over an evidence-collection issue).

    ``cache`` should be a :class:`~packages.source_intel.cache.SourceIntelCache`
    shared across the validator's lifetime; this avoids re-running
    spatch on the same target for every finding.
    """
    # NB: ``packages.source_intel.__init__`` re-exports the function
    # ``analyze`` into the package namespace, shadowing the
    # like-named submodule. ``import packages.source_intel.analyze
    # as _analyze_mod`` would resolve to the function. Use the
    # importlib path to bind to the module object explicitly.
    import importlib
    _analyze_mod = importlib.import_module("packages.source_intel.analyze")
    from packages.source_intel.render import derive_evidence_strings

    def _collector(dataflow, repo_path: Path) -> Optional[UntrustedBlock]:
        try:
            scan_target = (
                repo_path_resolver(dataflow, repo_path)
                if repo_path_resolver is not None
                else repo_path
            )

            result = None
            if cache is not None:
                result = cache.get(scan_target)
            if result is None:
                result = _analyze_mod.analyze(scan_target)
                if cache is not None:
                    cache.put(scan_target, None, result)

            # Cheap exit: skipped run with no salvageable observations.
            if result.is_skipped and not result.attributes and not result.aborts:
                return None

            flags = _safe_extract_flags(scan_target)
            sink_fn = _safe_enclosing_function(
                dataflow.sink.file_path, dataflow.sink.line
            )
            binary_verdict = _safe_binary_verdict(
                binary_verdict_resolver, dataflow, scan_target
            )
            # Axis-4 multi-hop privilege back-walk evidence (Phase D
            # follow-up). Best-effort — when prereqs are unavailable
            # or the sink function can't be determined, the helper
            # returns None and the renderer skips the line.
            back_walk = _safe_privilege_back_walk(
                sink_fn, scan_target, result,
            )

            lines = derive_evidence_strings(
                result,
                finding_function=sink_fn,
                build_flags=flags,
                style=style,
                max_lines=max_lines,
                binary_verdict=binary_verdict,
                privilege_back_walk=back_walk,
            )
            if not lines:
                return None

            return UntrustedBlock(
                content="\n".join(lines),
                kind="source-intel-evidence",
                origin="cocci-structural-evidence",
            )
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "source_intel collector failed for %s: %s; "
                "skipping evidence block",
                getattr(getattr(dataflow, "sink", None), "file_path", "?"),
                e,
            )
            return None

    return _collector


def make_cwe_dispatched_collector(
    *,
    sanitizer_collector,
    source_intel_collector,
    source_intel_rule_prefixes: Optional[Set[str]] = None,
):
    """Compose two collectors with rule_id-prefix dispatch.

    Returns a callable matching the
    :class:`~packages.codeql.dataflow_validator.EvidenceCollector`
    contract:

    * If ``dataflow.rule_id`` starts with any prefix in
      ``source_intel_rule_prefixes`` (default
      :data:`DEFAULT_SOURCE_INTEL_RULE_PREFIXES`) — route to
      ``source_intel_collector``.
    * Otherwise — route to ``sanitizer_collector``.

    Either collector may be ``None`` if the operator only wants one
    branch wired; the dispatcher returns ``None`` (no evidence block)
    for the unwired branch.

    Rationale: source_intel's axes target memory-corruption CWEs;
    PR1 V2's LLM extractor targets injection CWEs. Running the wrong
    collector on a finding is wasted LLM cost AND produces evidence
    irrelevant to the verdict.
    """
    prefixes = (
        frozenset(source_intel_rule_prefixes)
        if source_intel_rule_prefixes is not None
        else DEFAULT_SOURCE_INTEL_RULE_PREFIXES
    )

    def _dispatched(dataflow, repo_path: Path):
        rule_id = getattr(dataflow, "rule_id", "") or ""
        for prefix in prefixes:
            if rule_id.startswith(prefix):
                if source_intel_collector is None:
                    return None
                return source_intel_collector(dataflow, repo_path)
        if sanitizer_collector is None:
            return None
        return sanitizer_collector(dataflow, repo_path)

    return _dispatched


# ---- internal helpers ------------------------------------------------


def _safe_extract_flags(target: Path):
    """Best-effort wrapper around :func:`core.build.build_flags.extract_flags`.

    Returns ``None`` on any error so the renderer falls back to its
    'flags absent' branch instead of failing the whole collector.
    """
    try:
        from core.build.build_flags import extract_flags
        return extract_flags(target)
    except Exception:  # noqa: BLE001
        return None


def _safe_enclosing_function(file_path: str, line: int) -> Optional[str]:
    """Best-effort wrapper around analyze._enclosing_function.

    Returns ``None`` on any error; the renderer's
    ``finding_function=None`` branch surfaces ALL observations rather
    than filtering, which is the safe over-reporting fallback.
    """
    try:
        from packages.source_intel.analyze import _enclosing_function
        return _enclosing_function(file_path, line)
    except Exception:  # noqa: BLE001
        return None


def _safe_privilege_back_walk(
    sink_fn: Optional[str],
    scan_target: Path,
    result,
):
    """Best-effort wrapper around
    ``packages.source_intel.analyze.compute_privilege_back_walk_evidence``.

    Returns ``None`` when:
      * ``sink_fn`` is None (couldn't determine the finding's
        enclosing function)
      * the computation raises (PR-4 prereqs unavailable, gather
        failed, etc.)
      * the computation returns None (no callers AND no privileged
        cap in finding fn itself)

    The renderer skips emitting a back-walk line on None.
    """
    if not sink_fn:
        return None
    try:
        import importlib
        _analyze_mod = importlib.import_module(
            "packages.source_intel.analyze"
        )
        return _analyze_mod.compute_privilege_back_walk_evidence(
            sink_fn, scan_target, result,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "privilege_back_walk computation failed for %s: %s",
            sink_fn, e,
        )
        return None


def _safe_binary_verdict(
    resolver: Optional[Callable],
    dataflow,
    scan_target: Path,
) -> Optional[str]:
    """Best-effort wrapper around an operator-supplied binary
    verdict resolver.

    Returns ``None`` when no resolver is configured or the resolver
    raises (logged at debug level — the absence of a binary verdict
    is the common case, not an error). The renderer's
    ``binary_verdict=None`` branch then emits unchanged output.
    """
    if resolver is None:
        return None
    try:
        return resolver(dataflow, scan_target)
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "binary_verdict_resolver raised %s; "
            "rendering without Stage E binary supersession", e,
        )
        return None
