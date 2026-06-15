"""Phase D wiring: source_intel evidence into Stage D LLM prompts.

The orchestrator pre-seeds a target's source_intel result once per
run (one spatch invocation per target). The dispatch tasks pull
per-finding evidence from the cache and pass it into the prompt
bundle as additional :class:`UntrustedBlock` entries.

This is the second consumer wiring for source_intel — the first
(``packages.codeql.dataflow_validator``) plugs into the
``evidence_collector=`` channel for individual CodeQL findings.
This module plugs into the broader ``llm_analysis`` family used by
``/agentic`` and ``/analyze`` for any finding (CodeQL or otherwise)
whose rule_id matches the memory-corruption set.

  * Source_intel is a SIDECAR — evidence, never verdict.
  * Evidence renders as ``UntrustedBlock(kind="source-intel-evidence")``
    so the prompt-envelope discipline applies uniformly.
  * Only memory-corruption-class findings receive evidence — others
    would carry irrelevant prose that wastes LLM budget.

API:
  * :func:`prepare_source_intel(repo_path)` — pre-seed the cache.
    Called from the orchestrator after dispatch starts but before
    findings are processed. Best-effort: failures (spatch missing,
    target unreadable) are logged and skipped — the dispatch
    proceeds with no source_intel evidence rather than failing.
  * :func:`evidence_blocks_for_finding(finding)` — return a tuple
    of ``UntrustedBlock`` entries to inject into the prompt's
    ``extra_blocks``. Returns ``()`` when no relevant evidence
    exists for this finding.

Caching: process-global dict keyed by absolute resolved repo path.
Mirrors the inventory cache pattern in
``packages.source_intel.analyze``. One entry per target — multiple
findings in one repo share the spatch result.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from core.security.prompt_envelope import UntrustedBlock

# Module-level imports of optional dependencies — held as None when
# the package isn't available (minimal install / packaging strip).
# Tests can monkeypatch ``_analyze`` to inject a stub without
# wrestling with the import-binding semantics of the
# ``packages.source_intel.__init__`` re-exports.
try:
    from packages.source_intel import (
        analyze as _analyze,
        derive_evidence_strings as _derive_evidence_strings,
        DEFAULT_SOURCE_INTEL_RULE_PREFIXES as _DEFAULT_RULE_PREFIXES,
    )
except ImportError:
    _analyze = None
    _derive_evidence_strings = None
    _DEFAULT_RULE_PREFIXES = frozenset()

try:
    from core.build.build_flags import extract_flags as _extract_flags
except ImportError:
    _extract_flags = None

logger = logging.getLogger(__name__)

# CWE-based fallback gate for source-intel evidence injection.
# External scanners (Coverity, Snyk, Bandit, …) use tool-specific
# rule_id prefixes that never match _DEFAULT_RULE_PREFIXES (which is
# CodeQL-centric).  When a finding's rule_id doesn't match, we check
# its CWE against this set before rejecting.  The set mirrors the CWE
# coverage of _DEFAULT_RULE_PREFIXES.
_SOURCE_INTEL_CWES = frozenset({
    "CWE-120", "CWE-122",  # buffer / heap overflow
    "CWE-190",              # integer overflow
    "CWE-415", "CWE-416",  # double-free / use-after-free
    "CWE-476",              # null deref
    "CWE-787",              # OOB write
    "CWE-252",              # unchecked return
    "CWE-125",              # OOB read
    "CWE-134",              # format string
    "CWE-908",              # uninitialized memory
})

# Cache: absolute resolved target dir → ``(signature, result)``
# tuple. ``result`` is the ``SourceIntelResult`` or ``None`` when
# the build failed (distinguished from missing-key, which means
# "not yet attempted"). ``signature`` is the fast change-detection
# stamp from :func:`packages.source_intel.cache.compute_target_signature`
# — lookups re-stamp the target and drop the entry if it shifted,
# so two ``/agentic`` runs on the same target with content edits in
# between trigger a re-analyze rather than serve stale evidence.
#
# Thread-safety: ``_SI_LOCK`` (RLock) guards the dict ops. Same
# pattern as ``_INVENTORY_LOCK`` in ``packages.source_intel.analyze``
# — the lock is held only around the dict reads/writes, never
# during the filesystem-walking signature compute or the call to
# ``_analyze`` (which can take minutes for a kernel-sized target).
_SI_RESULT_CACHE: Dict[str, Tuple[str, Optional[Any]]] = {}
_SI_LOCK = threading.RLock()

def prepare_source_intel(repo_path: Path) -> None:
    """Pre-seed the source_intel result cache for ``repo_path``.

    Called once per orchestrator run, before dispatch starts. Runs
    ``packages.source_intel.analyze`` on the target and stashes the
    result in the cache. Subsequent
    :func:`evidence_blocks_for_finding` calls read the cache.

    Best-effort:
      * ``packages.source_intel`` not importable → skip (no
        injection wired for this run)
      * ``analyze()`` raises → log at warning, cache ``None`` so we
        don't retry for this target this process
      * ``analyze()`` returns ``is_skipped=True`` (spatch missing,
        no C/C++ source) → cache the result as-is; downstream
        ``evidence_blocks_for_finding`` returns ``()``

    Side effect: also seeds the inventory cache via the existing
    ``_maybe_register_inventory`` path inside ``analyze``. The
    tree-sitter-backed ``_enclosing_function`` resolution lights
    up for free.
    """
    try:
        key = str(repo_path.resolve())
    except (OSError, ValueError):
        logger.debug(
            "prepare_source_intel: unresolvable repo_path %s; skipping",
            repo_path,
        )
        return
    from packages.source_intel.cache import compute_target_signature
    sig = compute_target_signature(repo_path)
    with _SI_LOCK:
        cached = _SI_RESULT_CACHE.get(key)
        if cached is not None and cached[0] == sig:
            return  # already attempted on this exact tree state
    if _analyze is None:
        logger.debug(
            "prepare_source_intel: packages.source_intel not importable; "
            "skipping injection wiring",
        )
        with _SI_LOCK:
            _SI_RESULT_CACHE[key] = (sig, None)
        return
    try:
        result = _analyze(repo_path)
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "prepare_source_intel: analyze(%s) failed: %s; "
            "Stage D will run without source_intel evidence",
            repo_path, e,
        )
        with _SI_LOCK:
            _SI_RESULT_CACHE[key] = (sig, None)
        return
    with _SI_LOCK:
        _SI_RESULT_CACHE[key] = (sig, result)
    # INFO-level surfacing of the success path so operators can
    # visually confirm Phase D PR1 wiring fires during /agentic runs.
    # Pre-fix the only log lines were on failure paths — a clean run
    # produced zero log evidence the function had executed, making
    # gap-#2-style "does the wiring work?" questions unanswerable
    # without code archaeology. Counts are cheap to compute (already
    # attached to result) and short enough not to clutter logs.
    if result.is_skipped:
        logger.info(
            "prepare_source_intel: %s skipped (%s) — Stage D will run "
            "without source_intel evidence",
            repo_path, result.skipped_reason or "unknown reason",
        )
    else:
        # Defensive ``getattr`` — SourceIntelResult adds fields over
        # time; the log shouldn't crash if a stub or older shape lacks
        # a field. Counts default to 0 when the attribute is absent.
        def _count(attr: str) -> int:
            return len(getattr(result, attr, ()) or ())
        logger.info(
            "prepare_source_intel: %s ready — attributes=%d, aborts=%d, "
            "allocations=%d, capabilities=%d, lsm_hooks=%d, hazards=%d",
            repo_path,
            _count("attributes"), _count("aborts"),
            _count("allocations"), _count("capabilities"),
            _count("lsm_hooks"), _count("hazards"),
        )


def evidence_blocks_for_finding(
    finding: Dict[str, Any],
) -> Tuple[UntrustedBlock, ...]:
    """Build the source_intel ``UntrustedBlock`` tuple for one finding.

    Returns ``()`` when any of:
      * finding's rule_id doesn't match the memory-corruption set
      * finding has no ``repo_path`` (orchestrator didn't seed it)
      * source_intel cache miss (``prepare_source_intel`` wasn't
        called for this target, or analyze() failed)
      * source_intel result is skipped with no observations
      * renderer produced no lines for the finding's function

    Otherwise returns a 1-tuple with one ``UntrustedBlock(kind=
    "source-intel-evidence", origin="cocci-structural-evidence")``.

    Stage E binary-supersedes is NOT applied at this layer — the
    llm_analysis path doesn't currently consume binary verdicts.
    When it does, threading a ``binary_verdict`` through here
    matches the existing render API (already accepts the parameter).
    """
    rule_id = (finding.get("rule_id") or "").strip()
    if not rule_id:
        return ()
    if not _DEFAULT_RULE_PREFIXES:
        return ()
    if not any(rule_id.startswith(p) for p in _DEFAULT_RULE_PREFIXES):
        # Fallback: CWE-based gate for external scanners whose rule_id
        # prefixes won't match the CodeQL-centric _DEFAULT_RULE_PREFIXES.
        cwe = (finding.get("cwe_id") or "").strip()
        if cwe not in _SOURCE_INTEL_CWES:
            return ()

    repo_raw = finding.get("repo_path")
    if not repo_raw:
        return ()
    try:
        repo_key = str(Path(repo_raw).resolve())
    except (OSError, ValueError):
        return ()

    with _SI_LOCK:
        entry = _SI_RESULT_CACHE.get(repo_key)
    if entry is None:  # cache miss — orchestrator never called prepare_source_intel
        return ()
    # Validate freshness outside the lock — signature compute walks
    # the filesystem and would serialise unrelated lookups.
    from packages.source_intel.cache import compute_target_signature
    cached_sig, result = entry
    current_sig = compute_target_signature(Path(repo_key))
    if cached_sig != current_sig:
        # Re-check under the lock that we're popping the same
        # entry we read; a concurrent prepare may have refreshed it.
        with _SI_LOCK:
            current_entry = _SI_RESULT_CACHE.get(repo_key)
            if current_entry is not None and current_entry[0] == cached_sig:
                _SI_RESULT_CACHE.pop(repo_key, None)
        return ()
    if result is None:  # cached failure
        return ()
    if result.is_skipped and not result.attributes and not result.aborts:
        return ()
    if _derive_evidence_strings is None:
        return ()

    finding_function = (
        (finding.get("metadata") or {}).get("name")
        or finding.get("function")
        or ""
    )
    flags = None
    if _extract_flags is not None:
        try:
            flags = _extract_flags(Path(repo_key))
        except Exception:  # noqa: BLE001
            flags = None

    try:
        lines = _derive_evidence_strings(
            result,
            finding_function=finding_function or None,
            build_flags=flags,
            style="stage_d",
            max_lines=12,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "evidence_blocks_for_finding: render failed for %s: %s",
            rule_id, e,
        )
        return ()
    if not lines:
        return ()

    # INFO-level surfacing of the success path so /agentic logs make
    # the Phase D PR1 wiring visible. Pre-fix this function emitted
    # log lines only on render-failure (debug level) — successful
    # injections rendered silently, making "did source_intel evidence
    # reach the LLM prompt?" unanswerable without code archaeology.
    logger.info(
        "source_intel evidence injected for finding rule_id=%s "
        "function=%s (%d render lines)",
        rule_id, finding_function or "<unknown>", len(lines),
    )

    return (
        UntrustedBlock(
            content="\n".join(lines),
            kind="source-intel-evidence",
            origin="cocci-structural-evidence",
        ),
    )


def clear_si_result_cache() -> None:
    """Drop every cached source_intel result.

    Public invalidation lever for orchestrators that want an explicit
    fresh start (e.g. between two ``/agentic`` runs on different
    targets). Signature-based auto-invalidation already covers the
    same-path/content-changed case; this is the extra lever for
    callers that don't want to rely on the implicit path.
    """
    with _SI_LOCK:
        _SI_RESULT_CACHE.clear()


# Back-compat alias. Existing test code imports this name; the
# semantics are identical to ``clear_si_result_cache``.
clear_cache_for_tests = clear_si_result_cache
