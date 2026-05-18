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

Design intent (``~/design/dataflow-sanitizer-bypass.md``):
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


# Cache: absolute resolved target dir → ``SourceIntelResult``
# (best-effort, may be ``None`` if the build failed for any reason
# — distinguished from missing-key, which means "not yet attempted").
_SI_RESULT_CACHE: Dict[str, Optional[Any]] = {}

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
    if key in _SI_RESULT_CACHE:
        return  # already attempted (success or failure)
    if _analyze is None:
        logger.debug(
            "prepare_source_intel: packages.source_intel not importable; "
            "skipping injection wiring",
        )
        _SI_RESULT_CACHE[key] = None
        return
    try:
        result = _analyze(repo_path)
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "prepare_source_intel: analyze(%s) failed: %s; "
            "Stage D will run without source_intel evidence",
            repo_path, e,
        )
        _SI_RESULT_CACHE[key] = None
        return
    _SI_RESULT_CACHE[key] = result


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
        return ()

    repo_raw = finding.get("repo_path")
    if not repo_raw:
        return ()
    try:
        repo_key = str(Path(repo_raw).resolve())
    except (OSError, ValueError):
        return ()

    result = _SI_RESULT_CACHE.get(repo_key)
    if result is None:  # cache miss OR cached failure
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

    return (
        UntrustedBlock(
            content="\n".join(lines),
            kind="source-intel-evidence",
            origin="cocci-structural-evidence",
        ),
    )


def clear_cache_for_tests() -> None:
    """Test hook — reset module state between test runs."""
    _SI_RESULT_CACHE.clear()
