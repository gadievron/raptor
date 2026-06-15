"""Shared reachability-chokepoint helper for finding-suppression.

Both ``/agentic`` (packages/llm_analysis/agent.py) and ``/codeql``
(packages/codeql/autonomous_analyzer.py) consult the same reachability
witnesses to skip the LLM call when a finding's enclosing function is
provably dead. Adversarial review flagged duplication: the /agentic
hook was copy-paste-reduced without the autonomous_analyzer's path
normalisation and module-derivation helpers, producing wrong-path
lookups (file:// URI, absolute, repo-rooted ./ prefix) and
language-incorrect module strings (literal "src/util.c" for C
findings). This module is the canonical entry point.

Usage::

    from core.inventory.reach_chokepoint import check_suppress

    decision = check_suppress(
        checklist=checklist_inventory,
        file_path=finding_file,
        function_name=finding_function,
        line=finding_line,
        repo_root=repo_path,
        allow_unreachable=cli_allow_unreachable,
        manual_override=finding.get("manual_override"),
    )
    if decision is not None:
        verdict, reason = decision
        # suppress + record verdict on the finding's analysis
"""

from __future__ import annotations

import json
import logging
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


def normalise_path(file_path: str, repo_root: Path) -> Optional[str]:
    """SARIF emitters / semgrep / scanner output produce a mix of
    absolute paths, ``file://``-URI paths, and repo-relative paths.
    Normalise to a repo-relative ``a/b/c.ext`` form so the inventory
    lookup (keyed on repo-relative paths) matches. Returns ``None``
    when the input is absolute but not under ``repo_root`` —
    something outside the analysed tree, do not suppress.
    """
    if not file_path:
        return None
    if file_path.startswith("file://"):
        file_path = file_path[len("file://"):]
    p = Path(file_path)
    if p.is_absolute():
        try:
            return str(p.relative_to(repo_root.resolve()))
        except ValueError:
            return None
    # Strip a leading ./ that some tools emit so it matches the
    # inventory's ``files[].path`` convention (no leading ./).
    if file_path.startswith("./"):
        file_path = file_path[2:]
    return file_path


def path_to_module(rel_path: str) -> Optional[str]:
    """``packages/foo/bar.py`` → ``packages.foo.bar``. For non-Python
    languages, strip the extension and replace path separators with
    dots — the call_graph extractor produces dotted-form keys for
    every language it covers. Returns ``None`` for paths with no
    extension (can't derive a module).
    """
    if not rel_path:
        return None
    p = PurePosixPath(rel_path.replace("\\", "/"))
    if not p.suffix:
        return None
    parts = list(p.parts)
    parts[-1] = p.stem
    return ".".join(parts)


def check_suppress(
    *,
    checklist: dict,
    file_path: str,
    function_name: str,
    line: int,
    repo_root: Path,
    allow_unreachable: bool = False,
    manual_override: object = None,
) -> Optional[Tuple[str, str]]:
    """Single source of truth for "should this finding be suppressed?"

    Returns ``(verdict, reason)`` if the finding's enclosing function
    is unreachable via a SOUND, corpus-earned witness that licenses
    suppression. Returns ``None`` when:

      * ``manual_override`` is truthy (operator opted out explicitly),
      * ``allow_unreachable`` is True (CLI opted out globally),
      * the checklist is missing or empty,
      * path or module derivation fails,
      * the verdict isn't suppressable (heuristic / live).

    Caller's responsibility: record ``verdict`` + ``reason`` on the
    finding's audit output and skip the LLM call. Never modify the
    finding silently; the suppression must be visible to the operator
    via annotations / suppressions.jsonl / report output.
    """
    # NB: ``manual_override`` is a finding-level boolean. Coerce
    # explicit string-False to bool-False so an emitter that writes
    # ``"manual_override": "false"`` doesn't accidentally bypass the
    # chokepoint via Python truthiness on the non-empty string.
    if isinstance(manual_override, str):
        manual_override = manual_override.strip().lower() not in (
            "", "false", "0", "no", "off")
    if manual_override:
        return None
    if allow_unreachable:
        return None
    if not checklist or not isinstance(checklist, dict):
        return None
    if not file_path or not function_name:
        return None
    rel = normalise_path(file_path, repo_root)
    if rel is None:
        return None
    module = path_to_module(rel)
    if not module:
        return None

    # Local imports — the chokepoint module stays cheap to import; the
    # reach_audit + reach_witness graph is heavier and only paid on
    # the first suppression attempt.
    from core.inventory.reach_audit import classify_reachability
    from core.inventory.reach_witness import (
        STRUCTURALLY_SUPPRESSIBLE_KINDS,
        verdict_from_classification,
    )

    verdict = classify_reachability(
        checklist, rel, function_name, int(line or 0), module)
    spec = verdict_from_classification(verdict)
    if not spec.may_suppress(STRUCTURALLY_SUPPRESSIBLE_KINDS):
        return None
    reason = (
        f"Reachability chokepoint: the finding's enclosing function "
        f"({rel}:{function_name}) is unreachable via a SOUND, corpus-"
        f"earned witness ({verdict}). No exploit is reachable in this "
        f"build / deployment surface. To override, set "
        f"``manual_override: true`` on the finding and re-run, or "
        f"pass ``--allow-unreachable`` to evaluate the function's "
        f"inherent vulnerability shape regardless of deployment "
        f"reachability."
    )
    return (verdict, reason)


def record_suppression(
    out_dir: Path,
    *,
    finding: Dict[str, Any],
    verdict: str,
    reason: str,
    dropped: bool = True,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """Append one record to ``out_dir/suppressions.jsonl`` describing
    the finding the chokepoint just dropped. Best-effort — IO errors
    are logged at debug and never propagate. Adversarial review
    Agent C P1-1: per-finding ``analysis.reachability_suppression``
    + ``reachability_verdict`` records carry the data, but operators
    asked "show me the N findings the binary-oracle dropped" can't
    grep individual annotations cheaply. The JSONL gives them a
    one-stop aggregate view.

    Record schema (stable, additive)::

      {
        "finding_id": "...",         # or "id" if that's the key used
        "rule_id":    "...",         # if present
        "file_path":  "...",
        "line":       42,
        "function":   "...",
        "verdict":    "binary_oracle_absent",
        "reason":     "Reachability chokepoint: ...",
        "dropped":    true,          # phase 6 addition: false when the
                                     # record describes a finding that
                                     # SURVIVED to the LLM (e.g. the
                                     # sanitizer-cut ``candidate_only``
                                     # verdict)
        ...                          # phase 6 ``extra`` fields
                                     # merged in here; consumers
                                     # tolerant of unknown keys
      }

    Phase 6 added the optional ``dropped`` and ``extra`` kwargs:

    * ``dropped`` — back-compat default ``True`` so existing
      binary-oracle suppression records preserve their meaning.
      Set ``False`` for records that describe a NON-suppressed
      finding (the sanitizer-cut ``candidate_only`` case writes
      these so operators can see what the value-bound suppressor
      saw but didn't act on).
    * ``extra`` — additional fields merged into the record. Phase
      6's sanitizer-cut uses this to carry ``sink_arg``,
      ``bindings`` (the per-binding witness), and similar audit
      data. Unknown keys are tolerated by every existing reader.

    Order of operations between verdict producers (review #6 on
    PR #794). ``suppressions.jsonl`` has a SINGLE writer — this
    function. Two producers feed it:

    * binary-oracle reachability (``verdict="binary_oracle_absent"``)
      — the LIVE producer, invoked from the /agentic and /codeql
      reachability chokepoint as a PRE-LLM hard-suppress.
    * sanitizer-cut (``verdict="sanitizer_dominated"`` /
      ``candidate_only``) — bridged in via
      :func:`core.inventory.sanitizer_cut.record_sanitizer_cut_suppression`.
      It writes the same schema but is NOT yet wired into the
      pipeline (only tests call it — see that function's note), so
      today there is no live ordering interaction.

    When sanitizer-cut is wired, the intended order is binary-oracle
    FIRST: a function absent from the binary is dropped before any
    dataflow/sanitizer reasoning runs, so the sanitizer-cut gate never
    sees it and can't double-record it. The producers do not observe
    each other's verdicts; records are additive (one line per event,
    distinguished by ``verdict``), so a reader attributes a drop to its
    source by filtering on ``verdict``. (Note: ``binary_oracle_edges.py``
    builds call edges and does NOT write here — this is the only writer.)

    """
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        record: Dict[str, Any] = {
            "finding_id": (finding.get("finding_id")
                           or finding.get("id") or ""),
            "rule_id":    finding.get("rule_id") or "",
            "file_path":  (finding.get("file_path")
                           or finding.get("file") or ""),
            "line":       finding.get("line"),
            "function":   (finding.get("function")
                           or (finding.get("metadata") or {}).get(
                               "function_name", "")),
            "verdict":    verdict,
            "reason":     reason,
            "dropped":    bool(dropped),
        }
        if extra:
            record.update(extra)
        with (out_dir / "suppressions.jsonl").open("a") as f:
            f.write(json.dumps(record) + "\n")
    except OSError as e:
        logger.debug(
            "reach_chokepoint: failed to write suppression record: %s", e)


__all__ = [
    "normalise_path", "path_to_module",
    "check_suppress", "record_suppression",
]
