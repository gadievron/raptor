"""CodeQL → :class:`core.dataflow.Finding` adapter.

Two entry points:

* :func:`from_sarif_result` — convert one SARIF ``result`` entry (the
  canonical CodeQL wire format) into a :class:`Finding`. Returns
  ``None`` when the result isn't a dataflow path (no ``codeFlows``,
  empty ``threadFlows``, or fewer than 2 locations) — these are
  legitimate non-dataflow CodeQL results, not errors.

* :func:`from_dataflow_path` — convert the in-memory
  ``packages.codeql.dataflow_validator.DataflowPath`` shape that
  RAPTOR's existing validator already builds. Duck-typed so this
  module doesn't import ``packages.codeql``.

Stable :class:`Finding.finding_id` generation is exposed separately
via :func:`make_finding_id` — corpus tooling and run scripts call it
directly so the same id derives whether constructed from SARIF or
from an in-memory DataflowPath.

The full producer record is preserved in ``Finding.raw`` so corpus
JSON entries can later be re-parsed by the same adapter without loss.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Mapping, Optional

from core.dataflow.finding import Finding, Step


PRODUCER = "codeql"


def make_finding_id(
    rule_id: str, source: Step, sink: Step, *, producer: str = PRODUCER
) -> str:
    """Stable id from ``(producer, rule_id, source loc, sink loc)``.

    Same inputs → same id across reruns. The 12-character SHA-256
    prefix is sufficient for corpus-scale uniqueness; collisions
    surface via the corpus-integrity test
    (``test_corpus_finding_ids_are_unique``).
    """
    key = (
        f"{producer}|{rule_id}|"
        f"{source.file_path}:{source.line}|"
        f"{sink.file_path}:{sink.line}"
    )
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    rule_slug = rule_id.replace("/", "-").replace(".", "-") or "unknown"
    return f"{producer}_{rule_slug}_{digest}"


def from_sarif_result(
    result: Mapping[str, Any],
    *,
    producer: str = PRODUCER,
    finding_id: Optional[str] = None,
) -> Optional[Finding]:
    """Convert one SARIF ``result`` entry into a :class:`Finding`.

    Returns ``None`` when the result lacks a dataflow code-flow
    structure (rules emitting a single location without a path are
    not :class:`Finding` shapes).

    Raises :class:`ValueError` from :class:`Step` validation when the
    SARIF data is structurally a path but contains malformed entries
    (empty URI, ``startLine`` < 1). Better to surface than to silently
    coerce.
    """
    code_flows = result.get("codeFlows") or []
    if not code_flows:
        return None

    thread_flows = code_flows[0].get("threadFlows") or []
    if not thread_flows:
        return None

    locations = thread_flows[0].get("locations") or []
    if len(locations) < 2:
        return None

    steps: List[Step] = []
    for loc_wrapper in locations:
        loc = loc_wrapper.get("location", {})
        physical_loc = loc.get("physicalLocation", {})
        region = physical_loc.get("region", {})
        artifact = physical_loc.get("artifactLocation", {})

        message_text = loc.get("message", {}).get("text") or ""
        steps.append(
            Step(
                file_path=artifact.get("uri", ""),
                line=region.get("startLine", 0),
                column=region.get("startColumn", 0),
                snippet=region.get("snippet", {}).get("text", ""),
                label=message_text or None,
            )
        )

    source = steps[0]
    sink = steps[-1]
    intermediate = tuple(steps[1:-1])

    rule_id = result.get("ruleId") or "unknown"
    message_obj = result.get("message", {})
    message = message_obj.get("text") or "(no message)"

    if finding_id is None:
        finding_id = make_finding_id(rule_id, source, sink, producer=producer)

    return Finding(
        finding_id=finding_id,
        producer=producer,
        rule_id=rule_id,
        message=message,
        source=source,
        sink=sink,
        intermediate_steps=intermediate,
        raw=dict(result),
    )


def from_dataflow_path(
    dp: Any,
    *,
    producer: str = PRODUCER,
    finding_id: Optional[str] = None,
) -> Finding:
    """Convert ``packages.codeql.dataflow_validator.DataflowPath`` to
    :class:`Finding`.

    Duck-typed: any object with ``source``, ``sink``,
    ``intermediate_steps``, ``rule_id``, ``message``, and (optionally)
    ``sanitizers`` attributes works. The producer-side
    ``sanitizers: List[str]`` is preserved under
    ``raw["dataflow_path_sanitizers"]`` since :class:`Finding` doesn't
    model it directly — PR1's sanitizer-evidence pipeline derives
    structurally instead.
    """
    source = _step_from_dp_step(dp.source)
    sink = _step_from_dp_step(dp.sink)
    intermediate = tuple(_step_from_dp_step(s) for s in dp.intermediate_steps)

    rule_id = getattr(dp, "rule_id", "") or "unknown"
    message = getattr(dp, "message", "") or "(no message)"

    if finding_id is None:
        finding_id = make_finding_id(rule_id, source, sink, producer=producer)

    raw: Dict[str, Any] = {}
    sanitizers = getattr(dp, "sanitizers", None)
    if sanitizers:
        raw["dataflow_path_sanitizers"] = list(sanitizers)

    return Finding(
        finding_id=finding_id,
        producer=producer,
        rule_id=rule_id,
        message=message,
        source=source,
        sink=sink,
        intermediate_steps=intermediate,
        raw=raw,
    )


def _step_from_dp_step(s: Any) -> Step:
    return Step(
        file_path=s.file_path,
        line=s.line,
        column=s.column,
        snippet=s.snippet,
        label=(s.label or None),
    )
