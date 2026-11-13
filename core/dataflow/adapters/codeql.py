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
from collections.abc import Mapping
from typing import Any

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

    Known limitation: the id is location-anchored (file path + line
    of source and sink), so a file rename or move — or any edit that
    shifts those line numbers — yields a new id for the same defect,
    weakening cross-run correlation. A content-anchored redesign is
    deliberately deferred.
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
    finding_id: str | None = None,
) -> Finding | None:
    """Convert one SARIF ``result`` entry into a :class:`Finding`.

    Returns ``None`` when the result lacks a dataflow code-flow
    structure (rules emitting a single location without a path are
    not :class:`Finding` shapes).

    Raises :class:`ValueError` from :class:`Step` validation when the
    SARIF data is structurally a path but contains malformed entries
    (empty URI, ``startLine`` < 1). Better to surface than to silently
    coerce.
    """
    code_flows = result.get("codeFlows")
    if code_flows is not None and not isinstance(code_flows, (list, tuple)):
        raise ValueError("SARIF codeFlows must be an array")
    code_flows = code_flows or []
    if not code_flows:
        return None

    if not isinstance(code_flows[0], Mapping):
        raise ValueError("SARIF codeFlows entry must be an object")
    thread_flows = code_flows[0].get("threadFlows")
    if thread_flows is not None and not isinstance(thread_flows, (list, tuple)):
        raise ValueError("SARIF threadFlows must be an array")
    thread_flows = thread_flows or []
    if not thread_flows:
        return None

    if not isinstance(thread_flows[0], Mapping):
        raise ValueError("SARIF threadFlows entry must be an object")
    locations = thread_flows[0].get("locations")
    if locations is not None and not isinstance(locations, (list, tuple)):
        raise ValueError("SARIF locations must be an array")
    locations = locations or []
    if len(locations) < 2:
        return None

    def object_or_empty(value: Any, field: str) -> Mapping[str, Any]:
        if value is None:
            return {}
        if not isinstance(value, Mapping):
            raise ValueError(f"SARIF {field} must be an object")
        return value

    steps: list[Step] = []
    for loc_wrapper in locations:
        if not isinstance(loc_wrapper, Mapping):
            raise ValueError("SARIF locations entry must be an object")
        loc = object_or_empty(loc_wrapper.get("location"), "location")
        physical_loc = object_or_empty(loc.get("physicalLocation"), "physicalLocation")
        region = object_or_empty(physical_loc.get("region"), "region")
        artifact = object_or_empty(physical_loc.get("artifactLocation"), "artifactLocation")

        message_text = object_or_empty(loc.get("message"), "location.message").get("text") or ""
        # Explicit null objects retain their empty defaults; malformed
        # scalar objects must use the caller's ValueError refusal path.
        steps.append(
            Step(
                file_path=artifact.get("uri") or "",
                line=region.get("startLine") or 0,
                column=region.get("startColumn") or 0,
                snippet=object_or_empty(region.get("snippet"), "snippet").get("text") or "",
                label=message_text or None,
            )
        )

    source = steps[0]
    sink = steps[-1]
    intermediate = tuple(steps[1:-1])

    rule_id = result.get("ruleId") or "unknown"
    # Explicit null messages retain the documented default.
    message_obj = object_or_empty(result.get("message"), "result.message")
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
    finding_id: str | None = None,
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

    raw: dict[str, Any] = {}
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
