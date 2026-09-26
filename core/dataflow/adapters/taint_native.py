"""Cross-file taint engine → :class:`core.dataflow.Finding` adapter.

Converts the taint emission's SARIF ``result`` entries — the SAME
records the pipeline intake consumes, already bounded by the emission
artifact rail (per-field caps, list caps, record/budget bytes) — into
the producer-neutral :class:`Finding` shape for corpus replay. The
adapter adds no unbounded surface of its own: everything it reads
went through the emission boundary first, and the producer record is
preserved verbatim-as-emitted in ``Finding.raw``.

Degrade posture (differs from the CodeQL adapter, deliberately): the
taint step contract permits EMPTY location fields — an unresolvable
node renders ``""``/``0`` rather than a fabricated span — so an
unlocated step here is producer-known degradation, not malformed
input. Unlocated INTERMEDIATE locations are dropped (counted in
``raw["adapter_steps_dropped_unlocated"]``); an unlocated source or
sink returns ``None`` (a :class:`Finding` cannot anchor without both
ends — the SARIF record remains the full-fidelity artifact).

Verdict honesty: a :class:`Finding` is a dataflow CANDIDATE record;
nothing here adds a status, a verdict, or any absence claim.
"""

from __future__ import annotations

import hashlib
from typing import Any, TYPE_CHECKING

from core.dataflow.finding import Finding, Step

if TYPE_CHECKING:
    from collections.abc import Mapping


PRODUCER = "taint-crossfile"


def make_finding_id(
    rule_id: str, source: Step, sink: Step, *, producer: str = PRODUCER
) -> str:
    """Stable id from ``(producer, rule_id, source loc, sink loc)`` —
    the CodeQL adapter's derivation scheme with this producer's
    identity, kept local so the adapters stay independent modules.
    Same inputs → same id across reruns; the location-anchored
    limitation (a file rename mints a new id) is shared and
    deliberate."""
    key = (
        f"{producer}|{rule_id}|"
        f"{source.file_path}:{source.line}|"
        f"{sink.file_path}:{sink.line}"
    )
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    rule_slug = rule_id.replace("/", "-").replace(".", "-") or "unknown"
    return f"{producer}_{rule_slug}_{digest}"


def _step_from_location(
    loc_wrapper: Mapping[str, Any], label: str,
) -> Step | None:
    """One threadFlow location → :class:`Step` with the positional
    role label, or ``None`` when the location carries no real span
    (the step contract's honest-empty form)."""
    loc = loc_wrapper.get("location") or {}
    physical = loc.get("physicalLocation") or {}
    artifact = physical.get("artifactLocation") or {}
    region = physical.get("region") or {}
    uri = artifact.get("uri") or ""
    line = region.get("startLine") or 0
    if not uri or not isinstance(line, int) or line < 1:
        return None
    return Step(
        file_path=uri,
        line=line,
        column=region.get("startColumn") or 0,
        snippet=(region.get("snippet") or {}).get("text") or "",
        label=label,
    )


def from_sarif_result(
    result: Mapping[str, Any],
    *,
    producer: str = PRODUCER,
    finding_id: str | None = None,
) -> Finding | None:
    """Convert one emitted SARIF ``result`` into a :class:`Finding`.

    Returns ``None`` when the result carries no usable dataflow: no
    ``codeFlows`` (record-capped emission or a flow-less candidate),
    fewer than two locations, or an unlocated source/sink. The
    witness flow (``codeFlows[0]``) is the converted path —
    alternatives stay in ``raw`` for consumers that want them.
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

    source = _step_from_location(locations[0], "source")
    sink = _step_from_location(locations[-1], "sink")
    if source is None or sink is None:
        return None
    dropped = 0
    intermediate: list[Step] = []
    for loc_wrapper in locations[1:-1]:
        step = _step_from_location(loc_wrapper, "step")
        if step is None:
            dropped += 1
            continue
        intermediate.append(step)

    rule_id = result.get("ruleId") or "unknown"
    message = (result.get("message") or {}).get("text") or "(no message)"
    if finding_id is None:
        finding_id = make_finding_id(rule_id, source, sink,
                                     producer=producer)

    raw = dict(result)
    if dropped:
        raw["adapter_steps_dropped_unlocated"] = dropped
    return Finding(
        finding_id=finding_id,
        producer=producer,
        rule_id=rule_id,
        message=message,
        source=source,
        sink=sink,
        intermediate_steps=tuple(intermediate),
        raw=raw,
    )


def from_emission_report(report: Any) -> list[Finding]:
    """Every convertible result of one
    :class:`core.taint.emission.EmissionReport` (duck-typed on
    ``.sarif`` so this module doesn't import ``core.taint``).
    Flow-less results are skipped — they are location-only records,
    not dataflow findings."""
    findings: list[Finding] = []
    for run in (report.sarif.get("runs") or []):
        for result in (run.get("results") or []):
            finding = from_sarif_result(result)
            if finding is not None:
                findings.append(finding)
    return findings


__all__ = [
    "PRODUCER",
    "from_emission_report",
    "from_sarif_result",
    "make_finding_id",
]
