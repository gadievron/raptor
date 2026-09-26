"""Finding emission — candidates to SARIF-with-codeFlows at a bounded
byte boundary.

The propagation engine's :class:`~core.taint.engine.Candidate` records
carry a rendered witness path (step records), bounded alternatives and
killed-class provenance. This module serializes survivors into the two
consumer shapes the pipeline intake reads:

* **SARIF 2.1** results with ``codeFlows``/``threadFlows`` built from
  the step records — one codeFlow for the witness path plus one per
  alternative, matching how :func:`core.sarif.parser.extract_dataflow_path`
  reads multi-flow results back. Every threadFlow location carries the
  step's tier / kind / tags / sanitizers / killed classes as location
  PROPERTIES so tier-aware consumers get mechanical per-hop input,
  never just the path minimum.
* **Scan-shaped finding dicts** (the :func:`core.sarif.parser.
  parse_sarif_findings` key shape, ``dataflow_path`` included) for the
  OpenAnt-style post-scan merge — engine findings join the pipeline
  AFTER the scanner's SARIF set, so scanner-side postpasses never see
  them in their input.

Verdict honesty: every result is a CANDIDATE. ``cwe_id`` is always
set (the sink spec's CWE, else the pack coherence table's mapping for
the sink class, else the counted generic fallback) because CWE-less
findings are invisible to the recall matcher; ``level`` follows the
path tier (``resolved_static`` → ``warning``, anything weaker →
``note``); ``metadata.detection_tier`` stays ``"candidate"``. This
module exposes NO suppression surface: it never writes
``suppressions.jsonl`` records, and no emitted key spells refutation
— zero candidates prove nothing, and nothing here may say otherwise.

## The artifact rail (the enforcing half of the byte dimension)

Name-shaped fields ride verbatim into every step of every flow, so
serialized size is target-shaped in name length × candidates × steps
— measured upstream at hundreds of MB for crafted 64 KiB node ids.
The engine MEASURES (``stats.artifact_bytes_estimate`` + the
``artifact_bytes`` marker, flag-only); THIS boundary ENFORCES, at the
one place serialization actually happens:

* per-field character caps on name/file-shaped text and message prose
  (capped WITH an explicit elision marker, never dropped — counted);
* per-field item caps on step tag/sanitizer/killed lists (capped with
  a marker entry — counted);
* a per-record byte cap with a deterministic shed ladder
  (alternative codeFlows first, then all codeFlows; the result record
  itself is never dropped — counted and marked on the record);
* a per-run artifact byte budget: once the running total of emitted
  record bytes would cross it, every remaining record is REFUSED
  (counted, ``caps_hit`` marked). Refusal orders by the engine's own
  deterministic candidate priority (the result list is already
  sorted), so the tail refused is the lowest-priority tail. The
  in-memory candidates are untouched — the budget bounds the
  serialized artifact, never the run's knowledge;
* the FRONTIER block of the twin file rides the same rail: frontier
  records carry unbounded target-derived names (``function``,
  ``callee``), so they are per-field bounded here, priced at exact
  compact bytes, and charged against the same run budget AFTER the
  findings — a frontier flood can cap its own block (refused counted
  + marked) but never displace a finding, and never ships raw.

Record bytes are EXACT, not estimated: each record is priced as its
compact-JSON ``ensure_ascii`` byte length — the same form the SARIF
artifact is written in — so the enforced budget equals real artifact
bytes. The engine's upstream estimate rides into ``stats`` beside the
enforced actual for cross-checking.

Byte hostility: the SARIF egress is written compact with
``ensure_ascii=True`` (every non-ASCII and control byte is a JSON
``\\uXXXX`` escape at the byte level), and render-destined prose
(result messages, flow-location messages; step excerpts arrive
already escaped) goes through the ``core.security.log_sanitisation``
contract at build time. Name-shaped fields stay verbatim-but-bounded
— consumers join them against the inventory, and render chokepoints
escape at display time (the engine's standing contract).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from core.analysis.package_callgraph import TIER_RESOLVED_STATIC
from core.json import dumps_artifact
from core.security.log_sanitisation import escape_nonprintable
from core.taint.packs import PackSet

if TYPE_CHECKING:
    from core.taint.engine import Candidate, PropagationResult
    from core.taint.paths import Step

#: Producer identity — the tool driver name, the ``tool`` field of
#: every scan-shaped finding, and the prefix consumers key routing on.
PRODUCER = "taint-crossfile"

#: Rule-id family: ``raptor.taint.crossfile.<sink_class>.<language>``
#: (the Semgrep taint naming family, so rule-id-keyed consumers group
#: engine findings beside the intra-file taint rules).
RULE_ID_PREFIX = "raptor.taint.crossfile"

# ── named caps (both directions; hitting one is counted, never silent) ──

#: Per-field character cap for name/file-shaped text (node ids, file
#: paths, parameter and sanitizer names) at serialization. Over-cap
#: text keeps its prefix plus an explicit ``...[+N chars]`` marker —
#: capped, never dropped. Higher preserves inventory joinability for
#: deep-tree paths and generated names (genuine node ids run well
#: under 300 chars; kernel-style trees under 200); lower shrinks the
#: name-length amplification lever (a 64 KiB crafted name rides into
#: EVERY step of EVERY flow — at this cap it contributes ≤ 0.6 KiB
#: per field instead of 64 KiB).
MAX_NAME_FIELD_CHARS = 512

#: Character cap for render-destined prose (result message, flow
#: location messages) AFTER escaping, marker on top. Higher shows more
#: context; lower bounds attacker bytes per render surface. Excerpts
#: are bounded upstream (``MAX_EXCERPT_CHARS``) and ride unchanged.
MAX_MESSAGE_CHARS = 400

#: Item cap for per-step list fields (tags, sanitizers, killed
#: classes) — over-cap lists keep their head plus a ``...[+N more]``
#: marker entry. Higher keeps more per-hop annotation visible; lower
#: bounds a hostile store's ability to inflate every step with
#: hundreds of learned sanitizer names (the list-length lever the
#: field cap alone cannot bound).
MAX_LIST_ITEMS = 16

#: Per-record byte cap (compact serialized size of one SARIF result).
#: A worst-case LEGITIMATE record — 21 witness steps with excerpts +
#: 3 alternatives, every field at its cap — measures ≈ 130 KiB, so
#: this holds ~2x headroom for real findings while bounding crafted
#: shapes. Over-cap records shed deterministically (alternative
#: codeFlows first, then all codeFlows), marked on the record and
#: counted — the result itself is never dropped. Higher admits richer
#: single records; lower starves genuine multi-alternative paths of
#: their flows.
MAX_RECORD_BYTES = 256 * 1024

#: Per-run artifact byte budget over the sum of emitted record bytes.
#: Aligned with the engine's ``MAX_ARTIFACT_BYTES`` measurement marker
#: (64 MiB) so the flag-only upstream signal and the enforcing rail
#: name one threshold. Ordinary runs measure single-digit MB; only
#: name-length × candidate-count amplification approaches this.
#: Records past the budget are refused (counted + ``caps_hit``
#: ``artifact_budget``); candidates stay intact in memory. Higher
#: admits enormous genuine result sets at artifact-size cost
#: (downstream parsers re-read this file per stage); lower truncates
#: real findings out of the artifact.
MAX_EMISSION_ARTIFACT_BYTES = 64 * 1024 * 1024

#: Counted fallback CWE for a sink class no loaded pack sink declares
#: (reachable only through learned sinks, whose specs carry no CWE).
#: CWE-20 is the honest coarse parent — the finding stays visible to
#: CWE-keyed consumers instead of vanishing from the recall matcher.
GENERIC_FALLBACK_CWE = "CWE-20"

_ELISION_SUFFIX = "...[+{n} chars]"
_LIST_ELISION = "...[+{n} more]"

_SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)


@dataclass(frozen=True)
class EmissionLimits:
    """Per-run rail set. Defaults are the module caps; tests shrink
    individual fields to pin the ±1 boundaries."""

    max_name_field_chars: int = MAX_NAME_FIELD_CHARS
    max_message_chars: int = MAX_MESSAGE_CHARS
    max_list_items: int = MAX_LIST_ITEMS
    max_record_bytes: int = MAX_RECORD_BYTES
    max_artifact_bytes: int = MAX_EMISSION_ARTIFACT_BYTES


@dataclass
class EmissionReport:
    """One emission pass: the SARIF document, the scan-shaped finding
    dicts (same records, merge-channel shape), the bounded frontier
    block, and the honest account of every rail that fired.
    ``emitted`` + ``refused`` always equals the candidate count, and
    ``frontier`` + ``stats["frontier_refused_budget"]`` always covers
    the result's frontier records — nothing exits this boundary
    silently or unbounded."""

    sarif: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    frontier: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    caps_hit: tuple = ()
    emitted: int = 0
    refused: int = 0
    artifact_bytes: int = 0


class _Emitter:
    def __init__(self, packs: PackSet, language: str,
                 limits: EmissionLimits) -> None:
        self.language = language
        self.limits = limits
        self.stats: dict[str, int] = {}
        self.caps_hit: list[str] = []
        self.class_cwe = _class_cwe_table(packs)

    def _count(self, name: str, n: int = 1) -> None:
        self.stats[name] = self.stats.get(name, 0) + n

    def _mark_cap(self, name: str) -> None:
        if name not in self.caps_hit:
            self.caps_hit.append(name)

    # -- field rails ---------------------------------------------------------

    def _bound_name(self, text: str) -> str:
        """Cap one name/file-shaped field, marker on top (capped with
        an explicit elision marker, never dropped)."""
        cap = self.limits.max_name_field_chars
        if len(text) <= cap:
            return text
        self._count("name_fields_capped")
        return text[:cap] + _ELISION_SUFFIX.format(n=len(text) - cap)

    def _bound_prose(self, text: str) -> str:
        """Escape then cap render-destined prose. Escaping runs over a
        bounded raw window first (the excerpt-rail discipline: a
        crafted megabyte string must not buy a full scan)."""
        cap = self.limits.max_message_chars
        window = text[: cap * 4]
        escaped = escape_nonprintable(window)
        if len(window) == len(text) and len(escaped) <= cap:
            return escaped
        self._count("prose_fields_capped")
        kept: list[str] = []
        length = 0
        used = 0
        for ch in window:
            piece = ch if ch.isprintable() else escape_nonprintable(ch)
            if length + len(piece) > cap:
                break
            kept.append(piece)
            length += len(piece)
            used += 1
        return "".join(kept) + _ELISION_SUFFIX.format(n=len(text) - used)

    def _bound_list(self, items: tuple) -> list:
        cap = self.limits.max_list_items
        bounded = [self._bound_name(str(i)) for i in items[:cap]]
        if len(items) > cap:
            self._count("list_fields_capped")
            bounded.append(_LIST_ELISION.format(n=len(items) - cap))
        return bounded

    def _bound_origins(self, origins: tuple) -> list:
        """killed_origins under the same item cap as every sibling
        list — a vocab-heavy record must not ship an unbounded origin
        table (each entry carries target-derived sanitizer names)."""
        cap = self.limits.max_list_items
        bounded: list = [
            {
                "sink_class": self._bound_name(k.sink_class),
                "step": k.step,
                "sanitizers": self._bound_list(k.sanitizers),
            }
            for k in origins[:cap]
        ]
        if len(origins) > cap:
            self._count("list_fields_capped")
            bounded.append(_LIST_ELISION.format(n=len(origins) - cap))
        return bounded

    # -- per-candidate SARIF pieces -------------------------------------------

    def _cwe_for(self, c: Candidate) -> str:
        if c.sink_cwe:
            return c.sink_cwe
        mapped = self.class_cwe.get(c.sink_class)
        if mapped:
            self._count("cwe_from_coherence_table")
            return mapped
        self._count("cwe_fallback_generic")
        return GENERIC_FALLBACK_CWE

    def _rule_id(self, c: Candidate) -> str:
        sink_class = c.sink_class or "unspecified"
        return f"{RULE_ID_PREFIX}.{sink_class}.{self.language}"

    def _step_label(self, step: Step) -> str:
        parts = [f"{step.kind}: {step.function}"]
        if step.tainted_param:
            parts.append(f"taints {step.tainted_param}")
        if step.tags:
            parts.append("[" + ", ".join(step.tags) + "]")
        return self._bound_prose(" ".join(parts))

    def _flow_location(self, step: Step) -> dict:
        uri = step.call_file or step.file
        line = step.call_line or step.function_line
        region: dict = {}
        if line:
            region["startLine"] = line
        if step.excerpt:
            # Excerpts arrive escaped + bounded from the step renderer
            # — ride unchanged (re-escaping is idempotent by contract).
            region["snippet"] = {"text": step.excerpt}
        physical: dict = {"artifactLocation": {"uri": self._bound_name(uri)}}
        if region:
            physical["region"] = region
        location: dict = {
            "physicalLocation": physical,
            "logicalLocations": [
                {"kind": "function", "name": self._bound_name(step.function)},
            ],
            "message": {"text": self._step_label(step)},
        }
        return {
            "location": location,
            # The M3 per-step surface: tier-aware consumers read WHICH
            # hop is weak from these, never just the path minimum.
            "properties": {
                "tier": step.tier,
                "kind": step.kind,
                "tags": self._bound_list(step.tags),
                "sanitizers": self._bound_list(step.sanitizers),
                "killed_classes": self._bound_list(step.killed_classes),
                "tainted_param": self._bound_name(step.tainted_param),
                "excerpt_truncated": step.excerpt_truncated,
            },
        }

    def _code_flow(self, steps: tuple) -> dict | None:
        if len(steps) < 2:
            # extract_dataflow_path needs 2+ locations for a path —
            # a shorter chain is not a flow, and a padded one would
            # be a fabricated span.
            return None
        return {"threadFlows": [{
            "locations": [self._flow_location(s) for s in steps],
        }]}

    def _sink_span(self, c: Candidate) -> tuple[str, int, str]:
        """(uri, line, snippet) for the result's primary location —
        from the terminal sink step when rendered, else from the node
        id's file prefix (``<file>::<name>@<line>``), else empty
        (counted; never fabricated)."""
        if c.steps:
            sink = c.steps[-1]
            return (sink.call_file or sink.file, c.sink_line, sink.excerpt)
        node_id = c.sink_function
        if "::" in node_id:
            return (node_id.split("::", 1)[0], c.sink_line, "")
        self._count("sink_location_unavailable")
        return ("", c.sink_line, "")

    def _fingerprint(self, c: Candidate, rule_id: str, uri: str) -> str:
        hop_sig = "|".join(f"{h.function}@{h.line}" for h in c.hops)
        source_sig = "|".join(
            f"{k}={v}" for k, v in c.source)
        key = "\x1f".join((
            PRODUCER, rule_id, uri, str(c.sink_line), c.taint_class,
            source_sig, hop_sig,
        ))
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def _message(self, c: Candidate) -> str:
        hops = len(c.hops)
        return self._bound_prose(
            f"Cross-file taint candidate: {c.taint_class} reaches "
            f"{c.sink_class or 'unspecified'} sink {c.sink_match} "
            f"({hops} hop{'s' if hops != 1 else ''}, "
            f"path tier {c.path_tier})"
        )

    def _result(self, c: Candidate) -> tuple[dict, str, dict]:
        """Build (sarif_result, cwe, scan_finding) for one candidate —
        both consumer shapes from the SAME bounded pieces."""
        rule_id = self._rule_id(c)
        cwe = self._cwe_for(c)
        uri, line, snippet = self._sink_span(c)
        level = ("warning" if c.path_tier == TIER_RESOLVED_STATIC
                 else "note")
        message = self._message(c)
        fingerprint = self._fingerprint(c, rule_id, uri)

        code_flows: list[dict] = []
        witness = self._code_flow(c.steps)
        if witness is not None:
            code_flows.append(witness)
        else:
            self._count("results_without_codeflows")
        for alt in c.alternatives:
            flow = self._code_flow(alt.steps)
            if flow is not None:
                flow["threadFlows"][0]["properties"] = {
                    "alternative": True,
                    "path_tier": alt.path_tier,
                }
                code_flows.append(flow)

        result: dict = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
            "partialFingerprints": {"raptorTaintPathId/v1": fingerprint},
            "properties": {
                "detection_tier": "candidate",
                "path_tier": c.path_tier,
                "spec_tier": c.spec_tier,
                "pack": c.pack,
                "taint_class": c.taint_class,
                "sink_class": c.sink_class,
                "sink_confidence": c.sink_confidence,
                "cwe": cwe,
                "source": {
                    self._bound_name(str(k)): self._bound_name(str(v))
                    for k, v in c.source
                },
                "killed": self._bound_list(c.killed),
                "killed_origins": self._bound_origins(c.killed_origins),
            },
        }
        if code_flows:
            result["codeFlows"] = code_flows
        if uri:
            # Region only with a real line (mirrors the flow-location
            # guard): SARIF startLine must be >= 1, and a zero would
            # be a fabricated span anyway.
            region: dict = {}
            if line >= 1:
                region["startLine"] = line
                if snippet:
                    region["snippet"] = {"text": snippet}
            physical: dict = {
                "artifactLocation": {"uri": self._bound_name(uri)},
            }
            if region:
                physical["region"] = region
            location: dict = {
                "physicalLocation": physical,
                "logicalLocations": [{
                    "kind": "function",
                    "name": self._bound_name(c.sink_function),
                }],
            }
            result["locations"] = [location]
        else:
            result["properties"]["location_unavailable"] = True

        finding = self._scan_finding(
            c, rule_id=rule_id, cwe=cwe, uri=uri, line=line,
            snippet=snippet, level=level, message=message,
            fingerprint=fingerprint, code_flows=code_flows,
        )
        return result, cwe, finding

    # -- scan-shaped twin ------------------------------------------------------

    @staticmethod
    def _path_step(flow_loc: dict) -> dict:
        loc = flow_loc["location"]
        physical = loc["physicalLocation"]
        region = physical.get("region") or {}
        return {
            "file": physical["artifactLocation"]["uri"],
            "line": region.get("startLine", 0),
            "column": 0,
            "label": loc["message"]["text"],
            "snippet": (region.get("snippet") or {}).get("text", ""),
            "properties": dict(flow_loc.get("properties") or {}),
        }

    def _dataflow_path(self, code_flows: list[dict]) -> dict | None:
        """The internal ``dataflow_path`` dict — the exact shape
        :func:`core.sarif.parser.extract_dataflow_path` builds from
        these codeFlows, so the merge channel and a SARIF re-parse
        agree (per-step ``properties`` carried as an extra key)."""
        paths = []
        for flow in code_flows:
            locations = flow["threadFlows"][0]["locations"]
            steps = [self._path_step(fl) for fl in locations]
            paths.append({
                "source": steps[0],
                "sink": steps[-1],
                "steps": steps[1:-1],
                "total_steps": len(steps),
            })
        if not paths:
            return None
        primary = paths[0]
        primary["alternative_paths"] = paths[1:]
        return primary

    def _scan_finding(
        self, c: Candidate, *, rule_id: str, cwe: str, uri: str,
        line: int, snippet: str, level: str, message: str,
        fingerprint: str, code_flows: list[dict],
    ) -> dict:
        dataflow = self._dataflow_path(code_flows)
        return {
            "finding_id": f"{PRODUCER}-{fingerprint[:16]}",
            "rule_id": rule_id,
            "message": message,
            "file": uri or None,
            "startLine": line or None,
            "endLine": None,
            "snippet": snippet,
            "level": level,
            "cwe_id": cwe,
            "tool": PRODUCER,
            "has_dataflow": dataflow is not None,
            "dataflow_path": dataflow,
            "metadata": {
                "detection_tier": "candidate",
                "path_tier": c.path_tier,
                "spec_tier": c.spec_tier,
                "pack": c.pack,
                "taint_class": c.taint_class,
                "sink_class": c.sink_class,
                "sink_confidence": c.sink_confidence,
                "sink_function": self._bound_name(c.sink_function),
                "killed": self._bound_list(c.killed),
            },
        }

    # -- frontier (bounded twin block) ------------------------------------------

    def _frontier_record(self, f) -> dict:
        """One frontier record for the twin file, name fields under
        the same per-field discipline as every emitted record —
        ``function`` and ``callee`` are unbounded target-derived
        names and ride into the artifact otherwise uncapped."""
        return {
            "function": self._bound_name(f.function),
            "line": f.line,
            "callee": self._bound_name(f.callee),
            "resolution": self._bound_name(f.resolution),
            "taint_class": self._bound_name(f.taint_class),
            "derived_from_target": True,
        }

    # -- record rail -----------------------------------------------------------

    @staticmethod
    def _record_bytes(record: dict) -> int:
        """Exact compact ``ensure_ascii`` byte size — the same form
        the SARIF artifact is written in, so the enforced budget
        equals real artifact bytes."""
        return len(dumps_artifact(
            record, indent=None, ensure_ascii=True).encode("ascii"))

    def _shed_to_cap(self, result: dict, finding: dict) -> int:
        """Apply the per-record byte cap: shed alternative codeFlows,
        then all codeFlows — deterministic ladder, marked on the
        record, counted; the record itself is never dropped. Returns
        the final record byte size."""
        size = self._record_bytes(result)
        cap = self.limits.max_record_bytes
        if size <= cap:
            return size
        flows = result.get("codeFlows")
        if flows and len(flows) > 1:
            self._count("record_alternatives_shed")
            result["codeFlows"] = flows[:1]
            result["properties"]["record_capped"] = "alternatives"
            dataflow = finding.get("dataflow_path")
            if dataflow:
                dataflow["alternative_paths"] = []
            size = self._record_bytes(result)
            if size <= cap:
                return size
        if result.get("codeFlows"):
            self._count("record_codeflows_shed")
            result.pop("codeFlows", None)
            result["properties"]["record_capped"] = "codeflows"
            finding["dataflow_path"] = None
            finding["has_dataflow"] = False
            size = self._record_bytes(result)
        if size > cap:
            # Reachable when the cap is set below the record's
            # bounded floor — every field is individually capped, but
            # the floor still scales with the number of capped fields
            # (list entries × per-field cap), so a tiny cap or a
            # field-heavy record can land here. The record still
            # ships, marked + counted — never dropped, never silent.
            self._count("record_over_cap_after_shed")
            result["properties"]["record_capped"] = "floor"
        return size


def _class_cwe_table(packs: PackSet) -> dict[str, str]:
    """The pack coherence table: sink class → CWE, from the loaded
    pack sinks (deterministic — the lexicographically smallest CWE
    wins when several pack sinks share one class)."""
    table: dict[str, str] = {}
    for sink in packs.sinks:
        if not sink.sink_class or not sink.cwe:
            continue
        current = table.get(sink.sink_class)
        if current is None or sink.cwe < current:
            table[sink.sink_class] = sink.cwe
    return table


def emit(
    result: PropagationResult,
    packs: PackSet,
    *,
    language: str = "python",
    limits: EmissionLimits | None = None,
) -> EmissionReport:
    """Serialize one propagation result's candidates into the SARIF
    document + scan-shaped finding list, under the artifact rail.

    Pure: reads the result, never mutates it, writes nothing —
    callers own the file writes. Candidates are processed in the
    result's order (the engine's deterministic priority sort), so
    budget refusals always hit the lowest-priority tail.
    """
    emitter = _Emitter(packs, language, limits or EmissionLimits())
    rails = emitter.limits

    rules: dict[str, dict] = {}
    results: list[dict] = []
    findings: list[dict] = []
    total_bytes = 0
    refused = 0

    for candidate in result.candidates:
        if refused:
            # The budget already bound — every remaining record is
            # refused (deterministic prefix; no smaller-record rescue).
            refused += 1
            continue
        sarif_result, cwe, finding = emitter._result(candidate)
        size = emitter._shed_to_cap(sarif_result, finding)
        if total_bytes + size > rails.max_artifact_bytes:
            emitter._mark_cap("artifact_budget")
            refused += 1
            continue
        total_bytes += size
        results.append(sarif_result)
        findings.append(finding)
        rule_id = sarif_result["ruleId"]
        rule = rules.get(rule_id)
        if rule is None:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {
                    "text": f"Cross-file taint flow to a "
                            f"{candidate.sink_class or 'declared'} sink",
                },
                "properties": {
                    "cwe": [cwe],
                    "tags": ["security",
                             f"external/cwe/{cwe.lower()}"],
                },
            }
        elif cwe not in rule["properties"]["cwe"]:
            # One rule per sink class; a class mapping to several
            # CWEs keeps them all on the rule (sorted, first wins on
            # rule-level extraction) — the per-finding cwe_id in the
            # scan shape stays exact.
            rule["properties"]["cwe"] = sorted(
                [*rule["properties"]["cwe"], cwe])
            rule["properties"]["tags"].append(
                f"external/cwe/{cwe.lower()}")

    if refused:
        emitter._count("records_refused_budget", refused)

    # The frontier block rides the twin file, so it is artifact bytes
    # like any record: each record is bounded per field, priced at its
    # exact compact byte size, and charged against the SAME run budget
    # AFTER the findings (findings are the higher-value bytes; a
    # frontier flood can never displace them). Past the budget every
    # remaining frontier record is refused — counted + marked; the
    # full occurrence count survives in stats.taint_at_unresolved
    # upstream regardless.
    frontier: list[dict] = []
    frontier_bytes = 0
    frontier_refused = 0
    for record in result.frontier:
        if frontier_refused:
            frontier_refused += 1
            continue
        bounded = emitter._frontier_record(record)
        size = emitter._record_bytes(bounded)
        if total_bytes + size > rails.max_artifact_bytes:
            emitter._mark_cap("artifact_budget")
            frontier_refused += 1
            continue
        total_bytes += size
        frontier_bytes += size
        frontier.append(bounded)
    if frontier_refused:
        emitter._count("frontier_refused_budget", frontier_refused)

    sarif = {
        "$schema": _SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": PRODUCER,
                "rules": [rules[k] for k in sorted(rules)],
            }},
            "results": results,
            "properties": {
                "engine_version": result.engine_version,
                "caps_hit": sorted(
                    {*result.caps_hit, *emitter.caps_hit}),
                "candidates": len(result.candidates),
                "emitted": len(results),
                "refused": refused,
            },
        }],
    }

    stats = dict(emitter.stats)
    stats["artifact_bytes_emitted"] = total_bytes
    stats["frontier_bytes_emitted"] = frontier_bytes
    upstream = result.stats.get("artifact_bytes_estimate")
    if upstream is not None:
        stats["artifact_bytes_estimate_upstream"] = upstream
    return EmissionReport(
        sarif=sarif,
        findings=findings,
        frontier=frontier,
        stats=stats,
        caps_hit=tuple(emitter.caps_hit),
        emitted=len(results),
        refused=refused,
        artifact_bytes=total_bytes,
    )


def sarif_bytes(report: EmissionReport) -> bytes:
    """The SARIF artifact bytes: compact, ``ensure_ascii`` — every
    control / non-ASCII byte is a JSON escape, so the file is inert
    on any byte-level consumer."""
    return (dumps_artifact(
        report.sarif, indent=None, ensure_ascii=True,
    ) + "\n").encode("ascii")


__all__ = [
    "GENERIC_FALLBACK_CWE",
    "MAX_EMISSION_ARTIFACT_BYTES",
    "MAX_LIST_ITEMS",
    "MAX_MESSAGE_CHARS",
    "MAX_NAME_FIELD_CHARS",
    "MAX_RECORD_BYTES",
    "PRODUCER",
    "RULE_ID_PREFIX",
    "EmissionLimits",
    "EmissionReport",
    "emit",
    "sarif_bytes",
]
