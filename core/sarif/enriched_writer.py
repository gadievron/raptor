"""Write enriched SARIF 2.1.0 annotated with RAPTOR analysis verdicts.

Converts RAPTOR's internal analysis results to SARIF with
``result.properties.raptor.*`` annotations for verdicts, reachability,
and structural evidence. Suppressed findings (binary oracle ``absent``)
are emitted with SARIF-standard ``result.suppressions``.

Consumers: ``/agentic --sarif-out``, ``/project export --sarif``,
``/validate``.
"""

import math
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.json import save_json
from core.logging import get_logger
from core.run.finding_status import read_verdict
from core.sarif.parser import _coerce_line, _scope_fingerprint, extract_dataflow_path
from core.sarif.import_normalizer import _dataflow_to_codeflows, _finding_catalog_conflicts
from core.security.log_sanitisation import escape_nonprintable

logger = get_logger()

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_VALID_LEVELS = frozenset({"none", "note", "warning", "error"})


def _verdict_from_analysis(finding: dict[str, Any]) -> str:
    analysis = finding.get("analysis")
    if not isinstance(analysis, dict):
        analysis = {}
    if analysis.get("reachability_suppression"):
        return "suppressed"
    # Legacy alias, genuine-bool rule (agentic_passes precedent): a
    # truthy read would display junk shapes — and today's upstream
    # producers are bool-typed, so `is True` costs nothing.
    if finding.get("exploitable") is True:
        return "exploitable"
    tp = analysis.get("is_true_positive")
    if tp is True:
        return "confirmed"
    if tp is False:
        return "ruled_out"
    return "not_analyzed"


def _reachability_from_analysis(finding: dict[str, Any]) -> str:
    analysis = finding.get("analysis")
    if not isinstance(analysis, dict):
        analysis = {}
    verdict = analysis.get("reachability_verdict")
    if verdict:
        return verdict
    if analysis.get("reachability_suppression"):
        return "absent"
    return "not_evaluated"


def _build_raptor_properties(
    finding: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    """Build the (verdict, raptor properties) pair for one finding."""
    verdict = _verdict_from_analysis(finding)
    props: dict[str, Any] = {
        "verdict": verdict,
        "reachability": _reachability_from_analysis(finding),
    }

    if finding.get("source_type"):
        props["source_type"] = finding["source_type"]

    if finding.get("_cwe_inferred"):
        props["cwe_inferred"] = True

    if finding.get("has_dataflow"):
        props["has_dataflow"] = True

    analysis = finding.get("analysis")
    if not isinstance(analysis, dict):
        analysis = {}
    validation_status = analysis.get("validation_status")
    if isinstance(validation_status, str) and validation_status:
        props["validation_status"] = validation_status
    _exploitable = read_verdict(analysis, "is_exploitable")
    if _exploitable is not None:
        props["is_exploitable"] = _exploitable
    if analysis.get("reasoning"):
        props["reasoning"] = str(analysis["reasoning"])[:500]

    # findings.json rows are read back from run directories, where
    # numeric fields arrive as JSON strings ("9.8") or junk — a raw
    # `score > 0` comparison raised TypeError and killed the export.
    score = _coerce_score(finding.get("exploitability_score"))
    if score is not None and score > 0:
        props["exploitability_score"] = score

    if finding.get("has_exploit"):
        props["has_exploit"] = True
        if finding.get("exploit_compiled") is not None:
            props["exploit_compiled"] = finding["exploit_compiled"]

    return verdict, props


def _coerce_score(value: Any) -> float | None:
    """Finite float from an untrusted score field, or None."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    return score if math.isfinite(score) else None


def _line_value(finding: dict[str, Any], *keys: str) -> int | None:
    """First usable line number among *keys*, coerced.

    Row values read back from run-directory JSON arrive as ints,
    floats, strings, Infinity/NaN, or junk; ``_coerce_line`` (the
    import chokepoint's coercer) handles the numeric shapes and this
    wrapper additionally accepts integer STRINGS ("12") so a
    stringified-but-real line keeps its value instead of degrading
    to the fallback."""
    for key in keys:
        value = finding.get(key)
        coerced = _coerce_line(value)
        if coerced is None and isinstance(value, str):
            try:
                coerced = int(value.strip(), 10)
            except ValueError:
                coerced = None
        if coerced is not None:
            return coerced
    return None


def _build_result(finding: dict[str, Any]) -> dict[str, Any]:
    file_path = finding.get("file_path") or finding.get("file") or ""

    # Coerced first (pre-fix the raw values hit `< 1` comparisons:
    # one string-typed line in one row raised TypeError and killed
    # the whole export).
    start_line = _line_value(finding, "start_line", "startLine", "line")
    if start_line is None or start_line < 1:
        start_line = 1

    end_line = _line_value(finding, "end_line", "endLine")
    if end_line is None or end_line < start_line:
        end_line = start_line

    rule_id = finding.get("rule_id") or "unknown"
    message = finding.get("message") or ""
    level = finding.get("level") or finding.get("severity") or "warning"
    if level not in _VALID_LEVELS:
        level = "warning"

    region: dict[str, Any] = {
        "startLine": start_line,
        "endLine": end_line,
    }

    for field, alias in (("startColumn", "start_column"), ("endColumn", "end_column")):
        column = _coerce_line(finding.get(field))
        if column is None or column < 1:
            column = _coerce_line(finding.get(alias))
        if column is not None and column > 0:
            region[field] = column

    snippet = finding.get("snippet")
    if not snippet:
        code = finding.get("code")
        if code:
            lines = code.splitlines()
            snippet = "\n".join(lines[:10]) if len(lines) > 10 else code
    if snippet:
        region["snippet"] = {"text": snippet}

    verdict, raptor_props = _build_raptor_properties(finding)

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": file_path},
                "region": region,
            }
        }],
        "properties": {
            "raptor": raptor_props,
        },
    }

    for key in ("function", "function_name"):
        function = finding.get(key)
        if isinstance(function, str) and function:
            result["locations"][0]["logicalLocations"] = [{"kind": "function", "name": function}]
            break
    dataflow = finding.get("dataflow_path")
    flows = _dataflow_to_codeflows(dataflow) if finding.get("has_dataflow") else []
    # Legacy callers may supply raw SARIF arrays rather than parsed paths.
    # Their presence alone must not advertise usable source-to-sink evidence.
    if flows and isinstance(dataflow, list) and extract_dataflow_path(flows) is None:
        flows = []
    if flows:
        result["codeFlows"] = flows
    else:
        raptor_props.pop("has_dataflow", None)

    # Stamp finding_id back out as the tool fingerprint ONLY when it
    # is a genuine per-finding identity. Legacy findings parsed before
    # the finding_id fix carry the bare rule_id as their finding_id —
    # writing THAT as matchBasedId/v1 would make every same-rule
    # finding share a fingerprint on re-import, re-creating the
    # collision this pipeline just fixed.
    fid = finding.get("finding_id")
    if fid and fid != rule_id:
        result["fingerprints"] = {"matchBasedId/v1": fid}

    if verdict == "suppressed":
        analysis = finding.get("analysis")
        if not isinstance(analysis, dict):
            analysis = {}
        result["suppressions"] = [{
            "kind": "inSource",
            "justification": (
                f"binary-oracle: {analysis.get('reachability_verdict', 'absent')} "
                f"— function removed by compiler/linker"
            ),
        }]

    return result


def build_enriched_sarif(
    findings: Iterable[dict[str, Any]],
    *,
    tool_name: str = "RAPTOR",
    tool_version: str | None = None,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document from analysed findings.

    Groups findings by their original tool (``finding["tool"]``),
    splitting conflicting rule namespaces into separate runs. Each result carries
    ``properties.raptor`` with RAPTOR's verdicts.
    """
    # Planning needs two passes. Preserve support for one-shot iterable
    # callers without copying ordinary lists/tuples of findings.
    if not isinstance(findings, Sequence):
        findings = tuple(findings)

    if tool_version is None:
        try:
            from core.config import RaptorConfig
            tool_version = RaptorConfig.effective_version()
        except Exception:  # noqa: BLE001
            tool_version = "unknown"

    conflicting_rules, conflicting_cwes = _finding_catalog_conflicts(findings, tool_name)
    runs_by_tool: dict[tuple[str, str | None], list[dict[str, Any]]] = {}
    rules_by_tool: dict[tuple[str, str | None], dict[str, dict[str, Any]]] = {}
    skipped_by_tool: dict[tuple[str, str | None], list[dict[str, Any]]] = {}

    for idx, f in enumerate(findings):
        # The tool key must be a usable string BEFORE any dict use —
        # a junk-shaped (unhashable) tool value would otherwise kill
        # the export at the very bookkeeping that exists to contain
        # junk rows.
        tool = f.get("tool") if isinstance(f, dict) else None
        if not isinstance(tool, str) or not tool:
            tool = tool_name
        rid = f.get("rule_id") if isinstance(f, dict) else None
        rid = rid if isinstance(rid, str) and rid else "unknown"
        scope = _scope_fingerprint(f.get("rule_scope")) if isinstance(f, dict) else None
        group = (tool, scope if (tool, rid) in conflicting_rules else None)
        runs_by_tool.setdefault(group, [])
        rules_by_tool.setdefault(group, {})

        # Per-finding degrade: rows come back from run-directory JSON
        # (the sandbox-adjacent surface — producers vary, files are
        # hand-editable, junk shapes happen), and one malformed row
        # must not abort the ENTIRE export. A failed row becomes a
        # structured skip record (surfaced in the run's invocation
        # notifications below, the SARIF-standard slot for per-row
        # processing errors) instead of an export-fatal exception.
        try:
            if not isinstance(f, dict):
                msg = f"finding is {type(f).__name__}, expected dict"
                raise TypeError(msg)
            result = _build_result(f)
        except Exception as exc:  # noqa: BLE001 — any one row's junk shape degrades to a recorded skip
            rid = str(f.get("rule_id", "unknown")) if isinstance(f, dict) else "unknown"
            logger.warning(
                "enriched SARIF: skipping malformed finding %d (%s): "
                "%s: %s",
                idx, escape_nonprintable(rid)[:100],
                type(exc).__name__,
                escape_nonprintable(str(exc))[:200],
            )
            # The notification text carries finding-derived bytes and
            # downstream consumers render notifications to terminals —
            # escape here, same as the log line.
            skipped_by_tool.setdefault(group, []).append({
                "level": "error",
                "message": {"text": (
                    f"finding {idx} ({escape_nonprintable(rid)[:100]}) "
                    f"skipped: {type(exc).__name__}: "
                    f"{escape_nonprintable(str(exc))[:200]}"
                )},
            })
            continue
        runs_by_tool[group].append(result)

        # Keep conflicting classifications on their owning result, while
        # consistent rows share descriptor metadata without duplication.
        cwe = f.get("cwe_id")
        has_cwe = isinstance(cwe, str) and bool(cwe)
        cwe_conflict = (tool, scope, rid) in conflicting_cwes
        if has_cwe and cwe_conflict:
            result["properties"]["cwe"] = [cwe]
        if rid not in rules_by_tool[group]:
            rule_entry: dict[str, Any] = {"id": rid}
            if has_cwe and not cwe_conflict:
                rule_entry["properties"] = {"cwe": [cwe]}
            if scope is not None:
                rule_entry.setdefault("properties", {})["raptor_rule_scope"] = scope
            desc = f.get("message")
            if desc:
                rule_entry["shortDescription"] = {"text": str(desc)[:200]}
            rules_by_tool[group][rid] = rule_entry

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    runs = []
    for tool_key, results in runs_by_tool.items():
        skipped = skipped_by_tool.get(tool_key)
        invocation: dict[str, Any] = {
            "executionSuccessful": not bool(skipped),
            "endTimeUtc": now,
        }
        if skipped:
            invocation["toolExecutionNotifications"] = skipped
        runs.append({
            "tool": {
                "driver": {
                    "name": tool_key[0],
                    "version": tool_version,
                    "rules": list(rules_by_tool[tool_key].values()),
                },
            },
            "results": results,
            "invocations": [invocation],
        })

    return {
        "version": "2.1.0",
        "$schema": _SCHEMA,
        "runs": runs,
    }


def write_enriched_sarif(
    findings: Iterable[dict[str, Any]],
    output_path: Path,
    *,
    tool_name: str = "RAPTOR",
    tool_version: str | None = None,
) -> int:
    """Write enriched SARIF to *output_path*. Return the emitted finding count."""
    doc = build_enriched_sarif(
        findings, tool_name=tool_name, tool_version=tool_version,
    )
    # Atomic write via the shared primitive: random-suffix tempfile
    # opened with O_EXCL | O_NOFOLLOW. An earlier implementation wrote
    # to a predictable "<name>.sarif.tmp" sibling via open() — a
    # symlink squatted at that path would have been followed silently.
    save_json(output_path, doc)
    count = sum(len(run["results"]) for run in doc["runs"])
    logger.info("Wrote enriched SARIF: %s (%d findings)", output_path, count)
    return count
