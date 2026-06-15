"""Write enriched SARIF 2.1.0 annotated with RAPTOR analysis verdicts.

Converts RAPTOR's internal analysis results to SARIF with
``result.properties.raptor.*`` annotations for verdicts, reachability,
and structural evidence. Suppressed findings (binary oracle ``absent``)
are emitted with SARIF-standard ``result.suppressions``.

Consumers: ``/agentic --sarif-out``, ``/project export --sarif``,
``/validate`` (future).
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from core.logging import get_logger

logger = get_logger()

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_VALID_LEVELS = frozenset({"none", "note", "warning", "error"})


def _verdict_from_analysis(finding: Dict[str, Any]) -> str:
    analysis = finding.get("analysis") or {}
    if analysis.get("reachability_suppression"):
        return "suppressed"
    if finding.get("exploitable"):
        return "exploitable"
    tp = analysis.get("is_true_positive")
    if tp is True:
        return "confirmed"
    if tp is False:
        return "ruled_out"
    return "not_analyzed"


def _reachability_from_analysis(finding: Dict[str, Any]) -> str:
    analysis = finding.get("analysis") or {}
    verdict = analysis.get("reachability_verdict")
    if verdict:
        return verdict
    if analysis.get("reachability_suppression"):
        return "absent"
    return "not_evaluated"


def _build_raptor_properties(finding: Dict[str, Any]) -> Dict[str, Any]:
    verdict = _verdict_from_analysis(finding)
    props: Dict[str, Any] = {
        "verdict": verdict,
        "reachability": _reachability_from_analysis(finding),
    }

    if finding.get("source_type"):
        props["source_type"] = finding["source_type"]

    if finding.get("_cwe_inferred"):
        props["cwe_inferred"] = True

    if finding.get("has_dataflow"):
        props["has_dataflow"] = True

    analysis = finding.get("analysis") or {}
    if analysis.get("is_exploitable") is not None:
        props["is_exploitable"] = analysis["is_exploitable"]
    if analysis.get("reasoning"):
        props["reasoning"] = str(analysis["reasoning"])[:500]

    score = finding.get("exploitability_score")
    if score is not None and score > 0:
        props["exploitability_score"] = score

    if finding.get("has_exploit"):
        props["has_exploit"] = True
        if finding.get("exploit_compiled") is not None:
            props["exploit_compiled"] = finding["exploit_compiled"]

    return verdict, props


def _build_result(finding: Dict[str, Any]) -> Dict[str, Any]:
    file_path = finding.get("file_path") or finding.get("file") or ""

    start_line = finding.get("start_line")
    if start_line is None:
        start_line = finding.get("startLine")
    if start_line is None or start_line < 1:
        start_line = 1

    end_line = finding.get("end_line")
    if end_line is None:
        end_line = finding.get("endLine")
    if end_line is None or end_line < start_line:
        end_line = start_line

    rule_id = finding.get("rule_id") or "unknown"
    message = finding.get("message") or ""
    level = finding.get("level") or "warning"
    if level not in _VALID_LEVELS:
        level = "warning"

    region: Dict[str, Any] = {
        "startLine": start_line,
        "endLine": end_line,
    }

    snippet = finding.get("snippet")
    if not snippet:
        code = finding.get("code")
        if code:
            lines = code.splitlines()
            snippet = "\n".join(lines[:10]) if len(lines) > 10 else code
    if snippet:
        region["snippet"] = {"text": snippet}

    verdict, raptor_props = _build_raptor_properties(finding)

    result: Dict[str, Any] = {
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

    fid = finding.get("finding_id")
    if fid:
        result["fingerprints"] = {"matchBasedId/v1": fid}

    if verdict == "suppressed":
        analysis = finding.get("analysis") or {}
        result["suppressions"] = [{
            "kind": "inSource",
            "justification": (
                f"binary-oracle: {analysis.get('reachability_verdict', 'absent')} "
                f"— function removed by compiler/linker"
            ),
        }]

    return result


def build_enriched_sarif(
    findings: Sequence[Dict[str, Any]],
    *,
    tool_name: str = "RAPTOR",
    tool_version: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a SARIF 2.1.0 document from analysed findings.

    Groups findings by their original tool (``finding["tool"]``),
    creating one SARIF run per tool. Each result carries
    ``properties.raptor`` with RAPTOR's verdicts.
    """
    if tool_version is None:
        try:
            from core.version import effective_version
            tool_version = effective_version()
        except Exception:
            tool_version = "unknown"

    runs_by_tool: Dict[str, List[Dict[str, Any]]] = {}
    rules_by_tool: Dict[str, Dict[str, Dict[str, Any]]] = {}

    for f in findings:
        tool = f.get("tool") or tool_name
        runs_by_tool.setdefault(tool, [])
        rules_by_tool.setdefault(tool, {})

        result = _build_result(f)
        runs_by_tool[tool].append(result)

        rid = f.get("rule_id") or "unknown"
        if rid not in rules_by_tool[tool]:
            rule_entry: Dict[str, Any] = {"id": rid}
            cwe = f.get("cwe_id")
            if cwe:
                rule_entry["properties"] = {"cwe": [cwe]}
            desc = f.get("message")
            if desc:
                rule_entry["shortDescription"] = {"text": desc[:200]}
            rules_by_tool[tool][rid] = rule_entry

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    runs = []
    for tool_key, results in runs_by_tool.items():
        runs.append({
            "tool": {
                "driver": {
                    "name": tool_key,
                    "version": tool_version,
                    "rules": list(rules_by_tool[tool_key].values()),
                },
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": now,
            }],
        })

    return {
        "version": "2.1.0",
        "$schema": _SCHEMA,
        "runs": runs,
    }


def write_enriched_sarif(
    findings: Sequence[Dict[str, Any]],
    output_path: Path,
    *,
    tool_name: str = "RAPTOR",
    tool_version: Optional[str] = None,
) -> int:
    """Write enriched SARIF to *output_path*. Returns finding count."""
    doc = build_enriched_sarif(
        findings, tool_name=tool_name, tool_version=tool_version,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = output_path.with_suffix(output_path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
    tmp.replace(output_path)
    logger.info("Wrote enriched SARIF: %s (%d findings)", output_path, len(findings))
    return len(findings)
