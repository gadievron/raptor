"""Write enriched SARIF 2.1.0 annotated with RAPTOR analysis verdicts.

Converts RAPTOR's internal analysis results to SARIF with
``result.properties.raptor.*`` annotations for verdicts, reachability,
and structural evidence. Suppressed findings (binary oracle ``absent``)
are emitted with SARIF-standard ``result.suppressions``.

Consumers: ``/agentic --sarif-out``, ``/project export --sarif``,
``/validate`` (future).
"""

import math
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.json import save_json
from core.logging import get_logger
from core.run.finding_status import read_verdict
from core.sarif.parser import _coerce_line
from core.security.log_sanitisation import escape_nonprintable

logger = get_logger()

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_VALID_LEVELS = frozenset({"none", "note", "warning", "error"})


def _verdict_from_analysis(finding: dict[str, Any]) -> str:
    analysis = finding.get("analysis") or {}
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
    analysis = finding.get("analysis") or {}
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

    analysis = finding.get("analysis") or {}
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
    level = finding.get("level") or "warning"
    if level not in _VALID_LEVELS:
        level = "warning"

    region: dict[str, Any] = {
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
    findings: Sequence[dict[str, Any]],
    *,
    tool_name: str = "RAPTOR",
    tool_version: str | None = None,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document from analysed findings.

    Groups findings by their original tool (``finding["tool"]``),
    creating one SARIF run per tool. Each result carries
    ``properties.raptor`` with RAPTOR's verdicts.
    """
    if tool_version is None:
        try:
            from core.config import RaptorConfig
            tool_version = RaptorConfig.effective_version()
        except Exception:  # noqa: BLE001
            tool_version = "unknown"

    runs_by_tool: dict[str, list[dict[str, Any]]] = {}
    rules_by_tool: dict[str, dict[str, dict[str, Any]]] = {}
    skipped_by_tool: dict[str, list[dict[str, Any]]] = {}

    for idx, f in enumerate(findings):
        tool = (
            f.get("tool") if isinstance(f, dict) else None
        ) or tool_name
        runs_by_tool.setdefault(tool, [])
        rules_by_tool.setdefault(tool, {})

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
            skipped_by_tool.setdefault(tool, []).append({
                "level": "error",
                "message": {"text": (
                    f"finding {idx} ({rid[:100]}) skipped: "
                    f"{type(exc).__name__}: {str(exc)[:200]}"
                )},
            })
            continue
        runs_by_tool[tool].append(result)

        rid = f.get("rule_id") or "unknown"
        if rid not in rules_by_tool[tool]:
            rule_entry: dict[str, Any] = {"id": rid}
            cwe = f.get("cwe_id")
            if cwe:
                rule_entry["properties"] = {"cwe": [cwe]}
            desc = f.get("message")
            if desc:
                rule_entry["shortDescription"] = {"text": str(desc)[:200]}
            rules_by_tool[tool][rid] = rule_entry

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    runs = []
    for tool_key, results in runs_by_tool.items():
        invocation: dict[str, Any] = {
            "executionSuccessful": True,
            "endTimeUtc": now,
        }
        skipped = skipped_by_tool.get(tool_key)
        if skipped:
            invocation["toolExecutionNotifications"] = skipped
        runs.append({
            "tool": {
                "driver": {
                    "name": tool_key,
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
    findings: Sequence[dict[str, Any]],
    output_path: Path,
    *,
    tool_name: str = "RAPTOR",
    tool_version: str | None = None,
) -> int:
    """Write enriched SARIF to *output_path*. Returns finding count."""
    doc = build_enriched_sarif(
        findings, tool_name=tool_name, tool_version=tool_version,
    )
    # Atomic write via the shared primitive: random-suffix tempfile
    # opened with O_EXCL | O_NOFOLLOW. An earlier implementation wrote
    # to a predictable "<name>.sarif.tmp" sibling via open() — a
    # symlink squatted at that path would have been followed silently.
    save_json(output_path, doc)
    logger.info("Wrote enriched SARIF: %s (%d findings)", output_path, len(findings))
    return len(findings)
