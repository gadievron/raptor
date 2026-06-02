"""Operator-facing tool-execution coverage renderer.

Reads the ``coverage-<tool>.json`` records each scanner emits and
renders a small aligned block at /scan end so the operator sees
which tools actually ran, how many findings each produced, and any
silent-drop signal (failed packs surfaced by the scanner's own
detection).

Distinct from ``core/coverage/store_summary.py``: that one renders
the FUNCTION-level inventory coverage ("which functions did any
tool examine?"). This one renders the TOOL-EXECUTION coverage
("which tools ran with what result?"). They're complementary —
function-coverage answers "what code did we look at"; tool-coverage
answers "what did we look at it WITH".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional


# Tool display ordering — most-likely-to-fire first so the block
# reads top-to-bottom in approximate produce-findings order.
_TOOL_ORDER = ("semgrep", "coccinelle", "codeql", "sca")

# Display labels (capitalised, fixed-width for alignment).
_TOOL_LABELS = {
    "semgrep":    "Semgrep   ",
    "coccinelle": "Coccinelle",
    "codeql":     "CodeQL    ",
    "sca":        "SCA       ",
}


def _load_coverage_record(out_dir: Path, tool: str) -> Optional[Dict]:
    """Read ``coverage-<tool>.json`` from ``out_dir``. Best-effort —
    missing file / malformed JSON returns ``None`` (tool didn't run
    or its coverage emit failed; both fold to ''no record to render''
    in the caller's loop)."""
    p = out_dir / f"coverage-{tool}.json"
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _findings_for_tool(metrics: Dict, tool: str) -> int:
    """Count findings attributable to ``tool`` from
    ``scan_metrics.json::findings_by_rule``. The rule-id namespace
    distinguishes which tool produced each rule:

      * ``semgrep`` → keys start with ``engine.semgrep.rules.`` or
        the registry pack notation ``c.lang.security.foo``
      * ``codeql`` → keys match ``<lang>/<rule-id>`` (slash-separated)
      * ``coccinelle`` → keys typically snake_case (``lock_imbalance``)

    Returns 0 when no rules match (the tool ran but found nothing,
    OR the tool didn't run at all — caller distinguishes via
    coverage-file presence).
    """
    findings_by_rule = metrics.get("findings_by_rule") or {}
    total = 0
    for rule_id, count in findings_by_rule.items():
        if not isinstance(count, int):
            continue
        rule_lower = rule_id.lower()
        if tool == "semgrep":
            if (rule_lower.startswith("engine.semgrep.")
                    or rule_lower.startswith("c.lang.")
                    or rule_lower.startswith("python.lang.")
                    or "semgrep" in rule_lower):
                total += count
        elif tool == "codeql":
            # CodeQL convention: ``<lang>/<rule-id>``. The cpp/, py/,
            # js/ etc. prefixes disambiguate from
            # semgrep / coccinelle. Filter to slash-separated ids
            # whose first segment is a known language.
            head = rule_id.split("/", 1)[0] if "/" in rule_id else ""
            if head in {"cpp", "c", "py", "python", "js", "java",
                        "javascript", "ts", "typescript", "go",
                        "rb", "ruby", "cs", "csharp"}:
                total += count
        elif tool == "coccinelle":
            # Cocci ids are typically a single snake_case token with
            # no dots / slashes. Distinguish from Semgrep's dotted
            # ids by absence of separators.
            if "/" not in rule_id and "." not in rule_id:
                total += count
    return total


def render_scan_coverage(out_dir: Path) -> Optional[str]:
    """Render the operator-facing tool-execution coverage block for
    a /scan run. Returns ``None`` when no per-tool coverage files
    exist — caller suppresses the section entirely rather than
    printing an empty header.

    Output shape (aligned, one line per tool that ran)::

        Coverage: Semgrep    47 findings  (3 rule group(s); 0 failed)
                  Coccinelle  0 findings  (3 rule group(s))
                  CodeQL      skipped (autoreconf missing)

    The first line carries the ``Coverage:`` label; subsequent lines
    indent to align under the tool-name column for readability.
    """
    # scan_metrics.json gives per-tool finding counts via the
    # findings_by_rule namespace split. Best-effort: missing /
    # malformed metrics falls back to ''— findings'' on each line.
    metrics: Dict = {}
    metrics_path = out_dir / "scan_metrics.json"
    if metrics_path.is_file():
        try:
            metrics = json.loads(metrics_path.read_text())
        except (OSError, json.JSONDecodeError):
            metrics = {}

    rendered_lines: List[str] = []
    for tool in _TOOL_ORDER:
        rec = _load_coverage_record(out_dir, tool)
        if rec is None:
            continue
        label = _TOOL_LABELS[tool]
        finds = _findings_for_tool(metrics, tool)
        rules = rec.get("rules_applied")
        # rules_applied is either an int (legacy: count) or a list
        # (newer shape). Render the count regardless.
        if isinstance(rules, list):
            rule_count = len(rules)
        elif isinstance(rules, int):
            rule_count = rules
        else:
            rule_count = None

        # Failed-pack info — pulled from scan_metrics for semgrep
        # specifically (semgrep_failed_packs is the only per-tool
        # failure field surfaced today; codeql / cocci failures
        # surface through their own pipeline — extend as those
        # detectors grow).
        failed_packs: List = []
        if tool == "semgrep":
            failed_packs = metrics.get("semgrep_failed_packs") or []

        detail_parts: List[str] = []
        if rule_count is not None:
            detail_parts.append(
                f"{rule_count} rule group{'s' if rule_count != 1 else ''}"
            )
        if failed_packs:
            detail_parts.append(
                f"⚠️  {len(failed_packs)} pack(s) failed: "
                f"{', '.join(failed_packs[:3])}"
                + ("..." if len(failed_packs) > 3 else "")
            )
        detail = (
            f"  ({'; '.join(detail_parts)})" if detail_parts else ""
        )
        finds_part = f"{finds:>3} finding{'s' if finds != 1 else ''}"
        rendered_lines.append(f"{label} {finds_part}{detail}")

    if not rendered_lines:
        return None

    # First line gets the ``Coverage:`` label; remaining lines
    # indent to align the tool-name column.
    first, *rest = rendered_lines
    indent = " " * len("Coverage: ")
    out_lines = [f"Coverage: {first}"]
    for line in rest:
        out_lines.append(f"{indent}{line}")
    return "\n".join(out_lines)


__all__ = [
    "render_scan_coverage",
]
