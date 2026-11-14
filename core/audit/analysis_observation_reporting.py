"""Descriptive retained checker records, separate from execution and assurance."""
from pathlib import Path

from core.json import load_json
from core.reporting.document import Block
from core.security.prompt_output_sanitise import sanitise_string

from .check_trace import CHECK_RESULTS_FILENAME, _summarize_observations

_MAX_BYTES = 8 * 1024 * 1024
_MAX_CHECKS = 100_000
_MAX_GROUPS = 512
_MAX_DISPLAY_ROWS = 40


def load_analysis_observations(out_dir: Path) -> dict:
    unavailable = {"mode": "unavailable", "authoritative": False, "artifact": CHECK_RESULTS_FILENAME}
    path = out_dir / CHECK_RESULTS_FILENAME
    try:
        if not path.exists() and not path.is_symlink():
            return {**unavailable, "artifact": None}
        data = load_json(path, max_bytes=_MAX_BYTES)
        if (not isinstance(data, dict) or type(data.get("schema_version")) is not int
                or data["schema_version"] != 1 or data.get("history_complete") is not False):
            return unavailable
        checks = data.get("checks")
        if not isinstance(checks, list) or len(checks) > _MAX_CHECKS:
            return unavailable
        groups = set()
        for check in checks:
            if not isinstance(check, dict) or not isinstance(check.get("scope"), dict):
                return unavailable
            labels = tuple(check.get(key) for key in ("tool", "outcome"))
            if any(not isinstance(label, str) or not 0 < len(label) <= 128 for label in labels):
                return unavailable
            groups.add(labels)
            if len(groups) > _MAX_GROUPS:
                return unavailable
        # Use the producer's existing counting semantics, not a second model
        # of tool authority. Saved summaries must agree with all retained rows.
        summary = _summarize_observations(checks)
        if summary != data.get("summary"):
            return unavailable
    except Exception:
        # This optional descriptive projection cannot replace the run result.
        return unavailable
    return {"mode": "recorded", "authoritative": False, "artifact": CHECK_RESULTS_FILENAME,
            "history_complete": False, "summary": summary}


def _label(value: str) -> str:
    return sanitise_string(" ".join(value.split()).replace("`", ""), max_chars=128)


def analysis_observation_blocks(report: dict) -> list[Block]:
    record = report.get("analysis_observations")
    if not isinstance(record, dict):
        return []
    if record.get("mode") != "recorded":
        return [Block("paragraph", title="Retained checker observations unavailable", text=(
            "No consistent saved checker projection is available. Missing records do not mean no check ran, "
            "and do not establish zero analysis or complete coverage."))]
    summary = record["summary"]
    rows = [[_label(tool), _label(outcome), str(count)]
            for tool, counts in sorted(summary["by_tool"].items()) for outcome, count in sorted(counts.items())]
    children = [
        Block("paragraph", text=(
            f"{summary['records']} retained checker record(s), not distinct executions, unique defects, or proofs. "
            "Only recorded channels appear. Missing records do not mean no check ran. "
            "These historical observations do not establish current source freshness, final verdict correctness, "
            "or complete analysis of a vulnerability class. Payload completeness describes serialisation only.")),
        Block("table", columns=["Recorded tool", "Saved outcome", "Records"], rows=rows[:_MAX_DISPLAY_ROWS]),
        Block("table", columns=["Recorded dimension", "Records"], rows=[
            ["Complete serialised payload", str(summary["payloads"]["complete"])],
            ["Partial serialised payload", str(summary["payloads"]["partial"])],
            ["Payload unavailable", str(summary["payloads"]["unavailable"])],
            ["Source identity field recorded", str(summary["source_identity"]["recorded"])],
            ["Source identity field unavailable", str(summary["source_identity"]["unavailable"])],
            ["Checker assumptions reported", str(summary["checker_assumptions"]["reported"])],
            ["Checker assumptions unavailable", str(summary["checker_assumptions"]["unavailable"])],
        ]),
    ]
    if len(rows) > _MAX_DISPLAY_ROWS:
        children.append(Block("paragraph", text=(
            f"{len(rows) - _MAX_DISPLAY_ROWS} further tool/outcome groups retained in {CHECK_RESULTS_FILENAME}; "
            "the record totals include them.")))
    return [Block("section", title="Retained checker observations", children=children)]
