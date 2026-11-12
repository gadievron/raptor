"""Historical reviewer attribution from the selected owned journal records.

Neither an install MAC nor a descriptive basis is proof of current freshness,
mechanical verification, or complete correctness. Verdicts and grades are not
selected here.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from core.coverage import journal_mac
from core.coverage.journal import CLEAN_BASIS_VERDICT, entry_producer, is_mechanical_echo
from core.reporting.document import Block

from .assessment_basis import read_assessment_basis
from .review_claims import read_history
from .source_anchor import parse_source_anchor

ROLE = "historical_review_basis_not_assurance"
MAX_DISPLAYED = 100
_LABELS = {"model_judgment": "Model judgement",
           "model_judgment_withdrawal": "Explicit model withdrawal",
           "unavailable": "Unavailable (not recorded or unbound)"}


def journal_assessment_basis(entry: Any, out_dir: Path) -> dict[str, Any] | None:
    """Select only an integrity-checked, same-run, exactly bound record."""
    if (is_mechanical_echo(entry) or entry_producer(entry) != "audit"
            or journal_mac.entry_provenance(entry) != journal_mac.ROW_VERIFIED):
        return None
    try:
        run = Path(out_dir).resolve()
    except (OSError, ValueError):
        return None
    if entry.run_id != run.name or entry.run_path != str(run):
        return None
    # A later scoped-refutation or silence gate can keep the same status
    # while changing the selected assessment's basis. Do not describe it
    # as model-only by borrowing a historical contributing review.
    if entry.verdict == "clean" and entry.clean_basis != CLEAN_BASIS_VERDICT:
        return None
    history = read_history(entry.review_claims)
    review = history.get("review") if history is not None else None
    origin = review.get("origin") if isinstance(review, dict) else None
    if not isinstance(origin, dict):
        return None
    pass_id = origin.get("pass_id")
    if not isinstance(pass_id, str):
        return None
    basis = read_assessment_basis(history, pass_id=pass_id, status=entry.verdict)
    anchor = parse_source_anchor(entry.source_hash)
    if (basis is None or anchor is None
            or (origin.get("file"), origin.get("function"), origin.get("line_start"), origin.get("line_end"))
            != (entry.file, entry.function, entry.line_start, entry.line_end)
            or anchor[0] != basis["origin"]["source_identity"]["sha256"]):
        return None
    return basis


def assessment_basis_summary(audit_data: dict) -> dict[str, Any] | None:
    """Bounded presentation of known and unavailable reviewer provenance."""
    rows = []
    recorded = 0
    for item in audit_data.get("functions_analysed", []):
        if item.get("mechanical"):
            continue
        basis = item.get("assessment_basis")
        unit = {key: item.get(key) for key in ("file", "function", "line_start", "status")}
        if isinstance(basis, dict):
            recorded += 1
            rows.append({**unit, **basis})
        else:
            rows.append({**unit, "basis": "unavailable", "scope": "historical_review_only"})
    if not rows:
        return None
    rows.sort(key=lambda row: (row["basis"] == "unavailable", str(row.get("file")),
                               str(row.get("function")), row.get("line_start") or 0))
    total = len(rows)
    return {"role": ROLE, "recorded": recorded, "unavailable": total - recorded,
            "records": rows[:MAX_DISPLAYED], "records_omitted": max(0, total - MAX_DISPLAYED)}


def assessment_basis_blocks(report: dict) -> list[Block]:
    data = report.get("assessment_bases")
    if data is None:
        return []
    unavailable = [Block("paragraph", title="Recorded reviewer basis unavailable",
                         text="The recorded basis summary is invalid; no assurance is inferred.")]
    if (not isinstance(data, dict) or data.get("role") != ROLE
            or any(type(data.get(key)) is not int or data[key] < 0
                   for key in ("recorded", "unavailable", "records_omitted"))
            or not isinstance(data.get("records"), list) or len(data["records"]) > MAX_DISPLAYED):
        return unavailable
    rows = []
    for record in data["records"]:
        if (not isinstance(record, dict) or record.get("scope") != "historical_review_only"
                or not isinstance(record.get("basis"), str) or record["basis"] not in _LABELS
                or not isinstance(record.get("file"), str) or not isinstance(record.get("function"), str)
                or type(record.get("line_start")) is not int or not isinstance(record.get("status"), str)):
            return unavailable
        rows.append([f"{record['file']}:{record['line_start']} {record['function']}",
                     record["status"], _LABELS[record["basis"]]])
    children = [Block("paragraph", text=(
        "This records the historical basis of selected journaled reviews. It does not establish current "
        "source freshness, mechanical assurance, or complete correctness. Clean means no finding was "
        "established by that review in its stated scope; it never means proved safe.")),
        Block("paragraph", text=f"Recorded for {data['recorded']} function records; unavailable for {data['unavailable']}."),
        Block("table", columns=["Function", "Recorded verdict", "Basis"], rows=rows)]
    if data["records_omitted"]:
        children.append(Block("paragraph", text=f"{data['records_omitted']} further records omitted from this summary; consult the review journal for retained history."))
    return [Block("section", title="Recorded reviewer basis", children=children)]
