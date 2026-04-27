"""
Mermaid diagram generator for hypotheses.json (produced by /validate Stage B).

Shows the evidence chain: finding → hypothesis → predictions → results.
This is the diagram to look at when deciding whether something is exploitable
enough to write a PoC for,it shows the concrete predictions and their
outcomes, not just whether a node is "confirmed".
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.json import load_json
from .sanitize import sanitize as _sanitize, sanitize_id as _sid


_STATUS_SYMBOL = {
    "confirmed": "confirmed",
    "disproven": "disproven",
    "testing": "testing",
    "partial": "partial",
}


def _prediction_label(pred: dict) -> str:
    pid = _sanitize(pred.get("id", "?"))
    prediction = _sanitize(pred.get("prediction", pred.get("test", "")))
    result = _sanitize(pred.get("result", ""))
    status = _sanitize(pred.get("status", "testing"))

    short_pred = prediction if len(prediction) <= 70 else prediction[:67] + "..."
    parts = [f"{pid} [{status}]", short_pred]
    if result:
        short_result = result if len(result) <= 70 else result[:67] + "..."
        parts.append(short_result)
    return "\\n".join(parts)


def _hyp_label(hyp: dict) -> str:
    hid = _sanitize(hyp.get("id", "?"))
    claim = _sanitize(hyp.get("claim") or hyp.get("hypothesis", ""))
    status = _sanitize(hyp.get("status", "testing"))
    finding = _sanitize(hyp.get("finding") or hyp.get("finding_id", ""))

    parts = [f"{hid}"]
    if finding:
        parts[0] += f" → {finding}"
    parts[0] += f" [{status}]"
    if claim:
        short = claim if len(claim) <= 70 else claim[:67] + "..."
        parts.append(short)
    return "\\n".join(parts)


def generate(hypotheses: list[dict[str, Any]]) -> str:
    if not hypotheses:
        return 'flowchart TD\n    EMPTY["No hypotheses"]'

    # Group by finding
    by_finding: dict[str, list[dict]] = {}
    ungrouped: list[dict] = []
    for h in hypotheses:
        fid = h.get("finding") or h.get("finding_id", "")
        if fid:
            by_finding.setdefault(fid, []).append(h)
        else:
            ungrouped.append(h)

    lines = ["flowchart TD"]

    hyp_node_ids: dict[str, str] = {}  # hyp id → mermaid node id
    pred_node_ids: list[tuple[str, str, str]] = []  # (hyp_node_id, pred_node_id, pred_status)

    node_counter = [0]

    def next_id(prefix: str) -> str:
        node_counter[0] += 1
        return f"{prefix}{node_counter[0]}"

    def emit_hypothesis(hyp: dict, indent: str = "    ") -> str:
        hid = hyp.get("id", f"H{node_counter[0]}")
        nid = next_id("HN")
        hyp_node_ids[hid] = nid
        label = _hyp_label(hyp)
        status = _sanitize(hyp.get("status", "testing"))
        if status == "confirmed":
            lines.append(f'{indent}{nid}["{label}"]')
        elif status == "disproven":
            lines.append(f'{indent}{nid}["{label}"]')
        else:
            lines.append(f'{indent}{nid}{{"{label}"}}')

        # Predictions
        for pred in hyp.get("predictions", []):
            pnid = next_id("PN")
            plabel = _prediction_label(pred)
            pstatus = _sanitize(pred.get("status", "testing"))
            if pstatus == "confirmed":
                lines.append(f'{indent}{pnid}["{plabel}"]')
            elif pstatus == "disproven":
                lines.append(f'{indent}{pnid}["{plabel}"]')
            else:
                lines.append(f'{indent}{pnid}(("{plabel}"))')
            pred_node_ids.append((nid, pnid, pstatus))

        return nid

    # Emit by finding subgraphs
    finding_hyp_nodes: dict[str, list[str]] = {}
    for fid, hyps in by_finding.items():
        lines.append(f'    subgraph {_sid(fid)} ["{_sanitize(fid)}"]')
        hyp_nodes = []
        for hyp in hyps:
            nid = emit_hypothesis(hyp, indent="        ")
            hyp_nodes.append(nid)
        lines.append("    end")
        finding_hyp_nodes[fid] = hyp_nodes

    # Ungrouped hypotheses
    for hyp in ungrouped:
        emit_hypothesis(hyp)

    # Edges
    lines.append("")
    lines.append("    %% Prediction edges")
    for hyp_nid, pred_nid, _pstatus in pred_node_ids:
        lines.append(f"    {hyp_nid} --> {pred_nid}")

    # Style classes
    # Collect node IDs by status for confirmed/disproven/testing predictions and hypotheses
    confirmed_nodes: list[str] = []
    disproven_nodes: list[str] = []
    testing_nodes: list[str] = []

    for hyp in hypotheses:
        hid = hyp.get("id", "")
        nid = hyp_node_ids.get(hid)
        if not nid:
            continue
        status = _sanitize(hyp.get("status", "testing"))
        if status == "confirmed":
            confirmed_nodes.append(nid)
        elif status == "disproven":
            disproven_nodes.append(nid)
        else:
            testing_nodes.append(nid)

    lines.append("")
    lines.append("    classDef confirmed fill:#dcfce7,stroke:#16a34a,color:#14532d")
    lines.append("    classDef disproven fill:#f1f5f9,stroke:#94a3b8,color:#64748b")
    lines.append("    classDef testing fill:#fef9c3,stroke:#ca8a04,color:#713f12")
    lines.append("    classDef pred_confirmed fill:#bbf7d0,stroke:#16a34a,color:#14532d")
    lines.append("    classDef pred_disproven fill:#e2e8f0,stroke:#94a3b8,color:#475569")
    lines.append("    classDef pred_testing fill:#fefce8,stroke:#ca8a04,color:#713f12")

    if confirmed_nodes:
        lines.append(f"    class {','.join(confirmed_nodes)} confirmed")
    if disproven_nodes:
        lines.append(f"    class {','.join(disproven_nodes)} disproven")
    if testing_nodes:
        lines.append(f"    class {','.join(testing_nodes)} testing")

    # Apply prediction status classes
    pred_by_status: dict[str, list[str]] = {}
    for _hyp_nid, pred_nid, pstatus in pred_node_ids:
        key = f"pred_{pstatus}" if pstatus in ("confirmed", "disproven", "testing") else "pred_testing"
        pred_by_status.setdefault(key, []).append(pred_nid)
    for cls, ids in pred_by_status.items():
        lines.append(f"    class {','.join(ids)} {cls}")

    return "\n".join(lines)


def generate_from_file(path: Path) -> str:
    data = load_json(path)
    if data is None:
        raise ValueError(f"Failed to load {path}")
    if isinstance(data, dict):
        data = data.get("hypotheses", list(data.values())[0] if data else [])
    return generate(data if isinstance(data, list) else [])
