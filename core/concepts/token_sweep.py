"""Class-wide sweep seeds from a confirmed token-premise finding.

When a finding CONFIRMS on a premise involving the target's learned
token check (a token bypass, a missing-check exploit), every same-shape
entry the token map records as lacking enforcement is the obvious next
question. This module mechanises that sweep as HYPOTHESIS SEEDS in the
exact ``sibling-hypotheses.json`` contract the /audit intake already
consumes (``core.audit.hypothesis_intake``): seeds boost priority and
add hint-tier context — they never mint findings, carry no verdict
weight, and junk degrades to counted skips at the consumer.

Trigger discipline (learned, not hardcoded): a finding is
token-premised when its text names one of the map's LEARNED check
functions, or when it is explicitly tagged with the request-forgery
CWE. The generic seed shapes never trigger a sweep on their own.

Emission discipline: seeds are emitted for ``not_enforced`` entries
only. ``unknown`` entries are NOT swept — the map could not decide
them, and a seed claiming "lacks enforcement" would overstate the
evidence. ``enforced``/``indirect`` entries are not swept either;
bypassing a PRESENT check is a per-entry code question, not a
class-shape sweep.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

SWEEP_PRODUCER = "token-map-sweep"

#: Fallback artifact name when the canonical co-located
#: ``sibling-hypotheses.json`` already exists (another producer owns
#: it — e.g. the binary siblings ferry). The intake does not discover
#: this name; the operator passes it via ``--hypothesis-seeds``.
FALLBACK_SEEDS_FILENAME = "token-sweep-hypotheses.json"

#: Request-forgery CWE spellings accepted as an explicit trigger tag.
_CSRF_CWE_RE = re.compile(r"(?i)\bcwe[-_ ]?352\b")

#: Emission cap — matches the intake's MAX_SEED_RECORDS so nothing is
#: silently truncated at the consumer.
MAX_SWEEP_SEEDS = 200

_FINDING_TEXT_KEYS = (
    "title", "claim", "description", "summary", "hypothesis",
    "mechanism", "details",
)

_CONFIRMED_STATUSES = frozenset({"exploitable", "confirmed"})


def _finding_text(finding: dict[str, Any]) -> str:
    parts = []
    for key in _FINDING_TEXT_KEYS:
        value = finding.get(key)
        if isinstance(value, str):
            parts.append(value)
    return " ".join(parts)


def finding_is_confirmed(finding: dict[str, Any]) -> bool:
    status = str(
        finding.get("status") or finding.get("verdict") or "",
    ).lower()
    return status in _CONFIRMED_STATUSES


def finding_is_token_premised(
    finding: dict[str, Any], token_map: dict[str, Any],
) -> bool:
    """Whether *finding* rests on the learned token-check premise.

    True when the finding's prose names a LEARNED check function from
    the map (word-boundary match), or when the finding carries the
    request-forgery CWE tag. Never triggered by the generic discovery
    seed shapes — the trigger vocabulary is the map's own.
    """
    text = _finding_text(finding)
    cwe = str(finding.get("cwe") or finding.get("cwe_id") or "")
    if _CSRF_CWE_RE.search(cwe) or _CSRF_CWE_RE.search(text):
        return True
    for check in token_map.get("check_functions") or []:
        if not isinstance(check, dict):
            continue
        name = str(check.get("name") or "")
        if name and re.search(rf"\b{re.escape(name)}\b", text):
            return True
    return False


def _script_handler_name(
    checklist: dict[str, Any] | None, file_: str,
) -> str:
    """Checklist item name for the file's script-handler span, if any.

    The intake joins seeds on (file, name); PHP entry files review as
    interstitial items, so carrying the item's name lets the boost
    land instead of counting as a miss. Best-effort — no name means
    the seed still loads (the miss is counted, visibly).
    """
    if not isinstance(checklist, dict):
        return ""
    for f in checklist.get("files") or []:
        if not isinstance(f, dict) or str(f.get("path") or "") != file_:
            continue
        for item in f.get("items") or []:
            if isinstance(item, dict) and item.get("script_handler") is True:
                return str(item.get("name") or "")
    return ""


def sweep_seeds_for_finding(
    finding: dict[str, Any],
    token_map: dict[str, Any],
    checklist: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Hypothesis seeds for the not-enforced entries of *token_map*.

    Returns ``[]`` unless *finding* is confirmed AND token-premised.
    Seed fields follow the intake contract exactly
    (``core.audit.hypothesis_intake``): ``evidence_tier`` is
    ``heuristic`` (the map is a regex-lite static projection),
    ``evidence`` pointers are index-accurate into the map's own
    ``entries`` list, and ``derived_from_target`` records that claim
    and disproof embed target-derived names.
    """
    if not finding_is_confirmed(finding):
        return []
    if not finding_is_token_premised(finding, token_map):
        return []

    checks = ", ".join(
        str(c.get("name") or "")
        for c in token_map.get("check_functions") or []
        if isinstance(c, dict) and c.get("name")
    )
    finding_id = str(
        finding.get("id") or finding.get("finding_id") or "unidentified",
    )
    origin_file = str(finding.get("file") or finding.get("file_path") or "")

    seeds: list[dict[str, Any]] = []
    entries = token_map.get("entries") or []
    for idx, record in enumerate(entries):
        if not isinstance(record, dict):
            continue
        if str(record.get("status") or "") != "not_enforced":
            continue
        file_ = str(record.get("file") or "")
        if not file_:
            continue
        if origin_file and file_ == origin_file:
            continue  # the confirmed finding's own entry — already worked
        seed: dict[str, Any] = {
            "file": file_,
            "claim": (
                "Class sweep from confirmed token-premise finding "
                f"{finding_id}: this entry shows no pre-output path to "
                f"any learned token check ({checks}) — same-shape "
                "exposure candidate"
            ),
            "disproof": (
                "show a call path from the entry's pre-output prefix "
                "to the token check, or an equivalent guard the "
                "static projection cannot see (framework middleware, "
                "dynamic dispatch)"
            ),
            "evidence_tier": "heuristic",
            "evidence": [
                {"artifact": "token-map.json", "pointer": f"entries[{idx}]"},
            ],
            "derived_from_target": {"claim": True, "disproof": True},
        }
        name = _script_handler_name(checklist, file_)
        if name:
            seed["function"] = name
        seeds.append(seed)
        if len(seeds) >= MAX_SWEEP_SEEDS:
            break
    return seeds


def write_sweep_payload(
    out_dir: Path, seeds: list[dict[str, Any]],
) -> tuple[Path | None, bool]:
    """Persist *seeds* in the intake's file contract.

    Writes the canonical co-located ``sibling-hypotheses.json`` when
    the name is free; when another producer already owns it, falls
    back to :data:`FALLBACK_SEEDS_FILENAME` (never overwrites — the
    same rule the auto-siblings ferry follows) which the operator
    passes via ``--hypothesis-seeds`` on the next run.

    Returns ``(path, canonical)`` — path None when there was nothing
    to write.
    """
    if not seeds:
        return None, False
    import json

    from core.artifacts.provenance import stamp_provenance
    from core.atomic_fs import write_text_atomically
    from core.audit.hypothesis_intake import SEEDS_FILENAME

    payload: dict[str, Any] = {
        "schema_version": 1,
        "producer": SWEEP_PRODUCER,
        "seeds": seeds[:MAX_SWEEP_SEEDS],
    }
    stamp_provenance(payload, SWEEP_PRODUCER, untrusted=True)

    out_dir = Path(out_dir)
    canonical = out_dir / SEEDS_FILENAME
    target = canonical if not canonical.exists() else (
        out_dir / FALLBACK_SEEDS_FILENAME
    )
    write_text_atomically(target, json.dumps(payload, indent=2) + "\n")
    return target, target == canonical
