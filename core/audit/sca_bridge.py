"""SCA advisories → audit priors.

SCA knows which third-party components carry advisory history, which
CWE classes those advisories describe (GHSA ``cwe_ids``), and — via its
reachability evidence — which first-party files import or wrap each
component. The audit never used any of it: first-party code whose
safety contract depends on a third-party weakness (the wrapper that
must sanitise or version-gate a vulnerable API) is a class the audit
was blind to.

At audit prep this bridge:

* discovers the newest SCA ``findings.json`` (own run dir first, then
  sibling run dirs);
* maps each vulnerable component to the first-party files that import
  it (reachability evidence ``file:line`` rows);
* gives every gap in those files a priority boost, a per-CWE-family
  strategy hint, and a bounded context note through the sanctioned
  ``injected_hypotheses`` channel (the prompt renderer defangs the
  mechanism text — advisory prose never enters a prompt raw; the note
  itself is built only from identifier-charset-restricted parts).

Bounded and best-effort throughout: a broken or missing SCA artifact
must never affect the audit.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SCA_FINDINGS_FILENAME = "findings.json"
SCA_VULN_TYPE = "sca:vulnerable_dependency"

# Flat priority boost for functions in files that import a component
# with advisory history — same magnitude as SCORE_TOOL_FAILED /
# SCORE_OPEN_CONSTRAINT (a strong hint, not an entry-point override).
SCORE_SCA_ADVISORY = 4.0

MAX_COMPONENTS = 32
MAX_FILES_PER_COMPONENT = 16
MAX_ADVISORY_IDS = 4
MAX_CWES = 4
MAX_NOTE_LEN = 300

# Identifier-charset restriction for everything that reaches the note:
# advisory ids, component names and versions come from external feeds.
_SAFE_CHARS_RE = re.compile(r"[^A-Za-z0-9_.:@/+~-]")

# CWE family → audit strategy vocabulary (core/audit/strategy.py).
_CWE_STRATEGY: dict[str, str] = {
    "CWE-20": "input_handling", "CWE-22": "input_handling",
    "CWE-77": "input_handling", "CWE-78": "input_handling",
    "CWE-79": "input_handling", "CWE-89": "input_handling",
    "CWE-94": "input_handling", "CWE-502": "input_handling",
    "CWE-611": "input_handling", "CWE-918": "input_handling",
    "CWE-1333": "input_handling",
    "CWE-119": "memory", "CWE-120": "memory", "CWE-122": "memory",
    "CWE-125": "memory", "CWE-401": "memory", "CWE-415": "memory",
    "CWE-416": "memory", "CWE-457": "memory", "CWE-476": "memory",
    "CWE-787": "memory",
    "CWE-190": "integer", "CWE-191": "integer", "CWE-193": "integer",
    "CWE-287": "auth", "CWE-306": "auth", "CWE-639": "auth",
    "CWE-862": "auth", "CWE-863": "auth",
    "CWE-295": "crypto", "CWE-326": "crypto", "CWE-327": "crypto",
    "CWE-330": "crypto", "CWE-338": "crypto",
    "CWE-362": "concurrency", "CWE-367": "concurrency",
}


def _clean(value: Any, limit: int = 64) -> str:
    return _SAFE_CHARS_RE.sub("_", str(value or ""))[:limit]


def strategy_for_cwe(cwe: str) -> str | None:
    """Map an advisory CWE to the audit strategy vocabulary."""
    return _CWE_STRATEGY.get((cwe or "").upper().strip())


def _find_sca_findings(out_dir: Path) -> Path | None:
    """Newest SCA findings.json: own run dir first, then siblings."""
    try:
        out_dir = Path(out_dir)
        candidates = []
        own = out_dir / SCA_FINDINGS_FILENAME
        if own.is_file():
            candidates.append(own)
        parent = out_dir.parent
        if parent.is_dir():
            for sibling in parent.iterdir():
                if sibling == out_dir or not sibling.is_dir():
                    continue
                cand = sibling / SCA_FINDINGS_FILENAME
                if cand.is_file():
                    candidates.append(cand)
        # Keep only files whose rows actually look like SCA output
        # (audit runs write findings-graded.json, so collisions are
        # unlikely — but a list of sca-typed rows is the contract).
        sca_files = []
        for cand in candidates:
            try:
                rows = json.loads(cand.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(rows, list) and any(
                isinstance(r, dict) and r.get("vuln_type") == SCA_VULN_TYPE
                for r in rows
            ):
                sca_files.append(cand)
        if not sca_files:
            return None
        return max(sca_files, key=lambda p: p.stat().st_mtime)
    except Exception:
        logger.debug("SCA findings discovery failed", exc_info=True)
        return None


def load_component_priors(out_dir: Path) -> dict[str, dict[str, Any]]:
    """Build the per-file advisory prior map from SCA output.

    Returns ``{first-party file (relative) -> {"component", "version",
    "advisories": [ids], "cwes": [CWE-NNN], "strategies": [names]}}``.
    Files come from the reachability evidence rows (``file:line``) —
    a component nobody imports produces no priors.
    """
    findings_path = _find_sca_findings(out_dir)
    if findings_path is None:
        return {}
    try:
        rows = json.loads(findings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    priors: dict[str, dict[str, Any]] = {}
    components_seen = 0
    for row in rows:
        if not isinstance(row, dict) or row.get("vuln_type") != SCA_VULN_TYPE:
            continue
        sca = row.get("sca") or {}
        component = _clean(sca.get("name"))
        if not component:
            continue
        if components_seen >= MAX_COMPONENTS:
            break
        components_seen += 1

        advisories: list[str] = []
        cwes: list[str] = []
        all_advs = sca.get("all_advisories") or []
        primary = sca.get("advisory")
        if primary and primary not in all_advs:
            all_advs = [primary, *all_advs]
        for adv in all_advs:
            if not isinstance(adv, dict):
                continue
            adv_id = _clean(adv.get("id"))
            if adv_id and adv_id not in advisories:
                advisories.append(adv_id)
            for cwe in adv.get("cwe_ids") or []:
                cwe = _clean(cwe, 16).upper()
                if re.match(r"^CWE-\d{1,5}$", cwe) and cwe not in cwes:
                    cwes.append(cwe)
        advisories = advisories[:MAX_ADVISORY_IDS]
        cwes = cwes[:MAX_CWES]

        evidence = ((sca.get("reachability") or {}).get("evidence")) or []
        files: list[str] = []
        for ev in evidence:
            if not isinstance(ev, str):
                continue
            fp = ev.rsplit(":", 1)[0] if ":" in ev else ev
            if fp and fp not in files:
                files.append(fp)
            if len(files) >= MAX_FILES_PER_COMPONENT:
                break

        strategies = sorted({
            s for s in (strategy_for_cwe(c) for c in cwes) if s
        })
        for fp in files:
            entry = priors.setdefault(fp, {
                "component": component,
                "version": _clean(sca.get("version"), 32),
                "advisories": [],
                "cwes": [],
                "strategies": [],
            })
            for a in advisories:
                if a not in entry["advisories"]:
                    entry["advisories"].append(a)
            for c in cwes:
                if c not in entry["cwes"]:
                    entry["cwes"].append(c)
            for s in strategies:
                if s not in entry["strategies"]:
                    entry["strategies"].append(s)

    if priors:
        logger.info(
            "SCA bridge: advisory priors for %d file(s) from %s",
            len(priors), findings_path,
        )
    return priors


def _advisory_note(info: dict[str, Any]) -> str:
    ids = ", ".join(info["advisories"][:MAX_ADVISORY_IDS]) or "advisories"
    cwes = ", ".join(info["cwes"][:MAX_CWES])
    note = (
        f"file imports {info['component']}"
        f"{'@' + info['version'] if info['version'] else ''} which has "
        f"advisory history ({ids}{'; ' + cwes if cwes else ''}) — check "
        f"whether first-party wrappers of its APIs sanitise, bounds-check "
        f"or version-gate the vulnerable surface"
    )
    return note[:MAX_NOTE_LEN]


def apply_sca_advisories(
    gaps: list[dict[str, Any]],
    out_dir: Path | None,
) -> int:
    """Apply advisory priors to gaps in component-importing files.

    Mutates matching gaps: ``priority_score`` boost, CWE-family
    strategy hints appended to ``gap["strategies"]``, and one bounded
    ``injected_hypotheses`` note (rendered defanged by the prompt
    layer). Returns the number of gaps boosted. Never raises.
    """
    if not gaps or out_dir is None:
        return 0
    try:
        priors = load_component_priors(Path(out_dir))
    except Exception:
        logger.debug("SCA advisory prior load failed", exc_info=True)
        return 0
    if not priors:
        return 0

    boosted = 0
    for gap in gaps:
        info = priors.get(gap.get("file", ""))
        if info is None:
            continue
        gap["priority_score"] = (
            (gap.get("priority_score") or 0) + SCORE_SCA_ADVISORY
        )
        gap["sca_advisory"] = {
            "component": info["component"],
            "advisories": list(info["advisories"]),
            "cwes": list(info["cwes"]),
        }
        strategies = list(gap.get("strategies") or [])
        for s in info["strategies"]:
            if s not in strategies:
                strategies.append(s)
        gap["strategies"] = strategies
        hyps = gap.setdefault("injected_hypotheses", [])
        if not any(h.get("source") == "sca_advisory" for h in hyps):
            hyps.append({
                "mechanism": _advisory_note(info),
                "confidence": "medium" if info["cwes"] else "low",
                "source": "sca_advisory",
            })
        boosted += 1

    if boosted:
        logger.info(
            "SCA bridge: boosted %d gap(s) in component-importing files",
            boosted,
        )
    return boosted
