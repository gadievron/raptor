"""Bridge between /audit output and /validate input.

Discovers constraints.json from sibling audit run directories and
enriches attack-paths with parameter preconditions so the validation
pipeline can score paths by how constrained they are.

Usage (from Stage 0 in /validate):

    from core.orchestration.audit_bridge import find_audit_output, load_audit_constraints

    audit_dir = find_audit_output(validate_dir, target_path=target)
    if audit_dir:
        constraints = load_audit_constraints(audit_dir)
        if constraints:
            enrich_attack_paths(attack_paths_file, constraints)

The two-tier search in find_audit_output() covers:
  1. Project sibling directories (same project, different run)
  2. Global out/ scan (match by checklist target_path)

Co-located (tier 1) is not searched because /audit and /validate
always produce separate output directories.
"""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

CONSTRAINTS_FILENAME = "constraints.json"


def find_audit_output(
    validate_dir: Path,
    target_path: str | None = None,
) -> Path | None:
    """Find the best sibling audit run directory with constraints.json.

    Two-tier search:
      1. Sibling directories under the same project parent
      2. Global out/ for audit runs matching the target path

    Returns the path to the audit run directory, or None.
    """
    from core.orchestration.run_discovery import find_sibling_run

    validate_dir = Path(validate_dir)

    def _target_matches(d: Path) -> bool:
        if not target_path:
            return True
        try:
            meta = json.loads((d / ".raptor-run.json").read_text())
            stored = meta.get("target_path", "")
            return Path(stored).resolve() == Path(target_path).resolve()
        except Exception:  # noqa: BLE001 — unreadable metadata = no match
            return False

    best = find_sibling_run(
        validate_dir, CONSTRAINTS_FILENAME,
        search_global=bool(target_path),
        dir_filter=_target_matches if target_path else None,
    )
    if best:
        logger.info("audit_bridge: selected %s", best)
    return best


def load_audit_constraints(audit_dir: Path) -> list[dict[str, Any]]:
    """Load constraints from an audit run directory.

    Returns the list of constraint dicts, filtering out refuted ones.
    Returns empty list on any error.
    """
    path = Path(audit_dir) / CONSTRAINTS_FILENAME
    if not path.exists():
        return []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        logger.debug("audit_bridge: failed to read %s", path, exc_info=True)
        return []

    if not isinstance(data, list):
        return []

    return [
        c for c in data
        if isinstance(c, dict) and c.get("status") != "refuted"
    ]


def enrich_attack_paths(
    attack_paths_file: Path,
    constraints: list[dict[str, Any]],
) -> int:
    """Enrich attack-paths.json with audit constraints.

    For each attack path step that references a constrained function,
    adds a 'parameter_constraints' field with the relevant preconditions.
    This lets Stage B's hypothesis formation and SMT pre-flight use
    concrete parameter bounds.

    Returns the number of steps enriched.
    """
    attack_paths_file = Path(attack_paths_file)
    if not attack_paths_file.exists():
        return 0

    try:
        data = json.loads(attack_paths_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return 0

    if not isinstance(data, list):
        return 0

    constraint_index = _build_constraint_index(constraints)
    if not constraint_index:
        return 0

    enriched = 0
    for path_entry in data:
        if not isinstance(path_entry, dict):
            continue
        for step in path_entry.get("steps", []):
            if not isinstance(step, dict):
                continue
            func = step.get("function", "")
            file_path = step.get("file", "")
            if not func:
                continue

            matched = constraint_index.get(f"{file_path}:{func}", [])
            if not matched:
                matched = constraint_index.get(f":{func}", [])
            if matched:
                step["parameter_constraints"] = matched
                enriched += 1

    if enriched:
        try:
            tmp = attack_paths_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(attack_paths_file)
            logger.info(
                "audit_bridge: enriched %d attack-path steps with constraints",
                enriched,
            )
        except OSError:
            logger.debug(
                "audit_bridge: failed to write enriched attack-paths",
                exc_info=True,
            )
            return 0

    return enriched


def _build_constraint_index(
    constraints: list[dict[str, Any]],
) -> dict[str, list[dict[str, str]]]:
    """Index constraints by file:function and bare :function.

    Returns a dict mapping keys to lists of simplified constraint
    records (kind, target, rule, violation).
    """
    index: dict[str, list[dict[str, str]]] = {}
    for c in constraints:
        func = c.get("function", "")
        file_path = c.get("file", "")
        if not func:
            continue

        entry = {
            "kind": c.get("kind", ""),
            "target": c.get("target", ""),
            "rule": c.get("rule", ""),
            "violation": c.get("violation", ""),
        }

        key = f"{file_path}:{func}"
        index.setdefault(key, []).append(entry)
        bare_key = f":{func}"
        index.setdefault(bare_key, []).append(entry)

    return index



EVIDENCE_TOOL_CONFIDENCE = {
    "semgrep": "medium",
    "smt": "medium",
    "sink_discovery": "medium",
    "taint_approx": "low",
    "prefilter": "low",
    "sibling_asymmetry": "low",
    "sentinel_collapse": "low",
}


def normalize_audit_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize /audit findings for consumption by /validate Stage A.

    Maps audit-specific fields (title, description, hypothesis,
    evidence_tool, provenance_refs) into the /validate finding schema
    so Stage A has rich upstream context instead of re-deriving
    everything from scratch.

    Fields are added non-destructively — any field already present on a
    finding (e.g. from a hybrid audit+validate run) is kept as-is.
    """
    normalized = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        out = dict(f)

        if "source" in out and out.get("source") == "audit":
            out.setdefault("origin", "audit_import")

        evidence_tool = out.get("evidence_tool", "")
        tool_prefix = evidence_tool.split(":")[0] if evidence_tool else ""
        confidence = EVIDENCE_TOOL_CONFIDENCE.get(tool_prefix, "low")
        out.setdefault("confidence", confidence)

        desc = out.get("description", "")
        hypothesis = out.get("hypothesis", "")
        title = out.get("title", "")

        if desc and "candidate_reasoning" not in out:
            out["candidate_reasoning"] = desc

        audit_context = {}
        if title:
            audit_context["title"] = title
        if hypothesis and hypothesis != desc:
            audit_context["hypothesis"] = hypothesis
        if evidence_tool:
            audit_context["evidence_tool"] = evidence_tool
        provenance = out.get("provenance_refs")
        if provenance:
            audit_context["provenance_refs"] = provenance
        if audit_context:
            out["audit_context"] = audit_context

        normalized.append(out)
    return normalized


def is_audit_format(findings: list[dict[str, Any]]) -> bool:
    """Return True if findings look like /audit output (have audit-specific fields)."""
    if not findings:
        return False
    sample = findings[0] if isinstance(findings[0], dict) else {}
    audit_fields = {"evidence_tool", "hypothesis", "provenance_refs"}
    return bool(audit_fields & set(sample.keys()))


ATTACK_CHAINS_FILENAME = "attack-chains.json"
SUMMARIES_FILENAME = "summaries.json"
GRADED_FINDINGS_FILENAME = "findings-graded.json"


def load_dark_findings(audit_dir: Path) -> list[dict[str, Any]]:
    """Load status=dark findings from an audit run's graded export.

    Dark is /audit's "tool-blind, needs concrete verification" bucket
    (auth bypass, IDOR, business logic, ...) — no mechanical channel
    can decide these classes, which makes /validate exactly the
    consumer for them. Exported with ``needs_validation: true``.

    Returns list of finding dicts, empty on any error.
    """
    path = Path(audit_dir) / GRADED_FINDINGS_FILENAME
    if not path.exists():
        return []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        logger.debug("audit_bridge: failed to read %s", path, exc_info=True)
        return []

    findings = data.get("findings", []) if isinstance(data, dict) else []
    return [
        f for f in findings
        if isinstance(f, dict) and f.get("status") == "dark"
    ]


def inject_dark_as_hypotheses(
    dark_findings: list[dict[str, Any]],
    attack_surface_file: Path,
) -> int:
    """Inject /audit dark outcomes into attack-surface.json as hypotheses.

    Each dark finding becomes an entry in attack_surface.hypotheses[]
    with status="imported" and source="audit_dark". Stage B sees these
    and verifies/disproves the tool-blind claim instead of the bucket
    dying unexamined.

    Returns number of hypotheses injected.
    """
    if not dark_findings:
        return 0

    attack_surface_file = Path(attack_surface_file)
    if not attack_surface_file.exists():
        return 0

    try:
        surface = json.loads(attack_surface_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return 0

    if not isinstance(surface, dict):
        return 0

    hypotheses = surface.setdefault("hypotheses", [])
    injected = 0

    existing_keys: set = set()
    base_idx = 0
    for h in hypotheses:
        if isinstance(h, dict) and h.get("source") == "audit_dark":
            existing_keys.add(
                (h.get("file", ""), h.get("function", ""), h.get("description", "")),
            )
            base_idx += 1

    for f in dark_findings:
        file_path = f.get("file", "")
        function = f.get("function", "")
        desc = f.get("hypothesis", "") or f.get("title", "")
        key = (file_path, function, desc)
        if key in existing_keys:
            continue
        existing_keys.add(key)
        hypothesis = {
            "id": f"audit_dark_{base_idx + injected}",
            "source": "audit_dark",
            "status": "imported",
            "needs_validation": True,
            "description": desc,
            "file": file_path,
            "function": function,
            "line": f.get("line", 0),
            "cwe": f.get("cwe_class", ""),
            "verification_tier": f.get("verification_tier", ""),
        }
        hypotheses.append(hypothesis)
        injected += 1

    if injected:
        try:
            tmp = attack_surface_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(surface, indent=2), encoding="utf-8")
            tmp.replace(attack_surface_file)
            logger.info(
                "audit_bridge: injected %d dark-outcome hypotheses", injected,
            )
        except OSError:
            logger.debug(
                "audit_bridge: failed to write dark hypotheses", exc_info=True,
            )
            return 0

    return injected


def load_attack_chains(audit_dir: Path) -> list[dict[str, Any]]:
    """Load attack-chains.json from an audit run directory.

    Attack chains describe multi-finding exploit paths synthesised by
    /audit's attacker_synthesis pass. /validate Stage B consumes these
    as pre-formed hypotheses — each chain becomes a candidate attack path
    to verify rather than discover from scratch.

    Returns list of chain dicts, empty on any error.
    """
    path = Path(audit_dir) / ATTACK_CHAINS_FILENAME
    if not path.exists():
        return []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        logger.debug("audit_bridge: failed to read %s", path, exc_info=True)
        return []

    if not isinstance(data, list):
        return []

    return [c for c in data if isinstance(c, dict)]


def load_summaries(audit_dir: Path) -> dict[str, Any]:
    """Load summaries.json from an audit run directory.

    Summaries capture per-function security behavior (taint rules,
    preconditions, postconditions). Consumed by:
    - /validate: callee contracts enrich attack-path step annotations
    - /understand --map: augments entry-point and sink annotations

    Returns dict mapping "file:function" → summary dict, empty on error.
    """
    path = Path(audit_dir) / SUMMARIES_FILENAME
    if not path.exists():
        return {}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        logger.debug("audit_bridge: failed to read %s", path, exc_info=True)
        return {}

    if isinstance(data, list):
        return {
            f"{s.get('file', '')}:{s.get('function', '')}": s
            for s in data if isinstance(s, dict)
        }
    if isinstance(data, dict):
        return data

    return {}


def inject_chains_as_hypotheses(
    chains: list[dict[str, Any]],
    attack_surface_file: Path,
) -> int:
    """Inject attack chains into attack-surface.json as pre-formed hypotheses.

    Each chain becomes an entry in attack_surface.hypotheses[] with
    status="imported" and source="audit_chain". Stage B sees these and
    can verify/disprove them rather than discovering from scratch.

    Returns number of hypotheses injected.
    """
    if not chains:
        return 0

    attack_surface_file = Path(attack_surface_file)
    if not attack_surface_file.exists():
        return 0

    try:
        surface = json.loads(attack_surface_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return 0

    if not isinstance(surface, dict):
        return 0

    hypotheses = surface.setdefault("hypotheses", [])
    injected = 0

    # Build a set of existing content keys to avoid duplicate injection.
    existing_keys: set = set()
    base_idx = 0
    for h in hypotheses:
        if isinstance(h, dict) and h.get("source") == "audit_chain":
            key = (h.get("description", ""), h.get("goal", ""))
            existing_keys.add(key)
            base_idx += 1

    for chain in chains:
        desc = chain.get("description", "")
        goal = chain.get("goal", "")
        if (desc, goal) in existing_keys:
            continue
        existing_keys.add((desc, goal))
        hypothesis = {
            "id": f"audit_chain_{base_idx + injected}",
            "source": "audit_chain",
            "status": "imported",
            "description": desc,
            "primitives": chain.get("primitives", []),
            "findings": [
                f.get("finding_id", "")
                if isinstance(f, dict) else str(f)
                for f in chain.get("findings", [])
            ],
            "goal": goal,
        }
        hypotheses.append(hypothesis)
        injected += 1

    if injected:
        try:
            tmp = attack_surface_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(surface, indent=2), encoding="utf-8")
            tmp.replace(attack_surface_file)
            logger.info(
                "audit_bridge: injected %d attack-chain hypotheses", injected,
            )
        except OSError:
            logger.debug(
                "audit_bridge: failed to write hypotheses", exc_info=True,
            )
            return 0

    return injected


def enrich_with_summaries(
    attack_paths_file: Path,
    summaries: dict[str, Any],
) -> int:
    """Enrich attack-path steps with callee contract information from summaries.

    For each step in an attack path, if a summary exists for that function,
    annotates the step with preconditions and taint rules. This gives
    /validate concrete contract data without re-running /audit.

    Returns number of steps enriched.
    """
    if not summaries:
        return 0

    attack_paths_file = Path(attack_paths_file)
    if not attack_paths_file.exists():
        return 0

    try:
        data = json.loads(attack_paths_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return 0

    if not isinstance(data, list):
        return 0

    enriched = 0
    for path_entry in data:
        if not isinstance(path_entry, dict):
            continue
        for step in path_entry.get("steps", []):
            if not isinstance(step, dict):
                continue
            func = step.get("function", "")
            file_path = step.get("file", "")
            if not func:
                continue

            key = f"{file_path}:{func}"
            summary = summaries.get(key)
            if not summary:
                continue

            step["callee_contract"] = {
                "preconditions": summary.get("preconditions", []),
                "taint_rules": summary.get("taint_rules", []),
                "postconditions": summary.get("returns", []),
            }
            enriched += 1

    if enriched:
        try:
            tmp = attack_paths_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(attack_paths_file)
            logger.info(
                "audit_bridge: enriched %d steps with callee contracts", enriched,
            )
        except OSError:
            return 0

    return enriched