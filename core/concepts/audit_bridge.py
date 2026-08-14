"""Bridge between /understand --study domain model and /audit.

Provides functions for /audit to consume domain-model.json:
- Load and cache the domain model
- Extract relevant concepts/invariants/contracts for a given function
- Format as a prompt block for LLM context injection
- Queue items to the reading list when audit encounters unknown constructs

Usage in audit context assembly:
    from core.concepts.audit_bridge import domain_model_context
    block = domain_model_context(out_dir, file_path, function_name, source)
    if block:
        ctx["domain_model"] = block
"""

from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any

logger = logging.getLogger(__name__)

_STOPWORDS = frozenset((
    "causes", "which", "would", "could", "should", "their",
    "these", "those", "where", "while", "after", "before",
    "about", "above", "below", "between", "through", "during",
    "other", "there", "every", "being", "having", "never",
))


def _paths_match(a: str, b: str) -> bool:
    """Check if two paths refer to the same file (suffix-match on components).

    Handles relative vs absolute and different prefix depths:
    "crypto/algif_aead.c" matches "src/crypto/algif_aead.c".
    """
    if a == b:
        return True
    if a.endswith("/" + b) or b.endswith("/" + a):
        return True
    # Same basename + at least one shared parent component
    pa, pb = PurePosixPath(a), PurePosixPath(b)
    if pa.name != pb.name:
        return False
    return bool(set(pa.parts[:-1]) & set(pb.parts[:-1]))


@lru_cache(maxsize=4)
def _load_cached(path: str) -> dict[str, Any] | None:
    """Load domain-model.json with caching (path as string for hashability).

    Cached for the process lifetime — safe because audit is single-shot
    and domain-model.json is not rewritten mid-run.
    """
    p = Path(path)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.debug("domain model load failed: %s", exc)
        return None


_per_run_warned: set[str] = set()


def _warn_per_run_once(path: str) -> None:
    if path in _per_run_warned:
        return
    _per_run_warned.add(path)
    logger.warning(
        "domain-model.json found at per-run location %s — cross-run "
        "staleness is disabled. Move to <project>/concepts/domain-"
        "model.json for cross-run hash comparison.",
        path,
    )


def _find_domain_model(out_dir: Path) -> dict[str, Any] | None:
    """Search for domain-model.json — amendment §3 canonical order.

    Search order (project-scoped canonical first, per-run last):
      1. ``<project>/concepts/domain-model.json`` — canonical.
         ``domain_model_hash`` in journal entries hashes this file
         so cross-run staleness works.
      2. ``<project>/domain-model.json`` — legacy compat.
      3. ``<out_dir>/domain-model.json`` — per-run fallback for
         standalone runs. **Disables cross-run staleness** — logs
         a WARNING so operators know.

    Removed under this amendment: sibling-run scan (previously
    ``find_sibling_run`` walked adjacent ``understand_*`` dirs). It
    undermined the stable-hash invariant Phase-5 depends on — the
    domain model hash could come from any random sibling.
    """
    project_concepts = out_dir.parent / "concepts" / "domain-model.json"
    project_root = out_dir.parent / "domain-model.json"
    per_run = out_dir / "domain-model.json"

    if project_concepts.is_file():
        return _load_cached(str(project_concepts.resolve()))
    if project_root.is_file():
        return _load_cached(str(project_root.resolve()))
    if per_run.is_file():
        _warn_per_run_once(str(per_run))
        return _load_cached(str(per_run.resolve()))
    return None


def _relevance_score(
    item: dict[str, Any],
    file_path: str,
    function_name: str,
    source: str,
) -> float:
    """Score how relevant a concept/invariant/contract is to a function."""
    score = 0.0
    fn_lower = function_name.lower()
    source_lower = source.lower() if source else ""

    desc = (item.get("description") or item.get("statement") or "").lower()
    item_id = (item.get("id") or item.get("concept") or item.get("name") or "").lower()

    # Direct naming match (case-insensitive, no double-count)
    if fn_lower in desc or fn_lower in item_id:
        score += 5.0

    # Evidence references this file or function.
    # File-level match is a weak signal (same file, possibly unrelated
    # function); function-level match is strong.
    for ev in item.get("evidence", []):
        if isinstance(ev, dict):
            ev_file = ev.get("file", "")
            if ev_file and _paths_match(file_path, ev_file):
                ev_item = ev.get("item", "")
                if ev_item and ev_item == function_name:
                    score += 6.0
                else:
                    score += 1.5
                break

    # Contract is FOR this function specifically
    if item.get("function") == function_name:
        score += 8.0
    item_file = item.get("file") or item.get("source") or ""
    item_file = re.split(r":\d", item_file, maxsplit=1)[0]
    if item_file and _paths_match(file_path, item_file):
        score += 2.0

    # Concept ID parts appear in the source body (weak signal)
    id_parts = re.split(r"[_\-.]", item_id)
    for part in id_parts:
        if len(part) > 4 and part in source_lower:
            score += 0.5

    # Confidence acts as a tiebreaker, not a promotion — scale it down
    conf = item.get("confidence", "inferred")
    conf_bonus = {
        "tested": 0.5, "documented": 0.4, "corroborated": 0.3,
        "traced": 0.2, "inferred": 0.0,
    }
    score += conf_bonus.get(conf, 0.0)

    return score


def domain_model_context(
    out_dir: Path,
    file_path: str,
    function_name: str,
    source: str = "",
    *,
    max_concepts: int = 5,
    max_invariants: int = 5,
    max_contracts: int = 3,
) -> str | None:
    """Build a prompt block with relevant domain-model knowledge.

    Returns a formatted string ready for injection into the audit LLM
    prompt, or None if no relevant domain knowledge is available.
    """
    model = _find_domain_model(out_dir)
    if not model:
        return None

    concepts = model.get("concepts", [])
    invariants = model.get("invariants", [])
    contracts = model.get("contracts", [])

    sage_block = _sage_recall_for_context(out_dir, file_path, function_name)

    if not concepts and not invariants and not contracts and not sage_block:
        return None

    scored_concepts = sorted(
        [(c, _relevance_score(c, file_path, function_name, source)) for c in concepts],
        key=lambda x: x[1],
        reverse=True,
    )
    scored_invariants = sorted(
        [(i, _relevance_score(i, file_path, function_name, source)) for i in invariants],
        key=lambda x: x[1],
        reverse=True,
    )
    scored_contracts = sorted(
        [(c, _relevance_score(c, file_path, function_name, source)) for c in contracts],
        key=lambda x: x[1],
        reverse=True,
    )

    relevant_concepts = [c for c, s in scored_concepts[:max_concepts] if s > 1.0]
    relevant_invariants = [i for i, s in scored_invariants[:max_invariants] if s > 1.0]
    relevant_contracts = [c for c, s in scored_contracts[:max_contracts] if s > 1.0]

    if (
        not relevant_concepts
        and not relevant_invariants
        and not relevant_contracts
        and not sage_block
    ):
        return None

    parts: list[str] = ["## Domain Knowledge (from /understand --study)\n"]

    sc = model.get("security_context")
    if sc and sc.get("privilege_level"):
        parts.append("### Target Security Context\n")
        parts.append(f"- **Privilege level:** {sc['privilege_level']}")
        if sc.get("attack_surface"):
            parts.append(f"- **Attack surface:** {sc['attack_surface']}")
        if sc.get("isolation"):
            parts.append(f"- **Isolation:** {sc['isolation']}")
        parts.append(
            "\nUse this context when assessing severity. "
            "Memory corruption in kernel code reachable from "
            "unprivileged userspace is high or critical severity. "
            "Adjust severity relative to the privilege boundary "
            "the attacker crosses.\n"
        )

    if relevant_concepts:
        parts.append("### Semantic Concepts\n")
        for c in relevant_concepts:
            conf = c.get("confidence", "inferred")
            parts.append(f"- **{c['id']}** [{conf}]: {c.get('description', '')}")

    if relevant_invariants:
        parts.append("\n### Invariants\n")
        for i in relevant_invariants:
            parts.append(f"- **{i['id']}**: {i.get('statement', '')}")
            neg = i.get("negation", "")
            if neg:
                parts.append(f"  - Violation: {neg}")
            rule = i.get("mechanical_rule")
            if rule:
                parts.append(f"  - Mechanical check: {rule}")

    if relevant_contracts:
        parts.append("\n### Contracts\n")
        for c in relevant_contracts:
            parts.append(f"- **{c['function']}** ({c.get('file', '')})")
            if c.get("when"):
                parts.append(f"  - When: {c['when']}")
            if c.get("input_semantics"):
                parts.append(f"  - Input: {c['input_semantics']}")
            if c.get("output_semantics"):
                parts.append(f"  - Output: {c['output_semantics']}")
            if c.get("ownership_transfer"):
                parts.append(f"  - Ownership: {c['ownership_transfer']}")
            if c.get("implication"):
                parts.append(f"  - Implication: {c['implication']}")

    bug_patterns = model.get("bug_patterns", [])
    if bug_patterns:
        parts.append("\n### Bug Patterns (from study)\n")
        parts.append(
            "These are common mistake classes for this subsystem. "
            "Check whether the function under review matches any:\n",
        )
        for bp in bug_patterns:
            desc = bp.get("description", bp.get("id", ""))
            parts.append(f"- {desc}")
            grep_hint = bp.get("what_to_grep", "")
            if grep_hint:
                parts.append(f"  - Grep: `{grep_hint}`")

    if sage_block:
        parts.append(sage_block)

    return "\n".join(parts)


def _sage_recall_for_context(
    out_dir: Path,
    file_path: str,
    function_name: str,
    *,
    max_results: int = 3,
    min_confidence: float = 0.7,
) -> str | None:
    """Query SAGE for cross-session domain knowledge about a function.

    Supplements the local domain-model.json with knowledge accumulated
    across prior runs.  Returns a formatted prompt section or None.
    """
    try:
        from core.sage.hooks import _get_client, _concepts_domain
    except ImportError:
        return None

    client = _get_client()
    if client is None:
        return None

    target = _infer_repo_path(out_dir)
    if not target:
        return None

    domain = _concepts_domain(target)
    query = f"{function_name} {file_path}"

    try:
        results = client.query(
            query, domain_tag=domain,
            top_k=max_results, min_confidence=min_confidence,
        )
    except Exception:
        logger.debug("SAGE recall failed", exc_info=True)
        return None

    if not results:
        return None

    parts = ["\n### Cross-Session Knowledge (SAGE)\n"]
    for r in results:
        conf = r.get("confidence") or 0.0
        content = r.get("content") or ""
        first_line = content.split("\n", 1)[0][:200]
        try:
            parts.append(f"- [{conf:.0%}] {first_line}")
        except (TypeError, ValueError):
            parts.append(f"- {first_line}")

    return "\n".join(parts) if len(parts) > 1 else None


def _infer_repo_path(out_dir: Path) -> str | None:
    """Infer the target repository path from a run's study-list.json."""
    candidates = [
        out_dir / "study-list.json",
        out_dir.parent / "study-list.json",
    ]
    for c in candidates:
        if c.is_file():
            try:
                data = json.loads(c.read_text(encoding="utf-8"))
                target = data.get("target", "")
                if target:
                    return target
            except (OSError, json.JSONDecodeError):
                continue
    return None


def primers_from_domain_model(
    out_dir: Path,
    file_path: str,
    function_name: str,
    source: str = "",
) -> list[str]:
    """Generate dynamic review primers from study output.

    Unlike the fixed primers in strategy.py, these are derived from the
    actual domain model — they carry the specific invariants and contracts
    that study discovered for this codebase.  Each primer is an active
    review directive telling the LLM exactly what to check.

    All candidate primers are scored and ranked — contracts and paired
    operations naturally score highest (exact function match / direct
    source reference), so they are never crowded out by generic concepts.
    The relevance threshold (>1.0) is the only filter; no hard cap.

    Returns a list of primer strings (may be empty).
    """
    model = _find_domain_model(out_dir)
    if not model:
        return []

    candidates: list[tuple[float, str]] = []

    # --- Concepts (simple schema: name/kind/description/invariants as strings) ---
    for concept in model.get("concepts", []):
        inv_list = concept.get("invariants", [])
        if not inv_list:
            continue
        score = _relevance_score(concept, file_path, function_name, source)
        if score <= 1.0:
            continue
        kind_label = (concept.get("kind") or "domain concept").upper().replace("_", " ")
        lines = [f"DOMAIN-SPECIFIC: {kind_label} — {concept.get('name', '?')}"]
        if concept.get("description"):
            lines.append(concept["description"])
        lines.append("")
        lines.append("Check each invariant — a violation is a bug:")
        for inv in inv_list:
            lines.append(f"- {inv}")
        candidates.append((score, "\n".join(lines)))

    # --- Paired operations → check for unbalanced acquire/release ---
    paired = model.get("paired_operations", [])
    if paired and source:
        source_lower = source.lower()
        relevant_pairs = []
        for po in paired:
            acq = po.get("acquire", "")
            rel = po.get("release", "")
            if acq and re.search(r"\b" + re.escape(acq.lower()) + r"\b", source_lower):
                relevant_pairs.append(po)
            elif rel and re.search(r"\b" + re.escape(rel.lower()) + r"\b", source_lower):
                relevant_pairs.append(po)
        if relevant_pairs:
            score = 6.0 + len(relevant_pairs)
            lines = ["DOMAIN-SPECIFIC: PAIRED OPERATIONS"]
            lines.append(
                "This function touches paired acquire/release APIs. "
                "Every acquire must have a matching release on all paths "
                "(including error paths)."
            )
            lines.append("")
            for po in relevant_pairs:
                note = f" ({po['note']})" if po.get("note") else ""
                lines.append(
                    f"- {po['acquire']} / {po['release']} "
                    f"[{po.get('kind', '?')}]{note}"
                )
            candidates.append((score, "\n".join(lines)))

    # --- Top-level invariants (rich schema: id/statement/negation) ---
    top_invariants = model.get("invariants", [])
    if top_invariants:
        scored = sorted(
            [
                (inv, _relevance_score(inv, file_path, function_name, source))
                for inv in top_invariants
            ],
            key=lambda x: x[1],
            reverse=True,
        )
        relevant_invs = [(inv, s) for inv, s in scored[:5] if s > 1.0]
        if relevant_invs:
            avg_score = sum(s for _, s in relevant_invs) / len(relevant_invs)
            lines = ["DOMAIN-SPECIFIC: INVARIANTS FROM STUDY"]
            lines.append(
                "These invariants were extracted from this codebase by "
                "/understand --study. A violation is a real bug."
            )
            lines.append("")
            for inv, _ in relevant_invs:
                stmt = inv.get("statement") or inv.get("description", "")
                lines.append(f"- {stmt}")
                neg = inv.get("negation")
                if neg:
                    lines.append(f"  Violation consequence: {neg}")
            candidates.append((avg_score, "\n".join(lines)))

    # --- Contracts (rich schema: function/input_semantics/output_semantics) ---
    for contract in model.get("contracts", []):
        cf = (contract.get("function") or "").lower()
        if cf != function_name.lower():
            continue
        lines = [f"DOMAIN-SPECIFIC: CONTRACT FOR {contract['function']}"]
        if contract.get("input_semantics"):
            lines.append(f"Input: {contract['input_semantics']}")
        if contract.get("output_semantics"):
            lines.append(f"Output: {contract['output_semantics']}")
        if contract.get("ownership_transfer"):
            lines.append(f"Ownership: {contract['ownership_transfer']}")
        if contract.get("implication"):
            lines.append(f"Implication: {contract['implication']}")
        candidates.append((10.0, "\n".join(lines)))

    candidates.sort(key=lambda x: x[0], reverse=True)
    return [text for _, text in candidates]


def _inv_to_result(inv: dict[str, Any], *, match_pass: str = "") -> dict[str, str]:
    """Convert a raw invariant dict to a match result dict."""
    return {
        "invariant_id": inv.get("id", ""),
        "statement": inv.get("statement", ""),
        "negation": inv.get("negation", ""),
        "mechanical_rule": inv.get("mechanical_rule") or "",
        "confidence": inv.get("confidence", "inferred"),
        "match_pass": match_pass,
    }


def _extract_cwe_id(cwe: str) -> str:
    """Normalise a CWE string to 'CWE-NNN' form."""
    cwe = cwe.strip().upper()
    if cwe.startswith("CWE-"):
        return cwe
    m = re.match(r"(\d+)", cwe)
    if m:
        return f"CWE-{m.group(1)}"
    return cwe


def _match_pass_cwe(
    inv: dict[str, Any],
    finding_cwe: str,
) -> bool:
    """Pass 1: match if the finding's CWE is in the invariant's relevant_cwes."""
    inv_cwes = inv.get("relevant_cwes", [])
    if not inv_cwes or not finding_cwe:
        return False
    norm = _extract_cwe_id(finding_cwe)
    return norm in inv_cwes



def invariant_violations_for_hypothesis(
    out_dir: Path,
    hypothesis: str,
    *,
    finding_file: str = "",
    finding_cwe: str = "",
) -> list[dict[str, str]]:
    """Find invariants whose domain aligns with a hypothesis.

    Two-pass matching:
      Pass 1 (CWE): finding CWE is in invariant's ``relevant_cwes``.
      Pass 2 (keyword): keyword overlap between invariant negation/id
        and hypothesis text.

    Returns a list of dicts with 'invariant_id', 'statement', 'negation',
    'mechanical_rule', 'confidence', 'match_pass'.
    """
    model = _find_domain_model(out_dir)
    if not model:
        return []

    hyp_lower = hypothesis.lower()
    results: list[dict[str, str]] = []
    matched_ids: set[str] = set()

    for inv in model.get("invariants", []):
        inv_id = inv.get("id", "")

        if _match_pass_cwe(inv, finding_cwe):
            results.append(_inv_to_result(inv, match_pass="cwe"))
            matched_ids.add(inv_id)
            continue

        negation = (inv.get("negation") or "").lower()
        id_parts = re.split(r"[_\-.]", inv_id.lower())
        significant_parts = [p for p in id_parts if len(p) > 3]

        if not negation and not significant_parts:
            continue

        match = False
        if negation:
            neg_terms = [
                w for w in negation.split()
                if len(w) > 4 and w not in _STOPWORDS
            ]
            hits = sum(1 for w in neg_terms if w in hyp_lower)
            match = hits >= 2
        if not match and significant_parts:
            match = sum(
                1 for p in significant_parts if p in hyp_lower
            ) >= 2

        if match:
            results.append(_inv_to_result(inv, match_pass="keyword"))
            matched_ids.add(inv_id)

    return results


def invariants_contradicting_finding(
    out_dir: Path,
    hypothesis: str,
    preconditions: list[dict[str, Any]],
    *,
    finding_file: str = "",
    finding_cwe: str = "",
) -> list[dict[str, str]]:
    """Find invariants that contradict a finding's hypothesis or preconditions.

    Checks the hypothesis text and each precondition's assumption text
    against all invariants. Returns matching invariants (deduplicated).
    """
    matches = invariant_violations_for_hypothesis(
        out_dir, hypothesis,
        finding_file=finding_file, finding_cwe=finding_cwe,
    )
    seen_ids = {m["invariant_id"] for m in matches}

    for pre in preconditions:
        assumption = pre.get("assumption", "")
        if not assumption:
            continue
        pre_matches = invariant_violations_for_hypothesis(
            out_dir, assumption,
            finding_file=finding_file, finding_cwe=finding_cwe,
        )
        for m in pre_matches:
            if m["invariant_id"] not in seen_ids:
                matches.append(m)
                seen_ids.add(m["invariant_id"])

    return matches


def queue_reading_list_item(
    out_dir: Path,
    *,
    question: str,
    source_command: str = "/audit",
    source_file: str = "",
    source_function: str = "",
    priority: str = "normal",
    resolution: str = "identifier",
    context: str = "",
) -> bool:
    """Queue an item to the reading list for future study.

    Called by /audit when it encounters an unfamiliar type or concept
    that would benefit from semantic study before further analysis.

    Returns True if the item was queued (or already exists).
    """
    from .reading_list import ReadingList, ReadingListItem

    rl_path = out_dir / "reading-list.json"
    rl = ReadingList.load(rl_path)

    item_id = f"audit-{source_file}:{source_function}:{question[:30]}"
    item_id = re.sub(r"[^a-zA-Z0-9_\-:.]", "_", item_id)

    item = ReadingListItem(
        id=item_id,
        question=question,
        source_command=source_command,
        source_file=source_file,
        source_function=source_function,
        priority=priority,
        resolution=resolution,
        context=context,
    )

    rl.queue(item)
    try:
        rl.save(rl_path)
        return True
    except OSError as exc:
        logger.debug("failed to save reading list: %s", exc)
        return False
