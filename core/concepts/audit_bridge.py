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


def _find_domain_model(out_dir: Path) -> dict[str, Any] | None:
    """Search for domain-model.json in standard locations.

    Search order:
      1. ``out_dir/domain-model.json`` (co-located with audit output)
      2. ``out_dir.parent/concepts/domain-model.json`` (project concepts dir)
      3. ``out_dir.parent/domain-model.json`` (project root)
      4. Sibling run directories (same project or global ``out/``) —
         picks the newest ``understand_*`` run that contains the file
    """
    candidates = [
        out_dir / "domain-model.json",
        out_dir.parent / "domain-model.json",
    ]
    project_concepts = out_dir.parent / "concepts" / "domain-model.json"
    if project_concepts.is_file():
        candidates.insert(0, project_concepts)

    for c in candidates:
        model = _load_cached(str(c.resolve()))
        if model:
            return model

    try:
        from core.orchestration.run_discovery import find_sibling_run
        sibling = find_sibling_run(
            out_dir, "domain-model.json",
            dir_filter=lambda d: d.name.startswith("understand_"),
            exclude=out_dir,
            search_global=False,
        )
        if sibling:
            model = _load_cached(str((sibling / "domain-model.json").resolve()))
            if model:
                logger.debug("domain model found in sibling: %s", sibling)
                return model
    except Exception:
        logger.debug("sibling search for domain-model.json failed", exc_info=True)

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
    item_id = (item.get("id") or item.get("concept") or "").lower()

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
    elif item.get("file", "") and _paths_match(file_path, item.get("file", "")):
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

    if not concepts and not invariants and not contracts:
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

    if not relevant_concepts and not relevant_invariants and not relevant_contracts:
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

    return "\n".join(parts)


def _guard_in_scope(inv: dict[str, Any], finding_file: str) -> bool:
    """Check if a guard invariant's scope covers the finding's file."""
    scope = inv.get("scope")
    if not scope:
        return True
    files = scope.get("files")
    if not files:
        return True
    finding_base = PurePosixPath(finding_file).name
    return finding_base in files or finding_file in files


def _inv_to_result(inv: dict[str, Any], *, match_pass: str = "") -> dict[str, str]:
    """Convert a raw invariant dict to a match result dict."""
    return {
        "invariant_id": inv.get("id", ""),
        "statement": inv.get("statement", ""),
        "negation": inv.get("negation", ""),
        "mechanical_rule": inv.get("mechanical_rule") or "",
        "role": inv.get("role", "boost"),
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


def _match_pass_mechanism(
    inv: dict[str, Any],
    hyp_lower: str,
) -> bool:
    """Pass 2: match if mechanism keywords from the invariant appear in the hypothesis.

    Uses the invariant's curated ``mechanism_keywords`` list (stamped at
    study time).  Requires >=2 keyword hits for a match — same threshold
    as the old keyword matcher, but with domain-specific terms instead of
    generic word overlap.
    """
    keywords = inv.get("mechanism_keywords", [])
    if not keywords:
        return False
    hits = sum(1 for kw in keywords if kw and kw.lower() in hyp_lower)
    return hits >= 2


def invariant_violations_for_hypothesis(
    out_dir: Path,
    hypothesis: str,
    *,
    role: str | None = None,
    finding_file: str = "",
    finding_cwe: str = "",
) -> list[dict[str, str]]:
    """Find invariants whose domain aligns with a hypothesis.

    Two-pass matching:
      Pass 1 (CWE): finding CWE ∈ invariant's ``relevant_cwes``.
      Pass 2 (mechanism): >=2 of the invariant's ``mechanism_keywords``
        appear in the hypothesis text.

    Guards are file-scoped on both passes.  Boosts are scope-free —
    cross-file semantic relationships are the whole point.

    Falls back to the legacy keyword-overlap matcher for invariants
    that lack the new enrichment fields (backward compatibility).

    Returns a list of dicts with 'invariant_id', 'statement', 'negation',
    'mechanical_rule', 'role', 'confidence', 'match_pass'.
    """
    model = _find_domain_model(out_dir)
    if not model:
        return []

    hyp_lower = hypothesis.lower()
    results: list[dict[str, str]] = []
    matched_ids: set[str] = set()

    for inv in model.get("invariants", []):
        inv_role = inv.get("role", "boost")
        inv_id = inv.get("id", "")
        if role is not None and inv_role != role:
            continue

        if inv_role == "guard" and finding_file:
            if not _guard_in_scope(inv, finding_file):
                continue

        has_enrichment = bool(
            inv.get("relevant_cwes") or inv.get("mechanism_keywords"),
        )

        if has_enrichment:
            if _match_pass_cwe(inv, finding_cwe):
                results.append(_inv_to_result(inv, match_pass="cwe"))
                matched_ids.add(inv_id)
                continue

            if _match_pass_mechanism(inv, hyp_lower):
                results.append(_inv_to_result(inv, match_pass="mechanism"))
                matched_ids.add(inv_id)
                continue
        else:
            # Legacy fallback for invariants without enrichment fields
            negation = inv.get("negation", "").lower()
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
                results.append(_inv_to_result(inv, match_pass="legacy"))
                matched_ids.add(inv_id)

    return results


def guard_contradicts_finding(
    out_dir: Path,
    hypothesis: str,
    preconditions: list[dict[str, Any]],
    *,
    finding_file: str = "",
    finding_cwe: str = "",
) -> list[dict[str, str]]:
    """Find guard invariants that contradict a finding's hypothesis or preconditions.

    Checks the hypothesis text and each precondition's assumption text
    against guard invariants. Returns all matching guards (deduplicated).
    """
    guards = invariant_violations_for_hypothesis(
        out_dir, hypothesis, role="guard",
        finding_file=finding_file, finding_cwe=finding_cwe,
    )
    seen_ids = {g["invariant_id"] for g in guards}

    for pre in preconditions:
        assumption = pre.get("assumption", "")
        if not assumption:
            continue
        pre_guards = invariant_violations_for_hypothesis(
            out_dir, assumption, role="guard",
            finding_file=finding_file, finding_cwe=finding_cwe,
        )
        for g in pre_guards:
            if g["invariant_id"] not in seen_ids:
                guards.append(g)
                seen_ids.add(g["invariant_id"])

    return guards


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
