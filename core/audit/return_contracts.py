"""Failure-semantics binding for the return-usage census.

A call-site deviation matters only if the callee's return carries a
failure signal. This module binds that evidence — the *contract* — to
a callee, from the strongest source available (design §2.2), with the
provenance recorded on the receipt:

1. **Harvested / TU-declared ``wur:`` facts** — the target's own
   headers say ``warn_unused_result`` (``__must_check``, ``__wur``,
   ``[[nodiscard]]``, … via the curated ``packages.source_intel``
   alias table). Mechanical, per-target, registry-grade.
2. **Operator annotations** — prose on the callee that asserts a
   return contract ("returns NULL on failure", "must check").
3. **Study domain-model contracts** — ``Contract.output_semantics``
   prose, mined with the same bounded pattern set the fail-open
   channel uses (no second pattern list).
4. **Tier-A universal knowledge** — the *shared* registry in
   :mod:`core.audit.fail_open_roles` (this module consumes it, it
   does not grow a second list).
5. **IRIS/taint specs** — corroborated evidence tiers are
   registry-grade; heuristic-tier specs bind detection-grade only
   (the ``-majority`` rule-id variant).
6. **Majority evidence** — the census itself: the project's own
   convention says "check". Detection-grade, never promotes alone.

No hardcoded project-API lists anywhere in this module: a
target-specific name with no learned input resolves to *no* contract
(``contract-unresolved`` at the verdict layer).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .fail_open_roles import (
    _CORROBORATED_SPEC_TIERS,
    _MUST_CHECK_PROSE_RE,
    GRADE_DETECTION,
    GRADE_REGISTRY,
    RoleContext,
    _contract_from_prose,
    lookup_contract,
)

logger = logging.getLogger(__name__)

# Contract prose shapes accepted from annotations / domain models —
# the fail-open channel's bounded pattern set plus the return-signal
# phrasings the study loop emits (§2.2.2). Bounded by design: coverage
# gaps are fixed in the learned-vocab plumbing, never by growing this.
_RETURN_SIGNAL_PROSE_RE = re.compile(
    r"returns?\s+(?:NULL|nullptr|None|nil|-1|negative|false|an?\s+error"
    r"|error\s+code|non[- ]?zero)\s+(?:on|when|if)\s+(?:failure|error)"
    r"|fail(?:s|ure)?\s+is\s+signal+ed\s+by\s+the\s+return",
    re.IGNORECASE,
)

# Cap on annotation files scanned per lookup (bounded IO).
_MAX_ANNOTATION_SCAN = 200


@dataclass
class ContractEvidence:
    """One failure-semantics binding with source, provenance, grade."""

    source: str        # wur | annotation | domain_model | tier_a
                       #   | iris_spec | majority
    provenance: str    # e.g. "wur:harvested", "iris_spec:xref_backed"
    grade: str         # GRADE_REGISTRY | GRADE_DETECTION
    detail: str = ""   # contract string when a source records one
                       #   ("zero_ok", "tristate:…", prose excerpt)

    @property
    def registry_grade(self) -> bool:
        return self.grade == GRADE_REGISTRY

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "source": self.source,
            "provenance": self.provenance,
            "grade": self.grade,
        }
        if self.detail:
            d["detail"] = self.detail
        return d


# ── wur: facts ───────────────────────────────────────────────────────


def harvest_wur_declarations(
    source_texts: dict[str, str],
) -> frozenset[str]:
    """Function names the scanned sources declare warn-unused-result.

    A cheap bulk form of the fail-open channel's TU-declaration check:
    any line carrying a known WUR alias donates the function names
    declared within a ±2-line window. Names, not positions — the
    census owns positions.
    """
    try:
        from packages.source_intel.aliases import wur_alias_in
    except ImportError:
        return frozenset()

    decl_re = re.compile(r"\b([A-Za-z_]\w{1,})\s*\(")
    names: set[str] = set()
    for source in source_texts.values():
        if not wur_alias_in(source):
            continue
        lines = source.splitlines()
        for idx, line in enumerate(lines):
            if not wur_alias_in(line):
                continue
            # The attribute binds to the declaration it annotates: the
            # alias line itself, or — for an attribute on its own line
            # — the first following line that carries a name. Never
            # more than one declaration per alias occurrence.
            for candidate in lines[idx:idx + 3]:
                found = [
                    m.group(1) for m in decl_re.finditer(candidate)
                    if m.group(1) not in (
                        "__attribute__", "__declspec", "sizeof",
                    )
                ]
                if found:
                    names.update(found)
                    break
    return frozenset(names)


_WUR_SCAN_SUFFIXES = (".h", ".hpp", ".hh", ".hxx")
_MAX_WUR_SCAN_FILES = 400
_MAX_WUR_FILE_BYTES = 400_000


def harvest_wur_from_target(target_path: Path) -> frozenset[str]:
    """Bounded header sweep: the census's source set is the gap files,
    but warn_unused_result attributes live in headers no gap covers —
    harvest those too (declarations only, no call sites)."""
    texts: dict[str, str] = {}
    try:
        paths = sorted(
            p for p in Path(target_path).rglob("*")
            if p.is_file() and p.suffix in _WUR_SCAN_SUFFIXES
        )
    except OSError:
        return frozenset()
    for p in paths[:_MAX_WUR_SCAN_FILES]:
        try:
            if p.stat().st_size > _MAX_WUR_FILE_BYTES:
                continue
            texts[str(p)] = p.read_text(
                encoding="utf-8", errors="replace",
            )
        except OSError:
            continue
    return harvest_wur_declarations(texts)


def _wur_contract(callee: str, ctx: RoleContext) -> ContractEvidence | None:
    tail = callee.rsplit(".", 1)[-1]
    if tail in ctx.wur_functions:
        return ContractEvidence(
            source="wur",
            provenance=f"wur:{tail}",
            grade=GRADE_REGISTRY,
        )
    return None


# ── operator annotations ────────────────────────────────────────────


def _annotation_contract(
    callee: str, ctx: RoleContext,
) -> ContractEvidence | None:
    base = ctx.annotations_dir
    if base is None and ctx.out_dir is not None:
        candidate = Path(ctx.out_dir) / "annotations"
        base = candidate if candidate.is_dir() else None
    if base is None:
        return None
    tail = callee.rsplit(".", 1)[-1]
    try:
        from core.annotations.storage import iter_all_annotations
        scanned = 0
        for ann in iter_all_annotations(Path(base)):
            scanned += 1
            if scanned > _MAX_ANNOTATION_SCAN:
                break
            fn_tail = (ann.function or "").rsplit(".", 1)[-1]
            if fn_tail != tail:
                continue
            prose = ann.body or ""
            if _RETURN_SIGNAL_PROSE_RE.search(prose) \
                    or _MUST_CHECK_PROSE_RE.search(prose):
                return ContractEvidence(
                    source="annotation",
                    provenance="annotation",
                    grade=GRADE_REGISTRY,
                    detail=_contract_from_prose(prose),
                )
    except Exception:
        logger.debug("return contract: annotation scan failed",
                     exc_info=True)
    return None


# ── study domain-model contracts ────────────────────────────────────

# core.concepts.receipts.TIER_MECHANICAL — inlined to keep the import
# lazy-free on this hot path; pinned by the fallibility-feed tests.
_TIER_MECHANICAL = "mechanical"


def _fallibility_entry(
    model: dict[str, Any], tail: str,
) -> dict[str, Any] | None:
    for entry in model.get("fallibility_contracts") or []:
        if isinstance(entry, dict) and \
                str(entry.get("name") or "").rsplit(".", 1)[-1] == tail:
            return entry
    return None


def _domain_model_contract(
    callee: str, ctx: RoleContext,
) -> ContractEvidence | None:
    if ctx.out_dir is None:
        return None
    tail = callee.rsplit(".", 1)[-1]
    try:
        from core.concepts.audit_bridge import _find_domain_model
        model = _find_domain_model(Path(ctx.out_dir)) or {}
    except Exception:
        logger.debug("return contract: domain model load failed",
                     exc_info=True)
        return None

    # Structured fallibility contracts first (§2.2.2 phase-3 field):
    # the study loop's elicited {name, can_fail, convention} entries,
    # name-verified and tier-stamped. Prose-mining below stays the
    # fallback, not the mechanism. Tier discipline: the mechanical
    # tier (a study-prep signal corroborated the claim) is
    # registry-grade; llm_summarized binds detection-grade only (the
    # ``-majority`` rule-id variant at the verdict layer). Entries
    # whose failure signal is exception-borne — or which assert the
    # callee cannot fail — bind nothing: neither is a return-check
    # obligation.
    fallibility = _fallibility_entry(model, tail)
    if fallibility is not None:
        can_fail = bool(fallibility.get("can_fail"))
        convention = str(fallibility.get("convention") or "").lower()
        if can_fail and convention not in ("", "exception"):
            tier = str(fallibility.get("provenance") or "")
            return ContractEvidence(
                source="domain_model",
                provenance=(
                    f"domain_model:fallibility:{tier or 'unstamped'}"
                ),
                grade=(
                    GRADE_REGISTRY if tier == _TIER_MECHANICAL
                    else GRADE_DETECTION
                ),
                detail=convention,
            )

    for contract in model.get("contracts") or []:
        if not isinstance(contract, dict):
            continue
        if contract.get("function") != tail:
            continue
        prose = " ".join(
            str(contract.get(k) or "")
            for k in ("output_semantics", "implication", "when")
        )
        mined = _contract_from_prose(prose)
        if mined or _MUST_CHECK_PROSE_RE.search(prose) \
                or _RETURN_SIGNAL_PROSE_RE.search(prose):
            return ContractEvidence(
                source="domain_model",
                provenance="domain_model:contract",
                grade=GRADE_REGISTRY,
                detail=mined,
            )
    return None


# ── Tier-A registry (imported, never duplicated) ────────────────────


def _tier_a_contract(
    callee: str, language: str, ctx: RoleContext,
) -> ContractEvidence | None:
    contract = lookup_contract(callee, language=language, context=ctx)
    if not contract:
        return None
    # lookup_contract consults the domain model first; that source is
    # reported as domain_model by _domain_model_contract above, so a
    # hit here that ISN'T in the model is registry/seed knowledge.
    return ContractEvidence(
        source="tier_a",
        provenance=f"tier_a:{contract}",
        grade=GRADE_REGISTRY,
        detail=contract,
    )


# ── IRIS/taint specs ────────────────────────────────────────────────


def _iris_contract(
    callee: str, ctx: RoleContext,
) -> ContractEvidence | None:
    if ctx.out_dir is None:
        return None
    spec_path = Path(ctx.out_dir) / "iris-taint-specs.json"
    if not spec_path.is_file():
        return None
    try:
        from core.audit.iris_specs import specs_from_json
        specs = specs_from_json(spec_path.read_text(encoding="utf-8"))
    except Exception:
        logger.debug("return contract: iris spec load failed",
                     exc_info=True)
        return None
    tail = callee.rsplit(".", 1)[-1]
    for spec in specs:
        if spec.function != tail:
            continue
        role = getattr(spec, "role", "")
        if role not in ("sanitiser", "sink", "source"):
            continue
        tier = getattr(spec, "evidence_tier", None)
        tier_value = getattr(tier, "value", str(tier or "heuristic"))
        corroborated = tier_value in _CORROBORATED_SPEC_TIERS
        return ContractEvidence(
            source="iris_spec",
            provenance=f"iris_spec:{tier_value}",
            grade=GRADE_REGISTRY if corroborated else GRADE_DETECTION,
        )
    return None


# ── majority evidence (the census itself) ───────────────────────────


def _majority_contract(census_entry: Any) -> ContractEvidence | None:
    if census_entry is None:
        return None
    if getattr(census_entry, "majority_says_check", False):
        return ContractEvidence(
            source="majority",
            provenance=(
                f"majority:{census_entry.count('tested')}"
                f"/{census_entry.considered} sites test"
            ),
            grade=GRADE_DETECTION,
        )
    return None


# ── entry point ─────────────────────────────────────────────────────


def bind_return_contract(
    callee: str,
    *,
    language: str = "",
    context: RoleContext | None = None,
    census_entry: Any = None,
) -> ContractEvidence | None:
    """Bind failure semantics to *callee*, strongest source first.

    ``context.wur_functions`` should already include the harvested
    facts (:func:`harvest_wur_declarations` over the run's sources,
    plus any ``SourceIntelResult`` names the caller has). Returns
    ``None`` when no source binds — the verdict layer then reports
    ``contract-unresolved``; there is deliberately no fallback list.
    """
    ctx = context or RoleContext()
    if not callee:
        return None

    checks = (
        lambda: _wur_contract(callee, ctx),
        lambda: _annotation_contract(callee, ctx),
        lambda: _domain_model_contract(callee, ctx),
        lambda: _tier_a_contract(callee, language, ctx),
        lambda: _iris_contract(callee, ctx),
        lambda: _majority_contract(census_entry),
    )
    for check in checks:
        try:
            evidence = check()
        except Exception:
            logger.debug("return contract source failed", exc_info=True)
            continue
        if evidence is not None:
            return evidence
    return None
