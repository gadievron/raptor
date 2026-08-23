"""Receipt-tier invariant matching for the G2 designed exception.

The G2 gate ("finding requires tool-grounded evidence") carries one
designed exception: a hypothesis that matches a domain-model invariant
may ship as a ``finding`` without a tool receipt, justified by the
invariant's mechanical provenance from the study pipeline.  That
justification only holds when the invariant actually HAS mechanical
provenance.  The study pipeline keeps quote-less invariants in the
domain model demoted to ``llm_summarized`` (receipt=None) — unverified
LLM prose — so a match against ANY invariant lets LLM-to-LLM agreement
(study-phase prose x audit-phase prose) mint the tool-gated verdict
class with no tool in the loop.

This module is the single authority for which invariants may license
the exception, shared by the gate (grant side) and the
promotion-without-tool-evidence alarm (re-verification side):

* **receipt tier** — provenance must be an actionable tier
  (``verbatim`` / ``mechanical``) AND a verified receipt must be
  present.  ``llm_summarized`` / ``llm_prior`` invariants never
  qualify, matching the ``protocol_state`` provenance rule
  ("receipt present, provenance != llm_prior") and the
  ``ACTIONABLE_TIERS`` doctrine in :mod:`core.concepts.receipts`.
* **scope** — the invariant must apply to the outcome's file
  (:func:`core.concepts.audit_bridge._guard_in_scope` semantics: an
  invariant with explicit scope evidence is limited to it; one with
  none stays global).
* **structural anchor** — the hypothesis must share at least one
  source-anchored identifier with the invariant's verified receipt
  quote (or its mechanical rule), on top of the word-overlap floor.
  Generic English overlap ("length must not exceed buffer size" vs
  virtually every overflow hypothesis) is not a match; naming the
  actual code entities the receipt covers is.

The alarm side never trusts the ``g2_invariant_bypass`` stamp: the
stamp is advisory (and reachable from raw LLM output — the review
result is parsed model JSON), so the alarm re-derives the match from
the outcome's hypothesis, file, and the on-disk domain model, and
fires when the re-derivation finds nothing.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# Identifier-ish tokens (3+ chars). Anchors are compared lowercased so
# a hypothesis's `Buf_Size` matches a receipt's `buf_size`.
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")

# Same word shape the historical matcher used for the overlap floor.
_WORD_RE = re.compile(r"[a-z_]\w{3,}")

# Language keywords / boilerplate that appear in most receipt quotes
# and most hypotheses — sharing one of these anchors nothing.
_ANCHOR_STOPWORDS = frozenset({
    # C / C++ / Java / Go / Rust / JS keywords and stock types
    "int", "char", "void", "long", "short", "unsigned", "signed",
    "const", "static", "struct", "union", "enum", "typedef", "sizeof",
    "return", "break", "continue", "goto", "switch", "case", "default",
    "while", "else", "float", "double", "bool", "true", "false",
    "null", "nullptr", "size_t", "ssize_t", "uint8_t", "uint16_t",
    "uint32_t", "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t",
    "func", "var", "let", "def", "class", "self", "this", "none",
    "pub", "impl", "mut", "usize", "isize", "string", "byte",
    "public", "private", "protected", "final", "new", "delete",
    "import", "from", "package", "raise", "except", "try", "catch",
    "throw", "finally", "elif", "lambda", "pass", "print",
    # Prose words that pass the identifier shape
    "the", "and", "for", "not", "with", "when", "must", "never",
    "always", "value", "values", "length", "size", "buffer", "input",
    "output", "data", "byte", "bytes", "check", "checks", "checked",
    "function", "caller", "callers", "invariant", "exceed", "exceeds",
    "before", "after", "than", "then", "that", "this", "each",
})


def resolve_hypothesis(outcome: Any) -> str:
    """Extract the best hypothesis string from a review outcome.

    Prefers ``review_result["hypothesis"]``, then the outcome's own
    ``hypothesis`` field, then the highest-confidence entry in the
    ``hypotheses`` array.  Shared by the G2 gate and the promotion
    alarm so grant and re-verification read the same claim text.
    """
    review = getattr(outcome, "review_result", None) or {}
    hyp = ""
    if isinstance(review, dict):
        hyp = review.get("hypothesis") or ""
    hyp = hyp or getattr(outcome, "hypothesis", "") or ""
    if hyp and hyp.strip():
        return hyp

    hypotheses = (
        review.get("hypotheses") if isinstance(review, dict) else None
    ) or getattr(outcome, "hypotheses", None) or []
    _rank = {"high": 0, "medium": 1, "low": 2, "refuted": 3}
    best = None
    best_rank = 999
    for entry in hypotheses:
        if not isinstance(entry, dict):
            continue
        mechanism = entry.get("mechanism") or ""
        if not mechanism.strip():
            continue
        rank = _rank.get(entry.get("confidence", "low"), 2)
        if rank < best_rank:
            best = mechanism
            best_rank = rank
    return best or ""


def _receipt_checked(inv: dict[str, Any]) -> bool:
    """Actionable provenance tier AND a verified receipt present."""
    from core.concepts.receipts import ACTIONABLE_TIERS

    if str(inv.get("provenance") or "") not in ACTIONABLE_TIERS:
        return False
    receipt = inv.get("receipt")
    if not isinstance(receipt, dict):
        return False
    if not receipt.get("verified"):
        return False
    return bool(str(receipt.get("quote") or "").strip())


def _in_scope(inv: dict[str, Any], file_path: str) -> bool:
    """Scope the invariant to the outcome's file when scope evidence
    exists (fail open to global only when the invariant declares no
    scope at all — the ``_guard_in_scope`` contract)."""
    try:
        from core.concepts.audit_bridge import _guard_in_scope
    except ImportError:
        return True
    try:
        return _guard_in_scope(inv, file_path or "")
    except Exception:
        logger.debug("invariant scope check failed", exc_info=True)
        return True


def _anchor_identifiers(inv: dict[str, Any]) -> set[str]:
    """Source-anchored identifiers: tokens of the verified receipt
    quote plus the invariant's mechanical rule (both are code, not
    prose), minus keyword/prose stopwords."""
    receipt = inv.get("receipt") or {}
    sources = (
        str(receipt.get("quote") or ""),
        str(inv.get("mechanical_rule") or ""),
    )
    anchors: set[str] = set()
    for text in sources:
        for tok in _IDENT_RE.findall(text):
            low = tok.lower()
            if low in _ANCHOR_STOPWORDS:
                continue
            anchors.add(low)
    return anchors


def match_receipted_invariants(
    hypothesis: str,
    file_path: str,
    domain_model: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Invariants that may license the G2 exception for *hypothesis*.

    Returns ``[{"id", "tier", "anchors"}]`` for every invariant that
    is receipt-tier-checked, in scope for *file_path*, structurally
    anchored to the hypothesis, and past the word-overlap floor.
    Empty list when nothing qualifies — the caller must then hold the
    G2 violation.
    """
    if not domain_model or not hypothesis:
        return []
    invariants = domain_model.get("invariants") or []
    if not invariants:
        return []

    hyp_lower = hypothesis.lower()
    hyp_words = set(_WORD_RE.findall(hyp_lower))
    if len(hyp_words) < 2:
        return []
    hyp_idents = {
        t.lower() for t in _IDENT_RE.findall(hypothesis)
    } - _ANCHOR_STOPWORDS

    matched: list[dict[str, Any]] = []
    for inv in invariants:
        if not isinstance(inv, dict):
            continue
        if not _receipt_checked(inv):
            continue
        if not _in_scope(inv, file_path):
            continue
        statement = (
            str(inv.get("statement") or "")
            + " "
            + str(inv.get("negation") or "")
        ).lower()
        inv_words = set(_WORD_RE.findall(statement))
        if not inv_words:
            continue
        overlap = hyp_words & inv_words
        if len(overlap) < 3 or len(overlap) / len(inv_words) < 0.15:
            continue
        anchors = _anchor_identifiers(inv) & hyp_idents
        if not anchors:
            continue
        matched.append({
            "id": inv.get("id", ""),
            "tier": str(inv.get("provenance") or ""),
            "anchors": sorted(anchors)[:8],
        })
    return matched


def reverify_bypass(
    out_dir: Any,
    outcome: Any,
) -> bool:
    """Re-derive the G2 exception for *outcome* from the on-disk
    domain model.  True only when a receipt-tier invariant still
    matches — the alarm-side check that makes the
    ``g2_invariant_bypass`` stamp advisory instead of load-bearing.

    Fail closed: unverifiable (no domain model, load error, no match)
    is False — an unverifiable bypass claim must never silence the
    alarm.
    """
    try:
        from pathlib import Path

        from core.coverage.journal import load_domain_model

        dm = load_domain_model(Path(out_dir))
        if not dm:
            return False
        return bool(match_receipted_invariants(
            resolve_hypothesis(outcome),
            getattr(outcome, "file", "") or "",
            dm,
        ))
    except Exception:
        logger.debug("G2 bypass re-verification failed", exc_info=True)
        return False
