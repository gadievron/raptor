"""Receipts and provenance tiers for study-loop answers.

Wrong domain knowledge from the study loop must never silently
corrupt verdicts.  Every study answer therefore carries a provenance
tier, and the tiers gate what an answer is allowed to cause:

- ``verbatim``: the answer carries a verbatim source quote whose
  presence at the stated file:line was verified by the deterministic
  checker in this module.
- ``mechanical``: derived without an LLM — CST/extractor output,
  call-graph facts, constant spot-checks.
- ``llm_summarized``: an LLM answer over extracted snippets that did
  not produce a verifiable quote.
- ``llm_prior``: an LLM claim with no extracted snippet behind it.

Only ``verbatim`` and ``mechanical`` answers may resolve a
reading-list item, trigger a critical-assumption re-review, or feed
evidence decisions.  Lower tiers surface in prompts only as
envelope-marked unverified hints.

The receipt checker is deterministic: a quote is verified when its
whitespace-normalised text appears in the referenced file, within a
line window when a line number is given.  A failed check discards the
answer — it is never delivered.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from core.paths import confine

# ------------------------------------------------------------------
# Tiers
# ------------------------------------------------------------------

TIER_VERBATIM = "verbatim"
TIER_MECHANICAL = "mechanical"
TIER_LLM_SUMMARIZED = "llm_summarized"
TIER_LLM_PRIOR = "llm_prior"

#: Tiers allowed to resolve reading-list items / trigger re-reviews /
#: feed evidence decisions.
ACTIONABLE_TIERS = frozenset({TIER_VERBATIM, TIER_MECHANICAL})

_TIER_ORDER = (
    TIER_VERBATIM, TIER_MECHANICAL, TIER_LLM_SUMMARIZED, TIER_LLM_PRIOR,
)


def is_actionable_tier(tier: str) -> bool:
    """True when *tier* may cause consequences (resolution,
    re-review, evidence).  Unknown/empty tiers are NOT actionable —
    fail closed."""
    return tier in ACTIONABLE_TIERS


def tier_rank(tier: str) -> int:
    """Lower is stronger; unknown tiers rank weakest."""
    try:
        return _TIER_ORDER.index(tier)
    except ValueError:
        return len(_TIER_ORDER)


# ------------------------------------------------------------------
# Receipt
# ------------------------------------------------------------------

#: Quotes shorter than this (after whitespace normalisation) verify
#: trivially ("return;", "}") and carry no evidential weight.
MIN_QUOTE_CHARS = 12

#: Line window around a stated line number within which the quote
#: must appear.  Small enough to pin the location, wide enough to
#: absorb off-by-a-few line reporting from the LLM.
LINE_WINDOW = 20


@dataclass
class Receipt:
    """A verifiable pointer at source text supporting an answer."""

    file: str
    line: int | None
    quote: str
    verified: bool = False
    sha256: str = ""
    tier: str = ""
    note: str = field(default="")

    def to_dict(self) -> dict:
        return asdict(self)


def _normalise(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _confine(source_root: Path, file_path: str) -> Path | None:
    """Containment chokepoint for receipt file paths (same policy as
    the study doc loader): the resolved path must stay inside the
    resolved source root. Delegates to :func:`core.paths.confine`;
    the empty-path pre-reject stays (``confine`` would resolve it to
    the root itself)."""
    if not file_path:
        return None
    return confine(source_root, file_path)


def verify_receipt(
    source_root: Path,
    file_path: str,
    line: int | None,
    quote: str,
) -> Receipt:
    """Deterministically check that *quote* exists in *file_path*.

    Returns a :class:`Receipt` with ``verified`` set.  Verification
    requires: non-trivial quote length, path confined to the source
    root, and the whitespace-normalised quote appearing in the file —
    within ``LINE_WINDOW`` lines of *line* when a line is stated,
    anywhere in the file otherwise.  ``sha256`` records the
    normalised quote hash for downstream threading.
    """
    receipt = Receipt(file=file_path, line=line, quote=quote[:2000])
    norm = _normalise(quote)
    if len(norm) < MIN_QUOTE_CHARS:
        receipt.note = "quote too short to verify"
        return receipt
    receipt.sha256 = hashlib.sha256(norm.encode()).hexdigest()[:16]

    resolved = _confine(source_root, file_path)
    if resolved is None or not resolved.is_file():
        receipt.note = "file not found inside source root"
        return receipt
    try:
        content = resolved.read_text(encoding="utf-8", errors="replace")
    except OSError:
        receipt.note = "file unreadable"
        return receipt

    if line is not None and line > 0:
        lines = content.splitlines()
        lo = max(0, line - 1 - LINE_WINDOW)
        hi = min(len(lines), line - 1 + LINE_WINDOW + 1)
        window = _normalise("\n".join(lines[lo:hi]))
        if norm in window:
            receipt.verified = True
            return receipt
        # Fall through: quote may exist elsewhere in the file — that
        # still verifies existence, but record the imprecise line.
        if norm in _normalise(content):
            receipt.verified = True
            receipt.note = "quote found in file but not at stated line"
            return receipt
        receipt.note = "quote not found in file"
        return receipt

    if norm in _normalise(content):
        receipt.verified = True
        return receipt
    receipt.note = "quote not found in file"
    return receipt


def mechanical_receipt(
    file_path: str, line: int | None, snippet: str,
) -> Receipt:
    """Receipt for a mechanically extracted snippet.

    The snippet came out of the extractor, so existence is true by
    construction; the hash still pins the exact text.
    """
    norm = _normalise(snippet)
    return Receipt(
        file=file_path,
        line=line,
        quote=snippet[:2000],
        verified=True,
        sha256=hashlib.sha256(norm.encode()).hexdigest()[:16] if norm else "",
        tier=TIER_MECHANICAL,
        note="mechanical extraction",
    )


# ------------------------------------------------------------------
# Stale-doc detection (code-over-comments precedence)
# ------------------------------------------------------------------

_PARAM_DOC_RE = re.compile(
    r"(?:@param(?:eter)?\s+(\w+)|:param\s+(\w+)\s*:)",
)
_RETURNS_NULL_DOC_RE = re.compile(
    r"\breturns?\s+(?:``)?(NULL|None|nil|null)\b", re.IGNORECASE,
)
_GO_LEADING_IDENT_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]+)\b")


def detect_stale_doc(
    doc_comment: str,
    definition: str,
    name: str,
    language: str = "",
) -> str:
    """Mechanically decidable doc/code disagreements.

    Returns a human-readable reason when the doc comment and the code
    body disagree on the contract, else "".  The code wins — the
    caller flags the disagreement on the study item (stale-doc
    marker) instead of silently picking one.

    Checks (all conservative — only fire on decidable mismatches):
    - documented parameter names absent from the definition
    - Go doc convention: leading identifier names a different function
    - doc claims a NULL/None/nil return but the body has returns and
      never returns that value
    """
    if not doc_comment or not definition:
        return ""

    # (a) @param / :param names that do not appear in the definition
    missing_params = []
    for m in _PARAM_DOC_RE.finditer(doc_comment):
        pname = m.group(1) or m.group(2)
        if pname and not re.search(rf"\b{re.escape(pname)}\b", definition):
            missing_params.append(pname)
    if missing_params:
        return (
            "doc documents parameter(s) "
            f"{', '.join(missing_params[:3])} not present in the code — "
            "the code is the contract"
        )

    # (b) Go doc convention: comment should start with the item name
    if language == "go":
        m = _GO_LEADING_IDENT_RE.match(doc_comment)
        if m and m.group(1) != name and len(m.group(1)) > 2:
            # Only flag when the leading identifier looks like a
            # code name that exists nowhere in the definition —
            # ordinary sentence-initial words ("Returns", "The") are
            # excluded by requiring camel-case interior.
            leading = m.group(1)
            looks_like_ident = bool(re.search(r"[a-z][A-Z]", leading))
            if looks_like_ident and leading not in definition:
                return (
                    f"doc comment names '{leading}' but the code "
                    f"defines '{name}' — likely stale after a rename"
                )

    # (c) doc claims NULL/None/nil return the body never produces
    m = _RETURNS_NULL_DOC_RE.search(doc_comment)
    if m and "return" in definition:
        token = m.group(1)
        variants = {"NULL", "None", "nil", "null"}
        if not any(
            re.search(rf"return\s+.*\b{re.escape(v)}\b", definition)
            for v in variants
        ):
            return (
                f"doc claims a {token} return but the code never "
                f"returns {token} — the code is the contract"
            )

    return ""
