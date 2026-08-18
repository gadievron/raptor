"""Agreement gate for flip-causing study answers.

An answer about to trigger a re-review (the verdict-changing path)
must survive a second independent resolution: the question is
rephrased and re-asked over the same mechanically extracted snippets
(a second model is used when the caller provides one), and the second
answer must produce a verified receipt that agrees with the first.
Disagreement — or a failed/abstaining second resolution — quarantines
the answer as inconclusive: no re-review fires.  Fail-closed by
design: an unverifiable flip is worse than a missed one.

Cost-bounded: the gate runs only at the re-review trigger point, and
mechanical-tier answers (deterministic — a second run is the same
run) skip it.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from core.llm.coerce import structured_result
from core.security.prompt_framing import with_audit_framing

from .receipts import TIER_MECHANICAL, verify_receipt

logger = logging.getLogger(__name__)

_GATE_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "answerable": {
            "type": "boolean",
            "description": (
                "true only if the question can be answered strictly "
                "from the provided snippets."
            ),
        },
        "answer": {"type": "string"},
        "file": {"type": "string"},
        "line": {"type": ["integer", "null"]},
        "quote": {
            "type": "string",
            "description": (
                "VERBATIM supporting snippet copied exactly from the "
                "provided source."
            ),
        },
    },
    "required": ["answerable", "answer", "quote"],
}

_GATE_SYSTEM_PROMPT = with_audit_framing(
    "You are independently verifying a code-comprehension claim. "
    "Answer STRICTLY from the source snippets provided — never from "
    "prior knowledge. Copy a verbatim supporting quote (it is "
    "mechanically checked). If the snippets do not answer the "
    "question, set answerable=false.",
)

#: Overlap chunk length for quote agreement.
_OVERLAP_CHARS = 30
#: Line proximity fallback for agreement.
_LINE_PROXIMITY = 20


def _normalise(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _quotes_agree(first: dict, second_quote: str, second_line) -> bool:
    """Two receipts agree when their quotes overlap or point at the
    same source neighbourhood."""
    a = _normalise(first.get("quote") or "")
    b = _normalise(second_quote or "")
    if a and b:
        if a in b or b in a:
            return True
        probe = a[:_OVERLAP_CHARS]
        if len(probe) >= _OVERLAP_CHARS and probe in b:
            return True
        probe = b[:_OVERLAP_CHARS]
        if len(probe) >= _OVERLAP_CHARS and probe in a:
            return True
    fl = first.get("line")
    if fl is not None and second_line is not None:
        try:
            return abs(int(fl) - int(second_line)) <= _LINE_PROXIMITY
        except (TypeError, ValueError):
            return False
    return False


def _rephrase(question: str) -> str:
    """Mechanical rephrase so the second resolution is not a verbatim
    replay of the first prompt."""
    q = question.rstrip("?").strip()
    return (
        f"Independent verification request: confirm or refute — {q}. "
        "State the answer explicitly."
    )


def verify_flip_answer(
    question: str,
    snippets: list[dict],
    first_receipt: dict | None,
    llm_client,
    source_root: Path,
    *,
    tier: str = "",
) -> dict:
    """Second independent resolution for a flip-causing answer.

    *snippets* are study-list item dicts (name/file/line/definition)
    relevant to the question.  Returns ``{"agreed": bool, "reason":
    str}``.  Mechanical-tier answers pass without a call.
    """
    if tier == TIER_MECHANICAL:
        return {
            "agreed": True,
            "reason": "mechanical answer — deterministic, gate skipped",
        }
    if first_receipt is None or not first_receipt.get("verified"):
        return {
            "agreed": False,
            "reason": "no verified receipt on the first answer",
        }
    if not snippets:
        return {
            "agreed": False,
            "reason": "no extracted snippets to verify against",
        }

    blocks = []
    for item in snippets[:6]:
        defn = (item.get("definition") or "")[:1500]
        if not defn:
            continue
        blocks.append(
            f"## {item.get('file')}:{item.get('line')} "
            f"({item.get('name')})\n```\n{defn}\n```"
        )
    if not blocks:
        return {
            "agreed": False,
            "reason": "no extracted snippets to verify against",
        }

    prompt = (
        f"{_rephrase(question)}\n\n"
        "Source snippets (the ONLY permitted evidence):\n\n"
        + "\n\n".join(blocks)
    )

    try:
        response = llm_client.generate_structured(
            prompt,
            _GATE_SCHEMA,
            system_prompt=_GATE_SYSTEM_PROMPT,
            task_type="study",
        )
        result = structured_result(response)
    except Exception:
        logger.warning(
            "answer-gate: verification call failed — quarantining "
            "flip-causing answer", exc_info=True,
        )
        return {"agreed": False, "reason": "verification call failed"}

    if not isinstance(result, dict):
        return {"agreed": False, "reason": "malformed verification response"}
    if not result.get("answerable"):
        return {
            "agreed": False,
            "reason": "second resolution abstained (not answerable "
                      "from the snippets)",
        }

    second = verify_receipt(
        source_root,
        result.get("file") or first_receipt.get("file") or "",
        result.get("line"),
        result.get("quote") or "",
    )
    if not second.verified:
        return {
            "agreed": False,
            "reason": f"second receipt failed verification "
                      f"({second.note})",
        }
    same_file = (
        not result.get("file")
        or result.get("file") == first_receipt.get("file")
    )
    if same_file and _quotes_agree(
        first_receipt, result.get("quote") or "", result.get("line"),
    ):
        return {"agreed": True, "reason": "independent resolution agreed"}
    return {
        "agreed": False,
        "reason": "independent resolution cited different source",
    }
