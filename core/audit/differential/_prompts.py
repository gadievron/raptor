"""LLM prompt and parser for shared-vector proposals.

The LLM's only contribution to a differential run is the shared
argument vectors and the comparison contract. It never names the
members (the family roster comes from the lead's receipt and members
are selected mechanically), never writes code (vectors are plain JSON
data fed to the existing witness harnesses), and never renders a
verdict (the classifier does, from authenticated observations).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence

from core.audit.prompt_defence import sanitise_for_prompt

from ..dark_verify import DarkWitnessSpec, file_to_import_path
from ..dark_verify._prompts import _extract_json
from ._gate import ARGS_SHAPED_LANGS
from ._rails import MAX_VECTORS_PER_LEAD
from ._types import COMPARISON_CONTRACTS, DifferentialVector

#: Rationale strings are LLM prose carried into run records — bounded
#: so a rambling response cannot bloat every record it touches;
#: generous enough that the one-sentence ask survives verbatim.
_MAX_RATIONALE_CHARS = 300

# Interpolation-free system template. The deviant's file / function
# ride in slots; the lead text and family roster arrive as untrusted
# blocks in the user message.
_VECTOR_TEMPLATE = """\
You are comparing sibling implementations in a codebase to test a
suspected inconsistency.

## Lead

The deviant function's file and name are given in the `file` and
`function` slots. The static-analysis lead text arrives as an
untrusted block (kind `lead-description`) and the roster of
conforming sibling functions as kind `family-roster`.

## Task

The deviant and its siblings share an argument shape. Propose up to
3 shared argument vectors that probe the boundary the lead says the
deviant handles differently (values a guard should reject: boundary
values, nulls/None, empty or oversized inputs, wrong-unit values).
Every member — deviant and siblings alike — will be called with the
IDENTICAL vector, so pick vectors whose handling should agree across
correct implementations.

Also choose the comparison contract:
- "accept-reject-equivalence": members should agree on whether the
  input is accepted (call returns) or rejected (call raises).
- "exception-parity": the same axis, for families whose contract is
  to reject invalid input by raising.
- "return-equivalence": members should return identical values. Use
  ONLY when the siblings are true drop-in equivalents.

## Output format

Return a JSON object with these fields:
- "contract": one of the three contract strings above
- "vectors": list of up to 3 objects, each with:
  - "args": list of positional arguments (JSON-serialisable values only)
  - "kwargs": dict of keyword arguments (Python targets only; use {} otherwise)
  - "rationale": one sentence on what boundary this vector probes

Return ONLY the JSON object. No markdown fencing, no explanation outside the JSON.
"""


def build_vector_prompt(
    lead: Mapping[str, Any],
    members: Sequence[Mapping[str, Any]],
    *,
    model_id: str = "",
) -> tuple[str, str]:
    """Build the enveloped ``(user, system)`` pair for one lead.

    Everything target-derived — the lead's description text, the
    exhibit lines, and the family roster — travels in untrusted
    blocks; the deviant's file / function ride as untrusted slots.
    """
    from core.security.prompt_envelope import TaintedString, UntrustedBlock
    from core.security.prompt_framing import with_audit_framing

    from .._util import envelope_prompt

    file = str(lead.get("file") or "")
    function = str(lead.get("function") or "")
    key = f"{file}:{function}"

    description = str(lead.get("description") or "(no description)")
    sites = lead.get("sites")
    if isinstance(sites, list) and sites:
        description += "\n" + "\n".join(str(s) for s in sites[:3])

    roster = "\n".join(
        sanitise_for_prompt(str(m.get("file", "")), "path")
        + ":"
        + sanitise_for_prompt(str(m.get("function", "")), "name")
        for m in members
    )

    blocks = (
        UntrustedBlock(
            content=description,
            kind="lead-description",
            origin=key,
        ),
        UntrustedBlock(
            content=roster or "(no roster)",
            kind="family-roster",
            origin=key,
        ),
    )
    slots = {
        "file": TaintedString(value=file, trust="untrusted"),
        "function": TaintedString(value=function, trust="untrusted"),
    }
    return envelope_prompt(
        with_audit_framing(_VECTOR_TEMPLATE), blocks, slots,
        model_id=model_id,
    )


def parse_vector_response(
    response: str,
) -> tuple[str, list[DifferentialVector]] | None:
    """Parse the LLM's proposal into ``(contract, vectors)``.

    Fail-closed intake: an unrecognised contract refuses the whole
    response (defaulting one in would let a malformed response choose
    the comparison semantics), malformed vector entries are dropped
    (they simply never execute), and the surviving list is capped at
    the vector rail. Returns ``None`` when nothing usable remains.
    """
    data = _extract_json(response)
    if data is None:
        return None

    contract = data.get("contract")
    if contract not in COMPARISON_CONTRACTS:
        return None

    raw = data.get("vectors")
    if not isinstance(raw, list):
        return None
    vectors: list[DifferentialVector] = []
    for item in raw:
        if len(vectors) >= MAX_VECTORS_PER_LEAD:
            break
        if not isinstance(item, dict):
            continue
        args = item.get("args", [])
        kwargs = item.get("kwargs", {})
        if not isinstance(args, list) or not isinstance(kwargs, dict):
            continue
        if not all(isinstance(k, str) for k in kwargs):
            continue
        vectors.append(DifferentialVector(
            args=list(args),
            kwargs=dict(kwargs),
            rationale=str(item.get("rationale", ""))[:_MAX_RATIONALE_CHARS],
        ))
    if not vectors:
        return None
    return str(contract), vectors


def build_member_spec(
    *,
    finding_key: str,
    file: str,
    function: str,
    language: str,
    vector: DifferentialVector,
    target_root: Path | None = None,
) -> DarkWitnessSpec | None:
    """Mechanically build one member's witness spec for one vector.

    Nothing here comes from the LLM except the vector's plain-data
    args/kwargs: the load reference is derived from the member's FILE
    (Python import path here; the other args-shaped lanes leave
    ``lang_config`` empty so the harness derives its require/use
    reference from ``spec.file`` under the loader-binding engine's
    rules). No expectations are set — the differential layer reads
    the raw authenticated observation, not the expectation-relative
    verdict.

    Returns ``None`` when the member cannot be executed faithfully
    (non-args-shaped language; kwargs on a lane whose harness takes
    positional args only — silently dropping them would break the
    identical-shared-vector guarantee).
    """
    if language not in ARGS_SHAPED_LANGS:
        return None
    if vector.kwargs and language != "python":
        return None

    module_path = ""
    if language == "python":
        module_path = file_to_import_path(file, target_root or Path(".")) or ""
        if not module_path:
            return None

    return DarkWitnessSpec(
        finding_key=finding_key,
        file=file,
        function=function,
        language=language,
        module_path=module_path,
        args=list(vector.args),
        kwargs=dict(vector.kwargs),
        rationale=vector.rationale,
    )
