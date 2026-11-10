"""Small conditional C reading bundle for pipeline-owned initial reviews.

This helper neither chooses target language mode nor establishes applicability.
The caller owns source binding, prompt fitting, delivery records and rollout
policy. Returning a bundle does not schedule a model call or grant evidence.
"""

from __future__ import annotations

from core.language_reference import ReferenceAnswer, ReferenceContext, ReferenceEntry, lookup

_FOUNDATION_IDS = ("c.integer-promotion", "c.integer-conversion")
_MAX_ENTRIES = 32
_MAX_PACK_ENTRIES = 256
_UNAVAILABLE = "initial_reference_foundation_unavailable"


def _closed_pack() -> bool:
    """Bound relevant resolver traversal and refuse conflicting pack IDs."""
    from core.language_reference import c_integer

    entries = c_integer.ENTRIES
    if not isinstance(entries, tuple) or len(entries) > _MAX_PACK_ENTRIES:
        return False
    by_id: dict[str, ReferenceEntry] = {}
    for entry in entries:
        if not isinstance(entry, ReferenceEntry) or not isinstance(entry.entry_id, str):
            return False
        if entry.language != "c":
            continue
        if entry.entry_id in by_id:
            return False
        by_id[entry.entry_id] = entry
    visited: set[str] = set()
    visiting: set[str] = set()

    def visit(entry_id: str) -> bool:
        if entry_id in visiting:
            return False
        if entry_id in visited:
            return True
        entry = by_id.get(entry_id)
        if (entry is None or len(visited) + len(visiting) >= _MAX_ENTRIES
                or not isinstance(entry.prerequisites, tuple)
                or len(entry.prerequisites) > _MAX_ENTRIES):
            return False
        visiting.add(entry_id)
        for required in entry.prerequisites:
            if not isinstance(required, str) or not visit(required):
                return False
        visiting.remove(entry_id)
        visited.add(entry_id)
        return True

    return all(visit(entry_id) for entry_id in _FOUNDATION_IDS)


def foundation_answers(
    language: object, *, request_id: str, binary: bool = False,
) -> tuple[ReferenceAnswer, ...]:
    """Supply full current C11 cores conditionally, with one opaque identity.

    Exact C language selection is required. The target's edition, widths,
    signedness and other implementation facts remain unknown. Unsupported or
    incomplete pack data produces one explicit empty result, never half a rule.
    """
    if (not isinstance(request_id, str) or not request_id or len(request_id) > 128
            or any(ord(char) < 32 or ord(char) == 127 for char in request_id)):
        raise ValueError("invalid foundation request identity")
    if type(language) is not str or language != "c" or binary is not False:
        return ()

    def unavailable() -> tuple[ReferenceAnswer, ...]:
        return (ReferenceAnswer(request_id, "unsupported", reason=_UNAVAILABLE),)

    if not _closed_pack():
        return unavailable()
    combined: dict[str, ReferenceEntry] = {}
    pack: str | None = None
    try:
        for entry_id in _FOUNDATION_IDS:
            answer = lookup(request_id, "", ReferenceContext("c", edition=None), entry_id=entry_id)
            if (not isinstance(answer, ReferenceAnswer) or answer.request_id != request_id
                    or answer.status != "needs_target_facts"
                    or answer.missing_facts != ("language edition",)
                    or not isinstance(answer.pack_version, str) or not answer.pack_version
                    or len(answer.pack_version) > 128
                    or not isinstance(answer.entries, tuple) or not answer.entries
                    or len(answer.entries) > _MAX_ENTRIES):
                return unavailable()
            if pack is not None and pack != answer.pack_version:
                return unavailable()
            pack = answer.pack_version
            for entry in answer.entries:
                if (not isinstance(entry, ReferenceEntry) or not isinstance(entry.entry_id, str)
                        or not entry.entry_id or entry.language != "c" or "c11" not in entry.editions
                        or type(entry.version) is not int or entry.version < 1
                        or not isinstance(entry.rule, str) or not entry.rule
                        or not isinstance(entry.prerequisites, tuple) or len(entry.prerequisites) > _MAX_ENTRIES
                        or not all(isinstance(required, str) for required in entry.prerequisites)
                        or any(not isinstance(values, tuple) or not values
                               or not all(isinstance(value, str) and value for value in values)
                               for values in (entry.conditions, entry.citations, entry.required_target_facts))
                        or len(entry.render_core()) > 16 * 1024):
                    return unavailable()
                previous = combined.get(entry.entry_id)
                if previous is not None and previous != entry:
                    return unavailable()
                combined[entry.entry_id] = entry
                if len(combined) > _MAX_ENTRIES:
                    return unavailable()
            if entry_id not in combined:
                return unavailable()
    except (AttributeError, KeyError, RecursionError, TypeError, ValueError):
        return unavailable()
    if (pack is None or any(required not in combined for entry in combined.values()
                            for required in entry.prerequisites)):
        return unavailable()
    return (ReferenceAnswer(request_id, "needs_target_facts", tuple(combined.values()),
                            "conditional initial C11 foundation; target applicability remains unestablished",
                            ("language edition",), pack),)


def foundation_required_for_file(file: object) -> bool:
    """Initial rollout covers ordinary .c units, not ambiguous headers/binaries.

    This selects conditional reading; a suffix never establishes C11 mode.
    """
    return isinstance(file, str) and not file.startswith("binary:") and file.endswith(".c")


def review_has_current_foundation(history: object) -> bool:
    """Require actual current core identities, never a defaulted policy label."""
    from .reference_inputs import reference_answer_already_delivered

    if not isinstance(history, dict) or "reference_inputs" not in history:
        return False
    required = foundation_answers("c", request_id="current-foundation-policy")
    return bool(required) and all(reference_answer_already_delivered(answer, history["reference_inputs"])
                                  for answer in required)
