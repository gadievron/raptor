"""Review-dispatch prerequisites for an available binary implementation view.

These checks use the pipeline's representation metadata, not a detector for
instruction correctness, decompiler fidelity, coverage or program safety.
"""
from __future__ import annotations

from typing import Any

from core.inventory.binary_builder import BINARY_PATH_PREFIX

from .knowledge_calls import KnowledgeCallRefused

_IMPLEMENTATION_VIEWS = frozenset(("decompilation", "disassembly"))


_REVIEW_DEFERRAL_REASONS = {
    "binary_implementation_unavailable":
        "No implementation view was available for this binary unit; review deferred",
    "binary_module_changed_or_unavailable":
        "Binary module changed or became unavailable; review deferred",
    "binary_occurrence_unavailable":
        "Binary occurrence could not be bound to its module; review deferred",
    "binary_view_identity_unavailable":
        "Binary implementation input could not be bound; review deferred",
}
_ALLOWANCE_DEFERRED = "Knowledge review allowance exhausted"
REVIEW_DEFERRAL_LIMITATIONS = (*_REVIEW_DEFERRAL_REASONS.values(), _ALLOWANCE_DEFERRED)


def review_deferral_reason(reason: str) -> str:
    """Return the bounded existing dispatch-refusal disclosure, never raw text."""
    return _REVIEW_DEFERRAL_REASONS.get(reason, _ALLOWANCE_DEFERRED)


def require_binary_implementation(ctx: dict[str, Any]) -> None:
    """Refuse unavailable binary views before spending a reviewer attempt.

    A source context is unaffected. A binary unit needs a declared supported
    view and nonempty implementation text; a name/address placeholder is not
    an implementation review. Admission here establishes no semantic authority.
    """
    file_path = ctx.get("file")
    binary = ctx.get("is_binary") is True or (
        isinstance(file_path, str) and file_path.startswith(BINARY_PATH_PREFIX)
    )
    if not binary:
        return
    representation = ctx.get("representation")
    source = ctx.get("source")
    if (not isinstance(representation, str) or representation not in _IMPLEMENTATION_VIEWS
            or not isinstance(source, str) or not source.strip()):
        raise KnowledgeCallRefused("binary_implementation_unavailable")
    from pathlib import Path

    from .binary_review_scope import BinaryModuleSnapshot

    snapshot = ctx.get("_binary_module_snapshot")
    target = ctx.get("target_path")
    if (not isinstance(snapshot, BinaryModuleSnapshot)
            or not isinstance(target, str) or Path(target).absolute() != snapshot.path
            or not snapshot.current()):
        raise KnowledgeCallRefused("binary_module_changed_or_unavailable")
