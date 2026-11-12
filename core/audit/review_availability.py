"""Review-dispatch prerequisites for an available binary implementation view.

These checks use the pipeline's representation metadata, not a detector for
instruction correctness, decompiler fidelity, coverage or program safety.
"""
from __future__ import annotations

from typing import Any

from core.inventory.binary_builder import BINARY_PATH_PREFIX

from .knowledge_calls import KnowledgeCallRefused

_IMPLEMENTATION_VIEWS = frozenset(("decompilation", "disassembly"))


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
