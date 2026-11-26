"""Default review kinds shared by audit scheduling and coverage reporting.

Rust named layouts/aliases/traits carry kind ``class`` like C/C++ type
items. Enable that kind by default for Rust, without turning every other
language's class shell or typedef into an automatic review job.
"""

from core.inventory.languages import detect_language

FUNCTION_KINDS = frozenset({"function", "method", ""})
DEFAULT_EXTRA_KINDS = frozenset({"top_level", "macro", "global"})
DEFAULT_REVIEWABLE_KINDS = FUNCTION_KINDS | DEFAULT_EXTRA_KINDS


def default_extra_kinds(language: str = "", file_path: str = "") -> frozenset[str]:
    """Use measured language, falling back to the path for old checklists."""
    language = language.lower() if isinstance(language, str) else ""
    if not language and isinstance(file_path, str):
        language = detect_language(file_path) or ""
    return DEFAULT_EXTRA_KINDS | {"class"} if language == "rust" else DEFAULT_EXTRA_KINDS
