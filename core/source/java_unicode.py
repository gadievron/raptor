"""Shared refusal profile for Java pre-lexical Unicode translation."""
from __future__ import annotations

JAVA_UNICODE_UNVERIFIED = "java_unicode_translation_unverified"


def java_unicode_unverified(source: str, *, language: str | None = None,
                            file_path: str = "") -> bool:
    """Whether raw Java needs a translation profile we do not establish.

    This deliberately does not decide backslash eligibility: escaped or
    inactive spellings in literals also decline. Direct Unicode characters
    are unaffected. Translation cannot be approximated by replacing text
    without a verified mapping back to source coordinates.
    """
    is_java = language.lower() == "java" if language else str(file_path).lower().endswith(".java")
    return is_java and '\\u' in source
