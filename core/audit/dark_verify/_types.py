"""Data model for dark witness verification."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

_EXT_TO_LANG: dict[str, str] = {
    ".py": "python", ".pyw": "python",
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".go": "go",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript",
    ".rb": "ruby",
    ".php": "php",
    ".java": "java",
    ".rs": "rust",
    ".lua": "lua",
    ".pl": "perl", ".pm": "perl",
}

_SUPPORTED_LANGS = frozenset({
    "python", "c", "cpp", "go", "javascript", "typescript",
    "ruby", "php", "rust", "java", "lua", "perl",
})


def language_for_file(file_path: str) -> str | None:
    """Detect language from file extension."""
    ext = PurePosixPath(file_path.replace("\\", "/")).suffix.lower()
    return _EXT_TO_LANG.get(ext)


@dataclass(frozen=True)
class DarkWitnessSpec:
    """Structured witness from the LLM — never raw executable code."""

    finding_key: str
    file: str
    function: str
    language: str = ""
    module_path: str = ""
    args: list[Any] = field(default_factory=list)
    kwargs: dict[str, Any] = field(default_factory=dict)
    expected_return: Any = None
    expected_exception: str = ""
    expected_crash: bool = False
    expected_sanitizer: str = ""
    lang_config: dict[str, Any] = field(default_factory=dict)
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_key": self.finding_key,
            "file": self.file,
            "function": self.function,
            "language": self.language,
            "module_path": self.module_path,
            "args": self.args,
            "kwargs": self.kwargs,
            "expected_return": self.expected_return,
            "expected_exception": self.expected_exception,
            "expected_crash": self.expected_crash,
            "expected_sanitizer": self.expected_sanitizer,
            "lang_config": self.lang_config,
            "rationale": self.rationale,
        }


@dataclass
class DarkVerifyResult:
    """Result of executing one dark witness."""

    finding_key: str
    verdict: str  # "confirmed" | "refuted" | "error" | "inconclusive"
    language: str = ""
    actual_return: str = ""
    actual_exception: str = ""
    match_detail: str = ""
    oracle_reliability: str = "decisive"

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_key": self.finding_key,
            "verdict": self.verdict,
            "language": self.language,
            "actual_return": self.actual_return,
            "actual_exception": self.actual_exception,
            "match_detail": self.match_detail,
            "oracle_reliability": self.oracle_reliability,
        }
