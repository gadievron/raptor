"""Language detection by file extension."""

from pathlib import Path
from typing import Optional

LANGUAGE_MAP = {
    '.py': 'python',
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.mjs': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'tsx',
    '.c': 'c',
    '.h': 'c',
    '.cpp': 'cpp',
    '.cc': 'cpp',
    '.cxx': 'cpp',
    '.hpp': 'cpp',
    '.hh': 'cpp',
    '.hxx': 'cpp',
    '.java': 'java',
    '.go': 'go',
    '.rs': 'rust',
    '.rb': 'ruby',
    '.php': 'php',
    '.cs': 'csharp',
    '.swift': 'swift',
    '.kt': 'kotlin',
    '.kts': 'kotlin',
    '.scala': 'scala',
}


def detect_language(filepath: str) -> Optional[str]:
    """Detect language from file extension."""
    ext = Path(filepath).suffix.lower()
    return LANGUAGE_MAP.get(ext)


# Semgrep-canonical language id → operator-display name.
# Used by every consumer that prints language IDs to a human
# (``/scan`` pack-applicability lines, ``/prepare`` target
# analysis, future report renderers). Pinned here so a future
# language addition lands in one place rather than fanning out
# to every renderer.
LANG_DISPLAY = {
    "c": "C",
    "cpp": "C++",
    "python": "Python",
    "go": "Go",
    "rust": "Rust",
    "javascript": "JavaScript",
    "typescript": "TypeScript",
    "java": "Java",
    "ruby": "Ruby",
    "php": "PHP",
    "kotlin": "Kotlin",
    "swift": "Swift",
    "scala": "Scala",
    "csharp": "C#",
    "solidity": "Solidity",
    "bash": "Bash",
    "yaml": "YAML",
    "json": "JSON",
    "html": "HTML",
    "lua": "Lua",
}


def display_lang(lang: str) -> str:
    """Map a semgrep language id to its operator-display name.
    Unknown id → pass through unchanged (caller renders the
    raw id rather than guessing)."""
    return LANG_DISPLAY.get(lang, lang)


def display_langs(langs) -> str:
    """Operator-readable joined list, e.g. ``["c", "cpp"]`` →
    ``"C, C/C++"``."""
    return ", ".join(display_lang(lang) for lang in langs)
