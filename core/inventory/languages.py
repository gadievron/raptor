"""Language detection by file extension (plus content refinement)."""

import functools
import re
from pathlib import Path

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
    '.lua': 'lua',
    # Regex-fallback languages (no tree-sitter grammar wired). Added so
    # whole file classes stop contributing zero checklist items: a Perl
    # CGI codebase, a shell-script installer, or a repo whose only
    # injectable surface is a GitHub workflow previously produced an
    # EMPTY inventory for those files.
    '.pl': 'perl',
    '.pm': 'perl',
    '.sh': 'shell',
    '.bash': 'shell',
    '.m': 'objc',
    '.mm': 'objc',
    '.s': 'asm',      # suffix is lowercased, so .S (gas + cpp) folds here
    '.asm': 'asm',
    '.inc': 'inc',    # content-routed by refine_language (php/c/asm)
    '.yml': 'yaml',   # GitHub workflow YAML — jobs/steps as reviewable units
    '.yaml': 'yaml',
}

# Source-like extensions the inventory recognises but still cannot
# parse. They are collected and RECORDED as exclusions (reason
# ``unsupported_source_extension``) rather than silently invisible —
# an operator can see the recall loss in ``excluded_files``.
RECORD_ONLY_EXTENSIONS = frozenset({'.y', '.l', '.inl', '.sol'})


@functools.lru_cache(maxsize=64)
def detect_language(filepath: str) -> str | None:
    """Detect language from file extension."""
    ext = Path(filepath).suffix.lower()
    return LANGUAGE_MAP.get(ext)


# ---------------------------------------------------------------------
# Content-based refinement — extension alone misroutes two file classes:
#   * ``.h`` headers: C by default, but a C++ header (classes, templates,
#     namespaces) parsed with the C grammar loses every method.
#   * ``.inc`` fragments: PHP includes, assembler includes, and C source
#     fragments all share the extension.
# ---------------------------------------------------------------------

# C++-only constructs. tree-sitter-cpp parses plain C fine, so a false
# positive (C header routed to cpp) is harmless; the miss direction
# (C++ header parsed as C) is the recall bug this exists to fix.
_CPP_HEADER_RE = re.compile(
    r'(?m)'
    r'^\s*template\s*<'
    r'|^\s*namespace\s+[A-Za-z_{]'
    r'|^\s*class\s+[A-Za-z_]\w*'
    r'|^\s*(?:public|private|protected)\s*:'
    r'|\bextern\s+"C\+\+"'
    r'|\bstd::'
    r'|\bvirtual\s+[A-Za-z_~]'
    r'|\btypename\s+[A-Za-z_]'
)

_INC_PHP_RE = re.compile(r'<\?php|<\?=')
_INC_ASM_RE = re.compile(
    r'(?m)^\s*(?:\.(?:text|data|globl|global|section|macro|equ)\b'
    r'|%macro\b|%define\b|section\s+\.)'
)
_INC_C_RE = re.compile(
    r'(?m)^\s*#\s*(?:include|define|ifn?def|pragma)\b'
    r'|^\s*[\w*\s]+\w+\s*\([^;{)]*\)\s*\{'
)


def refine_language(language: str | None, filepath: str,
                    content: str) -> str | None:
    """Refine an extension-detected language using file content.

    ``.h`` headers carrying C++ markers route to ``cpp`` so class
    methods / templates parse; ``.inc`` fragments route to ``php`` /
    ``asm`` / ``c`` by content. Everything else passes through
    unchanged. Best-effort — unrecognisable content keeps the
    extension verdict.
    """
    if not content:
        return language
    ext = Path(filepath).suffix.lower()
    if language == 'c' and ext == '.h':
        head = content[:64 * 1024]
        if _CPP_HEADER_RE.search(head):
            return 'cpp'
        return language
    if language == 'inc':
        head = content[:16 * 1024]
        if _INC_PHP_RE.search(head):
            return 'php'
        if _INC_ASM_RE.search(head):
            return 'asm'
        if _INC_C_RE.search(head):
            return 'c'
        return language
    return language


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
    "perl": "Perl",
    "shell": "Shell",
    "objc": "Objective-C",
    "asm": "Assembly",
    "inc": "Include fragment",
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
