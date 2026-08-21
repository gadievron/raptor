"""Language-aware CodeQL database routing.

A run may carry one database per language (multi-language targets;
``--codeql-db`` is repeatable). CodeQL queries are language-specific,
so per-function dispatch must pick the database matching the file's
language — pointing a Python query at a C++ database errors out and
the channel silently degrades. Single-database runs keep the historic
behaviour: the one database serves every file (the query menu already
selects language-appropriate queries, and a mismatched sweep degrades
per-call exactly as before).
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

#: File extension → CodeQL extractor language. Mirrors the alias set
#: the discovery side applies (packages/llm_analysis/
#: dataflow_validation.py) — CodeQL handles Kotlin via the Java
#: extractor and TypeScript via the JavaScript one.
CODEQL_EXT_LANGUAGE = {
    ".c": "cpp", ".h": "cpp", ".cc": "cpp", ".hh": "cpp",
    ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hxx": "cpp",
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".ts": "javascript", ".tsx": "javascript",
    ".java": "java", ".kt": "java", ".kts": "java",
    ".go": "go",
    ".rb": "ruby", ".erb": "ruby",
    ".cs": "csharp",
    ".swift": "swift",
}

#: Language-tag aliases → CodeQL canonical form.
_LANGUAGE_ALIASES = {
    "c": "cpp",
    "c++": "cpp",
    "c-cpp": "cpp",
    "ts": "javascript",
    "js": "javascript",
    "typescript": "javascript",
    "kotlin": "java",
    "py": "python",
}


def normalise_language(lang: str | None) -> str | None:
    """Map any language tag to the CodeQL canonical form, lowercase."""
    if not lang:
        return None
    s = str(lang).strip().lower()
    return _LANGUAGE_ALIASES.get(s, s) or None


def database_language(db_path: Path) -> str | None:
    """Read a database's language: ``codeql-database.yml``
    ``primaryLanguage`` first, the DatabaseManager dir-name convention
    (``<lang>-db`` / ``codeql-db-<lang>`` / ``<lang>``) as fallback."""
    db_path = Path(db_path)
    marker = db_path / "codeql-database.yml"
    try:
        text = marker.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        text = ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("primaryLanguage:"):
            value = line.split(":", 1)[1].strip().strip("\"'")
            lang = normalise_language(value)
            if lang:
                return lang
    name = db_path.name.lower()
    if name.endswith("-db"):
        name = name[:-3]
    elif name.startswith("codeql-db-"):
        name = name[len("codeql-db-"):]
    return normalise_language(name) if name else None


class CodeqlDbRouter:
    """Route a source file to the CodeQL database for its language.

    - No databases: ``for_file`` always returns None.
    - One database: wildcard — serves every file (historic behaviour).
    - Multiple databases: strict language match via the file's
      extension; no match returns None and the caller takes its
      existing no-database degradation path.
    """

    def __init__(self, paths) -> None:
        self.paths: list[str] = [str(p) for p in (paths or []) if p]
        self._by_lang: dict[str, str] = {}
        for p in self.paths:
            lang = database_language(Path(p))
            if lang is None:
                logger.warning(
                    "codeql db router: could not determine language of "
                    "%s — it will only serve files when it is the sole "
                    "database", p,
                )
                continue
            if lang in self._by_lang:
                logger.warning(
                    "codeql db router: duplicate database for %s "
                    "(keeping %s, ignoring %s)",
                    lang, self._by_lang[lang], p,
                )
                continue
            self._by_lang[lang] = p
        if len(self.paths) > 1:
            logger.info(
                "codeql db router: %d databases (%s)",
                len(self.paths),
                ", ".join(sorted(self._by_lang)) or "languages unknown",
            )

    @property
    def primary(self) -> str | None:
        """First database — for single-database consumers that cannot
        route per-file (the IRIS tool runner, capability flags)."""
        return self.paths[0] if self.paths else None

    def for_file(self, file_path: str | None) -> str | None:
        if not self.paths:
            return None
        if len(self.paths) == 1:
            return self.paths[0]
        if not file_path:
            return None
        lang = CODEQL_EXT_LANGUAGE.get(Path(file_path).suffix.lower())
        if lang is None:
            return None
        return self._by_lang.get(lang)
