"""Language-aware CodeQL database routing.

A run may carry one database per language (multi-language targets;
``--codeql-db`` is repeatable). CodeQL queries are language-specific,
so per-function dispatch must pick the database matching the file's
language — pointing a Python query at a C++ database errors out and
the channel silently degrades. A single database whose language is
known serves only files of that language: dispatching a
foreign-language file at it makes every query either error or run
vacuously against a graph that cannot contain the file, and a
zero-row result then reads as refutation-grade silence. Only a
database whose language cannot be determined keeps the historic
serve-every-file behaviour (metadata-less stand-ins).
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

#: The real CodeQL extractor languages — the values a file extension
#: can route to. A database label outside this set (a dir-name
#: fallback artifact) is not a routable language claim.
_CODEQL_LANGUAGES = frozenset(CODEQL_EXT_LANGUAGE.values())

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
    - One database of KNOWN language: serves files of that language
      (and ``for_file(None)`` callers that cannot route); other files
      return None and the caller takes its existing no-database
      degradation path.
    - One database of UNKNOWN language: wildcard — serves every file
      (historic behaviour, kept for metadata-less stand-ins).
    - Multiple databases: strict language match via the file's
      extension; no match returns None.
    """

    def __init__(self, paths) -> None:
        self.paths: list[str] = [str(p) for p in (paths or []) if p]
        self._path_langs: list[str | None] = []
        self._by_lang: dict[str, str] = {}
        for p in self.paths:
            lang = database_language(Path(p))
            self._path_langs.append(lang)
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
        if not file_path:
            # Callers that cannot route (no file in hand) keep the
            # sole database; with several there is nothing to pick.
            return self.paths[0] if len(self.paths) == 1 else None
        lang = CODEQL_EXT_LANGUAGE.get(Path(file_path).suffix.lower())
        if len(self.paths) == 1:
            # Trade-off, both directions weighed: gating the sole
            # database on language match loses the old speculative
            # dispatch for extensions outside the routing table, but
            # those queries were unanswerable for the graph anyway —
            # they came back as errors or as zero rows that read like
            # refutation-grade silence downstream. Wildcard survives
            # only while the database's language is not a real CodeQL
            # extractor language (yml-less stand-ins, where the
            # dir-name fallback manufactures a label): there a match
            # is undecidable and lenient dispatch is the lesser harm.
            sole_lang = self._path_langs[0] if self._path_langs else None
            if sole_lang not in _CODEQL_LANGUAGES:
                return self.paths[0]
            return self.paths[0] if lang == sole_lang else None
        if lang is None:
            return None
        return self._by_lang.get(lang)
