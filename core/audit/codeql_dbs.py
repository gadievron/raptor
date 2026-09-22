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
import threading
from collections import OrderedDict
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
    ".mts": "javascript", ".cts": "javascript",
    # .vue is honest here: the CodeQL JavaScript extractor declares
    # Vue.js single-file components as one of its own file types
    # (codeql-extractor.yml ``file_types``), so an SFC routes to the
    # same extractor — and database — as plain .js/.ts.
    ".vue": "javascript",
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


#: Source-archive membership indexes: ``src.zip`` path → (stat
#: signature, basename → archive entries). A database's archive is
#: read once per run in practice; the stat signature catches a
#: rebuilt archive. Bounded because an entry pins one archive's full
#: name list in memory.
_SRC_INDEX_MAX = 8
_SRC_INDEX_CACHE: OrderedDict[
    str, tuple[tuple[int, int], dict[str, tuple[str, ...]]],
] = OrderedDict()
_SRC_INDEX_LOCK = threading.Lock()

#: Entry-count cap for the membership pre-flight. Deliberately far
#: above core.zip's DEFAULT_MAX_ENTRIES (10k): a legitimate CodeQL
#: ``src.zip`` carries one entry per extracted source file (system
#: headers included) and big targets clear 10k easily. Construction-
#: time RSS stays bounded by the central-directory BYTE caps, which
#: keep their defaults.
_SRC_INDEX_MAX_ENTRIES = 500_000


def _src_zip_index(src_zip: Path) -> dict[str, tuple[str, ...]] | None:
    """``basename → archive entries`` for a database source archive,
    or None when membership cannot be established (missing,
    unreadable, or bomb-shaped archive)."""
    try:
        st = src_zip.stat()
    except OSError:
        return None
    sig = (st.st_mtime_ns, st.st_size)
    key = str(src_zip)
    with _SRC_INDEX_LOCK:
        cached = _SRC_INDEX_CACHE.get(key)
        if cached is not None and cached[0] == sig:
            _SRC_INDEX_CACHE.move_to_end(key)
            return cached[1]
    # Built outside the lock (archive IO); racing builders store
    # identical indexes and the last store wins.
    try:
        from core.zip import bomb_shaped_reason, peek_eocd
        summary = peek_eocd(src_zip)
        if summary is not None:
            reason = bomb_shaped_reason(
                summary, max_entries=_SRC_INDEX_MAX_ENTRIES,
            )
            if reason is not None:
                logger.debug(
                    "codeql src.zip membership: %s — %s", src_zip, reason,
                )
                return None
        import zipfile
        with zipfile.ZipFile(src_zip) as zf:
            names = zf.namelist()
    except Exception:  # noqa: BLE001 — unreadable archive ⇒ no index
        logger.debug(
            "codeql src.zip membership index failed for %s",
            src_zip, exc_info=True,
        )
        return None
    buckets: dict[str, list[str]] = {}
    for name in names:
        if not name or name.endswith("/"):
            continue
        buckets.setdefault(name.rsplit("/", 1)[-1], []).append(name)
    index = {base: tuple(entries) for base, entries in buckets.items()}
    with _SRC_INDEX_LOCK:
        _SRC_INDEX_CACHE[key] = (sig, index)
        _SRC_INDEX_CACHE.move_to_end(key)
        while len(_SRC_INDEX_CACHE) > _SRC_INDEX_MAX:
            _SRC_INDEX_CACHE.popitem(last=False)
    return index


def db_contains_source(
    db_path: str | Path, file_path: str,
) -> bool | None:
    """Whether the database's source archive ingested ``file_path``.

    Tri-state: True (present in ``src.zip``'s name list), False
    (provably absent — the extractor never saw the file, so no query
    on this database can return a row for it), None (unknown — no,
    unreadable, or bomb-shaped archive). Trade-off, stated for
    callers: None fails OPEN to the pre-gate behaviour, because an
    unreadable archive must not kill the channel for every file; the
    price is that vacuous zero-row runs keep classifying as they did
    before in that degraded case.

    Matching mirrors run_codeql_sweep's SARIF URI match (exact or
    ``/``-anchored suffix), so presence here and result attribution
    there agree. False-negative direction: an unrelated archive entry
    sharing the relative-path suffix reads as present — the dispatch
    proceeds and behaves exactly as without this gate.
    """
    if not file_path:
        return None
    index = _src_zip_index(Path(db_path) / "src.zip")
    if index is None:
        return None
    for entry in index.get(file_path.rsplit("/", 1)[-1], ()):
        if entry == file_path or entry.endswith("/" + file_path):
            return True
    return False


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
    - ``language_hint`` (a checklist/inventory language) fills in only
      for extensions the routing table cannot map.
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

    def for_file(
        self,
        file_path: str | None,
        language_hint: str | None = None,
    ) -> str | None:
        if not self.paths:
            return None
        if not file_path:
            # Callers that cannot route (no file in hand) keep the
            # sole database; with several there is nothing to pick.
            return self.paths[0] if len(self.paths) == 1 else None
        lang = CODEQL_EXT_LANGUAGE.get(Path(file_path).suffix.lower())
        if lang is None:
            # A known extension stays authoritative over any hint: the
            # table states how CodeQL's extractors ingest a suffix,
            # while a hint (inventory content-routing, checklist
            # metadata) is a heuristic one step removed. The hint only
            # fills the gap for suffixes the table cannot map — .inc
            # fragments the inventory content-routes to php/c/asm,
            # niche extensions.
            lang = normalise_language(language_hint)
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
