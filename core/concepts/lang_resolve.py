"""Multi-language identifier/concept resolution for the study loop.

The reading-list study loop verifies external-contract assumptions a
review relied on ("Does ``json.loads`` reject NaN?") against the actual
source.  The C/C++ path lives in ``libexec/raptor-study-prep``; this
module is the equivalent resolution machinery for the other first-class
languages: Python, Go, Java, JavaScript/TypeScript, and Rust.

Two resolution modes, mirroring the C/C++ study-prep shapes:

- **identifier**: find the type/function/constant a question names,
  extract its definition and doc comment via the inventory extractor
  layer (tree-sitter when installed, AST/regex fallback otherwise),
  and emit :class:`~core.concepts.model.StudyItem` records that
  ``run_study`` consumes unchanged.
- **concept**: find module/package docs and README sections relevant
  to the question, emitted in the ``related_docs`` shape that
  ``run_study`` already loads as prompt context.

Honest boundaries: identifiers that cannot be statically resolved
(dynamic dispatch, monkey-patching, external dependencies) are returned
as *unresolved with a reason* — never guessed.  The study consumer marks
the originating reading-list item unresolvable rather than treating it
as resolved-clean.
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from core.inventory.extractors import (
    KIND_CLASS,
    KIND_FUNCTION,
    KIND_GLOBAL,
    KIND_MACRO,
    extract_items,
)
from core.inventory.languages import LANGUAGE_MAP

from .model import StudyItem

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Language support
# ------------------------------------------------------------------

#: Languages the study loop can resolve identifiers in (beyond C/C++).
#: Follows the inventory extractor layer: each of these has a wired
#: tree-sitter grammar branch plus an AST/regex fallback.
STUDY_LANGUAGES: frozenset[str] = frozenset({
    "python", "go", "java", "javascript", "typescript", "tsx", "rust",
})

#: File suffixes covered by :data:`STUDY_LANGUAGES`.
STUDY_SUFFIXES: frozenset[str] = frozenset(
    suffix for suffix, lang in LANGUAGE_MAP.items()
    if lang in STUDY_LANGUAGES
)

_C_SUFFIXES = frozenset(
    suffix for suffix, lang in LANGUAGE_MAP.items() if lang in ("c", "cpp")
)


def language_for_path(path: str | Path) -> str | None:
    """Study-resolvable language for *path*, or None.

    C/C++ returns None here — that path is handled by the dedicated
    study-prep machinery, not this module.
    """
    suffix = Path(path).suffix.lower()
    lang = LANGUAGE_MAP.get(suffix)
    return lang if lang in STUDY_LANGUAGES else None


def is_study_supported_path(path: str | Path) -> bool:
    """True when the study loop has ANY resolver for *path* (C/C++ or
    one of :data:`STUDY_LANGUAGES`)."""
    suffix = Path(path).suffix.lower()
    return suffix in _C_SUFFIXES or suffix in STUDY_SUFFIXES


# ------------------------------------------------------------------
# Result container
# ------------------------------------------------------------------

@dataclass
class LangResolution:
    """Outcome of a multi-language resolution pass."""

    items: list[StudyItem] = field(default_factory=list)
    #: ``[{"name", "reason", "language"}]`` — identifiers that could
    #: not be statically resolved.  The consumer marks the originating
    #: reading-list items unresolvable with the recorded reason.
    unresolved: list[dict] = field(default_factory=list)
    #: ``[{"file", "reason"}]`` — same shape study-prep writes; loaded
    #: by ``run_study`` as doc context.
    related_docs: list[dict] = field(default_factory=list)


# ------------------------------------------------------------------
# Identifier extraction from questions
# ------------------------------------------------------------------

_BACKTICK_RE = re.compile(r"`([A-Za-z_][\w.:]*)`")
_DOTTED_RE = re.compile(
    r"\b([A-Za-z_]\w*(?:(?:\.|::)[A-Za-z_]\w*)+)\b",
)
_BARE_RE = re.compile(
    r"\b([A-Za-z_]\w*_\w+|[A-Z][a-z]+[A-Z]\w*|[a-z]+[A-Z]\w*)\b",
)

_QUESTION_STOPWORDS = frozenset({
    # question scaffolding that survives the shape filters
    "does_not", "is_not", "non_zero", "so_called",
})


def extract_question_identifiers(
    question: str, context: str = "",
) -> list[str]:
    """Candidate identifiers named by a reading-list question.

    Order of preference: backtick-quoted names, dotted/qualified paths
    (``json.loads``, ``bytes::from``), then bare identifier-shaped
    tokens (snake_case, CamelCase, mixedCase).  Plain lowercase words
    are ignored — they are prose, not identifiers.
    """
    seen: set[str] = set()
    out: list[str] = []

    def _add(name: str) -> None:
        name = name.strip(".:")
        if not name or name.lower() in _QUESTION_STOPWORDS:
            return
        if name not in seen:
            seen.add(name)
            out.append(name)

    for text in (question, context):
        if not text:
            continue
        for m in _BACKTICK_RE.finditer(text):
            _add(m.group(1))
        for m in _DOTTED_RE.finditer(text):
            _add(m.group(1))
        for m in _BARE_RE.finditer(text):
            _add(m.group(1))
    return out


def identifier_tail(name: str) -> str:
    """Last path segment of a qualified identifier
    (``json.loads`` → ``loads``, ``Vec::new`` → ``new``)."""
    return re.split(r"\.|::", name)[-1]


# ------------------------------------------------------------------
# Source-tree walking
# ------------------------------------------------------------------

_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "vendor", "third_party",
    "third-party", "external", "dist", "__pycache__", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", "site-packages",
})


def has_study_sources(root: Path) -> bool:
    """True when *root* contains at least one non-C study-resolvable
    source file (vendor dirs excluded)."""
    return bool(_iter_source_files(Path(root), max_files=1))


def _iter_source_files(
    root: Path, *, max_files: int = 4000,
) -> list[Path]:
    """Supported-language source files under *root*, vendor dirs skipped."""
    out: list[Path] = []
    stack = [root]
    while stack and len(out) < max_files:
        d = stack.pop()
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        for entry in entries:
            if len(out) >= max_files:
                break
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir():
                    if entry.name not in _SKIP_DIRS and not entry.name.startswith("."):
                        stack.append(entry)
                    continue
                if entry.suffix.lower() in STUDY_SUFFIXES and entry.is_file():
                    out.append(entry)
            except OSError:
                continue
    return out


# ------------------------------------------------------------------
# Doc comments
# ------------------------------------------------------------------

_LINE_COMMENT = {
    "go": ("//",),
    "java": ("//",),
    "javascript": ("//",),
    "typescript": ("//",),
    "tsx": ("//",),
    "rust": ("///", "//!", "//"),
    "python": ("#",),
}

# Lines that sit between a doc comment and the definition and should be
# skipped while scanning upwards (annotations / attributes / decorators).
_ATTR_LINE = re.compile(r"^\s*(?:@\w|#\[|#!\[)")


def _doc_comment_above(
    lines: list[str], def_line: int, language: str,
) -> str:
    """Contiguous comment block immediately above *def_line* (1-based)."""
    prefixes = _LINE_COMMENT.get(language, ("//",))
    collected: list[str] = []
    i = def_line - 2  # index of the line above the definition
    # Skip attribute/annotation/decorator lines
    while i >= 0 and _ATTR_LINE.match(lines[i]):
        i -= 1
    # Block comment ending directly above (/** ... */ or /* ... */)
    if i >= 0 and lines[i].strip().endswith("*/"):
        block: list[str] = []
        while i >= 0:
            block.append(lines[i])
            if lines[i].lstrip().startswith(("/*", "/**")):
                break
            i -= 1
        block.reverse()
        text = "\n".join(
            ln.strip().lstrip("/*").rstrip("*/").lstrip("*").strip()
            for ln in block
        ).strip()
        return text[:1000]
    # Line-comment block
    while i >= 0:
        stripped = lines[i].strip()
        matched = next((p for p in prefixes if stripped.startswith(p)), None)
        if matched is None:
            break
        collected.append(stripped[len(matched):].strip())
        i -= 1
    collected.reverse()
    return "\n".join(collected).strip()[:1000]


def _python_docstrings(content: str) -> dict[tuple[str, int], str]:
    """Map ``(name, lineno)`` → docstring for defs/classes in *content*."""
    out: dict[tuple[str, int], str] = {}
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return out
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            doc = ast.get_docstring(node)
            if doc:
                out[(node.name, node.lineno)] = doc[:1000]
    return out


# ------------------------------------------------------------------
# Constant / definition regex fallback
# ------------------------------------------------------------------

def _const_pattern(language: str, name: str) -> re.Pattern | None:
    esc = re.escape(name)
    if language == "python":
        return re.compile(rf"^{esc}[ \t]*(?::[^=\n]+)?=[ \t]*\S", re.MULTILINE)
    if language == "go":
        return re.compile(
            rf"^[ \t]*(?:const|var)\s+(?:\([ \t]*)?{esc}\b|"
            rf"^[ \t]*{esc}[ \t]+[^=\n]*=",
            re.MULTILINE,
        )
    if language == "rust":
        return re.compile(
            rf"^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:const|static)\s+{esc}\b",
            re.MULTILINE,
        )
    if language == "java":
        return re.compile(
            rf"^[ \t]*(?:(?:public|private|protected|static|final)\s+)*"
            rf"final\s+\w[\w<>\[\], ]*\s+{esc}\s*=|"
            rf"^[ \t]*(?:(?:public|private|protected|final)\s+)*"
            rf"static\s+\w[\w<>\[\], ]*\s+{esc}\s*=",
            re.MULTILINE,
        )
    if language in ("javascript", "typescript", "tsx"):
        return re.compile(
            rf"^[ \t]*(?:export\s+)?(?:const|let|var)\s+{esc}\b",
            re.MULTILINE,
        )
    return None


# Type/class definitions — the inventory extractor emits functions and
# globals as items but records classes only as method metadata, so type
# lookups need their own pass.
def _type_pattern(language: str, name: str) -> re.Pattern | None:
    esc = re.escape(name)
    if language == "python":
        return re.compile(rf"^class\s+{esc}\b", re.MULTILINE)
    if language == "go":
        return re.compile(
            rf"^type\s+{esc}\s+(?:struct|interface)\b", re.MULTILINE,
        )
    if language == "rust":
        return re.compile(
            rf"^[ \t]*(?:pub(?:\([^)]*\))?\s+)?"
            rf"(?:struct|enum|trait|union|type)\s+{esc}\b",
            re.MULTILINE,
        )
    if language == "java":
        return re.compile(
            rf"^[ \t]*(?:(?:public|private|protected|abstract|final|static)\s+)*"
            rf"(?:class|interface|enum|record)\s+{esc}\b",
            re.MULTILINE,
        )
    if language in ("javascript", "typescript", "tsx"):
        return re.compile(
            rf"^[ \t]*(?:export\s+)?(?:abstract\s+)?"
            rf"(?:class|interface|enum|type)\s+{esc}\b",
            re.MULTILINE,
        )
    return None


def _slice_block(lines: list[str], start_line: int, *, max_lines: int = 60) -> str:
    """Definition text from *start_line* (1-based) to the end of its
    brace-balanced block (or dedent for Python), capped."""
    i = start_line - 1
    if i >= len(lines):
        return ""
    first = lines[i]
    indent = len(first) - len(first.lstrip())
    depth = 0
    seen_open = False
    end = min(len(lines), i + max_lines)
    j = i
    while j < end:
        line = lines[j]
        depth += line.count("{") - line.count("}")
        if "{" in line:
            seen_open = True
        if seen_open and depth <= 0:
            j += 1
            break
        if (
            not seen_open
            and j > i
            and line.strip()
            and (len(line) - len(line.lstrip())) <= indent
        ):
            break
        j += 1
    return "\n".join(lines[i:j])[:_MAX_DEFINITION_CHARS]


# Identifier appears as a dynamic attribute assignment — evidence of
# monkey-patching / prototype patching we refuse to "resolve".
def _dynamic_assignment_found(
    contents: dict[Path, tuple[str, str]], name: str,
) -> bool:
    tail = identifier_tail(name)
    pattern = re.compile(rf"[\w\)\]]\.{re.escape(tail)}\s*=[^=]")
    for lang, content in contents.values():
        if tail not in content:
            continue
        if lang == "python" and re.search(
            rf"\bsetattr\s*\([^,]+,\s*['\"]{re.escape(tail)}['\"]", content,
        ):
            return True
        if pattern.search(content):
            return True
    return False


# ------------------------------------------------------------------
# Kind mapping (mirror the C/C++ study-prep item shapes)
# ------------------------------------------------------------------

_KIND_MAP = {
    KIND_FUNCTION: "function",
    KIND_CLASS: "struct",
    KIND_GLOBAL: "macro",
    KIND_MACRO: "macro",
}

_CALL_RE = re.compile(r"\b([A-Za-z_]\w{2,})\s*\(")
_CALL_STOPWORDS = frozenset({
    "if", "for", "while", "switch", "return", "catch", "match",
    "assert", "print", "println", "printf", "len", "cap", "new",
    "make", "range", "defer", "func", "fn", "def", "lambda", "super",
    "self", "this", "typeof", "instanceof", "await", "async", "yield",
    "raise", "except", "elif", "else", "try", "with", "import",
})


def _extract_calls(definition: str) -> list[str]:
    calls: list[str] = []
    seen: set[str] = set()
    for m in _CALL_RE.finditer(definition):
        name = m.group(1)
        if name in _CALL_STOPWORDS or name in seen:
            continue
        seen.add(name)
        calls.append(name)
        if len(calls) >= 20:
            break
    return calls


# ------------------------------------------------------------------
# Identifier resolution
# ------------------------------------------------------------------

_MAX_MATCHES_PER_IDENT = 5
_MAX_DEFINITION_CHARS = 2400


def resolve_identifiers(
    source_root: Path,
    identifiers: list[str],
    *,
    scope: Path | None = None,
    max_files: int = 4000,
) -> LangResolution:
    """Resolve *identifiers* against non-C sources under *scope*
    (default: *source_root*).

    Returns study items for every definition found, plus an
    ``unresolved`` record (with reason) for each identifier that has no
    static definition in the scanned tree.
    """
    result = LangResolution()
    if not identifiers:
        return result

    root = Path(source_root)
    files = _iter_source_files(Path(scope) if scope else root, max_files=max_files)
    if not files:
        for name in identifiers:
            result.unresolved.append({
                "name": name,
                "language": "",
                "reason": "no study-resolvable source files in scope",
            })
        return result

    tails = {identifier_tail(n): n for n in identifiers}

    # Read + language-tag every candidate file once; grep-scope to
    # files that mention at least one identifier tail.
    contents: dict[Path, tuple[str, str]] = {}
    for f in files:
        lang = language_for_path(f)
        if lang is None:
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if any(tail in text for tail in tails):
            contents[f] = (lang, text)

    matched: dict[str, list[StudyItem]] = {}
    lang_seen: dict[str, str] = {}
    file_items: dict[Path, list] = {}

    for path, (lang, content) in sorted(contents.items()):
        rel = (
            str(path.relative_to(root))
            if path.is_relative_to(root) else str(path)
        )
        wanted_tails = [t for t in tails if t in content]
        if not wanted_tails:
            continue
        lines = content.splitlines()
        py_docs = _python_docstrings(content) if lang == "python" else {}

        try:
            code_items = extract_items(str(path), lang, content)
        except Exception:
            logger.debug("extract_items failed for %s", path, exc_info=True)
            code_items = []
        file_items[path] = code_items

        for ci in code_items:
            tail_hit = next(
                (t for t in wanted_tails if ci.name == t
                 or ci.name.endswith("." + t)),
                None,
            )
            if tail_hit is None:
                continue
            orig = tails[tail_hit]
            # Qualified questions (Foo.bar): require the match to live
            # in a namespace whose tail chain is consistent when we can
            # check it (class name from metadata).
            qualifier = None
            parts = re.split(r"\.|::", orig)
            if len(parts) >= 2:
                qualifier = parts[-2]
            meta = getattr(ci, "metadata", None)
            class_name = getattr(meta, "class_name", None) if meta else None
            if qualifier and class_name and qualifier != class_name:
                # e.g. question names json.loads; this is Foo.loads —
                # a different contract.  Skip rather than guess.
                continue
            lang_seen.setdefault(orig, lang)
            bucket = matched.setdefault(orig, [])
            if len(bucket) >= _MAX_MATCHES_PER_IDENT:
                continue

            start = max(1, ci.line_start or 1)
            end = ci.line_end or start
            definition = "\n".join(lines[start - 1:end])
            definition = definition[:_MAX_DEFINITION_CHARS]

            if lang == "python":
                doc = py_docs.get((ci.name, start), "")
                if not doc:
                    doc = _doc_comment_above(lines, start, lang)
            else:
                doc = _doc_comment_above(lines, start, lang)

            kind = _KIND_MAP.get(ci.kind, "function")
            from .receipts import detect_stale_doc
            item = StudyItem(
                id=f"{lang}_{ci.kind}_{ci.name}_{rel}_{start}".replace("/", "_"),
                kind=kind,
                name=ci.name,
                file=rel,
                line=start,
                definition=definition,
                doc_comment=doc,
                calls=_extract_calls(definition) if kind == "function" else [],
                relevance_tier=0,
                stale_doc=detect_stale_doc(doc, definition, ci.name, lang),
            )
            if class_name:
                item.related_items = [class_name]
            bucket.append(item)

    # Type + constant regex fallback for identifiers the extractors
    # missed (classes/structs are only method metadata in the
    # inventory layer; constants may be missed without tree-sitter).
    _FALLBACK_PASSES = (
        ("struct", _type_pattern),
        ("macro", _const_pattern),
    )
    for orig, tail in ((v, k) for k, v in tails.items()):
        if orig in matched:
            continue
        for kind, pattern_fn in _FALLBACK_PASSES:
            if orig in matched:
                break
            for path, (lang, content) in sorted(contents.items()):
                if tail not in content:
                    continue
                pat = pattern_fn(lang, tail)
                if pat is None:
                    continue
                m = pat.search(content)
                if not m:
                    continue
                lang_seen.setdefault(orig, lang)
                lines = content.splitlines()
                line_no = content.count("\n", 0, m.start()) + 1
                # ^[ \t]* anchors keep the match on one line, but a
                # match can still start at the newline of line N-1
                # when the pattern begins with the anchor itself.
                while line_no <= len(lines) and tail not in lines[line_no - 1]:
                    line_no += 1
                rel = (
                    str(path.relative_to(root))
                    if path.is_relative_to(root) else str(path)
                )
                doc = _doc_comment_above(lines, line_no, lang)
                if lang == "python" and not doc:
                    doc = _python_docstrings(content).get(
                        (tail, line_no), "",
                    )
                from .receipts import detect_stale_doc
                snippet = _slice_block(lines, line_no)
                matched[orig] = [StudyItem(
                    id=(
                        f"{lang}_{kind}_{tail}_{rel}_{line_no}"
                    ).replace("/", "_"),
                    kind=kind,
                    name=tail,
                    file=rel,
                    line=line_no,
                    definition=snippet,
                    doc_comment=doc,
                    relevance_tier=0,
                    stale_doc=detect_stale_doc(doc, snippet, tail, lang),
                )]
                break

    # Callers among resolved items: reverse map over scanned contents
    resolved_names = {
        it.name for bucket in matched.values() for it in bucket
    }
    if resolved_names:
        caller_map: dict[str, list[str]] = {}
        for _path, (lang, content) in contents.items():
            fn_items = [
                ci for ci in file_items.get(_path, [])
                if ci.kind == KIND_FUNCTION
            ]
            lines = content.splitlines()
            for ci in fn_items:
                start = max(1, ci.line_start or 1)
                end = ci.line_end or start
                body = "\n".join(lines[start - 1:end])
                for name in resolved_names:
                    if name != ci.name and re.search(
                        rf"\b{re.escape(name)}\s*\(", body,
                    ):
                        callers = caller_map.setdefault(name, [])
                        if ci.name not in callers and len(callers) < 10:
                            callers.append(ci.name)
        for bucket in matched.values():
            for it in bucket:
                it.callers = caller_map.get(it.name, [])

    for bucket in matched.values():
        result.items.extend(bucket)

    # Unresolved: honest reasons, never guesses
    for orig, tail in ((v, k) for k, v in tails.items()):
        if orig in matched:
            continue
        referenced = any(tail in c for _l, c in contents.values())
        if not referenced:
            reason = (
                "not found in the scanned source tree — likely an "
                "external dependency or training-knowledge contract"
            )
        elif _dynamic_assignment_found(contents, orig):
            reason = (
                "only dynamic attribute assignment found (monkey-"
                "patching / prototype patching) — cannot statically "
                "resolve"
            )
        else:
            reason = (
                "referenced in source but no static definition found "
                "(dynamic dispatch, re-export, or external dependency)"
            )
        result.unresolved.append({
            "name": orig,
            "language": lang_seen.get(orig, ""),
            "reason": reason,
        })

    return result


# ------------------------------------------------------------------
# Study-list merge (per-batch consumer dispatch)
# ------------------------------------------------------------------

def merge_into_study_list(
    study_list_path: Path,
    items: list[StudyItem],
    *,
    related_docs: list[dict] | None = None,
    unresolved: list[dict] | None = None,
) -> int:
    """Merge resolved items into an existing ``study-list.json``.

    Used by the study consumer to add per-batch multi-language
    resolutions after study-prep has already run.  Deduplicates on
    item id and on ``(name, file, line)``.  Returns the number of
    items actually added.  Creates a minimal skeleton when the file
    does not exist yet.
    """
    import json
    import os
    import tempfile
    from dataclasses import asdict

    path = Path(study_list_path)
    data: dict = {"target": "", "source_root": "", "items": []}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, json.JSONDecodeError):
            pass
    existing = data.setdefault("items", [])
    seen_ids = {i.get("id") for i in existing if isinstance(i, dict)}
    seen_keys = {
        (i.get("name"), i.get("file"), i.get("line"))
        for i in existing if isinstance(i, dict)
    }
    added = 0
    for item in items:
        key = (item.name, item.file, item.line)
        if item.id in seen_ids or key in seen_keys:
            continue
        existing.append(asdict(item))
        seen_ids.add(item.id)
        seen_keys.add(key)
        added += 1

    if related_docs:
        docs = data.setdefault("related_docs", [])
        doc_files = {d.get("file") for d in docs if isinstance(d, dict)}
        for d in related_docs:
            if d.get("file") not in doc_files:
                docs.append(d)
                doc_files.add(d.get("file"))

    if unresolved:
        recs = data.setdefault("unresolved_identifiers", [])
        rec_names = {r.get("name") for r in recs if isinstance(r, dict)}
        for r in unresolved:
            if r.get("name") not in rec_names:
                recs.append(r)
                rec_names.add(r.get("name"))

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), suffix=".tmp", prefix="study-list-",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        Path(tmp_name).rename(path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return added


# ------------------------------------------------------------------
# Concept resolution (docs / READMEs / module docs)
# ------------------------------------------------------------------

_DOC_SUFFIXES = frozenset((".md", ".rst", ".txt"))
_DOC_DIR_NAMES = ("doc", "docs", "documentation")
_STOP_KEYWORDS = frozenset({
    "does", "the", "that", "this", "with", "from", "when", "what",
    "how", "why", "are", "and", "for", "not", "can", "will", "should",
    "would", "into", "have", "has", "its", "any", "all",
})


def _concept_keywords(question: str) -> set[str]:
    words = re.findall(r"[A-Za-z_][\w.]{3,}", question)
    return {
        w.lower() for w in words if w.lower() not in _STOP_KEYWORDS
    }


def resolve_concept_docs(
    source_root: Path,
    questions: list[str],
    *,
    max_docs: int = 10,
) -> list[dict]:
    """Find README/module docs relevant to concept-resolution questions.

    Returns entries in the ``related_docs`` shape ``run_study`` loads:
    ``{"file": <path>, "reason": <one-liner>}``.
    """
    if not questions:
        return []
    root = Path(source_root)
    keywords: set[str] = set()
    for q in questions:
        keywords |= _concept_keywords(q)
    if not keywords:
        return []

    candidates: list[Path] = []
    try:
        for entry in sorted(root.iterdir()):
            if entry.is_file() and entry.suffix.lower() in _DOC_SUFFIXES:
                candidates.append(entry)
            elif (
                entry.is_dir()
                and entry.name.lower() in _DOC_DIR_NAMES
                and not entry.is_symlink()
            ):
                candidates.extend(
                    p for p in sorted(entry.rglob("*"))
                    if p.is_file() and p.suffix.lower() in _DOC_SUFFIXES
                )
    except OSError:
        return []

    results: list[dict] = []
    for doc in candidates:
        if len(results) >= max_docs:
            break
        try:
            snippet = doc.read_text(encoding="utf-8", errors="ignore")[:8192]
        except OSError:
            continue
        snippet_lower = snippet.lower()
        hits = [k for k in keywords if k in snippet_lower]
        if len(hits) >= 2 or (hits and doc.name.lower().startswith("readme")):
            results.append({
                "file": str(doc),
                "reason": f"mentions {', '.join(sorted(hits)[:4])}",
            })
    return results
