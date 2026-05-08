"""On-disk format + read/write for annotation markdown files.

Layout: ``<base_dir>/<source_path>.md`` mirrors the source tree.
For source file ``packages/foo/bar.py`` the annotation file is
``<base_dir>/packages/foo/bar.py.md``.

Format:

    # packages/foo/bar.py

    ## function_a
    <!-- meta: status=suspicious cwe=CWE-78 -->

    This function takes user input via ``sys.argv`` and passes it
    to ``os.system`` without sanitisation. Confirmed via:
      * semgrep rule ``raw-command`` matched at line 42

    ## function_b
    <!-- meta: status=clean -->

    Pure, no side effects.

The first ``# <source_file>`` heading is a label only — readers
ignore it. Each ``## <name>`` heading starts a new function
section; the immediately-following HTML comment carries metadata;
the rest until the next ``##`` (or EOF) is the prose body.

Atomic write: each save writes to a sibling tempfile and renames
into place. Concurrent writers may race the rename; last-writer-wins
is acceptable for the audit / annotation workflow (the operator
adding manual notes shouldn't conflict with an LLM run).
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Dict, List, Optional

from .models import Annotation

import logging

logger = logging.getLogger(__name__)


# Current on-disk format version. Bumped when the format changes in
# a way that older readers can't handle. The marker is emitted as the
# first line of every annotation file so that future readers can
# detect format drift and either upgrade-in-place or refuse to read.
#
# Versioning policy:
#   * v1 is the initial format (markdown with ``## function`` sections
#     and ``<!-- meta: ... -->`` HTML-comment frontmatter).
#   * Files without the marker are treated as v1 (legacy files written
#     before this commit; reader is permissive).
#   * Files with a marker > CURRENT_VERSION trigger a warning but the
#     reader still tries — better to surface a partial result than to
#     silently drop data.
CURRENT_VERSION = 1
_VERSION_MARKER_RE = re.compile(
    r"^<!--\s*annotations-version:\s*(\d+)\s*-->\s*$",
    re.MULTILINE,
)


# Allowed values for ``write_annotation(overwrite=...)``. ``all``
# matches the original behaviour. ``respect-manual`` refuses to
# overwrite an existing same-name annotation whose
# ``metadata.source == "human"`` — used by LLM-driven callers
# (``/agentic``, ``/understand`` post-processor) so a manual edit
# is never silently clobbered.
_OVERWRITE_MODES = ("all", "respect-manual")


# Section heading regex. ``## name`` at start-of-line. Name captures
# any non-newline up to end-of-line; we don't constrain to identifier
# chars because operators, templated symbols, and qualified names all
# need to be expressible.
_SECTION_HEADING_RE = re.compile(r"^##[ \t]+(.+?)\s*$", re.MULTILINE)

# Metadata HTML comment, anchored to immediately after a heading.
# Format: ``<!-- meta: key=value key2=value2 -->``. Values may
# contain spaces if quoted: ``key="value with spaces"``.
_META_RE = re.compile(
    r"^<!--\s*meta:\s*(.*?)\s*-->\s*$",
    re.MULTILINE,
)
_META_KV_RE = re.compile(
    # ``key="quoted value"`` or ``key=bareword`` (no spaces, no quotes)
    r'(\w[-\w]*)=(?:"([^"]*)"|(\S+))'
)


def _validate_source_path(source_file: str) -> None:
    """Reject paths that could escape ``base_dir`` via traversal.

    Defense-in-depth: even though callers pass repo-relative paths,
    a target-supplied identifier (e.g. a finding's ``file_path``
    attribute pulled from scanner output) could contain ``..`` or
    an absolute path. Refuse before any filesystem access.
    """
    if not source_file:
        raise ValueError("source_file must be non-empty")
    # Reject newlines / nulls / other control chars — would let an
    # attacker forge file headings or break path semantics.
    if any(c in source_file for c in "\n\r\x00"):
        raise ValueError(
            f"source_file may not contain newline / null characters: "
            f"{source_file!r}"
        )
    # Reject absolute paths and ``..`` segments in any component.
    p = Path(source_file)
    if p.is_absolute():
        raise ValueError(f"source_file must be relative: {source_file!r}")
    parts = p.parts
    if any(part == ".." for part in parts):
        raise ValueError(
            f"source_file may not contain '..' segments: {source_file!r}"
        )


def _validate_function_name(function: str) -> None:
    """Reject function names that would corrupt the on-disk format.

    Newlines / carriage returns let an attacker inject fake ``##``
    section headings on subsequent lines (the parser then reads them
    as separate functions). Reject before any rendering."""
    if not function:
        raise ValueError("function name must be non-empty")
    if any(c in function for c in "\n\r\x00"):
        raise ValueError(
            f"function name may not contain newline / null characters: "
            f"{function!r}"
        )


# Sequences that would corrupt the metadata HTML comment if present
# in a value. ``-->`` closes the comment early; ``<!--`` would open
# a nested comment that some parsers handle differently.
_FORBIDDEN_META_VALUE_SUBSTRINGS = ("-->", "<!--")


def _validate_metadata(metadata) -> None:
    """Reject metadata key/value pairs that would corrupt the
    HTML-comment frontmatter on disk."""
    if metadata is None:
        return
    for k, v in dict(metadata).items():
        if not isinstance(k, str) or not k:
            raise ValueError(f"metadata key must be a non-empty string: {k!r}")
        if any(c in k for c in "\n\r\x00=\"' "):
            raise ValueError(
                f"metadata key may not contain newline / quote / equals / "
                f"space characters: {k!r}"
            )
        v_str = str(v)
        if any(c in v_str for c in "\n\r\x00"):
            raise ValueError(
                f"metadata value for {k!r} may not contain newline / null "
                f"characters: {v_str!r}"
            )
        for forbidden in _FORBIDDEN_META_VALUE_SUBSTRINGS:
            if forbidden in v_str:
                raise ValueError(
                    f"metadata value for {k!r} may not contain {forbidden!r} "
                    f"(would corrupt the on-disk HTML-comment format): "
                    f"{v_str!r}"
                )


def annotation_path(base_dir: Path, source_file: str) -> Path:
    """Resolve the annotation .md path for one source file. Doesn't
    create the file; callers do."""
    _validate_source_path(source_file)
    return base_dir / (source_file + ".md")


def _parse_meta(comment_body: str) -> Dict[str, str]:
    """Parse ``key=value`` pairs from the inside of a meta comment.
    Quoted values keep spaces; bare values are whitespace-delimited."""
    out: Dict[str, str] = {}
    for m in _META_KV_RE.finditer(comment_body):
        key = m.group(1)
        value = m.group(2) if m.group(2) is not None else m.group(3)
        out[key] = value
    return out


def _format_meta(metadata: Dict[str, str]) -> str:
    """Render ``metadata`` back to the comment's body string. Keys
    sorted for stable output; values quoted only when they contain
    spaces or quotes."""
    parts: List[str] = []
    for k in sorted(metadata):
        v = str(metadata[k])
        if (" " in v) or ('"' in v) or v == "":
            v_escaped = v.replace('"', '\\"')
            parts.append(f'{k}="{v_escaped}"')
        else:
            parts.append(f"{k}={v}")
    return " ".join(parts)


def _split_sections(text: str) -> List[tuple[str, int, int]]:
    """Split a markdown body into ``(name, start_offset, end_offset)``
    triples, one per ``## name`` heading. Offsets are byte positions
    of the heading line (start) and start of next heading or EOF (end).
    """
    headings = list(_SECTION_HEADING_RE.finditer(text))
    out: List[tuple[str, int, int]] = []
    for i, m in enumerate(headings):
        name = m.group(1).strip()
        start = m.start()
        end = headings[i + 1].start() if i + 1 < len(headings) else len(text)
        out.append((name, start, end))
    return out


def _parse_section(
    text: str, name: str, start: int, end: int,
) -> tuple[Dict[str, str], str]:
    """Parse one section: returns (metadata, body)."""
    section = text[start:end]
    # Drop the heading line.
    nl = section.find("\n")
    if nl == -1:
        body = ""
        meta_search = ""
    else:
        rest = section[nl + 1:]
        meta_match = _META_RE.match(rest)
        if meta_match:
            meta_search = meta_match.group(1)
            body = rest[meta_match.end():]
        else:
            meta_search = ""
            body = rest
    return _parse_meta(meta_search), body.strip("\n")


def read_file_annotations(
    base_dir: Path, source_file: str,
) -> List[Annotation]:
    """Read all annotations for one source file. Returns an empty
    list if no annotation file exists for the source path."""
    path = annotation_path(base_dir, source_file)
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        # Corrupt or unreadable annotation file — return empty rather
        # than propagate. The caller can detect "no annotations" and
        # decide what to do; crashing the reader on a single bad file
        # would block iter_all_annotations across the whole tree.
        return []
    # Detect format version. Files without a marker are legacy v1 —
    # parse permissively. Files with a future version emit a warning
    # but still try (partial-results-better-than-nothing).
    version_match = _VERSION_MARKER_RE.search(text)
    if version_match:
        try:
            version = int(version_match.group(1))
        except ValueError:
            version = CURRENT_VERSION
        if version > CURRENT_VERSION:
            logger.warning(
                f"annotation file {path} declares version {version} "
                f"(reader supports up to {CURRENT_VERSION}); "
                f"attempting to parse anyway"
            )
    out: List[Annotation] = []
    for name, start, end in _split_sections(text):
        meta, body = _parse_section(text, name, start, end)
        out.append(Annotation(
            file=source_file,
            function=name,
            body=body,
            metadata=meta,
        ))
    return out


def read_annotation(
    base_dir: Path, source_file: str, function: str,
) -> Optional[Annotation]:
    """Read one specific annotation. Returns None if absent."""
    for ann in read_file_annotations(base_dir, source_file):
        if ann.function == function:
            return ann
    return None


def write_annotation(
    base_dir: Path, ann: Annotation,
    *, overwrite: str = "all",
) -> Optional[Path]:
    """Write or replace one function's annotation in its source
    file's annotation .md.

    Returns the path written, or ``None`` if the write was refused
    by the ``overwrite`` policy.

    ``overwrite``:
      * ``"all"`` (default) — always write, replacing any existing
        same-name annotation. Existing annotations for OTHER
        functions in the same file are still preserved.
      * ``"respect-manual"`` — if an existing same-name annotation
        carries ``metadata.source == "human"``, skip this write
        (return ``None``). LLM-driven callers should pass this so
        operator notes never get clobbered. LLM-over-LLM and
        write-when-no-prior-record proceed normally.

    Atomic via tempfile + rename — concurrent readers see either the
    pre-write or post-write content, never a partial rewrite.
    """
    if overwrite not in _OVERWRITE_MODES:
        raise ValueError(
            f"invalid overwrite mode {overwrite!r}; "
            f"expected one of {_OVERWRITE_MODES}"
        )
    _validate_function_name(ann.function)
    _validate_metadata(ann.metadata)

    if overwrite == "respect-manual":
        prior = read_annotation(base_dir, ann.file, ann.function)
        if prior is not None and prior.metadata.get("source") == "human":
            return None

    path = annotation_path(base_dir, ann.file)
    path.parent.mkdir(parents=True, exist_ok=True)

    existing = read_file_annotations(base_dir, ann.file)
    by_name = {a.function: a for a in existing}
    by_name[ann.function] = ann
    rendered = _render_file(ann.file, by_name.values())

    # Atomic write — tempfile in same directory so rename is on
    # the same filesystem (cross-fs rename isn't atomic).
    tmp = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8",
        dir=path.parent, prefix=".annotation-", suffix=".tmp",
        delete=False,
    )
    try:
        tmp.write(rendered)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp.close()
        os.replace(tmp.name, path)
    except Exception:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        raise
    return path


def remove_annotation(
    base_dir: Path, source_file: str, function: str,
) -> bool:
    """Remove one function's annotation. Returns True if a record was
    actually removed; False if the function had no annotation.

    Removes the file entirely when the last annotation is deleted —
    keeps the annotation tree from accumulating empty .md files.
    """
    existing = read_file_annotations(base_dir, source_file)
    if not any(a.function == function for a in existing):
        return False
    remaining = [a for a in existing if a.function != function]
    path = annotation_path(base_dir, source_file)
    if not remaining:
        try:
            path.unlink()
        except OSError:
            pass
        return True
    rendered = _render_file(source_file, remaining)
    tmp = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8",
        dir=path.parent, prefix=".annotation-", suffix=".tmp",
        delete=False,
    )
    try:
        tmp.write(rendered)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp.close()
        os.replace(tmp.name, path)
    except Exception:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        raise
    return True


def iter_all_annotations(base_dir: Path) -> Iterator[Annotation]:
    """Walk the annotation tree, yielding every annotation. Order is
    filesystem-dependent — callers needing deterministic order
    should collect into a list and sort."""
    if not base_dir.exists():
        return
    for md in base_dir.rglob("*.md"):
        # Recover the source path by stripping the .md suffix and
        # the base_dir prefix.
        try:
            rel = md.relative_to(base_dir)
        except ValueError:
            continue
        if rel.suffix != ".md":
            continue
        # rel.with_suffix("") drops the final .md, leaving e.g.
        # "packages/foo/bar.py" for "packages/foo/bar.py.md".
        source_file = str(rel.with_suffix(""))
        yield from read_file_annotations(base_dir, source_file)


def compute_function_hash(
    source_path: Path, start_line: int, end_line: int,
) -> str:
    """Compute a stable short hash of a function's source lines for
    staleness detection.

    Returns the first 12 hex chars of sha256 over the slice. 12 chars
    keeps the metadata line short while still being collision-resistant
    for the use case (a few thousand annotations per project).

    ``start_line`` and ``end_line`` are 1-indexed and inclusive on
    both ends. If the file is unreadable or the range is empty,
    returns ``""`` so callers can detect "no hash available" and
    skip the staleness check.

    Lines are read with ``errors="replace"`` so a stray non-UTF-8
    byte in source doesn't crash the hash computation — the hash
    is for change-detection, not cryptographic integrity.
    """
    if start_line <= 0 or end_line < start_line:
        return ""
    try:
        text = source_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    lines = text.splitlines()
    s = max(0, start_line - 1)
    e = min(len(lines), end_line)
    if s >= e:
        return ""
    snippet = "\n".join(lines[s:e])
    return hashlib.sha256(snippet.encode("utf-8")).hexdigest()[:12]


def _render_file(source_file: str, anns) -> str:
    """Render an annotation file from a sequence of Annotation
    objects. Sections are sorted by function name for stable output
    (diff-friendly under git)."""
    sorted_anns = sorted(anns, key=lambda a: a.function)
    lines: List[str] = []
    # Format version marker — first line. Reader uses this to detect
    # future format changes and warn rather than silently mis-parse.
    lines.append(f"<!-- annotations-version: {CURRENT_VERSION} -->")
    lines.append(f"# {source_file}")
    lines.append("")
    for ann in sorted_anns:
        lines.append(f"## {ann.function}")
        if ann.metadata:
            lines.append(f"<!-- meta: {_format_meta(dict(ann.metadata))} -->")
        if ann.body:
            lines.append("")
            lines.append(ann.body)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
