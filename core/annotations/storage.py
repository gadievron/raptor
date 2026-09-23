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
into place. Concurrent writers may race the rename; the file lock
around each read-modify-write cycle serialises them (two operators,
or an operator and a scripted pass, editing the same file's
annotations).
"""

from __future__ import annotations

import dataclasses
import os
import re
import unicodedata
from contextlib import contextmanager
from pathlib import Path

from core.atomic_fs import write_text_atomically

try:
    import fcntl  # POSIX
    _HAS_FCNTL = True
except ImportError:  # pragma: no cover — only triggers on Windows
    _HAS_FCNTL = False

import logging

from .models import Annotation
from .provenance import (
    CORROBORATION_ERA_START,
    CORROBORATION_KEY,
    CORROBORATION_PRE_ERA,
    ENV_MARKERS_KEY,
    IMPORTED,
    INTERACTIVE_TTY,
    LEGACY,
    LEGACY_PRE_ERA,
    NON_TTY,
    PARENTS_KEY,
    PROVENANCE_KEY,
    SID_KEY,
    SID_VALUES,
    STAMP_ERA_START,
    TTY_KEY,
    classify_provenance,
    valid_env_markers_value,
    valid_parents_value,
    valid_tty_value,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

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
# ``metadata.source == "human"`` — for scripted / non-interactive
# adds, so a manual note is never silently clobbered. (The one-time
# LLM annotation producers that used this are gone; the mode remains
# for any scripted caller.)
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
    # ``key="quoted value"`` or ``key=bareword`` (no spaces, no quotes).
    # Quoted values handle ``\"`` escapes so round-tripping values
    # containing double-quote characters works correctly.
    r'(\w[-\w]*)=(?:"((?:[^"\\]|\\.)*)"|(\S+))'
)


def _validate_source_path(source_file: str) -> None:
    """Reject paths that could escape ``base_dir`` via traversal.

    Defense-in-depth: even though callers pass repo-relative paths,
    a target-supplied identifier (e.g. a finding's ``file_path``
    attribute pulled from scanner output) could contain ``..`` or
    an absolute path. Refuse before any filesystem access.
    """
    if not source_file:
        msg = "source_file must be non-empty"
        raise ValueError(msg)
    # Reject newlines / nulls / other line-splice chars — would let
    # an attacker forge file headings or break path semantics. (The
    # splice set is defined just below; functions bind names at call
    # time, so the forward reference is fine.)
    if any(c in source_file for c in "\n" + _LINE_SPLICE_CHARS):
        msg = (
            f"source_file may not contain newline / null characters: "
            f"{source_file!r}"
        )
        raise ValueError(msg)
    # Reject absolute paths and ``..`` segments in any component.
    p = Path(source_file)
    if p.is_absolute():
        msg = f"source_file must be relative: {source_file!r}"
        raise ValueError(msg)
    parts = p.parts
    if any(part == ".." for part in parts):
        msg = f"source_file may not contain '..' segments: {source_file!r}"
        raise ValueError(msg)
    # Reject empty and '.' segments on the RAW string — Path()
    # normalises them away, but annotation_path builds the on-disk
    # name by string concatenation, so 'a/b/' writes '<base>/a/b/.md'
    # (a suffix-less hidden file every tree walker skips): the note
    # is written yet invisible to every cross-run reader.
    if any(seg in ("", ".") for seg in source_file.split("/")):
        msg = (
            f"source_file may not contain empty or '.' path segments "
            f"(trailing slash included): {source_file!r}"
        )
        raise ValueError(msg)


# Line-splice characters that the ``\n``-anchored forged-structure
# regexes (below) cannot see. re.MULTILINE anchors ``^`` only after
# ``\n``, but the on-disk bytes are read back with ``read_text()``'s
# universal-newline translation (``\r`` / ``\r\n`` become real ``\n``
# line breaks at parse time), and ``str.splitlines()``-based consumers
# additionally split on ``\v \f \x1c \x1d \x1e \x85 \u2028 \u2029``.
# Any of these smuggles a "line start" past validation and re-opens
# the section/metadata forgery primitive. In bodies, ``\r`` is
# normalised to ``\n`` by ``write_annotation`` (CRLF prose is
# legitimate operator input); everywhere else, and for the rest of
# the set — plus NUL — the characters have no legitimate use and are
# refused outright.
_LINE_SPLICE_CHARS = "\r\x00\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"

# Remaining C0 / C1 control characters (plus DEL) that carry no
# legitimate use in names, bodies, or metadata values but survive the
# line-splice checks above — ESC first among them: today's CLI sinks
# sanitise on render, but persisting terminal-control bytes makes
# every current and future display sink individually responsible for
# defanging them. Reject at write time instead. ``\t`` and ``\n``
# stay legal where each field's own rules allow them.
_CONTROL_CHARS_RE = re.compile(
    "[\x00-\x08\x0e-\x1f\x7f\x80-\x9f]"
)


def _reject_control_chars(text: str, what: str) -> None:
    m = _CONTROL_CHARS_RE.search(text)
    if m:
        msg = (
            f"{what} may not contain control characters "
            f"(found {m.group(0)!r})"
        )
        raise ValueError(msg)


def _validate_function_name(function: str) -> None:
    """Reject function names that would corrupt the on-disk format.

    Newlines / carriage returns let an attacker inject fake ``##``
    section headings on subsequent lines (the parser then reads them
    as separate functions). Reject before any rendering."""
    if not function:
        msg = "function name must be non-empty"
        raise ValueError(msg)
    if any(c in function for c in "\n" + _LINE_SPLICE_CHARS):
        msg = (
            f"function name may not contain newline / null / "
            f"line-separator characters: {function!r}"
        )
        raise ValueError(msg)
    if function != function.strip():
        # The heading parser strips the captured name, so an edge-
        # whitespace name ("victim ") would silently collide with the
        # stripped one on re-parse — two on-disk sections resolving to
        # the same function, letting a later rewrite replace the other
        # record (respect-manual bypass). Validated must equal parsed.
        msg = (
            f"function name may not have leading/trailing whitespace "
            f"(the parser strips it, so the name would not "
            f"round-trip): {function!r}"
        )
        raise ValueError(msg)
    _reject_control_chars(function, "function name")
    if unicodedata.normalize("NFC", function) != function:
        # A non-NFC name is byte-distinct from its visually identical
        # NFC twin: writing one beside the other creates duplicate
        # sections no operator can tell apart, and byte-exact joins
        # (respect-manual, replacement, lookups) silently miss the
        # twin. Source languages normalise identifiers (Python:
        # NFKC), so a legitimate non-NFC name does not occur; refuse
        # rather than silently rewrite the caller's key.
        msg = (
            f"function name must be Unicode NFC-normalised (a non-NFC "
            f"name would create a visually identical duplicate of its "
            f"NFC twin): {function!r}"
        )
        raise ValueError(msg)


# Sequences that would corrupt the metadata HTML comment if present
# in a value. ``-->`` closes the comment early; ``<!--`` would open
# a nested comment that some parsers handle differently.
_FORBIDDEN_META_VALUE_SUBSTRINGS = ("-->", "<!--")

# Bound metadata key + value length. Pre-cap an LLM emitter (or a
# malicious annotation-file edit) could attach a multi-MB metadata
# value — survives the newline/null/HTML-escape checks above but
# bloats the on-disk annotation file and slows every subsequent
# parse pass. Realistic legitimate metadata weighs <200 chars per
# value (status enum, line range, hash prefix, source attribution).
# 4 KiB per field is comfortable headroom.
_MAX_META_KEY_LEN = 256
_MAX_META_VALUE_LEN = 4096

# Bound the prose body too — the metadata cap's own rationale applies
# verbatim to the 1000x-larger sibling field (agent-tier CLI adds via
# --body-file are sanctioned writers, and 29 whole-tree reader sites
# materialise every body per pass). Trade-off both ways: higher and a
# single scripted add can bloat the tree every reader walks; lower
# and legitimate pasted evidence (long traces, tool transcripts) gets
# refused — realistic operator prose tops out well under 100 KiB, so
# 1 MiB is comfortable headroom while still bounding a hostile body
# to ~one page-cache blip.
_MAX_BODY_LEN = 1024 * 1024

# Read-side budget for one annotation file. The tolerant read path
# exists so one bad file can't take the whole-tree readers down, and
# an unbudgeted read_text() materialises whatever a planted file
# weighs. Trade-off both ways: lower and a legitimately large file
# (many sections near the body cap) fails its own rewrite — data
# lockout; higher and every reader pays more memory per planted file
# before the parse even starts. 32 MiB holds 30+ cap-sized bodies,
# far beyond any legitimate per-source-file annotation set.
_MAX_FILE_BYTES = 32 * 1024 * 1024


def _validate_metadata(metadata) -> None:
    """Reject metadata key/value pairs that would corrupt the
    HTML-comment frontmatter on disk, and reject enum-valued keys
    (``source``, ``provenance``, ``tty``) carrying values outside
    their enums — a typoed ``source=humman`` or a hand-rolled
    provenance stamp must fail the write, not silently skew every
    consumer that branches on the value."""
    if metadata is None:
        return
    for k, v in dict(metadata).items():
        if not isinstance(k, str) or not k:
            msg = f"metadata key must be a non-empty string: {k!r}"
            raise ValueError(msg)
        if len(k) > _MAX_META_KEY_LEN:
            msg = f"metadata key exceeds {_MAX_META_KEY_LEN} chars: {len(k)}"
            raise ValueError(msg)
        if not re.fullmatch(r'\w[-\w]*', k):
            msg = (
                f"metadata key may not contain newline / quote / equals / "
                f"space characters: {k!r}"
            )
            raise ValueError(msg)
        v_str = str(v)
        if len(v_str) > _MAX_META_VALUE_LEN:
            msg = (
                f"metadata value for {k!r} exceeds {_MAX_META_VALUE_LEN} "
                f"chars: {len(v_str)}"
            )
            raise ValueError(msg)
        if any(c in v_str for c in "\n\t" + _LINE_SPLICE_CHARS):
            msg = (
                f"metadata value for {k!r} may not contain newline / null "
                f"/ line-separator characters: {v_str!r}"
            )
            raise ValueError(msg)
        _reject_control_chars(v_str, f"metadata value for {k!r}")
        for forbidden in _FORBIDDEN_META_VALUE_SUBSTRINGS:
            if forbidden in v_str:
                msg = (
                    f"metadata value for {k!r} may not contain {forbidden!r} "
                    f"(would corrupt the on-disk HTML-comment format): "
                    f"{v_str!r}"
                )
                raise ValueError(msg)
        if k == "status" and v_str not in _VALID_ANNOTATION_STATUSES:
            msg = (
                f"invalid annotation status {v_str!r}; expected one of "
                f"{sorted(_VALID_ANNOTATION_STATUSES)}"
            )
            raise ValueError(msg)
        if k == "source" and v_str not in _VALID_ANNOTATION_SOURCES:
            msg = (
                f"invalid annotation source {v_str!r}; expected one of "
                f"{sorted(_VALID_ANNOTATION_SOURCES)}"
            )
            raise ValueError(msg)
        if k == PROVENANCE_KEY and v_str not in (
            INTERACTIVE_TTY, NON_TTY, IMPORTED, LEGACY_PRE_ERA,
        ):
            msg = (
                f"invalid provenance tag {v_str!r}; expected "
                f"{INTERACTIVE_TTY!r}, {NON_TTY!r}, {IMPORTED!r} or "
                f"{LEGACY_PRE_ERA!r}"
            )
            raise ValueError(msg)
        if k == TTY_KEY and not valid_tty_value(v_str):
            msg = (
                f"invalid tty stamp {v_str!r}; expected 'none' or a "
                f"comma-joined subset of stdin,stdout,stderr"
            )
            raise ValueError(msg)
        if k == SID_KEY and v_str not in SID_VALUES:
            msg = (
                f"invalid sid stamp {v_str!r}; expected one of "
                f"{SID_VALUES}"
            )
            raise ValueError(msg)
        if k == ENV_MARKERS_KEY and not valid_env_markers_value(v_str):
            msg = (
                f"invalid envm stamp {v_str!r}; expected 'none' or a "
                f"comma-joined subset of the known marker names"
            )
            raise ValueError(msg)
        if k == PARENTS_KEY and not valid_parents_value(v_str):
            msg = f"invalid parents stamp {v_str!r}"
            raise ValueError(msg)
        if k == CORROBORATION_KEY and v_str != CORROBORATION_PRE_ERA:
            msg = (
                f"invalid corroboration marker {v_str!r}; expected "
                f"{CORROBORATION_PRE_ERA!r}"
            )
            raise ValueError(msg)


# Reserved on-disk grammar inside a section body. A body line matching
# the section-heading pattern is parsed as a NEW section on the next
# read, and a meta comment line directly below it is parsed as that
# section's provenance — the annotation-forgery primitive:
#
#   raptor-annotate add f.py fn -m $'note\n## victim\n<!-- meta:
#   source=human provenance=interactive-tty -->'
#
# fabricates a human-graded section for `victim` through the
# sanctioned CLI, defeating the TTY provenance model (Reflexion veto,
# IRIS promotion both key on human-grade annotations). The write path
# must refuse such bodies; level-3+ headings (###) and indented text
# remain available for legitimate structured prose.
_BODY_FORGED_HEADING_RE = re.compile(r"^##[ \t]", re.MULTILINE)
_BODY_FORGED_META_RE = re.compile(
    r"^<!--\s*(?:meta:|annotations-version)", re.MULTILINE,
)

def _normalise_body_newlines(body: str) -> str:
    r"""Normalise ``\r\n`` / bare ``\r`` to ``\n``.

    ``read_text()`` performs exactly this translation when the file is
    parsed back, so normalising at write time makes the validated body
    identical to what every reader will see — a raw ``\r`` on disk
    would otherwise turn into a real line break that the ``\n``-anchored
    forged-structure regexes never inspected."""
    return body.replace("\r\n", "\n").replace("\r", "\n")


def _validate_body(body) -> None:
    """Reject annotation bodies that would forge on-disk structure.

    Multiline prose is legitimate and preserved; only lines that the
    reader would re-parse as a section heading (``## `` at line start)
    or as metadata/format-marker comments (``<!-- meta:`` /
    ``<!-- annotations-version``) are refused — plus the line-splice
    control characters (see ``_LINE_SPLICE_CHARS``) that would let
    body text open such a line invisibly to these ``\\n``-anchored
    checks."""
    if not body:
        return
    body_str = str(body)
    if len(body_str) > _MAX_BODY_LEN:
        msg = (
            f"annotation body exceeds {_MAX_BODY_LEN} chars: "
            f"{len(body_str)}"
        )
        raise ValueError(msg)
    bad = sorted({c for c in _LINE_SPLICE_CHARS if c in body_str})
    if bad:
        msg = (
            f"annotation body may not contain control / line-separator "
            f"characters {bad!r} — they can splice forged section or "
            f"metadata lines past validation (use plain '\\n' line "
            f"breaks)"
        )
        raise ValueError(msg)
    _reject_control_chars(body_str, "annotation body")
    if _BODY_FORGED_HEADING_RE.search(body_str):
        msg = (
            "annotation body may not contain a line starting with '## ' — "
            "it would be re-parsed as a new section heading on disk "
            "(use '###' or indent the line)"
        )
        raise ValueError(msg)
    if _BODY_FORGED_META_RE.search(body_str):
        msg = (
            "annotation body may not contain a '<!-- meta:' or "
            "'<!-- annotations-version' comment line — it would forge "
            "on-disk metadata"
        )
        raise ValueError(msg)


def annotation_path(base_dir: Path, source_file: str) -> Path:
    """Resolve the annotation .md path for one source file. Doesn't
    create the file; callers do.

    Beyond the lexical checks in ``_validate_source_path``, the final
    parent is resolve()-checked against ``base_dir`` — a symlinked
    intermediate directory inside the annotation tree could otherwise
    redirect reads/writes outside it even though every path component
    passed the lexical validation."""
    _validate_source_path(source_file)
    path = Path(base_dir) / (source_file + ".md")
    base_resolved = Path(base_dir).resolve()
    parent_resolved = path.parent.resolve()
    if not (
        parent_resolved == base_resolved
        or base_resolved in parent_resolved.parents
    ):
        msg = (
            f"annotation path escapes base dir: {source_file!r} "
            f"(resolved parent {parent_resolved} is not under "
            f"{base_resolved})"
        )
        raise ValueError(msg)
    return path


def _assert_parent_contained(base_dir: Path, path: Path) -> None:
    """Re-verify (post-mkdir, under the write lock) that ``path``'s
    parent still resolves inside ``base_dir``.

    ``annotation_path`` performs the same resolve check, but that is
    point-in-time: a same-privilege writer who swaps an intermediate
    directory for a symlink between the check and the rename would
    redirect the atomic write outside the base. Re-checking under the
    lock, after the parents exist, narrows the window to the
    lock-to-rename span. (The final component needs no follow-guard
    on write: ``os.replace`` replaces a symlink itself rather than
    following it. Reads lstat the final component separately.)"""
    base_resolved = Path(base_dir).resolve()
    parent_resolved = path.parent.resolve()
    if not (
        parent_resolved == base_resolved
        or base_resolved in parent_resolved.parents
    ):
        msg = (
            f"annotation path escaped base dir between check and "
            f"write: resolved parent {parent_resolved} is not under "
            f"{base_resolved}"
        )
        raise ValueError(msg)


def annotation_file_mtime(base_dir: Path, source_file: str) -> float | None:
    """The annotation .md file's mtime for one source file, or None
    when the file (or its path) doesn't resolve.

    This is the ``note_mtime`` input to
    :func:`core.annotations.provenance.is_human_grade` — the date
    fence on the legacy stamp-less grandfather clause. Kept here so
    every human-grade reader derives the timestamp the same way.
    """
    try:
        return annotation_path(Path(base_dir), source_file).stat().st_mtime
    except (OSError, ValueError):
        return None


@contextmanager
def _file_lock(path: Path):
    """Cross-process exclusive lock on the annotation file's read-
    modify-write window.

    Two operators (or a scripted pass + operator) writing to the same
    source file's annotations concurrently could otherwise lose data via
    last-writer-wins on the read-modify-write cycle: both read state
    A, both write back A+B1 / A+B2 → one of B1/B2 is dropped.

    The lock target is a sibling ``.lock`` file in the parent dir.
    Using a sibling rather than the .md itself avoids racing on the
    .md's existence (atomic writes replace it) and avoids leaving
    a lock fd on a file we just unlinked.

    On non-POSIX (Windows): no-op. The substrate's typical deployment
    is Linux/macOS dev or CI; Windows operators get last-writer-wins
    semantics — same as before this commit, no regression.
    """
    if not _HAS_FCNTL:
        yield
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    # Open with O_CREAT — creates if absent, doesn't truncate.
    # O_NOFOLLOW: the lock file has a predictable sibling name; a
    # symlink squatted there must fail loudly (ELOOP) rather than be
    # followed to an attacker-chosen target.
    # O_RDONLY: flock() needs no write permission, and the previous
    # O_WRONLY open crashed the write path with an unhandled
    # PermissionError whenever the existing lock file wasn't writable
    # by this caller — exactly the documented two-operator scenario,
    # where operator B meets operator A's lock file across UIDs.
    # Mode 0o666 (umask applies) for the same reason: a 0600 lock
    # would still deny B the read-open. The file is empty and carries
    # no content — it only serialises the RMW window — so the wide
    # mode grants nothing beyond the ability to take the lock, which
    # any same-tree writer legitimately needs.
    try:
        fd = os.open(
            str(lock_path),
            os.O_RDONLY | os.O_CREAT | os.O_NOFOLLOW,
            0o666,
        )
    except PermissionError as e:
        msg = (
            f"cannot open annotation lock file {lock_path} ({e}); "
            f"fix its permissions (it only serialises writers and "
            f"holds no content — safe to delete when no write is in "
            f"flight), then retry"
        )
        raise AnnotationFileError(msg) from e
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


# Who authored the annotation. ``human`` — operator via an
# interactive CLI (see ``provenance`` for how the claim is graded);
# ``agent`` — a non-interactive / agent-driven CLI invocation (the
# default when no fd is a TTY); ``llm`` — legacy pre-migration LLM
# annotations (new LLM verdicts go to the review journal instead).
_VALID_ANNOTATION_SOURCES = frozenset({"human", "llm", "agent"})

# The ``status`` enum: review verdicts plus the role markers the
# readers consume (sink / entry_point / trust_boundary — the set
# fail_open_roles._ROLE_ANNOTATION_STATUSES binds and IRIS spec
# promotion reads). Validated at write time like the other
# conventional enum keys (``source`` / the stamp) — its own
# rationale applies: a typoed ``status=cleaan`` silently skews every
# consumer that branches on the value. The CLI restricts --status to
# this same set; the library check closes the direct-API and --meta
# routes.
_VALID_ANNOTATION_STATUSES = frozenset({
    "clean", "suspicious", "finding", "dormant", "error",
    "sink", "entry_point", "trust_boundary",
})


def _parse_meta(comment_body: str) -> dict[str, str]:
    r"""Parse ``key=value`` pairs from the inside of a meta comment.
    Quoted values keep spaces; bare values are whitespace-delimited.
    Escaped double-quotes (``\"``) inside quoted values are unescaped.

    Amendment §6 (Phase 3.5): warn when ``source=`` carries a value
    outside the ``{human, llm, agent}`` enum. The read path stays
    permissive (legacy / hand-edited files must remain readable);
    the write path (``_validate_metadata``) rejects such values
    outright.
    """
    out: dict[str, str] = {}
    for m in _META_KV_RE.finditer(comment_body):
        key = m.group(1)
        value = m.group(2) if m.group(2) is not None else m.group(3)
        if m.group(2) is not None:
            value = value.replace('\\"', '"').replace('\\\\', '\\')
        out[key] = value
    src = out.get("source")
    if src is not None and src not in _VALID_ANNOTATION_SOURCES:
        logger.warning(
            "annotation metadata: unknown source=%r (expected one of %s) — "
            "consumers checking source=='human' will treat as non-human",
            src, sorted(_VALID_ANNOTATION_SOURCES),
        )
    return out


def _format_meta(metadata: dict[str, str]) -> str:
    """Render ``metadata`` back to the comment's body string. Keys
    sorted for stable output; values quoted when they contain ANY
    whitespace (matching the bare-value parser's \\S+ boundary —
    quoting only on spaces let a hand-edited quoted value containing
    a tab re-emit bare and silently truncate at the tab on the next
    parse), quote characters, or are empty."""
    parts: list[str] = []
    for k in sorted(metadata):
        v = str(metadata[k])
        if re.search(r"\s", v) or ('"' in v) or v == "":
            v_escaped = v.replace('\\', '\\\\').replace('"', '\\"')
            parts.append(f'{k}="{v_escaped}"')
        else:
            parts.append(f"{k}={v}")
    return " ".join(parts)


def _split_sections(text: str) -> list[tuple[str, int, int]]:
    """Split a markdown body into ``(name, start_offset, end_offset)``
    triples, one per ``## name`` heading. Offsets are ``str``
    code-point offsets (not byte positions) of the heading line
    (start) and start of next heading or EOF (end).
    """
    headings = list(_SECTION_HEADING_RE.finditer(text))
    out: list[tuple[str, int, int]] = []
    for i, m in enumerate(headings):
        name = m.group(1).strip()
        start = m.start()
        end = headings[i + 1].start() if i + 1 < len(headings) else len(text)
        out.append((name, start, end))
    return out


def _parse_section(
    text: str, _name: str, start: int, end: int,
) -> tuple[dict[str, str], str]:
    """Parse one section: returns (metadata, body)."""
    section = text[start:end]
    # Drop the heading line.
    nl = section.find("\n")
    if nl == -1:
        body = ""
        meta_search = ""
    else:
        rest = section[nl + 1:]
        # Bound the meta match to the FIRST line only: _META_RE's
        # trailing \s*$ is MULTILINE and would otherwise swallow a
        # following whitespace-only body line into the match,
        # dropping it from the body.
        line_end = rest.find("\n")
        head = rest if line_end == -1 else rest[:line_end]
        meta_match = _META_RE.match(head)
        if meta_match:
            meta_search = meta_match.group(1)
            body = "" if line_end == -1 else rest[line_end + 1:]
        else:
            meta_search = ""
            body = rest
    return _parse_meta(meta_search), body.strip("\n")


class AnnotationFileError(ValueError):
    """An existing annotation file could not be read faithfully
    (unreadable, undecodable, future-format, or unattributable
    zero-section content).

    Raised only by strict reads — the read-modify-write cycle inside
    ``write_annotation`` / ``remove_annotation``. A write path that
    treated such a file as empty would render only the new record and
    atomically replace the file, silently destroying every prior
    operator note; failing the write loudly leaves the original bytes
    untouched for the operator to inspect or repair. (Content outside
    ``##`` sections in an otherwise-parseable file is NOT an error:
    the writer round-trips it verbatim — see ``_FileState.extra``.)
    Subclasses ``ValueError`` so existing callers that surface
    write-validation errors report this one the same way."""


@dataclasses.dataclass(frozen=True)
class _FileState:
    """Everything a rewrite must faithfully re-render for one file.

    ``extra`` is the out-of-section content the section parser does
    not own: the preamble lines between the renderer's own header
    (version marker + ``# <label>`` line) and the first ``##``
    heading — operators hand-add file-level prose there, the format
    being advertised as operator-editable markdown. When no sections
    parse, the whole file is preamble. The writer preserves ``extra``
    verbatim (edge blank lines normalised) on every rewrite; a
    rewrite that dropped it would silently destroy operator notes.
    """

    exists: bool
    has_marker: bool
    extra: str
    annotations: list[Annotation]


def _preamble_extra(preamble: str, source_file: str) -> str:
    """The preamble lines the renderer does NOT own.

    The renderer's own header is exactly: the version-marker line,
    one ``# <source_file>`` label line, and blank separation. Those
    are dropped (matched at most once each, header-position only);
    every other line is preserved verbatim. Edge blank lines are
    trimmed — the renderer re-adds separation."""
    out: list[str] = []
    marker_seen = False
    label_seen = False
    for line in preamble.splitlines():
        stripped = line.strip()
        if not out:
            if not marker_seen and _VERSION_MARKER_RE.match(stripped):
                marker_seen = True
                continue
            if not label_seen and stripped == f"# {source_file}":
                label_seen = True
                continue
            if not stripped:
                continue
        out.append(line)
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out)


def _load_file_state(
    base_dir: Path, source_file: str, *, strict: bool = False,
) -> _FileState:
    """Load one annotation file's full rewrite state (out-of-section
    content + parsed sections). See :func:`read_file_annotations`
    for the strict/tolerant contract."""
    path = annotation_path(base_dir, source_file)
    if path.is_symlink():
        # The parent-containment resolve above never inspects the
        # final component, and read_text() would follow it anywhere —
        # a symlinked .md is not a file this writer produces, and
        # following it lets a planted link exfiltrate/parse any
        # reachable file's content into annotation surfaces.
        if strict:
            msg = (
                f"annotation file {path} is a symlink; refusing to "
                f"read or rewrite through it"
            )
            raise AnnotationFileError(msg)
        logger.warning(
            "annotation file %s is a symlink — skipping", path,
        )
        return _FileState(False, False, "", [])
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    if size > _MAX_FILE_BYTES:
        if strict:
            msg = (
                f"annotation file {path} is {size} bytes (budget "
                f"{_MAX_FILE_BYTES}); refusing to rewrite it — "
                f"inspect the file (the writer never produces this), "
                f"then retry"
            )
            raise AnnotationFileError(msg)
        logger.warning(
            "annotation file %s is %s bytes (budget %s) — skipping",
            path, size, _MAX_FILE_BYTES,
        )
        return _FileState(False, False, "", [])
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        # Genuinely absent — the legitimate new-file path.
        return _FileState(False, False, "", [])
    except (OSError, UnicodeDecodeError) as e:
        if strict:
            msg = (
                f"annotation file {path} is unreadable ({e}); refusing "
                f"to rewrite it — inspect or repair the file (it may "
                f"hold operator notes), then retry"
            )
            raise AnnotationFileError(msg) from e
        logger.warning(
            "annotation file %s unreadable (%s) — treating as empty",
            path, e,
        )
        return _FileState(False, False, "", [])
    # Detect format version. Files without a marker are legacy v1 —
    # parse permissively. Files with a future version emit a warning
    # but still try (partial-results-better-than-nothing). In strict
    # mode a future version refuses instead: rewriting it with this
    # version's renderer would destroy structure this parser cannot
    # see.
    version_match = _VERSION_MARKER_RE.search(text)
    if version_match:
        try:
            version = int(version_match.group(1))
        except ValueError:
            # Reachable despite the (\d+) capture: CPython caps
            # int(str) conversion length, so an absurdly long digit
            # run raises — treat it as the current version and let
            # the sections still parse.
            version = CURRENT_VERSION
        if version > CURRENT_VERSION:
            if strict:
                msg = (
                    f"annotation file {path} declares format version "
                    f"{version} (writer supports up to "
                    f"{CURRENT_VERSION}); refusing to rewrite it"
                )
                raise AnnotationFileError(msg)
            logger.warning(
                "annotation file %s declares version %s (reader supports up to %s); attempting to parse anyway", path, version, CURRENT_VERSION
            )
    sections = _split_sections(text)
    preamble = text[: sections[0][1]] if sections else text
    extra = _preamble_extra(preamble, source_file)
    has_marker = version_match is not None
    if strict and not sections and extra and not has_marker:
        # Zero sections AND no version marker: not a file this writer
        # produced (a rewrite always emits the marker, and preserved
        # preamble rides under it), so the content is unattributable
        # — truncated, or a foreign markdown file. Refuse rather than
        # guess; marker-bearing files round-trip their content as
        # preamble instead.
        msg = (
            f"annotation file {path} is non-empty but no ## sections "
            f"parse and no format marker is present (truncated or "
            f"foreign?); refusing to rewrite it — inspect or repair "
            f"the file, then retry"
        )
        raise AnnotationFileError(msg)
    out: list[Annotation] = []
    for name, start, end in sections:
        meta, body = _parse_section(text, name, start, end)
        out.append(Annotation(
            file=source_file,
            function=name,
            body=body,
            metadata=meta,
        ))
    return _FileState(True, has_marker, extra, out)


def read_file_annotations(
    base_dir: Path, source_file: str, *, strict: bool = False,
) -> list[Annotation]:
    """Read all annotations for one source file. Returns an empty
    list if no annotation file exists for the source path.

    ``strict=False`` (default, read-only consumers): a corrupt or
    unreadable file degrades to an empty result with a warning —
    crashing the reader on a single bad file would block
    ``iter_all_annotations`` across the whole tree.

    ``strict=True`` (the write paths' read-modify-write cycle):
    the same conditions raise :class:`AnnotationFileError` instead.
    Fail-closed rationale: the writer re-renders the whole file, so
    anything it cannot faithfully re-render — unreadable bytes, a
    future format version, or unattributable zero-section content —
    must refuse the rewrite. Out-of-section content in a parseable
    file is not an error: the writer preserves it verbatim (see
    ``_FileState.extra``).
    """
    return _load_file_state(base_dir, source_file, strict=strict).annotations


def read_annotation(
    base_dir: Path, source_file: str, function: str,
) -> Annotation | None:
    """Read one specific annotation. Returns None if absent."""
    for ann in read_file_annotations(base_dir, source_file):
        if ann.function == function:
            return ann
    return None


def _materialise_era_markers(
    ann: Annotation, file_mtime: float | None,
) -> Annotation:
    """Durably materialise a passing mtime-era fence on a carried-over
    section.

    Both grandfather fences in :mod:`core.annotations.provenance` key
    on the annotation FILE's mtime, and every write path re-renders
    the whole file — so one sibling add/rm/edit (or a fresh checkout)
    silently stripped human-grade authority from untouched pre-era
    notes. A rewrite is the last moment the fence input still exists;
    record its outcome as an explicit marker readers honour without
    an mtime:

      * a stamp-less ``source=human`` section in a file predating
        ``STAMP_ERA_START`` gets ``provenance=legacy-pre-era``;
      * an interactive-tty ``source=human`` section without
        corroboration facts in a file predating
        ``CORROBORATION_ERA_START`` gets ``corroboration=pre-era``.

    A failing fence materialises nothing — the note demotes exactly
    as it would have under the mtime rule (fail toward the lower
    tier, never grant)."""
    if file_mtime is None or ann.metadata.get("source") != "human":
        return ann
    tag = classify_provenance(ann.metadata)
    updates: dict[str, str] = {}
    if tag == LEGACY and file_mtime < STAMP_ERA_START:
        updates[PROVENANCE_KEY] = LEGACY_PRE_ERA
    elif (
        tag == INTERACTIVE_TTY
        and file_mtime < CORROBORATION_ERA_START
        and not any(
            k in ann.metadata
            for k in (SID_KEY, ENV_MARKERS_KEY, PARENTS_KEY,
                      CORROBORATION_KEY)
        )
    ):
        updates[CORROBORATION_KEY] = CORROBORATION_PRE_ERA
    if not updates:
        return ann
    return dataclasses.replace(
        ann, metadata={**dict(ann.metadata), **updates},
    )


def write_annotation(
    base_dir: Path, ann: Annotation,
    *, overwrite: str = "all",
) -> Path | None:
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
        (return ``None``). Scripted callers should pass this so
        operator notes never get clobbered. Overwriting non-human
        records and write-when-no-prior-record proceed normally.

    Atomic via tempfile + rename — concurrent readers see either the
    pre-write or post-write content, never a partial rewrite.

    Content outside ``##`` sections (hand-added file-level operator
    prose — the format is operator-editable markdown) is preserved
    verbatim across the rewrite; see ``_FileState.extra``.

    Raises :class:`AnnotationFileError` (a ``ValueError``) when an
    existing annotation file for ``ann.file`` cannot be read
    faithfully — the write is refused so the rewrite can't silently
    destroy the notes already on disk.
    """
    if overwrite not in _OVERWRITE_MODES:
        msg = (
            f"invalid overwrite mode {overwrite!r}; "
            f"expected one of {_OVERWRITE_MODES}"
        )
        raise ValueError(msg)
    _validate_function_name(ann.function)
    _validate_metadata(ann.metadata)
    if ann.body and "\r" in str(ann.body):
        # Normalise before validation so the forged-structure checks
        # inspect exactly the line structure the reader will parse
        # (see _normalise_body_newlines) — and so what lands on disk
        # round-trips byte-identically through read_text().
        ann = dataclasses.replace(
            ann, body=_normalise_body_newlines(str(ann.body)),
        )
    _validate_body(ann.body)

    path = annotation_path(base_dir, ann.file)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Cross-process lock around the read-modify-write cycle. Without
    # it, two concurrent writers could each load state A, then write
    # A+B1 and A+B2 — one B is dropped. The lock serialises them.
    with _file_lock(path):
        _assert_parent_contained(base_dir, path)
        # Strict read: an unreadable/corrupt existing file raises
        # AnnotationFileError here instead of reading as empty — the
        # render below would otherwise atomically replace the file
        # with just the new record, silently destroying every prior
        # note (respect-manual included: a prior human note it cannot
        # read is one it must not clobber).
        state = _load_file_state(base_dir, ann.file, strict=True)
        pre_mtime = annotation_file_mtime(base_dir, ann.file)
        existing = [
            _materialise_era_markers(a, pre_mtime)
            for a in state.annotations
        ]
        if overwrite == "respect-manual":
            # NFC-equivalent comparison: legacy on-disk sections may
            # predate the NFC validation, and a visually identical
            # twin of a human note is still the operator's record —
            # the protective gate must cover it. (Joins/replacement
            # stay byte-exact: silently merging pre-existing twins
            # would itself destroy one of them.)
            target = unicodedata.normalize("NFC", ann.function)
            prior = next(
                (
                    a for a in existing
                    if unicodedata.normalize("NFC", a.function) == target
                ),
                None,
            )
            if prior is not None and prior.metadata.get("source") == "human":
                return None

        by_name = {a.function: a for a in existing}
        by_name[ann.function] = ann
        rendered = _render_file(
            ann.file, by_name.values(), extra=state.extra,
        )

        # Atomic write: each save operation is a per-function annotation
        # an operator relies on; a torn write on interrupt would lose
        # the annotation with no recovery path. write_text_atomically
        # gives us tempfile+fsync+rename with a fully audited implementation.
        write_text_atomically(
            path, rendered, tmp_prefix=".annotation-",
        )
    return path


def remove_annotation(
    base_dir: Path, source_file: str, function: str,
) -> bool:
    """Remove one function's annotation. Returns True if a record was
    actually removed; False if the function had no annotation.

    Removes the file entirely when the last annotation is deleted —
    keeps the annotation tree from accumulating empty .md files —
    unless the file carries preserved out-of-section operator prose,
    which keeps the (section-less, marker-bearing) file alive.
    """
    path = annotation_path(base_dir, source_file)
    with _file_lock(path):
        _assert_parent_contained(base_dir, path)
        # Strict read — same fail-closed contract as write_annotation:
        # a corrupt file must not be re-rendered (or unlinked) from a
        # partial parse.
        state = _load_file_state(base_dir, source_file, strict=True)
        existing = state.annotations
        if not any(a.function == function for a in existing):
            return False
        pre_mtime = annotation_file_mtime(base_dir, source_file)
        remaining = [
            _materialise_era_markers(a, pre_mtime)
            for a in existing if a.function != function
        ]
        if not remaining and not state.extra:
            try:
                path.unlink()
            except OSError as e:
                # Swallowing this reported 'removed' while readers
                # still saw the note (e.g. read-only parent dir).
                msg = (
                    f"could not remove annotation file {path} ({e}); "
                    f"the annotation is still on disk"
                )
                raise AnnotationFileError(msg) from e
            return True
        # Preserved out-of-section prose keeps the file alive past
        # the last section's removal — unlinking would destroy it.
        rendered = _render_file(source_file, remaining, extra=state.extra)
        # Atomic write: same reasoning as write_annotation above — the
        # remove path also rewrites the on-disk file, and a torn write
        # would lose the survivor annotations.
        write_text_atomically(
            path, rendered, tmp_prefix=".annotation-",
        )
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
        try:
            anns = read_file_annotations(base_dir, source_file)
        except ValueError as e:
            # A directory entry whose recovered source path fails
            # validation (control characters, symlinked final
            # component, ...) is one bad file — the tolerant-walk
            # contract says it must not take the whole tree's
            # readers down with it. Same degrade-with-a-warning
            # semantics as an unreadable file.
            logger.warning(
                "skipping annotation file %r: %s", str(md), e,
            )
            continue
        yield from anns


def compute_function_hash(
    source_path: Path, start_line: int, end_line: int,
) -> str:
    """Compute a stable short hash of a function's source lines for
    staleness detection.

    Delegates to ``core.staleness.hash_span`` — the shared span-level
    hashing primitive.  This wrapper is kept for backward compatibility
    with callers that import from ``core.annotations.storage``.
    """
    from core.staleness import hash_span
    return hash_span(source_path, start_line, end_line)


def _render_file(source_file: str, anns, extra: str = "") -> str:
    """Render an annotation file from a sequence of Annotation
    objects. Sections are sorted by function name for stable output
    (diff-friendly under git). ``extra`` — preserved out-of-section
    content (see ``_FileState.extra``) — is re-emitted verbatim
    between the header and the first section."""
    sorted_anns = sorted(anns, key=lambda a: a.function)
    lines: list[str] = []
    # Format version marker — first line. Reader uses this to detect
    # future format changes and warn rather than silently mis-parse.
    lines.append(f"<!-- annotations-version: {CURRENT_VERSION} -->")
    lines.append(f"# {source_file}")
    lines.append("")
    if extra:
        lines.extend(extra.splitlines())
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
