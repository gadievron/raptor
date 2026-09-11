"""Transport-tolerant parsing of Joern ``MARKER:{json}`` record lines.

Joern queries emit one ``MARKER:{json}`` record per line, println'd for
the ``joern --script`` subprocess transport AND carried in the final
expression's string echo for the server transport (``/query-sync``
returns the final-expression echo but not println output).  The echo
framing varies by REPL version and string shape:

* multi-line strings echo triple-quoted: the FIRST line is prefixed
  ``val resN: String = \"\"\"`` (record content raw) and the LAST line
  carries a trailing ``\"\"\"``;
* short strings echo single-quoted on ONE line with Java-escaped
  content (``val resN: String = "MARKER:{\\"k\\":...}"``) — quotes
  escaped, embedded newlines rendered as ``\\n`` sequences;
* INTERMEDIATE binders echo too: a top-level
  ``val flowLines = ...`` statement echoes as
  ``val flowLines: List[String] = List(`` followed by one Java-escaped
  ``"MARKER:...",`` element per line (or the whole List inline for a
  single short element), closed by ``)`` framing lines;
* subprocess transcripts can carry BOTH the println copy and a value
  echo of the same records;
* ANSI colour codes may wrap any of it.

``startswith(marker)`` parsers missed the first echoed record and
raised "Extra data" on the last; this module is the one place that
knows the echo shapes, shared by every marker-record parser
(reachability gates, hunt call-site enumeration, the flow parser in
``packages.joern.runner``).
"""

from __future__ import annotations

import json
import re
from typing import Any

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Scala REPL value-echo prefix, anchored to the exact echo shape
# (binder ``resN``, declared type String, opening quote). Scanned-repo
# text inside a record payload can only reach echo handling when the
# record ALSO fails strict JSON parsing, which the emit-side jsonEsc
# discipline prevents for genuinely printed records.
_ECHO_PREFIX_RE = re.compile(r'\bval res\d+: String = "')

# List-binder value echo framing. An element line of a multi-line List
# echo is optional indentation followed by the element's OPENING quote
# (genuinely printed records start AT the marker, never behind a
# quote); the inline form starts with the binder declaration itself
# (``val flowLines: List[String] = List("...")``). Payload text inside
# a printed record cannot reach this branch without ALSO failing
# strict JSON parsing first, same as the resN prefix rule above.
_LIST_ECHO_LINE_RE = re.compile(r'^\s*"|^val \w+: \S+ = \w+\(')


def strip_ansi(text: str) -> str:
    """Remove ANSI colour codes."""
    return _ANSI_RE.sub("", text)


def _unescape_echo_body(body: str) -> str | None:
    """One unescape round of an echoed string-literal body.

    The echo body is Java-escaped — JSON string escaping is a
    compatible subset, so one loads round undoes it.  ``None`` when the
    body does not decode (width-truncated echo, dangling backslash).
    """
    try:
        text = json.loads('"' + body + '"')
    except ValueError:
        return None
    return text if isinstance(text, str) else None


def _marker_records_in_text(
    text: str, marker: str,
) -> tuple[list[Any], str | None]:
    """Strict-parse every marker record in already-unescaped text.

    Returns ``(records, error)``.  A marker-bearing segment that fails
    to parse (width-truncated echo interior) is a dropped record: on
    the server transport the echo is the ONLY carrier, so skipping it
    silently turned dropped records into healthy zeros.
    """
    records: list[Any] = []
    error: str | None = None
    for segment in text.splitlines():
        idx = segment.find(marker)
        if idx < 0:
            continue
        try:
            records.append(json.loads(segment[idx + len(marker):].strip()))
        except ValueError as exc:
            error = (
                f"unrecoverable {marker} echo record "
                f"{segment[idx:idx + 200]!r}: {exc}"
            )
    return records, error


def _recover_echo_records(
    plain_line: str,
    marker_idx: int,
    marker: str,
) -> tuple[list[Any], str | None] | None:
    """Recover records from a single-line Java-escaped value echo.

    Returns ``None`` when the line is not echo-shaped (no
    ``val resN: String = "`` before the marker); otherwise
    ``(records, error)`` after one unescape round.  An echo body that
    carries the marker but stays undecodable (width-truncated echo,
    dangling backslash) is an ERROR: on the server transport the
    value echo is the ONLY carrier of the records — reading the
    failure as noise turned dropped records into healthy zeros, and
    consumers demoted findings on that phantom evidence.
    """
    m = _ECHO_PREFIX_RE.search(plain_line[:marker_idx])
    if m is None:
        return None
    interior = plain_line[m.end():].rstrip().rstrip('"')
    text = _unescape_echo_body(interior)
    if text is None:
        return [], (
            f"unrecoverable {marker} echo body {interior[:200]!r}"
        )
    return _marker_records_in_text(text, marker)


def _scan_string_literal_bodies(line: str) -> list[str]:
    """Bodies of double-quote-delimited literals in *line*, escape-aware.

    A backslash escapes the next character, so ``\\"`` inside a body
    never terminates it.  An unterminated trailing literal (a
    width-truncated echo) is returned as-is — its recovery attempt then
    fails, silently.
    """
    bodies: list[str] = []
    start: int | None = None
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if start is None:
            if ch == '"':
                start = i + 1
        elif ch == "\\":
            i += 1
        elif ch == '"':
            bodies.append(line[start:i])
            start = None
        i += 1
    if start is not None:
        bodies.append(line[start:])
    return bodies


def _recover_list_echo_records(
    plain_line: str,
    marker: str,
) -> tuple[list[Any], str | None] | None:
    """Recover records from a List-binder value echo line.

    Returns ``None`` when the line is not binder-echo shaped
    (:data:`_LIST_ECHO_LINE_RE`); otherwise ``(records, error)`` from
    every marker-bearing string literal on the line.  Recovery
    requires each literal body to survive one unescape round AND
    yield strictly-parsing marker JSON; a genuinely printed record
    carries raw quote delimiters and no binder framing, so it can
    never read as this shape.  A marker-bearing element body that
    stays undecodable (width-truncated echo element) is an ERROR —
    on the server transport the binder echo can be the only carrier,
    so a silently dropped element read as a healthy zero (see
    :func:`_recover_echo_records`).
    """
    if _LIST_ECHO_LINE_RE.match(plain_line) is None:
        return None
    records: list[Any] = []
    error: str | None = None
    for body in _scan_string_literal_bodies(plain_line):
        if marker not in body:
            continue
        text = _unescape_echo_body(body)
        if text is None:
            error = (
                f"unrecoverable {marker} echo element {body[:200]!r}"
            )
            continue
        recs, rec_error = _marker_records_in_text(text, marker)
        records.extend(recs)
        error = error or rec_error
    return records, error


def parse_marker_line(line: str, marker: str) -> tuple[list[Any], str | None]:
    """Parse one stdout line for *marker* records.

    Returns ``(records, error)``.  ``records`` is empty when the line
    carries no marker; ``error`` describes a marker record that was
    dropped — a genuinely printed record that failed to decode, OR an
    echo body/element that stayed unrecoverable (width truncation).
    Echo errors matter because the server transport carries records
    ONLY in the value echo — an unrecoverable echo is a dropped
    record there, not a re-print, and reading it as noise let
    healthy-looking zeros drive wrongful demotions.  On the
    subprocess transport a println copy of the same record usually
    survives elsewhere in the transcript; consumers that hold records
    should prefer them over the error (``_joern_find_callers`` only
    degrades when NO records decoded).
    """
    plain = strip_ansi(line)
    idx = plain.find(marker)
    if idx < 0:
        return [], None
    # A record payload always ends at '}' / ']' — trailing quotes are
    # REPL echo framing (the closing \"\"\" of a multi-line value echo).
    payload = plain[idx + len(marker):].strip().rstrip('"')
    try:
        return [json.loads(payload)], None
    except ValueError as exc:
        recovered = _recover_echo_records(plain, idx, marker)
        if recovered is None:
            recovered = _recover_list_echo_records(plain, marker)
        if recovered is not None:
            return recovered
        return [], f"unparseable {marker} payload {payload[:200]!r}: {exc}"


def parse_marker_records(
    raw_output: str,
    marker: str,
) -> tuple[list[Any], list[str]]:
    """Parse every *marker* record in *raw_output*, deduplicated.

    Dedup is by canonical JSON: a transcript carrying both the println
    copy and a recovered echo copy of the same record must yield it
    once.  Returns ``(records, errors)`` — errors only for genuinely
    printed records that failed to decode.
    """
    records: list[Any] = []
    errors: list[str] = []
    seen: set[str] = set()
    for line in (raw_output or "").splitlines():
        recs, err = parse_marker_line(line, marker)
        if err is not None:
            errors.append(err)
        for rec in recs:
            key = json.dumps(rec, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            records.append(rec)
    return records, errors


def extract_scalar_marker(raw_output: str, marker: str) -> str | None:
    """Last ``MARKER:<scalar>`` payload in *raw_output*, transport-
    tolerant.  For queries whose answer is a short non-JSON scalar
    (e.g. the guard summary ``guarded/total``) rather than one JSON
    record per line.

    Handles the same echo framings as :func:`parse_marker_line`: a
    bare println line (subprocess transport), a single-line value
    echo (``val resN: String = "MARKER:3/5"`` — trailing quote is
    framing), the first line of a triple-quoted multi-line echo, and
    ANSI wrapping.  Scalar payloads are escape-free by construction
    (the emitting queries interpolate only digits and ``/``), so the
    payload is cut at the first backslash — in a Java-escaped echo
    that is the start of an escape sequence, never scalar content.

    Returns ``None`` when no marker line is present — the caller
    must read that as "consultation degraded", never as a value.
    """
    found: str | None = None
    for line in (raw_output or "").splitlines():
        plain = strip_ansi(line)
        idx = plain.find(marker)
        if idx < 0:
            continue
        payload = plain[idx + len(marker):]
        payload = payload.split("\\", 1)[0].strip().rstrip('"').strip()
        if payload:
            found = payload
    return found
