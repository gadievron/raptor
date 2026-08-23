"""JSON utilities — load, save, and comment-stripping.

Centralises the json.loads(path.read_text()) and json.dump(f, indent=2)
patterns used across 60+ files, with consistent error handling and
serialization of Path/datetime objects.
"""

import json
import logging
import math
from datetime import datetime
from pathlib import Path
from typing import Any

from core.atomic_fs import write_text_atomically

logger = logging.getLogger(__name__)

try:
    import orjson as _orjson
except ImportError:
    _orjson = None


def _loads(
    text: str | bytes | bytearray,
    *,
    parse_constant=None,
    allow_non_finite: bool = False,
) -> Any:
    """Parse JSON text, using orjson when available for speed.

    KNOWN DIVERGENCE — big integers become floats on the orjson path.
    orjson parses integer literals outside ``[-2**63, 2**64 - 1]`` as
    lossy IEEE-754 floats where stdlib ``json`` returns exact
    arbitrary-precision ints (probed on orjson 3.11:
    ``18446744073709551619`` → ``1.8446744073709552e+19``). orjson
    raises nothing for these, so there is no rejection to intercept,
    and detecting the loss would need a digit pre-scan of every input
    or a post-parse tree walk — a tax on every call to guard a value
    class no RAPTOR artifact carries as identity (ids here are string
    hashes/UUIDs; numeric fields are line numbers, counts, scores,
    epoch-second timestamps — all far inside 64 bits). The divergence
    is therefore documented and pinned by regression test
    (``test_utils.TestOrjsonBigIntDivergence``) instead of guarded.

    Callers that DO need exact >64-bit integers must not go through
    this fast path — use stdlib ``json`` directly or the stdlib-only
    ``core.json.bounded`` helpers.
    """
    if _orjson is not None and not allow_non_finite:
        # Fast path. NOTE: silently coerces ints outside the 64-bit
        # range to float — see the docstring before routing any
        # big-int-identity data through here.
        return _orjson.loads(text)
    return json.loads(text, parse_constant=parse_constant)


class JsonBudgetExceededError(ValueError):
    """JSON input exceeds its byte budget.

    Raised (never returned) so an over-budget payload can't be
    mistaken for an empty-but-valid document. The message always
    names the observed size and the budget.

    Subclasses ``ValueError`` so call sites with an existing
    ``except ValueError`` / ``except json.JSONDecodeError``
    malformed-input path degrade the same way for over-budget input
    without new plumbing — while callers that want to report the
    refusal distinctly can catch the subclass. Defined here (not in
    ``core.json.bounded``, which re-exports it) so both the bounded
    helpers and :func:`loads` can raise it without an import cycle.
    """


def _orjson_default(obj: Any) -> Any:
    if isinstance(obj, Path):
        return str(obj)
    return str(obj)


def _reject_non_finite(token: str) -> Any:
    """`parse_constant` callback rejecting JSON5-ish ``NaN``/``Infinity``.

    Stdlib `json` accepts the literal tokens ``NaN``, ``Infinity``, and
    ``-Infinity`` by default — strictly an extension to RFC 8259, but
    enabled out of the box. Once those land in a Python float, every
    downstream `int(...)` / range check has to defend against
    ``OverflowError`` and ``ValueError`` (``int(float('inf'))`` raises
    ``OverflowError``; ``int(float('nan'))`` raises ``ValueError``;
    comparisons against NaN are silently False), and forgetting that
    branch leaks an unrelated exception type to a caller whose
    ``except (OSError, ValueError)`` doesn't cover it.

    Reject at parse time so corrupt or hostile config files surface
    as a clean ``json.JSONDecodeError`` (the existing handler) rather
    than as an arbitrary downstream crash.
    """
    msg = f"non-finite JSON constant rejected: {token}"
    raise ValueError(msg)


def load_json(
    path: str | Path,
    strict: bool = False,
    *,
    allow_non_finite: bool = False,
    max_bytes: int | None = None,
) -> Any | None:
    r"""Load a JSON file.

    Returns None if the file does not exist. If the file exists but is
    malformed or unreadable, behaviour depends on ``strict``:

    - strict=False (default): return None (for optional/best-effort files)
    - strict=True: raise the underlying exception (for required files)

    Reads with ``utf-8-sig`` to transparently handle UTF-8 BOM
    (`\ufeff` at the start of the file). Pre-fix utf-8 read passed
    the BOM straight to the JSON parser which rejected it with
    "Expecting value: line 1 column 1 (char 0)" — Windows-edited
    config files, files round-tripped through some text editors,
    and many JSON exports from Office tools all carry a BOM.
    `utf-8-sig` is a strict superset of `utf-8`: identical for
    BOM-less files, transparent for BOM-prefixed ones.

    ``allow_non_finite`` (keyword-only): opt in to accepting
    ``NaN``, ``Infinity``, ``-Infinity`` literals at parse time. Off by
    default — see ``_reject_non_finite`` for the threat model.
    Callers reading reports from upstream analysers that legitimately
    emit non-finite numeric scores (LLM confidence layers, certain
    fuzzers) opt in here so the parse doesn't reject the whole file
    on one NaN cell. Caller is then responsible for handling
    non-finite values downstream (treat-as-zero, skip, etc).

    ``max_bytes`` (keyword-only): byte budget for the file. The size
    is checked via ``stat()`` BEFORE any read, so an oversize file is
    rejected without ever being loaded into memory. An oversize file
    follows the malformed-file contract: ``strict=True`` raises
    ``ValueError``, ``strict=False`` warns and returns ``None``.
    ``None`` (the default) keeps the historical unbounded behaviour.
    Use a budget whenever the file lives somewhere another principal
    can influence (target repos, importable archives, shared tmp).

    Backend note: parsing prefers orjson when installed; integer
    literals outside ``[-2**63, 2**64 - 1]`` then come back as lossy
    floats instead of exact ints (see :func:`_loads`). Callers that
    consume >64-bit integers as identity must use the stdlib-only
    ``core.json.bounded`` helpers instead.
    """
    p = Path(path)
    if not p.exists():
        return None
    if max_bytes is not None:
        try:
            size = p.stat().st_size
        except OSError as e:
            if strict:
                raise
            logger.warning("load_json: failed to stat %s: %s", p, e)
            return None
        if size > max_bytes:
            msg = (
                f"file size {size} bytes exceeds max_bytes={max_bytes}: {p}"
            )
            if strict:
                raise ValueError(msg)
            logger.warning("load_json: refusing oversize file: %s", msg)
            return None
    parse_constant = None if allow_non_finite else _reject_non_finite
    if strict:
        return _loads(
            p.read_text(encoding="utf-8-sig"),
            parse_constant=parse_constant,
            allow_non_finite=allow_non_finite,
        )
    try:
        return _loads(
            p.read_text(encoding="utf-8-sig"),
            parse_constant=parse_constant,
            allow_non_finite=allow_non_finite,
        )
    except (json.JSONDecodeError, ValueError, OSError, RecursionError) as e:
        # Pre-fix this returned None silently. Operators investigating
        # "why is my config not loading" had no signal — the file
        # existed, the function returned None, downstream code
        # crashed on missing data without any breadcrumb pointing
        # at the parse failure. Log at warning so a developer
        # debugging "missing data" sees the JSON error and the file
        # path; not error so legitimate optional/best-effort callers
        # don't trigger alarm.
        #
        # RecursionError is included because deeply-nested JSON
        # (>~500 levels) blows the Python recursion limit during
        # json.loads — caller should see the same warn-and-None
        # path as a JSONDecodeError rather than an uncaught crash.
        logger.warning("load_json: failed to parse %s: %s", p, e)
        return None


def loads(
    data: str | bytes | bytearray,
    *,
    max_bytes: int | None = None,
    allow_non_finite: bool = False,
) -> Any:
    """Parse in-memory JSON text with an optional size gate.

    The string-level counterpart of :func:`load_json` for non-file
    sources — subprocess stdout, HTTP bodies, artifact lines — with
    the same backend (orjson when installed; see :func:`_loads` for
    the big-int divergence) and the same non-finite hardening.

    Strict contract: in-memory sources have no missing-file soft
    path, so every failure raises — ``JsonBudgetExceededError``
    (a ``ValueError`` subclass) when the input exceeds ``max_bytes``,
    ``json.JSONDecodeError`` / ``ValueError`` on malformed input or a
    rejected non-finite constant, ``RecursionError`` on pathological
    nesting. The budget gate runs BEFORE the parse: for ``bytes`` it
    is exact; for ``str`` it counts characters (a lower bound on the
    UTF-8 byte length — the string is already materialised, so the
    gate's job is bounding parse cost, which scales with length).

    A single leading UTF-8 BOM is stripped (both ``str`` and
    ``bytes``), mirroring ``load_json``'s ``utf-8-sig`` tolerance —
    the backends otherwise disagree on BOM-prefixed input. Bytes are
    expected to be UTF-8.
    """
    if max_bytes is not None and len(data) > max_bytes:
        unit = "bytes" if isinstance(data, (bytes, bytearray)) else "characters"
        msg = (
            f"JSON input is {len(data)} {unit} — exceeds the "
            f"{max_bytes}-byte budget; refusing to parse"
        )
        logger.warning("%s", msg)
        raise JsonBudgetExceededError(msg)
    if isinstance(data, (bytes, bytearray)):
        if data[:3] == b"\xef\xbb\xbf":
            data = data[3:]
    elif data[:1] == "\ufeff":
        data = data[1:]
    parse_constant = None if allow_non_finite else _reject_non_finite
    return _loads(
        data, parse_constant=parse_constant, allow_non_finite=allow_non_finite,
    )


def _strip_json_comments(text: str) -> str:
    r"""Strip ``//`` and ``#`` comments from JSON text, respecting strings.

    Handles full-line comments, inline trailing comments, and comment
    characters inside quoted strings (e.g. ``"url": "https://x.com"``
    or ``"color": "#fff"``).

    `in_string` state persists across line boundaries. Pre-fix the
    state was reset per line, so a multi-line string (legal in JSON5
    via `\\\n` line continuations and accepted by tolerant parsers
    like simdjson; common in human-edited config) lost track of the
    in-string context at line breaks. A `//` or `#` inside the
    spanning string was then incorrectly treated as a comment start
    and the rest of that line was stripped — corrupting the value.
    """
    result = []
    in_string = False  # persists across lines
    for line in text.split('\n'):
        i = 0
        while i < len(line):
            ch = line[i]
            if ch == '\\' and in_string:
                i += 2
                continue
            if ch == '"':
                in_string = not in_string
            elif not in_string:
                if ch == '/' and line[i:i + 2] == '//':
                    line = line[:i]
                    break
                if ch == '#':
                    line = line[:i]
                    break
            i += 1
        result.append(line)
    return '\n'.join(result)


def load_json_with_comments(path: str | Path) -> Any | None:
    """Load a JSON file that may contain ``//`` or ``#`` comments.

    Strips full-line and inline comments before parsing, while
    preserving comment characters inside quoted strings. Used for
    config files (e.g. ``tuning.json``, ``models.json``). Returns
    None on missing file or parse error.
    """
    p = Path(path)
    if not p.exists():
        return None
    try:
        # `utf-8-sig` for BOM tolerance — config files written /
        # round-tripped through Windows editors commonly carry a
        # leading `﻿` that vanilla utf-8 read passes through
        # to the JSON parser as an unexpected character.
        text = p.read_text(encoding="utf-8-sig")
        stripped = _strip_json_comments(text)
        if not stripped.strip():
            return None
        return _loads(stripped, parse_constant=_reject_non_finite)
    except (json.JSONDecodeError, ValueError, OSError, RecursionError) as e:
        logger.warning("load_json_with_comments: failed to parse %s: %s", p, e)
        return None


class _RaptorEncoder(json.JSONEncoder):
    """JSON encoder that handles Path and datetime objects."""

    def default(self, obj):
        if isinstance(obj, Path):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        # Fallback: stringify unknown types (matches the default=str pattern
        # used by several callers before centralisation)
        try:
            return super().default(obj)
        except TypeError:
            return str(obj)


def _reject_non_finite_floats(data: Any) -> None:
    """Raise ``ValueError`` if *data* contains a NaN/Infinity float.

    Parity guard for the orjson save path: the stdlib branch passes
    ``allow_nan=False`` so ``json.dumps`` raises on non-finite floats,
    but orjson has no equivalent strict knob — it silently serialises
    NaN/Infinity as ``null``. Whether a write raised or quietly
    corrupted a numeric field then depended on which JSON library
    happened to be installed. Pre-scan (iterative, so deep structures
    can't blow the recursion limit) and raise the same exception type
    with the stdlib's message so both paths behave identically.

    Values inside containers the encoder stringifies wholesale
    (arbitrary objects via ``default=``) are out of scope on both
    paths — the stdlib encoder never sees them as floats either.
    """
    stack = [data]
    while stack:
        obj = stack.pop()
        # bool is an int, never a float — no special-casing needed.
        if isinstance(obj, float):
            if not math.isfinite(obj):
                msg = (
                    "Out of range float values are not JSON compliant: "
                    f"{obj!r}"
                )
                raise ValueError(msg)
        elif isinstance(obj, dict):
            stack.extend(obj.keys())
            stack.extend(obj.values())
        elif isinstance(obj, (list, tuple, set, frozenset)):
            stack.extend(obj)


def dumps_canonical(data: Any) -> str:
    """Serialise *data* to the repo's canonical JSON byte form.

    THE ONLY ``dumps`` that MAC / hash / content-address call sites may
    use (enforced by ``.github/scripts/check_canonical_json.py``).
    Always stdlib ``json`` — never orjson, never configurable — with
    the exact option pin::

        json.dumps(data, sort_keys=True, separators=(",", ":"),
                   default=str)

    This byte-matches the review-journal MAC canonical form
    (``core/coverage/journal_mac.row_sha256``): key order and
    whitespace never vary, arbitrary objects stringify via
    ``default=str``, and non-ASCII escapes via the ``ensure_ascii``
    default. Tokens minted at version N are verified at version N+1,
    so this form is frozen FOREVER — byte drift here flips every
    previously-minted artifact to "tampered" and invalidates every
    digest-keyed cache built on it.

    Deliberately NOT pinned: ``allow_nan``. The stdlib default (emit
    the non-RFC ``NaN`` / ``Infinity`` tokens) is part of the frozen
    byte contract — journal-MAC rows minted over payloads containing
    a non-finite float must verify forever, so this helper must keep
    producing the same bytes for them. New callers should reject
    non-finite floats before canonicalising rather than rely on that
    token form.

    orjson is never eligible here: it emits raw UTF-8 where the
    stdlib escapes (``caf\\u00e9`` vs ``café``), refuses int keys and
    >64-bit ints the stdlib accepts, and has no custom-separator
    support — any of which silently forks the canonical bytes on
    hosts where orjson happens to be installed.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def dumps_display(
    data: Any,
    *,
    indent: int | None = 2,
    sort_keys: bool = False,
) -> str:
    """Serialise *data* for human / LLM eyes (terminal output, log
    lines, prompt embeds, LLM tool-return strings, report snippets).

    Display contract: the returned string is READ, never re-parsed
    programmatically, never hashed, never byte-compared. Callers that
    need stable bytes want :func:`dumps_canonical` (MAC/hash lanes) or
    :func:`save_json` (artifact files) instead. Because no consumer
    depends on exact bytes, this helper is free to use orjson when
    installed (measured 5-7x faster on pretty dumps of real RAPTOR
    artifacts) and to differ cosmetically between the two encoders
    (compact-mode separators, non-finite float rendering).

    ``ensure_ascii=False`` on the stdlib branch — prompts and reports
    should show readable UTF-8, not ``\\uXXXX`` escapes (orjson always
    emits raw UTF-8, so the branches agree).

    Path / datetime / arbitrary objects stringify via the same
    encoder hooks as :func:`save_json`. Inputs orjson cannot encode
    (int keys beyond ``OPT_NON_STR_KEYS``, ints outside 64 bits,
    structures past its depth limit) fall back to the stdlib branch
    rather than raising — a display helper must be total on anything
    the repo can throw at it.

    Args:
        indent: 2 (default, pretty) or ``None`` (single line) or any
            other stdlib indent. orjson only accelerates ``2``/``None``;
            other indents take the stdlib branch.
        sort_keys: sort object keys for stable-looking output
            (cosmetic only — never rely on the bytes).
    """
    if _orjson is not None and indent in (2, None):
        opt = _orjson.OPT_NON_STR_KEYS
        if indent == 2:
            opt |= _orjson.OPT_INDENT_2
        if sort_keys:
            opt |= _orjson.OPT_SORT_KEYS
        try:
            return _orjson.dumps(
                data, option=opt, default=_orjson_default,
            ).decode("utf-8")
        except TypeError:
            # orjson-only refusals (>64-bit ints, exotic keys, depth
            # limit) — the stdlib branch below handles them all.
            pass
    return json.dumps(
        data,
        indent=indent,
        sort_keys=sort_keys,
        ensure_ascii=False,
        cls=_RaptorEncoder,
    )


def save_json(path: str | Path, data: Any, mode: int | None = None) -> None:
    """Save data as pretty-printed JSON. Handles Path/datetime serialization.

    Non-finite floats (NaN, Infinity) raise ``ValueError`` on BOTH
    encoder paths: the stdlib branch via ``allow_nan=False``, the
    orjson branch via a pre-scan (orjson would otherwise silently
    write ``null``).

    Delegates to :func:`core.atomic_fs.write_text_atomically` — the shared
    primitive owns the tempfile + fsync + rename + parent-dir fsync dance,
    plus O_EXCL/O_NOFOLLOW tempfile hardening.

    Atomic write: threat models, checklists, run reports, project state —
    every JSON produced through this helper is an operator-facing artefact
    where a torn write (interrupt, power loss, sigkill) surfaces as
    "path exists but fails to parse" on the next read.

    Args:
        path: Destination file path. The parent directory is created if
              missing (by ``write_text_atomically``).
        data: Object to serialise. Path, datetime, and other non-JSON
              types are stringified via the encoder's default hook.
        mode: Optional POSIX file permission bits (e.g. 0o600). When set,
              the mode is installed on the tempfile before rename — no
              chmod-after-rename window.
    """
    if _orjson is not None:
        _reject_non_finite_floats(data)
        content = _orjson.dumps(
            data,
            option=_orjson.OPT_INDENT_2 | _orjson.OPT_NON_STR_KEYS,
            default=_orjson_default,
        ).decode("utf-8") + "\n"
    else:
        content = json.dumps(data, indent=2, cls=_RaptorEncoder, allow_nan=False) + "\n"
    write_text_atomically(path, content, mode=mode, tmp_prefix=".~savejson-")
