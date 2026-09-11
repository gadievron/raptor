"""Joern helpers for `/understand --hunt` variant analysis.

Two entry points, both optional supplements to grep-based hunting:

* :func:`find_sink_callsites` (HUNT-2) — enumerate every call site of a
  sink via the CPG. Catches indirect calls, function-pointer dispatch,
  and vtable calls that grep misses. Results are shaped like grep hits
  (``file`` / ``line`` / ``code`` / ``caller``) so
  :func:`merge_matches` can union them with grep output, deduplicated
  by ``file:line``.

* :func:`classify_taint_batch` (HUNT-3) — mechanically pre-classify
  each match by asking whether data from the enclosing function's
  parameters reaches the sink call. ``joern_tainted: true`` maps to
  ``confirmed_tainted``; ``false`` maps to ``likely_tainted`` — NOT
  ``false_positive``, because Joern's inter-procedural depth is
  bounded. The LLM still makes the final call.

Opt-in — callers skip this entirely when Joern is not installed or no
CPG cache exists, falling back to grep-only hunting.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from core.analysis._joern_lines import parse_marker_line

logger = logging.getLogger(__name__)

# Import direction is packages → core elsewhere too (the runner itself
# imports core.analysis._joern_lines), so this cross-package import is
# cycle-free; the canonical Scala-side escape definition must come from
# its single authority rather than a drifting local copy.
from packages.joern.runner import SCALA_JSON_ESC_DEF, _escape_scala_string

_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_CALL_NAME_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")

_CALLER_MARKER = "JOERN_CALLER:"

# Same shape as packages/joern/queries/callers.sc, inlined so the sink
# name is substituted after identifier validation (no template file
# round-trip) and the marker parsing stays next to its producer.
# Every interpolated value (caller, file, code) routes through the
# canonical jsonEsc, so a filename containing a quote, newline, tab, or
# U+2028-class separator cannot break the JSON line or forge extra
# records. Dual transport: records are println'd (the subprocess
# transport sees stdout but not the final expression) AND carried in
# the final expression's string echo (the server's /query-sync returns
# the final-expression echo but not println output).
_CALLSITE_QUERY_TEMPLATE = (
    "import io.shiftleft.semanticcpg.language._\n\n"
    + SCALA_JSON_ESC_DEF
    + r'''
val callSites = cpg.call.name("__SINK__")
val callerLines = callSites.map { c =>
  val callerFn = jsonEsc(c.method.name)
  val callerFile = jsonEsc(c.method.filename)
  val line = c.lineNumber.getOrElse(0)
  // .take(200) on the RAW string BEFORE jsonEsc — escape-then-truncate
  // can bisect an injected \" and leave a dangling backslash.
  val code = jsonEsc(c.code.take(200))
  s"""JOERN_CALLER:{"caller":"$callerFn","file":"$callerFile","line":$line,"code":"$code"}"""
}.l
callerLines.foreach(println)
callerLines.mkString("\n")
'''
)


def _is_identifier(value: Any) -> bool:
    # fullmatch, not match — a $-anchored match() still admits a
    # trailing newline.
    return isinstance(value, str) and bool(_IDENTIFIER_RE.fullmatch(value))


def _first_call_name(text: Any) -> str | None:
    if not isinstance(text, str):
        return None
    m = _CALL_NAME_RE.search(text)
    return m.group(1) if m else None


def find_sink_callsites(
    sink_call: str,
    server: Any,
    *,
    timeout: int | None = None,
) -> list[dict[str, Any]]:
    """Enumerate call sites of *sink_call* from the CPG.

    *server* is a started :class:`packages.joern.server.JoernServer`
    with the target's CPG already imported. Returns grep-hit-shaped
    dicts: ``{"file", "line", "code", "caller", "source": "joern"}``,
    deduplicated by ``(file, line)``. Marker lines that fail to decode
    (other than REPL value echoes) are logged as warnings — the result
    shape has no slot for a failure counter, so the log is the record.
    """
    if not _is_identifier(sink_call):
        logger.warning(
            "find_sink_callsites: rejecting sink %r — fails identifier "
            "validation", str(sink_call)[:80],
        )
        return []

    # Identifier validation already excludes quotes/backslashes; the
    # escape is defence in depth for the Scala literal context.
    query = _CALLSITE_QUERY_TEMPLATE.replace(
        "__SINK__", _escape_scala_string(sink_call))
    def _run_query() -> Any:
        return server.query(
            query, timeout=timeout, validate=True, check_length=False,
        )

    try:
        # Restart-window retry when the server offers the public seam
        # (a JoernServer; thinner test doubles without it keep the
        # plain query): a query landing mid-restart otherwise silently
        # degrades this path to its grep fallback, losing the
        # indirect-call/vtable hits only Joern resolves.
        retry = getattr(server, "retry_once_after_restart", None)
        if callable(retry):
            result = retry(_run_query, max_wait_s=timeout)
        else:
            result = _run_query()
    except Exception:
        logger.debug(
            "find_sink_callsites query failed for %s", sink_call,
            exc_info=True,
        )
        return []

    if result.errors:
        logger.warning(
            "find_sink_callsites(%s) errors: %s", sink_call, result.errors,
        )

    matches: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    decode_failures = 0
    for raw_line in (result.raw_output or "").splitlines():
        # parse_marker_line owns the transport tolerance: ANSI strip,
        # echo-prefix unwrap, trailing echo-framing quotes.  Echo
        # discrimination is by the ``val resN: String = "`` prefix
        # shape, NOT by escaped quotes in the payload — genuinely
        # printed records deliberately CONTAIN ``\"`` (jsonEsc), so a
        # real parse failure on quote-bearing code must still surface.
        records, decode_error = parse_marker_line(raw_line, _CALLER_MARKER)
        if decode_error is not None:
            # A directly printed record that does not parse means a
            # call site is being dropped — say so instead of a
            # silent continue.
            decode_failures += 1
            logger.warning(
                "find_sink_callsites(%s): undecodable JOERN_CALLER "
                "line (call site dropped): %s", sink_call, decode_error,
            )
            continue
        for data in records:
            if not isinstance(data, dict):
                continue
            key = (data.get("file", ""), int(data.get("line") or 0))
            if key in seen:
                continue
            seen.add(key)
            matches.append({
                "file": data.get("file", ""),
                "line": int(data.get("line") or 0),
                "code": data.get("code", ""),
                "caller": data.get("caller", ""),
                "sink": sink_call,
                "source": "joern",
            })
    if decode_failures:
        logger.warning(
            "find_sink_callsites(%s): %d marker line(s) failed to "
            "decode — call sites were dropped", sink_call, decode_failures,
        )
    return matches


def merge_matches(
    grep_matches: list[dict[str, Any]],
    joern_matches: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Union grep and Joern hits, deduplicated by ``file:line``.

    Grep hits win on collision (they carry the operator's own
    annotations); every match present in the Joern set — whether it
    also came from grep or not — gains ``joern_callers_found: true``.
    """
    joern_keys = {
        (m.get("file", ""), int(m.get("line") or 0)) for m in joern_matches
    }
    merged: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for m in list(grep_matches) + list(joern_matches):
        key = (m.get("file", ""), int(m.get("line") or 0))
        if key in seen:
            continue
        seen.add(key)
        if key in joern_keys:
            m["joern_callers_found"] = True
        merged.append(m)
    return merged


def classify_taint_batch(
    matches: list[dict[str, Any]],
    server: Any,
    *,
    sink_call: str | None = None,
    timeout: int | None = None,
) -> list[dict[str, Any]]:
    """Pre-classify hunt matches with taint-existence verdicts.

    For each match, asks Joern whether data from the enclosing
    function's parameters reaches the sink call. The enclosing function
    comes from ``match["caller"]`` (or ``match["function"]``); the sink
    from ``match["sink"]``, the *sink_call* argument, or the call name
    parsed from ``match["code"]``.

    Annotates each resolvable match with ``joern_tainted: true/false``
    (unresolvable matches are left untouched). Queries are deduplicated
    per unique (caller, sink) pair; a query failure OR a server-degraded
    query (errors with no flows — ambiguous, see ``run_taint_query``'s
    ``errors_out`` contract) degrades that pair to unclassified rather
    than booking a false negative or aborting the batch.

    Uses the path query (``run_taint_query``) rather than the cheaper
    existence query: only the path query exposes ``errors_out``, and
    without it a restarting/timed-out server reads as ``joern_tainted:
    false`` — a verdict downstream consumers act on. Slightly heavier
    per unique pair; verdict-equivalent at the same bounded depth.

    Mutates and returns *matches*.
    """
    verdicts: dict[tuple[str, str], bool | None] = {}
    for match in matches:
        caller = match.get("caller") or match.get("function")
        sink = match.get("sink") or sink_call or _first_call_name(
            match.get("code"))
        if not _is_identifier(caller) or not _is_identifier(sink):
            continue
        key = (caller, sink)
        if key not in verdicts:
            query_errors: list = []
            try:
                flows = server.run_taint_query(
                    caller, sink, timeout=timeout,
                    errors_out=query_errors,
                ) or []
                if not flows and query_errors:
                    logger.warning(
                        "taint classification degraded for %s -> %s: %s",
                        caller, sink, query_errors,
                    )
                    verdicts[key] = None
                else:
                    verdicts[key] = bool(flows)
            except Exception:
                logger.debug(
                    "taint query failed for %s -> %s",
                    caller, sink, exc_info=True,
                )
                verdicts[key] = None
        if verdicts[key] is not None:
            match["joern_tainted"] = verdicts[key]
    return matches
