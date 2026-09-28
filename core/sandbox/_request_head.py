"""Pure CONNECT request-line parser — the egress proxy's byte-parsing core.

This is the ONLY code that interprets raw request-line bytes from a
sandboxed (hostile) client. It is a leaf module — stdlib plus the
non-printable scan from ``core.security.log_sanitisation`` — so it can
run inside the confined parser-jail child (``_parser_jail_child.py``)
and be imported directly by differential tests that compare the jailed
round-trip against this in-process reference.

The logic is the former inline parse from ``proxy._serve_tunnel``,
extracted verbatim: same latin-1 decode, same validation order, same
refusal reason strings, same per-case host/port attribution. Behaviour
here is CONTRACT — the proxy's audit events and error responses are
built from these results, and the differential tests pin old-vs-jailed
equivalence on exact field identity. Do not "fix" quirks (e.g.
``int()`` accepting unicode digits or underscores) without updating the
proxy's documented semantics and the tests together.
"""

from dataclasses import dataclass

from core.security.log_sanitisation import has_nonprintable

# Default request-line byte budget, matching the proxy's read cap: the
# proxy reads the line with max_len=4096 counted INCLUDING the CRLF
# terminator, so the line content handed here is at most 4094 bytes.
# Re-checked here as defence-in-depth (the jail frame cap is larger).
DEFAULT_MAX_LINE_LEN = 4096

# Method-census classification of the request line, for the proxy's
# requests_connect / requests_non_connect counters. Computed here —
# beside the split whose result it describes — because the proxy never
# sees the split parts: classifying in the parent would mean
# re-interpreting the hostile bytes in-process, which this module
# exists to prevent. Semantics mirror the proxy's historical inline
# counting exactly:
#   * "connect"     — structurally well-formed CONNECT line (3 parts,
#                     method CONNECT, HTTP/ version), regardless of
#                     whether the target later validates;
#   * "non_connect" — the line split to at least one part and the
#                     method is not CONNECT (a plain HTTP client
#                     pointed at the proxy);
#   * "neither"     — empty/whitespace-only or overlong lines, and
#                     malformed lines whose method IS CONNECT.
CENSUS_CONNECT = "connect"
CENSUS_NON_CONNECT = "non_connect"
CENSUS_NEITHER = "neither"
CENSUS_VALUES = frozenset({CENSUS_CONNECT, CENSUS_NON_CONNECT,
                           CENSUS_NEITHER})


@dataclass(frozen=True)
class ParsedRequestLine:
    """A validated CONNECT target: the only fields policy consumes.

    Method census: an accepted line is ``CENSUS_CONNECT`` by
    construction (only structurally well-formed CONNECT lines reach
    acceptance), so no census field is carried here.
    """

    host: str
    port: int


@dataclass(frozen=True)
class ParseRefusal:
    """A refused request line.

    ``reason`` is the audit-event reason string (contract — see module
    docstring). ``host``/``port`` carry the partial attribution the
    inline parse historically stamped onto the event for that refusal
    class: "non-numeric port" attributes the host; "port out of range"
    attributes host and the out-of-range port value; earlier refusals
    attribute neither.

    ``census`` is the method-census classification (see CENSUS_*): the
    proxy counts requests_connect / requests_non_connect from it, since
    only this parser sees the split method. Defaults to
    ``CENSUS_NEITHER`` so synthetic refusals built outside the parse
    (worker crash, protocol violation) never inflate either counter —
    their bytes were never honestly classified.
    """

    reason: str
    host: "str | None" = None
    port: "int | None" = None
    census: str = CENSUS_NEITHER


def parse_connect_request_line(
    raw: bytes, max_len: int = DEFAULT_MAX_LINE_LEN,
) -> "ParsedRequestLine | ParseRefusal":
    """Parse one raw CONNECT request line (CRLF already stripped).

    *raw* is the line content WITHOUT the trailing CRLF — exactly what
    the proxy's line reader hands over. *max_len* mirrors the reader's
    cap, which counts the CRLF, hence the ``+ 2`` below.
    """
    if len(raw) + 2 > max_len:
        # The reader refuses overlong lines before they get here; this
        # re-check keeps the parser safe standalone and mirrors the
        # reader's reason string.
        return ParseRefusal(reason="empty/overlong CONNECT line")
    # latin-1 never fails on bytes — every byte value maps to exactly
    # one code point, so the decode is a bijection and no hostile byte
    # sequence can crash it or alias another sequence.
    request_line = raw.decode("latin-1")

    parts = request_line.split()
    if len(parts) != 3 or parts[0] != "CONNECT" or not parts[2].startswith("HTTP/"):
        # Method census on the malformed branch, mirroring the former
        # inline counting: a non-CONNECT method is "non_connect"; a
        # garbled line whose method IS CONNECT (or an empty split) is
        # "neither".
        census = (CENSUS_NON_CONNECT if parts and parts[0] != "CONNECT"
                  else CENSUS_NEITHER)
        return ParseRefusal(reason=f"malformed: {request_line[:80]!r}",
                            census=census)

    target = parts[1]
    # Reject non-printable characters in the CONNECT target. ESC / CR /
    # NUL / C1 controls / Unicode line separators in the host field
    # would otherwise be echoed verbatim into the proxy's log output —
    # terminal escape injection. JSON logging is safe (json.dumps
    # escapes control chars); the human-readable logger lines are not.
    # Every refusal below is on a structurally well-formed CONNECT
    # line, so the census is "connect" — exactly the point where the
    # former inline parse counted requests_connect, BEFORE the target
    # validation.
    if has_nonprintable(target):
        return ParseRefusal(reason="non-printable characters in CONNECT target",
                            census=CENSUS_CONNECT)
    if ":" not in target:
        return ParseRefusal(reason="no port in target",
                            census=CENSUS_CONNECT)
    host, _, port_str = target.rpartition(":")
    # Strip IPv6 brackets if present: [::1]:443.
    # `str.strip("[]")` strips ANY leading/trailing `[` or `]`
    # regardless of pairing, so `]example.com[` would also collapse
    # to `example.com` — which doesn't match the IPv6-bracket
    # intent. Only strip when both bookends are present together.
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        port = int(port_str)
    except ValueError:
        return ParseRefusal(reason="non-numeric port", host=host,
                            census=CENSUS_CONNECT)
    if not (0 < port < 65536):
        return ParseRefusal(reason="port out of range", host=host, port=port,
                            census=CENSUS_CONNECT)
    return ParsedRequestLine(host=host, port=port)
