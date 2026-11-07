"""Bounded HTTP/1 CONNECT negotiation with an operator-selected upstream.

Target authorization and stream ownership belong to the caller. Only a
complete successful response head permits tunnel payload to be relayed.
No response text is copied into failure diagnostics.
"""

import asyncio

MAX_STATUS_BYTES = 4096
MAX_HEADER_LINE_BYTES = 4096
MAX_HEADER_BYTES = 16 * 1024
MAX_HEADERS = 100
_FIELD_TOKEN = frozenset(b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


class UpstreamConnectError(OSError):
    """An incomplete, malformed, rejected or over-budget response head."""


def _text_bytes_valid(value: bytes) -> bool:
    return all(byte == 9 or byte >= 32 and byte != 127 for byte in value)


async def _read_response_line(reader, limit: int) -> bytes:
    try:
        line = await reader.readuntil(b"\r\n")
    except asyncio.IncompleteReadError as exc:
        raise UpstreamConnectError("upstream response ended before header terminator") from exc
    except asyncio.LimitOverrunError as exc:
        raise UpstreamConnectError("upstream response line exceeds limit") from exc
    if len(line) > limit:
        raise UpstreamConnectError("upstream response line exceeds limit")
    return line[:-2]


def _check_status(line: bytes) -> None:
    parts = line.split(b" ", 2)
    if (len(parts) < 2 or parts[0] not in (b"HTTP/1.0", b"HTTP/1.1")
            or len(parts[1]) != 3 or not parts[1].isdigit()
            or not _text_bytes_valid(line)):
        raise UpstreamConnectError("malformed upstream status line")
    status = int(parts[1])
    if status != 200:
        raise UpstreamConnectError(f"upstream returned HTTP status {status}")


def _check_header(line: bytes) -> None:
    name, separator, value = line.partition(b":")
    if (not separator or not name or any(byte not in _FIELD_TOKEN for byte in name)
            or not _text_bytes_valid(value)):
        raise UpstreamConnectError("malformed upstream response header")


async def negotiate_connect(connect, host: str, port: int, timeout: float):
    """Connect, write and read one bounded response under one deadline.

    ``connect`` must register returned streams with the enclosing tunnel's
    owner before returning. Cancellation and every failure retain that
    caller-owned cleanup path. Ignore CONNECT response body-framing fields;
    bytes after the empty header line belong to the tunnel unchanged.
    """
    authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    request = (f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").encode("latin-1")
    phase = "proxy connect"
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await connect()
            phase = "CONNECT request"
            writer.write(request)
            await writer.drain()
            phase = "CONNECT status"
            _check_status(await _read_response_line(reader, MAX_STATUS_BYTES))
            phase = "header drain"
            count = size = 0
            while True:
                line = await _read_response_line(reader, MAX_HEADER_LINE_BYTES)
                if not line:
                    return reader, writer
                count += 1
                size += len(line) + 2
                if count > MAX_HEADERS or size > MAX_HEADER_BYTES:
                    raise UpstreamConnectError("upstream response header budget exceeded")
                _check_header(line)
    except UpstreamConnectError:
        raise
    except OSError as exc:
        raise UpstreamConnectError(f"upstream {phase}: {type(exc).__name__}") from exc
