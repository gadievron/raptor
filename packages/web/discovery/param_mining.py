"""Hidden-parameter mining via chunked differential probing.

The efficient way to discover undocumented parameters is not one
request per candidate name: send ~40 candidates per request with
benign values, compare against a baseline, and bisect any chunk that
changes the response until the responsive parameter(s) are isolated.
ffuf remains the raw-scale single-parameter fallback; this module is
the precision path, running through the scoped, rate-limited
WebClient so every probe inherits origin pinning, redaction, and the
execution-policy audit.

Honesty guard: two baselines are taken first. If the page is unstable
(the baselines disagree on status or length), differential mining
cannot distinguish signal from noise — the miner reports the target
unstable and returns nothing rather than minting phantom parameters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from core.logging import get_logger

if TYPE_CHECKING:
    from packages.web.client import WebClient

logger = get_logger()

# Small seed list of conventionally meaningful parameter names; an
# operator wordlist extends it. Deliberately compact — the point of
# chunking is that a real wordlist (hundreds of names) costs tens of
# requests, not hundreds.
DEFAULT_PARAM_SEEDS: tuple[str, ...] = (
    "id", "uid", "user", "user_id", "userid", "account", "email", "name",
    "q", "query", "search", "keyword", "filter", "sort", "order", "orderby",
    "page", "limit", "offset", "count", "per_page", "start", "end",
    "url", "uri", "next", "redirect", "redirect_uri", "return", "return_url",
    "callback", "continue", "dest", "destination", "target", "goto",
    "file", "path", "dir", "folder", "document", "template", "view", "include",
    "lang", "language", "locale", "country", "currency", "format", "type",
    "debug", "test", "admin", "mode", "action", "cmd", "command", "exec",
    "token", "key", "api_key", "apikey", "access", "auth", "session",
    "role", "level", "group", "priv", "privilege", "is_admin",
    "host", "ip", "server", "port", "domain", "site",
    "data", "input", "value", "content", "message", "text", "body",
    "preview", "draft", "version", "rev", "source", "ref", "referrer",
    "enable", "disable", "show", "hide", "expand", "raw", "json", "xml",
)

_CHUNK_SIZE = 40
_BENIGN_VALUE = "raptorparam1"


@dataclass
class ParamMiningResult:
    """Outcome of one mining pass against one URL."""

    url: str
    discovered: list[str] = field(default_factory=list)
    requests_used: int = 0
    stable: bool = True
    exhausted_budget: bool = False


class _ResponseShape:
    """Comparable summary of a response for the differential."""

    __slots__ = ("status", "length")

    def __init__(self, response: Any) -> None:
        self.status = getattr(response, "status_code", None)
        self.length = len(getattr(response, "content", b"") or b"")

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, _ResponseShape)
            and self.status == other.status
            and self.length == other.length
        )

    def __repr__(self) -> str:
        return f"HTTP {self.status}/{self.length}b"


def mine_parameters(
    client: WebClient,
    url: str,
    *,
    candidates: tuple[str, ...] | None = None,
    known: set[str] | None = None,
    max_requests: int = 60,
    chunk_size: int = _CHUNK_SIZE,
) -> ParamMiningResult:
    """Discover hidden parameters on *url* by chunked differential probing.

    Args:
        client: The scan's WebClient (scope, rate limit, redaction
            inherited — no new network paths).
        url: Target URL; existing query parameters are preserved.
        candidates: Names to probe (defaults to the built-in seeds).
        known: Names already known for this URL — excluded up front.
        max_requests: Hard request budget for the whole pass.
        chunk_size: Candidates carried per probe request.
    """
    result = ParamMiningResult(url=url)
    names = [
        name for name in (candidates or DEFAULT_PARAM_SEEDS)
        if name not in (known or set())
    ]
    if not names:
        return result

    def probe(params: dict[str, str]) -> _ResponseShape | None:
        if result.requests_used >= max_requests:
            result.exhausted_budget = True
            return None
        result.requests_used += 1
        try:
            return _ResponseShape(client.get(url, params=params))
        except Exception:
            logger.debug("param-mining probe failed", exc_info=True)
            return None

    # Stability gate: two baselines with only a nonsense parameter.
    base_a = probe({"raptornosuchparam": _BENIGN_VALUE})
    base_b = probe({"raptornosuchparam": _BENIGN_VALUE})
    if base_a is None or base_b is None or base_a != base_b:
        result.stable = False
        logger.info(
            "param mining: target unstable (%r vs %r) — refusing to mine noise",
            base_a, base_b,
        )
        return result
    baseline = base_a

    def bisect(chunk: list[str]) -> None:
        shape = probe({name: _BENIGN_VALUE for name in chunk})
        if shape is None or shape == baseline:
            return
        if len(chunk) == 1:
            result.discovered.append(chunk[0])
            return
        mid = len(chunk) // 2
        bisect(chunk[:mid])
        bisect(chunk[mid:])

    for i in range(0, len(names), chunk_size):
        if result.requests_used >= max_requests:
            result.exhausted_budget = True
            break
        bisect(names[i:i + chunk_size])

    if result.discovered:
        logger.info(
            "param mining: %d hidden parameter(s) at %d request(s): %s",
            len(result.discovered), result.requests_used,
            ", ".join(sorted(result.discovered)),
        )
    return result
