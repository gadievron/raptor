"""Principal-differential access-control testing (IDOR / 403 bypass).

The house differential-oracle pattern applied to authorization: fetch
the same resource as different principals and compare. Three
principals matter — the authenticated scan session (A), an optional
second credential set (B), and an anonymous client — and two shapes
of evidence come out:

* horizontal/vertical access: an object-scoped resource that returns
  principal A's content unchanged to B or to anonymous;
* 403-bypass: a resource that is forbidden anonymously but opens up
  under a rewrite primitive (path casing, encoded dots, trailing
  slash, or an override header).

Verdicts stay honest: everything here is mechanical status/shape
evidence on live responses, reported as needs_review with the full
per-principal differential attached — never auto-confirmed. Public
pages return 200 to everyone; only resources that LOOK object-scoped
(ID-shaped parameters or numeric path segments) are tested, and the
response-shape comparison is the signal, not the status code alone.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, urlparse

from core.logging import get_logger
from packages.web.execution_policy import WebPolicyError

if TYPE_CHECKING:
    from packages.web.client import WebClient
    from packages.web.execution_policy import WebExecutionPolicy

logger = get_logger()

# Parameters whose values look like object identifiers.
_OBJECT_PARAM_RE = re.compile(
    r"(?:^|_)(?:id|uid|uuid|guid|key|ref|no|num|number|account|order|doc|file)s?$",
    re.IGNORECASE,
)
# Path segments that are bare numeric or uuid-shaped object ids.
_OBJECT_SEGMENT_RE = re.compile(
    r"^(?:\d{1,10}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$",
    re.IGNORECASE,
)

# 403-bypass rewrite primitives, applied to the PATH of a forbidden URL.
# Header primitives ride separately.
_PATH_PRIMITIVES: tuple[tuple[str, Any], ...] = (
    ("trailing_slash", lambda path: path + "/"),
    ("trailing_dot", lambda path: path + "/."),
    ("encoded_dot_segment", lambda path: "/%2e" + path),
    ("double_slash", lambda path: "/" + path),
    ("case_flip", lambda path: path.upper() if path.lower() == path else path.lower()),
)
_HEADER_PRIMITIVES: tuple[tuple[str, dict[str, str]], ...] = (
    ("x_original_url", {"X-Original-URL": "__PATH__"}),
    ("x_rewrite_url", {"X-Rewrite-URL": "__PATH__"}),
)


@dataclass
class Principal:
    """One identity the differential fetches resources as."""

    name: str                      # "session_a" | "session_b" | "anonymous"
    client: WebClient
    authenticated: bool = False


@dataclass
class _Shape:
    status: int | None = None
    length: int = 0
    excerpt: str = ""

    @classmethod
    def of(cls, response: Any) -> _Shape:
        body = response.text if isinstance(getattr(response, "text", None), str) else ""
        return cls(
            status=getattr(response, "status_code", None),
            length=len(getattr(response, "content", b"") or b""),
            excerpt=body[:160].replace("\n", "\\n"),
        )

    def similar(self, other: _Shape, tolerance: float = 0.1) -> bool:
        """Same status and body length within tolerance."""
        if self.status != other.status:
            return False
        bigger = max(self.length, other.length) or 1
        return abs(self.length - other.length) / bigger <= tolerance


@dataclass
class AccessControlResult:
    findings: list[dict[str, Any]] = field(default_factory=list)
    requests_used: int = 0
    targets_tested: int = 0


def object_scoped_urls(urls: list[str], parameters: list[str]) -> list[str]:
    """URLs that look like they address a specific object."""
    object_params = {p for p in parameters if _OBJECT_PARAM_RE.search(str(p))}
    selected = []
    for url in dict.fromkeys(urls):
        parsed = urlparse(url)
        query_names = {n for n, _ in parse_qsl(parsed.query, keep_blank_values=True)}
        if query_names & object_params:
            selected.append(url)
            continue
        segments = [s for s in parsed.path.split("/") if s]
        if any(_OBJECT_SEGMENT_RE.match(s) for s in segments):
            selected.append(url)
    return selected


def run_access_differential(
    *,
    principals: list[Principal],
    urls: list[str],
    parameters: list[str],
    policy: WebExecutionPolicy,
    max_targets: int = 15,
) -> AccessControlResult:
    """Fetch object-scoped resources as every principal and compare."""
    result = AccessControlResult()
    primary = next((p for p in principals if p.authenticated), None)
    if primary is None or len(principals) < 2:
        return result

    others = [p for p in principals if p is not primary]
    targets = object_scoped_urls(urls, parameters)[:max_targets]

    for url in targets:
        try:
            policy.authorize(
                tool_id="raptor-http", url=url, risk="active",
                action="access_control_differential",
            )
        except WebPolicyError:
            continue
        result.targets_tested += 1
        baseline = _fetch(primary, url, result)
        if baseline is None or baseline.status != 200:
            continue
        for other in others:
            shape = _fetch(other, url, result)
            if shape is None:
                continue
            if shape.similar(baseline):
                result.findings.append({
                    "kind": "idor_candidate",
                    "url": url,
                    "primary": primary.name,
                    "other": other.name,
                    "evidence": {
                        primary.name: vars(baseline),
                        other.name: vars(shape),
                    },
                })
            elif (
                other.name == "anonymous"
                and shape.status in (401, 403)
            ):
                bypass = _try_forbidden_bypass(other, url, result)
                if bypass is not None:
                    result.findings.append(bypass)
    return result


def _fetch(principal: Principal, url: str, result: AccessControlResult) -> _Shape | None:
    result.requests_used += 1
    try:
        return _Shape.of(principal.client.get(url))
    except Exception:
        logger.debug("access differential probe failed", exc_info=True)
        return None


def _try_forbidden_bypass(
    principal: Principal, url: str, result: AccessControlResult,
) -> dict[str, Any] | None:
    """A forbidden resource opened by a rewrite primitive."""
    parsed = urlparse(url)
    for name, rewrite in _PATH_PRIMITIVES:
        candidate = parsed._replace(path=rewrite(parsed.path)).geturl()
        if candidate == url:
            continue
        result.requests_used += 1
        try:
            response = principal.client.get(candidate)
        except Exception:
            continue
        if getattr(response, "status_code", None) == 200:
            return {
                "kind": "forbidden_bypass",
                "url": url,
                "primitive": name,
                "bypass_url": candidate,
                "other": principal.name,
                "evidence": {"bypass_status": 200, "original_status": "401/403"},
            }
    for name, headers in _HEADER_PRIMITIVES:
        sent = {
            key: value.replace("__PATH__", parsed.path)
            for key, value in headers.items()
        }
        result.requests_used += 1
        try:
            response = principal.client.get("/", headers=sent)
        except Exception:
            continue
        if getattr(response, "status_code", None) == 200 and _looks_like(
            response, parsed.path,
        ):
            return {
                "kind": "forbidden_bypass",
                "url": url,
                "primitive": name,
                "bypass_url": f"/ + {name}",
                "other": principal.name,
                "evidence": {"bypass_status": 200, "original_status": "401/403"},
            }
    return None


def _looks_like(response: Any, path: str) -> bool:
    """Weak containment check that the override actually routed to *path*."""
    body = response.text if isinstance(getattr(response, "text", None), str) else ""
    token = path.rstrip("/").rsplit("/", 1)[-1]
    return bool(token) and token.lower() in body.lower()
