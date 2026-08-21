"""Registry manifest probing: candidates, inspect, digest pinning.

Given a product/version, generate likely image references across a
mirrors-first registry cascade, probe them with ``docker manifest
inspect``, classify failures, and pin the digest matching the host
platform. All mechanics, no policy: cross-call rate-limit budgets,
cooldown decisions, and pivot-hint text belong to the calling planner.

The cascade is mirrors-first by design: Docker Hub's anonymous 100/6h
pull limit is easily exhausted on batch workloads — probing independent
registries (mirror.gcr.io, public.ecr.aws, quay, ghcr, mcr) first gives
unauthenticated users the high-quota path; the Hub variants stay last
(``vulhub/*`` lives only there).
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Callable, Literal

from core.container.proc import PROXY_ENV_VARS, run_cli

logger = logging.getLogger(__name__)

InspectClass = Literal["ok", "not_found", "rate_limited", "transport", "auth"]
"""Classification of a docker manifest inspect failure.

* ``ok``           — probe succeeded
* ``not_found``    — manifest unknown / repo not found (permanent)
* ``rate_limited`` — DockerHub anonymous rate limit (HTTP 429 / "toomanyrequests")
* ``transport``    — timeout / connection error / 5xx (transient, retry)
* ``auth``         — 401 / unauthorized (do not retry without creds)
"""

RETRY_BACKOFF_RATE_LIMITED_S: float = 10.0
RETRY_BACKOFF_TRANSPORT_S: float = 5.0

_UNKNOWN_PLATFORM = "unknown/unknown"

_TRANSIENT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"received unexpected HTTP status:?\s*(?:429|500|502|503|504)", re.IGNORECASE
    ),
    re.compile(r"\btoomanyrequests\b", re.IGNORECASE),
    re.compile(r"\bconnection reset\b", re.IGNORECASE),
    re.compile(r"network is unreachable", re.IGNORECASE),
    re.compile(r"i/o timeout", re.IGNORECASE),
    re.compile(r"temporary failure in name resolution", re.IGNORECASE),
    re.compile(r"server misbehaving", re.IGNORECASE),
)
_AUTH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bunauthorized\b", re.IGNORECASE),
    re.compile(r"\bauthentication required\b", re.IGNORECASE),
    re.compile(r"\b401\b"),
)
_NOT_FOUND_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bmanifest unknown\b", re.IGNORECASE),
    re.compile(r"\bnot found\b", re.IGNORECASE),
    re.compile(r"repository .+ not found", re.IGNORECASE),
)

_DOCKERHUB_ALIASES = frozenset(
    {
        "docker.io",
        "dockerhub",
        "index.docker.io",
        "registry-1.docker.io",
    }
)


def candidate_refs(product: str, version: str) -> list[str]:
    """Generate likely image references for a product+version,
    mirrors-first, deduped preserving order. Empty product/version → []."""
    p = product.strip().lower()
    v = version.strip()
    if not p or not v:
        return []
    candidates = [
        # Independent registries first (no Docker Hub rate-limit pool).
        # mirror.gcr.io is Google's DH mirror of the library/* namespace
        # with high anonymous quota; byte-identical to docker.io/library.
        f"mirror.gcr.io/library/{p}:{v}",
        # public.ecr.aws is AWS ECR Public's DH library/* mirror —
        # independent quota pool, probed second (lower anon quota).
        f"public.ecr.aws/docker/library/{p}:{v}",
        # Vendor registries — each has its own quota pool.
        f"quay.io/{p}/{p}:{v}",
        f"ghcr.io/{p}/{p}:{v}",
        f"mcr.microsoft.com/{p}:{v}",
        # Docker Hub variants LAST — rate-limited as a single pool.
        f"{p}:{v}",
        f"library/{p}:{v}",
        f"vulhub/{p}:{v}",
        f"docker.io/{p}:{v}",
        f"docker.io/library/{p}:{v}",
    ]
    seen: set[str] = set()
    out: list[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def normalize_registry_token(raw: str) -> str:
    """Normalize an operator-supplied registry token to a comparable host.

    Accepts URL-ish inputs (``https://docker.io/v2/``), host:port
    (``mirror.gcr.io:443``), or bare hostnames. Returns the lowercase
    hostname stripped of scheme, port, path, and trailing dots. The
    Docker Hub aliases (``index.docker.io``, ``registry-1.docker.io``,
    ``dockerhub``) collapse to ``docker.io``.
    """
    token = raw.strip().lower()
    if not token:
        return ""
    if "://" in token:
        token = token.split("://", 1)[1]
    token = token.split("/", 1)[0]
    token = token.split("?", 1)[0]
    if token.startswith("[") and "]" in token:
        token = token[1 : token.index("]")]
    elif ":" in token:
        token = token.rsplit(":", 1)[0]
    token = token.rstrip(".")
    if token in _DOCKERHUB_ALIASES:
        return "docker.io"
    return token


def filter_denied_registries(candidates: list[str], denied_str: str) -> list[str]:
    """Drop candidates whose registry is in the comma-separated denylist.

    Operators may pass URL-ish forms (``https://docker.io``) — values
    are normalized to bare hostnames before comparison. Denying
    ``docker.io`` also drops bare-name refs (``foo:1.0``) and
    ``library/*`` (both default to Docker Hub). Empty ``denied_str`` is
    a no-op.
    """
    denied_str = (denied_str or "").strip()
    if not denied_str:
        return candidates
    denied = {
        normalized
        for d in denied_str.split(",")
        if (normalized := normalize_registry_token(d))
    }
    if not denied:
        return candidates

    # Superset form rather than ``in`` — semantically identical, but it
    # sidesteps CodeQL's py/incomplete-url-substring-sanitization
    # heuristic which can't see that ``denied`` carries normalized tokens.
    drop_dockerhub = denied >= {"docker.io"}
    out: list[str] = []
    for c in candidates:
        cl = c.lower()
        first_seg = normalize_registry_token(cl.split("/", 1)[0])
        if first_seg in denied:
            continue
        if drop_dockerhub:
            # Bare names (no '/' before tag) default to docker.io.
            if "/" not in cl:
                continue
            # library/* and bare-namespace user names also default to
            # docker.io: anything whose first segment is NOT a registry
            # hostname (no '.' / ':' / localhost) is a Docker Hub ref.
            if (
                "." not in first_seg
                and ":" not in first_seg
                and first_seg != "localhost"
            ):
                continue
        out.append(c)
    return out


def classify_inspect_failure(stderr: str) -> InspectClass:
    """Map docker-manifest-inspect stderr to a class."""
    if not stderr:
        return "transport"  # subprocess died w/o stderr -> assume transport
    for pat in _TRANSIENT_PATTERNS:
        if pat.search(stderr):
            if "429" in stderr or "toomanyrequests" in stderr.lower():
                return "rate_limited"
            return "transport"
    for pat in _AUTH_PATTERNS:
        if pat.search(stderr):
            return "auth"
    for pat in _NOT_FOUND_PATTERNS:
        if pat.search(stderr):
            return "not_found"
    # Unknown stderr shape — treat as transport (retry-eligible).
    return "transport"


def worst_inspect_class(seen: set[InspectClass] | set[str]) -> InspectClass:
    """Pick the most-actionable class across a set of failures.

    Priority (transient classes signal "retry later" → bias away from
    terminal ``not_found``): rate_limited > transport > auth > not_found.
    """
    if "rate_limited" in seen:
        return "rate_limited"
    if "transport" in seen:
        return "transport"
    if "auth" in seen:
        return "auth"
    return "not_found"


def parse_inspect_payload(
    data: object,
) -> tuple[list[str], dict[str, str]]:
    """Parse a ``docker manifest inspect -v`` payload into
    ``(platforms, per_arch_digests)``."""
    platforms: list[str] = []
    per_arch_digests: dict[str, str] = {}

    # ``-v`` returns a list of descriptors for manifest-list refs and a
    # single descriptor dict for single-arch refs.
    entries = data if isinstance(data, list) else [data]
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        plat = entry.get("Descriptor", {}).get("platform") or entry.get("platform")
        if not isinstance(plat, dict):
            continue
        os_name = plat.get("os")
        arch = plat.get("architecture")
        if not (isinstance(os_name, str) and isinstance(arch, str)):
            continue
        platform_str = f"{os_name}/{arch}"
        # Filter BuildKit cache entries — they advertise a platform but
        # carry no runtime bytes.
        if platform_str == _UNKNOWN_PLATFORM:
            continue
        platforms.append(platform_str)
        d_value = (
            entry.get("Descriptor", {}).get("digest")
            if isinstance(entry.get("Descriptor"), dict)
            else None
        )
        if isinstance(d_value, str) and d_value.startswith("sha256:"):
            # First digest wins for a given platform — prefer earliest entry.
            per_arch_digests.setdefault(platform_str, d_value)

    return platforms, per_arch_digests


def pin_digest_ref(image_ref: str, digest: str) -> str:
    """``repo:tag`` + ``sha256:...`` → ``repo@sha256:...``."""
    base = image_ref.rsplit(":", 1)[0] if ":" in image_ref else image_ref
    return f"{base}@{digest}"


def pick_digest_for_host(
    per_arch: dict[str, str],
    *,
    host_platform: str,
    rosetta_available: bool,
) -> tuple[str, str] | None:
    """Return ``(chosen_platform, digest)`` for the host, or ``None`` if
    neither native nor rosetta-compatible digest is available."""
    if host_platform in per_arch:
        return host_platform, per_arch[host_platform]
    if (
        host_platform == "linux/arm64"
        and rosetta_available
        and "linux/amd64" in per_arch
    ):
        return "linux/amd64", per_arch["linux/amd64"]
    return None


def probe_manifest_once(
    image_ref: str, *, timeout_seconds: int
) -> tuple[tuple[list[str], dict[str, str]] | None, InspectClass, str]:
    """Single inspect attempt. Returns ``(parsed_or_None, class, stderr_tail)``.

    Returning the class lets the caller decide retry vs pivot.
    """
    # manifest inspect is a CLIENT-side registry call — the daemon's
    # proxy config doesn't apply, so the ambient proxy env must ride
    # along or every probe on a proxy-only host classifies "transport".
    outcome = run_cli(
        ["docker", "manifest", "inspect", "-v", image_ref],
        timeout=timeout_seconds,
        keep_env=PROXY_ENV_VARS,
    )
    if outcome.timed_out:
        return None, "transport", "timeout"
    if outcome.returncode is None and outcome.stderr.startswith("command_not_found:"):
        return None, "transport", "docker CLI not found on PATH"
    if outcome.returncode != 0:
        return (
            None,
            classify_inspect_failure(outcome.stderr or ""),
            (outcome.stderr or "")[:400],
        )
    if not outcome.stdout.strip():
        return None, "not_found", "empty stdout"
    try:
        data = json.loads(outcome.stdout)
    except json.JSONDecodeError:
        return None, "transport", "non-JSON stdout"
    return parse_inspect_payload(data), "ok", ""


def probe_manifest(
    image_ref: str,
    *,
    timeout_seconds: int = 30,
    enable_retry: bool = True,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[tuple[list[str], dict[str, str]] | None, InspectClass]:
    """Inspect a manifest with one retry on transient failure.

    Returns the parsed result (or None) PLUS the failure class so the
    caller can react. On a transient first attempt, sleeps the
    class-appropriate backoff (injectable via ``sleep`` for callers
    that meter waits themselves) and retries once; permanent classes
    (``not_found``, ``auth``) surface immediately.
    """
    result, klass, _stderr = probe_manifest_once(
        image_ref, timeout_seconds=timeout_seconds
    )
    if klass == "ok" or klass in ("not_found", "auth") or not enable_retry:
        return result, klass
    backoff = (
        RETRY_BACKOFF_RATE_LIMITED_S
        if klass == "rate_limited"
        else RETRY_BACKOFF_TRANSPORT_S
    )
    logger.info(
        "registry probe transient (%s) on %s; retrying in %ss",
        klass, image_ref, backoff,
    )
    sleep(backoff)
    retry_result, retry_klass, _retry_stderr = probe_manifest_once(
        image_ref, timeout_seconds=timeout_seconds
    )
    return retry_result, retry_klass
