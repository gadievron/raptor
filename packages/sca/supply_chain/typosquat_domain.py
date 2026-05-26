"""Domain-typosquat detector — Levenshtein-distance check on URLs.

The Trivy supply-chain attack (March 2026, CVE-2026-33634) used the
domain ``scan.aquasecurtiy.org`` (typosquat of ``aquasecurity.org``)
as a payload host. The pattern: a malicious package fetches additional
content from a URL whose hostname is a near-miss for a legitimate
vendor / registry / GitHub host.

This detector:

  1. Walks ``*.py`` / ``*.js`` / ``*.ts`` / ``*.sh`` / install-script
     files in the project.
  2. Extracts URL hostnames.
  3. For each hostname, computes Damerau-Levenshtein distance against
     a curated list of legitimate registry / CDN / GitHub / common-
     vendor host names.
  4. Distance 1-2 from a popular host = candidate; exact match excluded
     (the host IS the popular one, not a squat).
  5. Skips raw-IP and localhost hosts (handled by exfil_destinations).

Curated list of legitimate hosts is bundled at
``packages/sca/data/popular_domains.json`` and refreshed via the same
weekly auto-PR mechanism as the typosquat name lists.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .._test_paths import TEST_DIR_NAMES as _SHARED_TEST_DIR_NAMES
from ..discovery import EXCLUDED_DIR_NAMES
from ..models import Confidence, Dependency, Manifest

logger = logging.getLogger(__name__)


_DEFAULT_MAX_DEPTH = 12
_MAX_DISTANCE = 2

_DATA_FILE = Path(__file__).resolve().parents[1] / "data" / "popular_domains.json"

# Skip these — exfil_destinations already covers raw IPs / known-bad
# pastebin-class hosts.
_SKIP_HOSTS = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
}

# URL pattern — same shape as exfil_destinations to keep behaviour
# consistent.
_URL_RE = re.compile(
    r"https?://(?P<host>[A-Za-z0-9._\-]+)",
)

# Test-path detection is delegated to the shared ``_test_paths``
# module (imported above) so this detector picks up Go / Ruby /
# Java / Rust / C# / PHP test-file naming conventions, not just
# dir-name conventions. The local set below was retained as a
# backstop for the ``fixtures`` dir name that isn't in the shared
# TEST_DIR_NAMES.
_LOCAL_FIXTURE_DIRS = {"specs", "fixtures"}
_TEST_DIR_NAMES = _SHARED_TEST_DIR_NAMES | _LOCAL_FIXTURE_DIRS

# Canonical skip set — drift-free with discovery.EXCLUDED_DIR_NAMES.
_SKIP_DIRS = EXCLUDED_DIR_NAMES

_EXTENSIONS = {".py", ".js", ".ts", ".sh", ".bash", ".rb", ".go",
                ".rs", ".php", ".cs", ".java", ".kt", ".gradle",
                ".dockerfile", ".yml", ".yaml", ".json"}


@dataclass
class TyposquatDomainFinding:
    dependency: Dependency
    path: Path
    line: int
    suspect_host: str
    nearest_popular: str
    distance: int
    detail: str
    severity: str
    confidence: Confidence


def scan_target(
    target: Path,
    manifests: Iterable[Manifest],
    *,
    max_depth: int = _DEFAULT_MAX_DEPTH,
) -> List[TyposquatDomainFinding]:
    """Walk the project, extract URLs, flag near-miss hostnames."""
    target = target.resolve()
    popular = _load_popular_domains()
    if not popular:
        return []

    # Group manifests by parent dir so the synthesised Dependency for a
    # finding gets attached to a real declared_in.
    manifests_list = list(manifests)
    fallback_manifest: Optional[Manifest] = (
        manifests_list[0] if manifests_list else None)

    # Per-scan cache: a popular-near-miss check is purely a function
    # of the host string and the popular set, both stable across the
    # whole walk. The same host appears in many files (URLs in
    # docstrings, comments, generated code) — recomputing the
    # Damerau-Levenshtein matrix per occurrence dominates runtime.
    # Caching collapses 1.2M DL calls (raptor on itself) to ~ 15K.
    near_miss_cache: Dict[str, Optional[Tuple[int, str]]] = {}

    out: List[TyposquatDomainFinding] = []
    for src in _walk_sources(target, max_depth=max_depth):
        if _is_test_file(src, target):
            continue
        try:
            text = src.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.debug("sca.supply_chain.typosquat_domain: skip %s (%s)",
                          src, e)
            continue
        for host, line in _hosts_in(text):
            if host in _SKIP_HOSTS:
                continue
            if "." not in host:
                continue
            if host in popular:
                continue
            if host in near_miss_cache:
                best = near_miss_cache[host]
            else:
                best = _nearest_popular(host, popular)
                near_miss_cache[host] = best
            if best is None:
                continue
            distance, nearest = best
            dep = _stub_dep(fallback_manifest, src)
            detail = (
                f"{src.relative_to(target)}:{line} references "
                f"`{host}` — distance {distance} from popular "
                f"`{nearest}` (typosquat domain candidate)"
            )
            out.append(TyposquatDomainFinding(
                dependency=dep,
                path=src,
                line=line,
                suspect_host=host,
                nearest_popular=nearest,
                distance=distance,
                detail=detail,
                severity="high" if distance == 1 else "medium",
                confidence=Confidence(
                    "medium",
                    reason=f"distance {distance} from `{nearest}`",
                ),
            ))
    return out


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _load_popular_domains() -> Set[str]:
    if not _DATA_FILE.exists():
        return set()
    try:
        data = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("sca.supply_chain.typosquat_domain: cannot load "
                        "%s: %s", _DATA_FILE, e)
        return set()
    if not isinstance(data, list):
        return set()
    return {str(d).lower() for d in data}


def _hosts_in(text: str) -> Iterable[Tuple[str, int]]:
    """Yield ``(host, line_number)`` for every URL in ``text``.

    Line numbers are computed by walking forward from the previous
    match's offset rather than re-scanning the whole text from 0 per
    match — the naive ``text.count('\\n', 0, m.start())`` form is
    O(matches × text_length), which dominated scan time on URL-heavy
    source files (e.g. files with many docstring URLs).
    """
    last_pos = 0
    last_line = 1
    for m in _URL_RE.finditer(text):
        last_line += text.count("\n", last_pos, m.start())
        last_pos = m.start()
        yield m.group("host").lower(), last_line


def _nearest_popular(
    host: str, popular: Set[str],
) -> Optional[Tuple[int, str]]:
    best: Optional[Tuple[int, str]] = None
    for pop in popular:
        d = _damerau_levenshtein(host, pop, _MAX_DISTANCE + 1)
        if d > _MAX_DISTANCE:
            continue
        if d == 0:
            continue                    # exact = popular, not a squat
        if _same_registrable_domain(host, pop):
            # In-family variation, not a typosquat. ``registry-2.docker.io``
            # vs ``registry-1.docker.io`` share the ``docker.io``
            # registrable; the only attacker who can publish on
            # ``*.docker.io`` is Docker themselves. Documented + observed
            # FP on the docker-moby project's own API docs (May 2026
            # sweep).
            continue
        if best is None or d < best[0]:
            best = (d, pop)
    return best


def _same_registrable_domain(a: str, b: str) -> bool:
    """Heuristic for "same registrable domain" without a publicsuffix
    list dep. True when both hostnames have >= 3 labels AND their
    trailing N-1 labels (everything except the leftmost) are
    identical — i.e. they differ only in the leftmost subdomain
    label.

    Examples:
      * ``registry-2.docker.io`` <-> ``registry-1.docker.io`` ->
        trailing ``docker.io`` matches, 3 labels each -> True
        (in-family, not a squat).
      * ``goagle.com`` <-> ``google.com`` -> 2 labels each, fails
        the >= 3-label gate -> False (real typosquat caught).
      * ``api.shop.example.com`` <-> ``cdn.shop.example.com`` ->
        trailing ``shop.example.com`` matches -> True (in-family).
      * ``evil.com`` <-> ``evil.io`` -> trailing TLDs differ ->
        False (different domain).

    The >= 3-label gate is the load-bearing guard against false
    negatives on bare TLD attacks (``goagle.com`` -> ``google.com``).
    Without publicsuffix data we can't tell ``co.uk`` from ``.com``,
    so the rule errs toward flagging anything where both sides have
    only 2 labels.
    """
    a_parts = a.split(".")
    b_parts = b.split(".")
    if len(a_parts) != len(b_parts):
        return False
    if len(a_parts) < 3:
        # Fewer than 3 labels means trailing-N-1 is just the TLD;
        # we can't safely declare "same owner" without publicsuffix
        # data so default to "different".
        return False
    return a_parts[1:] == b_parts[1:]


def _damerau_levenshtein(a: str, b: str, cap: int) -> int:
    """Damerau-Levenshtein with full DP matrix (small strings only).

    Hostnames are short (≤ ~40 chars typically), so the O(la·lb)
    matrix is fine. Returns ``cap + 1`` when the distance exceeds
    ``cap`` to give callers an early-exit signal.
    """
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if abs(la - lb) > cap:
        return cap + 1
    # dp[i][j] = distance between a[:i] and b[:j].
    dp = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        dp[i][0] = i
    for j in range(lb + 1):
        dp[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(
                dp[i - 1][j] + 1,           # delete
                dp[i][j - 1] + 1,           # insert
                dp[i - 1][j - 1] + cost,    # substitute
            )
            if (i > 1 and j > 1
                    and a[i - 1] == b[j - 2]
                    and a[i - 2] == b[j - 1]):
                dp[i][j] = min(dp[i][j], dp[i - 2][j - 2] + 1)
        if min(dp[i]) > cap:
            return cap + 1
    return dp[la][lb]


def _walk_sources(target: Path, *, max_depth: int) -> Iterable[Path]:
    root_depth = len(target.parts)
    for dirpath, dirnames, filenames in os.walk(str(target),
                                                  followlinks=False):
        cur = Path(dirpath)
        if len(cur.parts) - root_depth >= max_depth:
            dirnames[:] = []
        else:
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if any(fn.endswith(ext) for ext in _EXTENSIONS):
                yield cur / fn
            elif fn in ("Dockerfile", "Containerfile"):
                yield cur / fn


def _is_test_file(path: Path, target: Path) -> bool:
    """True for files in test-shaped dirs OR with test-shaped filenames.

    Delegates to the shared ``is_test_path`` so we pick up Go's
    ``*_test.go``, Ruby's ``*_test.rb`` / ``*_spec.rb``, Java's
    ``*Test.java``, etc — not just dir-name conventions. The
    ``fixtures/`` and ``specs/`` dir-name backstops live in the
    local ``_TEST_DIR_NAMES`` extension above.
    """
    from .._test_paths import is_test_path
    if is_test_path(path, target):
        return True
    try:
        rel = path.relative_to(target)
    except ValueError:
        rel = path
    return any(p in _TEST_DIR_NAMES for p in rel.parts)


def _stub_dep(manifest: Optional[Manifest], src: Path) -> Dependency:
    """Synthesise a Dependency row for the finding's required field.

    Domain typosquats aren't tied to a specific dep — they're a signal
    in source files. We attach the finding to the project's first
    discovered manifest as a representative reference; the file path
    is captured separately in ``TyposquatDomainFinding.path``.
    """
    declared_in = manifest.path if manifest else src
    return Dependency(
        ecosystem=manifest.ecosystem if manifest else "Inline",
        name="<project>",
        version=None,
        declared_in=declared_in,
        scope="main",
        is_lockfile=False,
        pin_style=__import__("packages.sca.models",
                              fromlist=["PinStyle"]).PinStyle.UNKNOWN,
        direct=True,
        purl=f"pkg:project/{src.parent.name}",
        parser_confidence=Confidence(
            "high",
            reason="domain typosquat — project-level finding",
        ),
        source_kind="manifest",
    )


__all__ = ["TyposquatDomainFinding", "scan_target"]
