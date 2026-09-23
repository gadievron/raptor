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

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

from core.json import load_json_bounded

from .._test_paths import TEST_DIR_NAMES as _SHARED_TEST_DIR_NAMES
from ..discovery import EXCLUDED_DIR_NAMES
from ..models import Confidence, Dependency, Manifest
from ..parsers import _safe_read
from ._closest_manifest import project_host_dep
from ._edit_distance import damerau_levenshtein
from ._source_exts import SOURCE_CODE_EXTS as _SOURCE_CODE_EXTS
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

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
# consistent. The optional userinfo section (``user:pass@``) is
# consumed BEFORE the host capture: URL semantics resolve
# ``https://api.github.com@evil.example/x`` to host ``evil.example``
# (everything before ``@`` is userinfo the server never sees), so a
# regex that captured the userinfo as the host would evaluate the
# decoy name while the runtime connects to the real one. The group
# requires a literal ``@`` to consume anything, so plain URLs are
# unaffected.
# IGNORECASE: URL schemes are case-insensitive at runtime —
# ``HTTPS://pastebin.com/x`` fetches exactly like the lowercase
# spelling, so a cased scheme must not slip past the extractor.
_URL_RE = re.compile(
    r"https?://(?:[A-Za-z0-9._%+:\-]*@)?(?P<host>[A-Za-z0-9._\-]+)",
    re.IGNORECASE,
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

# Shared with exfil_destinations — see ``_source_exts`` (the two
# walkers drifted; the typosquat one was missing the primary npm
# hook-payload extensions .mjs/.cjs/.jsx/.tsx).
_EXTENSIONS = _SOURCE_CODE_EXTS


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
) -> list[TyposquatDomainFinding]:
    """Walk the project, extract URLs, flag near-miss hostnames."""
    target = target.resolve()
    popular = _load_popular_domains()
    if not popular:
        return []

    # Anchor findings through the shared dominance-based resolver
    # (``project_host_dep``) like every other tree-walking detector:
    # pinning to the FIRST discovered manifest with a literal
    # ``<project>`` name produced a dep key no sibling detector ever
    # matched, so SQUAT-family composite promotions could never
    # co-fire, and multi-manifest repos got a wrong ``declared_in``.
    manifests_list = list(manifests)

    # Per-scan cache: a popular-near-miss check is purely a function
    # of the host string and the popular set, both stable across the
    # whole walk. The same host appears in many files (URLs in
    # docstrings, comments, generated code) — recomputing the
    # Damerau-Levenshtein matrix per occurrence dominates runtime.
    # Caching collapses 1.2M DL calls (raptor on itself) to ~ 15K.
    near_miss_cache: dict[str, tuple[int, str] | None] = {}

    out: list[TyposquatDomainFinding] = []
    for src in _walk_sources(target, max_depth=max_depth):
        if _is_test_file(src, target):
            continue
        text = _safe_read.read_bounded(src, follow_symlinks=False)
        if text is None:
            # ``read_bounded`` already logged the underlying reason.
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
            dep = project_host_dep(
                manifests_list, src, target,
                reason="domain typosquat — project-level finding",
            )
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

def _load_popular_domains() -> set[str]:
    if not _DATA_FILE.exists():
        return set()
    try:
        # Repo-bundled data file; ValueError also covers the
        # byte-budget refusal.
        data = load_json_bounded(_DATA_FILE, max_bytes=8 * 1024 * 1024)
    except (OSError, ValueError) as e:
        logger.warning("sca.supply_chain.typosquat_domain: cannot load "
                        "%s: %s", _DATA_FILE, e)
        return set()
    if not isinstance(data, list):
        return set()
    return {str(d).lower() for d in data}


def _hosts_in(text: str) -> Iterable[tuple[str, int]]:
    r"""Yield ``(host, line_number)`` for every URL in ``text``.

    Line numbers are computed by walking forward from the previous
    match's offset rather than re-scanning the whole text from 0 per
    match — the naive ``text.count('\n', 0, m.start())`` form is
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
    host: str, popular: set[str],
) -> tuple[int, str] | None:
    """Best near-miss for ``host`` against the popular set —
    whole-host comparison PLUS trailing 2- / 3-label suffixes.

    The suffix pass exists for the module's own motivating attack
    shape: ``scan.aquasecurtiy.org`` (CVE-2026-33634) is distance ≥5
    from ``aquasecurity.org`` as a whole host, but its registrable
    suffix is distance 1 — attackers control DNS for the squat
    domain, so subdomain hosting is the OBSERVED shape.  An exact
    suffix match means the host is a subdomain of a popular domain
    (only that domain's owner can serve it) and is skipped as
    in-family.
    """
    best = _nearest_whole(host, popular)
    labels = host.split(".")
    for n in (2, 3):
        if len(labels) <= n:
            continue
        suffix = ".".join(labels[-n:])
        if suffix in popular:
            # Subdomain of a popular domain — same owner, not a squat.
            return best
        cand = _nearest_whole(suffix, popular)
        if cand is not None and (best is None or cand[0] < best[0]):
            best = cand
    return best


def _nearest_whole(
    host: str, popular: set[str],
) -> tuple[int, str] | None:
    best: tuple[int, str] | None = None
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
    """Damerau-Levenshtein with this module's historical overflow
    convention: returns the EXACT distance when it is ``<= cap`` and
    ``cap + 1`` when the distance exceeds ``cap`` (the ``cap + 1``
    value gives callers an early-exit signal).

    Delegates to the shared rolling-row implementation, whose
    convention clamps AT its ``cutoff`` argument — calling it with
    ``cutoff = cap + 1`` returns exact distances up to ``cap`` and
    ``cap + 1`` beyond, which is this convention precisely.
    """
    return damerau_levenshtein(a, b, cap + 1)


def _walk_sources(target: Path, *, max_depth: int) -> Iterable[Path]:
    root_depth = len(target.parts)
    for dirpath, dirnames, filenames in os.walk(str(target),
                                                  followlinks=False):
        cur = Path(dirpath)
        if len(cur.parts) - root_depth >= max_depth:
            dirnames[:] = []
        else:
        # Sorted so evidence/walk order is filesystem-independent
        # (parity with reachability._walker's determinism rule).
            dirnames[:] = sorted(
                d for d in dirnames if d not in _SKIP_DIRS
            )
        for fn in sorted(filenames):
            if any(fn.endswith(ext) for ext in _EXTENSIONS) or fn in ("Dockerfile", "Containerfile"):
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


__all__ = ["TyposquatDomainFinding", "scan_target"]
