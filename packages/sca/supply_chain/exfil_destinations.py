"""Detector for ``known_exfil_destination``.

Greps the project source for URLs / domains that recur in
known supply-chain attacks as exfiltration or payload-staging
endpoints. The match list lives in
``packages/sca/data/exfil_destinations.json`` so it can be extended
without code changes; each entry carries a category + severity +
human-readable reason.

The check is an *enumeration of known-bad shapes* (paste sites,
URL shorteners, anonymous file-sharing, Tor, Discord webhooks,
Telegram bots, raw IP URLs). It catches the recurring shapes that
attackers reach for; it doesn't catch novel C2 hosts. The recall
floor is the bundled list — operators extend the file as new
patterns surface.

Walk policy:
- Same vendored-tree exclusions as the artefact walks.
- Source extensions only (``.py``, ``.js``, ``.ts``, ``.sh``,
  ``.json``, ``.yaml``, ``.toml``, ``.md``, ``.html``). README and
  docs files commonly link to legitimate URLs; the list is
  curated such that those won't trigger.
- Cap each file's read at 1 MB; URLs in larger files are an
  unusual shape worth a separate flag if it ever happens.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple

from ..discovery import EXCLUDED_DIR_NAMES
from ..models import Confidence, Dependency, Manifest, PinStyle

logger = logging.getLogger(__name__)

_DATA_FILE = Path(__file__).resolve().parent.parent / "data" / \
    "exfil_destinations.json"

# Canonical skip set + this walker's extras. Drift-free: a new entry
# in discovery.EXCLUDED_DIR_NAMES propagates to every walker.
_EXCLUDED_DIRS: Set[str] = EXCLUDED_DIR_NAMES | {
    "site-packages",        # any virtualenv that snuck in
}

# Files we'll scan. Source + config. Exclude binary / archive types.
_SCAN_EXTS: Set[str] = {
    ".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".sh", ".bash", ".zsh", ".rb", ".go", ".rs", ".java", ".kt",
    ".json", ".yaml", ".yml", ".toml", ".xml", ".cfg", ".ini",
    ".md", ".rst", ".txt", ".html",
}

_MAX_BYTES_PER_FILE = 1024 * 1024
_DEFAULT_MAX_DEPTH = 12

# Generic URL regex — captures `<scheme>://<host>[:port][/path][?qs]`.
_URL_RE = re.compile(
    rb"\bhttps?://(?P<host>[A-Za-z0-9.\-]+)(?::\d+)?(?P<rest>[^\s'\"<>`)\]]*)"
)


@dataclass(frozen=True)
class ExfilFinding:
    dependency: Dependency
    detail: str
    path: Path
    line: int
    severity: str
    confidence: Confidence
    category: str


# Compiled rules cache — one load per process, then reuse.
_RULES_CACHE: Optional[List["_Rule"]] = None


@dataclass(frozen=True)
class _Rule:
    category: str
    severity: str
    reason: str
    host_suffix: Optional[str]      # match on URL host
    pattern: Optional[re.Pattern]   # match on the full URL
    tld: Optional[str]              # match on TLD (e.g., "onion")


def scan_target(
    target: Path,
    manifests: Iterable[Manifest],
    *,
    max_depth: int = _DEFAULT_MAX_DEPTH,
) -> List[ExfilFinding]:
    """Walk ``target`` source files; return URL-pattern matches."""
    rules = _load_rules()
    if not rules:
        return []
    target = target.resolve()
    manifests_list = list(manifests)
    out: List[ExfilFinding] = []
    for path in _walk_source_files(target, max_depth=max_depth):
        out.extend(_scan_file(path, target, manifests_list, rules))
    return out


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _load_rules() -> List[_Rule]:
    global _RULES_CACHE
    if _RULES_CACHE is not None:
        return _RULES_CACHE
    if not _DATA_FILE.exists():
        logger.warning(
            "sca.supply_chain.exfil_destinations: no data file at %s",
            _DATA_FILE,
        )
        _RULES_CACHE = []
        return _RULES_CACHE
    try:
        data = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.warning(
            "sca.supply_chain.exfil_destinations: cannot read %s: %s",
            _DATA_FILE, e,
        )
        _RULES_CACHE = []
        return _RULES_CACHE

    entries = data.get("entries") if isinstance(data, dict) else None
    rules: List[_Rule] = []
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            severity = entry.get("severity") or "medium"
            reason = entry.get("reason") or "matches known-bad pattern"
            category = entry.get("category") or "unspecified"
            pattern_raw = entry.get("pattern")
            pattern: Optional[re.Pattern] = None
            if isinstance(pattern_raw, str):
                try:
                    pattern = re.compile(pattern_raw)
                except re.error as e:
                    logger.warning(
                        "sca.supply_chain.exfil_destinations: bad pattern "
                        "%r: %s", pattern_raw, e,
                    )
                    continue
            host_suffix = (
                entry.get("host") if isinstance(entry.get("host"), str)
                else None
            )
            tld = entry.get("tld") if isinstance(entry.get("tld"), str) else None
            if not (pattern or host_suffix or tld):
                continue
            rules.append(_Rule(
                category=str(category),
                severity=str(severity),
                reason=str(reason),
                host_suffix=host_suffix,
                pattern=pattern,
                tld=tld,
            ))
    _RULES_CACHE = rules
    return rules


def _scan_file(
    path: Path, target: Path, manifests: List[Manifest],
    rules: List[_Rule],
) -> Iterable[ExfilFinding]:
    try:
        with path.open("rb") as fh:
            data = fh.read(_MAX_BYTES_PER_FILE)
    except OSError as e:
        logger.debug(
            "sca.supply_chain.exfil_destinations: read failed for %s: %s",
            path, e,
        )
        return
    if not data:
        return
    seen: Set[Tuple[str, str]] = set()         # (category, host) dedup per file
    for m in _URL_RE.finditer(data):
        url_bytes = m.group(0)
        host_bytes = m.group("host") or b""
        try:
            url = url_bytes.decode("utf-8", errors="replace")
            host = host_bytes.decode("utf-8", errors="replace").lower()
        except UnicodeDecodeError:
            continue
        for rule in rules:
            if not _matches_rule(rule, url, host):
                continue
            key = (rule.category, host)
            if key in seen:
                continue
            seen.add(key)
            line = data.count(b"\n", 0, m.start()) + 1
            yield ExfilFinding(
                dependency=_project_host_dep(manifests, path, target),
                detail=(
                    f"`{_rel(path, target)}:{line}` references `{url}` — "
                    f"{rule.reason}"
                ),
                path=path,
                line=line,
                severity=rule.severity,
                confidence=Confidence(
                    "high" if rule.pattern is not None else "medium",
                    reason=f"matches {rule.category} pattern",
                ),
                category=rule.category,
            )


def _matches_rule(rule: _Rule, url: str, host: str) -> bool:
    if rule.tld is not None and host.endswith("." + rule.tld.lower()):
        return True
    if rule.host_suffix is not None:
        suffix = rule.host_suffix.lower()
        if host == suffix or host.endswith("." + suffix):
            return True
    if rule.pattern is not None and rule.pattern.search(url):
        # The ``raw_ip`` pattern matches every IPv4. Threat model is
        # "WAN IP bypasses CDN/DNS oversight" — loopback, RFC 1918,
        # link-local, and the documentation prefixes (TEST-NET) don't
        # fit. Filter them out here rather than complicate the regex
        # in data/exfil_destinations.json.
        if rule.category == "raw_ip" and _is_non_routable_ipv4(host):
            return False
        return True
    return False


def _is_non_routable_ipv4(host: str) -> bool:
    """True if ``host`` is an IPv4 address that's not WAN-routable.

    Scope is narrow on purpose: loopback / RFC 1918 private / link-
    local. Operators binding services to ``127.0.0.1`` /
    ``192.168.x`` / ``10.x.x.x`` aren't bypassing CDN oversight;
    they're using local infrastructure.

    We DON'T use ``is_private`` — Python's ``ipaddress`` includes
    IANA special-purpose ranges (TEST-NET-1/2/3, 192.0.2/24, etc.)
    in that bucket, but those ranges look like real WAN IPs to a
    casual reader and are exactly what the rule's threat model
    wants to flag (a payload pointing at a "real-looking" IP). So
    we check the three RFC 1918 prefixes explicitly.
    """
    import ipaddress
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_link_local:
        return True
    rfc1918 = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )
    return any(ip in net for net in rfc1918)


def _walk_source_files(target: Path, *, max_depth: int) -> Iterable[Path]:
    """Walk source files looking for hardcoded URLs / IPs / Tor onions.

    Skips test directories and test-shaped filenames — fixtures
    intentionally contain things this detector flags (mocked exfil
    destinations, fake C2 URLs), so scanning them produces only
    self-finding noise. Operators auditing a security-research repo
    where the test corpus IS the target can fork the detector or
    filter on path post-hoc.
    """
    from .._test_paths import TEST_DIR_NAMES, is_test_path

    base = len(target.parts)
    for dirpath, dirnames, filenames in os.walk(str(target), followlinks=False):
        cur = Path(dirpath)
        depth = len(cur.parts) - base
        if depth >= max_depth:
            dirnames[:] = []
        else:
            dirnames[:] = [
                d for d in dirnames
                if d not in _EXCLUDED_DIRS and d not in TEST_DIR_NAMES
            ]
        for fn in filenames:
            if Path(fn).suffix.lower() not in _SCAN_EXTS:
                continue
            full = cur / fn
            if is_test_path(full, target):
                continue
            yield full


def _project_host_dep(
    manifests: List[Manifest], path: Path, target: Path,
) -> Dependency:
    closest: "Manifest | None" = None
    for m in manifests:
        if m.is_lockfile:
            continue
        try:
            common = os.path.commonpath([m.path.parent, path])
        except ValueError:
            continue
        if not closest or len(common) > len(
            os.path.commonpath([closest.path.parent, path])
        ):
            closest = m
    declared_in = closest.path if closest else target
    ecosystem = closest.ecosystem if closest else "Project"
    return Dependency(
        ecosystem=ecosystem,
        name="<project>",
        version=None,
        declared_in=declared_in,
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.UNKNOWN,
        direct=True,
        purl="",
        parser_confidence=Confidence(
            "low",
            reason="placeholder for known-exfil finding host",
        ),
    )


def _rel(path: Path, target: Path) -> Path:
    try:
        return path.relative_to(target)
    except ValueError:
        return path


__all__ = ["ExfilFinding", "scan_target"]
