"""Firmware ELF component inventory for SCA.

Extracts component versions (busybox, dropbear, openssl, ...) from the
ELF binaries of an extracted firmware root via bounded binary-safe
regex scanning, and converts them into Debian-ecosystem
:class:`~packages.sca.models.Dependency` rows so the existing OSV
pipeline matches advisories (Debian shards are release-agnostically
queryable; the Debian security tracker's records for these components
are rich).

OSV's Debian ranges are keyed on Debian version strings (epochs,
revisions), so raw upstream versions are mapped through the madison
registry client when available — the newest Debian version whose
upstream part equals the extracted version — falling back to the raw
upstream version when madison is offline or has no match.

Sibling of ``dockerfile_from``'s package-DB inventory: same injection
seam in the pipeline, same Dependency shape,
``source_kind="firmware_elf"``.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from core.logging import get_logger

from .models import Confidence, Dependency, PinStyle

if TYPE_CHECKING:
    from .registries.debian import DebianClient

logger = get_logger()

# Per-file scan bound: component version strings live in .rodata near
# the front of stripped firmware binaries; 32 MiB covers every real
# busybox/daemon while keeping a hostile multi-GB blob from being
# slurped whole.
_MAX_SCAN_BYTES = 32 * 1024 * 1024

# Evidence binaries recorded per emitted dependency row.
_MAX_EVIDENCE_BINARIES = 5


@dataclass(frozen=True)
class ComponentPattern:
    """One recognizable firmware component.

    ``osv_name`` is the Debian SOURCE package (what OSV's Debian shard
    keys advisories on); ``madison_name`` is a BINARY package (what the
    madison service resolves) — they differ where Debian splits or
    renames (zlib → zlib1g, wpa → wpasupplicant).
    """

    component: str
    osv_name: str
    madison_name: str
    version_re: re.Pattern[bytes]


# Seed set of embedded-Linux components with distinctive version
# strings. Additions should keep the version group tight (anchored
# prose around the number) — a loose pattern over binary data invents
# versions out of unrelated bytes.
_COMPONENT_PATTERNS: tuple[ComponentPattern, ...] = (
    ComponentPattern(
        "busybox", "busybox", "busybox",
        re.compile(rb"BusyBox v(\d+\.\d+\.\d+)"),
    ),
    ComponentPattern(
        "dropbear", "dropbear", "dropbear",
        re.compile(rb"[Dd]ropbear[_ -]?(?:SSH[_ ])?v?(\d{4}\.\d\d(?:\.\d+)?)"),
    ),
    ComponentPattern(
        "openssl", "openssl", "openssl",
        re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]?)[\s\x00]"),
    ),
    ComponentPattern(
        "lighttpd", "lighttpd", "lighttpd",
        re.compile(rb"lighttpd/(\d+\.\d+\.\d+)"),
    ),
    ComponentPattern(
        "dnsmasq", "dnsmasq", "dnsmasq",
        re.compile(rb"dnsmasq-(\d+\.\d+)"),
    ),
    ComponentPattern(
        "curl", "curl", "curl",
        re.compile(rb"libcurl/(\d+\.\d+\.\d+)"),
    ),
    ComponentPattern(
        "zlib", "zlib", "zlib1g",
        re.compile(rb"(?:inflate|deflate) (\d+\.\d+\.\d+) Copyright"),
    ),
    ComponentPattern(
        "wpa_supplicant", "wpa", "wpasupplicant",
        re.compile(rb"wpa_supplicant v(\d+\.\d+(?:\.\d+)?)"),
    ),
)


@dataclass(frozen=True)
class ComponentHit:
    """One component version observed in one firmware binary."""

    component: str
    osv_name: str
    madison_name: str
    version: str            # raw upstream version as extracted
    binary: str             # path relative to the firmware root


def _scan_bytes(data: bytes) -> list[tuple[ComponentPattern, str]]:
    """All component/version matches in one binary's bytes. When a
    pattern matches several versions (an update binary carrying both
    old and new strings), the most frequent one wins."""
    out: list[tuple[ComponentPattern, str]] = []
    for pattern in _COMPONENT_PATTERNS:
        versions = [
            m.decode("ascii", errors="replace")
            for m in pattern.version_re.findall(data)
        ]
        if versions:
            version, _count = Counter(versions).most_common(1)[0]
            out.append((pattern, version))
    return out


def scan_firmware_components(firmware_root: Path) -> list[ComponentHit]:
    """Scan every ELF in the extracted firmware root for known
    component version strings.

    The candidate set comes from :func:`core.binary.firmware_inventory.
    inventory_firmware` (symlink-safe walk, ELF-classified), so
    non-ELF content is never read and the walk cannot escape the root.
    """
    from core.binary.firmware_inventory import inventory_firmware

    inventory = inventory_firmware(firmware_root)
    hits: list[ComponentHit] = []
    for entry in inventory.get("binaries") or []:
        rel = entry.get("path")
        if not isinstance(rel, str):
            continue
        path = firmware_root / rel
        try:
            with open(path, "rb") as fh:
                data = fh.read(_MAX_SCAN_BYTES)
        except OSError as e:
            logger.debug("sca.firmware_elf: read failed for %s: %s", path, e)
            continue
        for pattern, version in _scan_bytes(data):
            hits.append(ComponentHit(
                component=pattern.component,
                osv_name=pattern.osv_name,
                madison_name=pattern.madison_name,
                version=version,
                binary=rel,
            ))
    return hits


def _upstream_of(debian_version: str) -> str:
    """Upstream part of a Debian version string: strip the epoch, the
    Debian revision, and common packaging suffixes."""
    v = debian_version.split(":", 1)[-1]
    v = v.split("-", 1)[0]
    # ``+really`` marks a downgrade-in-disguise: the ACTUAL packaged
    # upstream follows the marker ("1.3.5+really1.3.4" ships 1.3.4).
    if "+really" in v:
        v = v.split("+really", 1)[1]
    for marker in ("+dfsg", "+repack", "~"):
        v = v.split(marker, 1)[0]
    return v


def map_debian_version(
    client: DebianClient, madison_name: str, upstream: str,
) -> str | None:
    """OLDEST Debian version of ``madison_name`` whose upstream part
    equals ``upstream``, or None when madison has no match (vendor
    fork, version never packaged, network refused).

    Oldest-matching is the conservative floor for a vulnerability
    scanner: later Debian revisions of the same upstream carry Debian
    security patches a vendor firmware build certainly lacks — mapping
    to the newest revision would mark advisories "fixed in -2" as not
    applicable and suppress exactly the CVE class this feature hunts.
    """
    try:
        versions = client.list_versions(madison_name)
    except Exception as e:                       # noqa: BLE001 — enrichment only
        logger.debug(
            "sca.firmware_elf: madison lookup failed for %s: %s",
            madison_name, e,
        )
        return None
    for debian_version in reversed(versions):    # list is newest-first
        if _upstream_of(debian_version) == upstream:
            return debian_version
    return None


_EXTRACT_CONFIDENCE = Confidence(
    "medium",
    reason="version string extracted from binary content",
)


def firmware_components_to_dependencies(
    hits: list[ComponentHit],
    *,
    firmware_root: Path,
    debian_client: DebianClient | None = None,
) -> list[Dependency]:
    """Convert component hits into Debian-ecosystem Dependency rows.

    One row per distinct (component, upstream version) — the same
    busybox observed in fifty applet copies is one dependency; the
    evidence binaries ride ``source_extra``. When madison maps the
    upstream version to a Debian version string the row uses it
    (``source_extra["debian_version"]`` records the mapping); otherwise
    the raw upstream version is queried as-is — OSV still matches
    exact-version events, just with weaker range recall.
    """
    grouped: dict[tuple[str, str], list[ComponentHit]] = {}
    for hit in hits:
        grouped.setdefault((hit.component, hit.version), []).append(hit)

    out: list[Dependency] = []
    for (component, upstream), group in sorted(grouped.items()):
        first = group[0]
        debian_version = None
        if debian_client is not None:
            debian_version = map_debian_version(
                debian_client, first.madison_name, upstream,
            )
        version = debian_version or upstream
        binaries = sorted({h.binary for h in group})
        out.append(Dependency(
            ecosystem="Debian",
            name=first.osv_name,
            version=version,
            declared_in=firmware_root / first.binary,
            scope="main",
            is_lockfile=True,
            pin_style=PinStyle.EXACT,
            direct=True,
            purl=f"pkg:deb/debian/{first.osv_name}@{version}",
            parser_confidence=_EXTRACT_CONFIDENCE,
            source_kind="firmware_elf",
            source_extra={
                "component": component,
                "upstream_version": upstream,
                "debian_version": debian_version,
                "binaries": binaries[:_MAX_EVIDENCE_BINARIES],
                "binary_count": len(binaries),
            },
        ))
    return out
