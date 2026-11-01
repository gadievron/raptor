"""Per-layer SBOM extraction — turn package-state files into
``(ecosystem, name, version)`` records.

Three formats covered:

  * **dpkg** (``var/lib/dpkg/status``) — Debian + Ubuntu and any
    Debian-derivative. RFC822-ish text format: stanzas of
    ``Field: value`` separated by blank lines, with continuation
    lines indented. We pick out ``Package``, ``Version``,
    ``Status`` (so we can skip half-removed packages).

  * **apk** (``lib/apk/db/installed``) — Alpine Linux. Two-letter
    field-prefix format: ``P:<name>``, ``V:<version>``, blank-line-
    separated stanzas.

  * **rpm** (``var/lib/rpm/rpmdb.sqlite``) — modern RHEL / Rocky /
    Alma / Fedora. SQLite database with a ``Packages`` table whose
    blob columns hold serialised RPM headers. We parse the binary
    header structure to extract NAME + VERSION + RELEASE.

The output ecosystem strings match raptor's existing OSV
ecosystem mapping (``inline_installs.py`` already produces these
for ``apt``/``yum``/``apk`` install commands; the SBOM extractor
mirrors them).

Limitations (also noted in :doc:`README`):
  * Berkeley DB-format RPM (``var/lib/rpm/Packages`` without
    sqlite suffix, used through CentOS 7) is NOT parsed. Modern
    distros (CentOS 8+, RHEL 8+, Fedora 36+, Rocky/Alma) all use
    SQLite. Operators scanning legacy images will see "no SBOM
    found" — accurate; supporting BDB-format RPM means embedding
    a DB driver, which expands the trust surface.
  * APK v3 (the future format) isn't yet stable enough to support;
    Alpine still ships v2 today.
"""

from __future__ import annotations

import contextlib
import logging
import re
import sqlite3
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

from .distro import release_ecosystem

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class InstalledPackage:
    """One installed package found in a layer's package-state file.

    ``ecosystem`` matches raptor's OSV ecosystem strings ("Debian",
    "Alpine", "Red Hat") — the OSV pipeline takes ``(ecosystem,
    name, version)`` and dispatches the right query handler.
    """
    ecosystem: str
    name: str
    version: str


class PackageDbLimitExceeded(Exception):
    """Raised when a single package-state file yields more records
    than :data:`MAX_PACKAGE_RECORDS`. The input files are size-capped
    upstream (64 MiB/member), but minimal stanzas amplify bytes into
    Python objects at a high constant factor — a hostile registry
    image could otherwise drive a multi-GB heap spike. Real package
    databases top out in the low tens of thousands of records."""


# Per-file record ceiling for the parsers below. Debian's full
# archive is ~70k packages; a single installed-state file above this
# is hostile or corrupt, never real.
MAX_PACKAGE_RECORDS = 300_000


def _check_record_cap(records: list, source: str) -> None:
    if len(records) >= MAX_PACKAGE_RECORDS:
        raise PackageDbLimitExceeded(
            f"{source} exceeds {MAX_PACKAGE_RECORDS} package records "
            f"(bomb-shape); refusing"
        )


# ---------------------------------------------------------------------------
# dpkg / Debian / Ubuntu
# ---------------------------------------------------------------------------


def parse_dpkg_status(content: bytes) -> list[InstalledPackage]:
    """Parse ``var/lib/dpkg/status``.

    The format is RFC 822-ish: stanzas separated by blank lines,
    each stanza is ``Field: value`` lines. Multi-line values are
    indented by one space + continuation. We only need ``Package``,
    ``Version``, and ``Status`` — skip the rest.

    Status filter: only emit packages with status ``installed``
    (the ``installed`` flag is the third space-separated word in
    the Status field, e.g. ``Status: install ok installed``).
    Half-removed / unpacked / config-files-only states aren't
    real installs from a CVE-matching perspective.
    """
    out: list[InstalledPackage] = []
    seen: set[tuple[str, str]] = set()
    text = content.decode("utf-8", errors="replace")
    for stanza in _split_rfc822_stanzas(text):
        fields = _parse_rfc822_stanza(stanza)
        package = fields.get("Package")
        version = fields.get("Version")
        status = (fields.get("Status") or "").strip()
        if not package or not version:
            continue
        if not _dpkg_status_is_installed(status):
            continue
        # OSV's Debian / Ubuntu feeds key advisories by SOURCE
        # package name (DEBIAN-CVE-* for ``openssl``; nothing under
        # the ``libssl1.1`` binary split). ``Source:`` may carry a
        # version qualifier (``Source: openssl (1.1.0l-1)``) — use
        # that source version rather than a binary rebuild suffix.
        # Binary-only stanzas (no Source field) ARE their own
        # source. Deduplicate per (source, version): one source
        # builds many binaries and one advisory row is enough.
        source = (fields.get("Source") or "").strip()
        if source:
            match = re.fullmatch(r"([a-z0-9][a-z0-9+.-]*)(?: \(([^()\s]+)\))?", source)
            if not match:
                raise ValueError("invalid dpkg Source field")
            name, source_version = match[1], match[2] or version.strip()
        else:
            name, source_version = package.strip(), version.strip()
        key = (name, source_version)
        if key in seen:
            continue
        seen.add(key)
        _check_record_cap(out, "dpkg status")
        out.append(InstalledPackage(
            ecosystem="Debian", name=name,
            version=source_version,
        ))
    return out


def _split_rfc822_stanzas(text: str) -> Iterator[str]:
    """Split on blank lines. Tolerates Windows line endings."""
    cur: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            if cur:
                yield "\n".join(cur)
                cur = []
        else:
            cur.append(line)
    if cur:
        yield "\n".join(cur)


def _parse_rfc822_stanza(stanza: str) -> dict:
    """Parse one RFC822-ish stanza into a {field: value} dict.
    Multi-line values (continuation lines indented by whitespace)
    get joined with the leading whitespace stripped per dpkg
    convention.

    Values accumulate as line lists and are joined once at the end.
    The previous per-continuation-line ``out[key] = out.get(key, "")
    + ...`` rebuilt a dict-held string on every line (the dict
    reference keeps the refcount above 1, so CPython's in-place
    concat fast path never applies) — O(n²) CPU on
    attacker-controlled input: a 64 MiB member made entirely of
    continuation lines burned hours in this loop.
    """
    parts: dict[str, list[str]] = {}
    current_key: str | None = None
    for line in stanza.splitlines():
        if not line:
            continue
        if line[0].isspace():
            # Continuation of previous field's value.
            if current_key is not None:
                parts[current_key].append(line.strip())
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        current_key = key.strip()
        parts[current_key] = [value.strip()]
    return {key: "\n".join(lines) for key, lines in parts.items()}


def _dpkg_status_is_installed(status: str) -> bool:
    """Status string is three space-separated words: want, eflag,
    status. Only ``installed`` in the third position counts. See
    ``man dpkg-deb`` for the full state machine."""
    parts = status.split()
    if len(parts) != 3:
        return False
    return parts[2] == "installed"


# ---------------------------------------------------------------------------
# apk / Alpine
# ---------------------------------------------------------------------------


def parse_apk_installed(content: bytes) -> list[InstalledPackage]:
    """Parse ``lib/apk/db/installed``.

    Format: stanzas separated by blank lines. Each line is
    ``X:value`` where ``X`` is a one- or two-letter prefix. Fields
    we care about:
        * ``P:<name>``
        * ``V:<version>``

    No "is-installed" flag — apk only tracks installed packages in
    this file (uninstalled packages have their stanzas removed),
    so every parsed stanza is a real install.
    """
    out: list[InstalledPackage] = []
    seen: set[tuple[str, str]] = set()
    text = content.decode("utf-8", errors="replace")
    for stanza in _split_rfc822_stanzas(text):
        package: str | None = None
        version: str | None = None
        origin: str | None = None
        for line in stanza.splitlines():
            if line.startswith("P:"):
                package = line[2:].strip()
            elif line.startswith("V:"):
                version = line[2:].strip()
            elif line.startswith("o:"):
                # Origin (source) package — Alpine's secdb (and
                # OSV's ALPINE-CVE mirror) key advisories by it,
                # not by the subpackage split.
                origin = line[2:].strip()
        if package and version:
            name = origin or package
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            _check_record_cap(out, "apk installed db")
            out.append(InstalledPackage(
                ecosystem="Alpine", name=name, version=version,
            ))
    return out


# ---------------------------------------------------------------------------
# rpm (sqlite-backed, modern only)
# ---------------------------------------------------------------------------


# RPM header tag IDs. Numeric constants from ``rpm/rpmtag.h``
# (the canonical RPM source). Only what we need.
_RPMTAG_NAME = 1000
_RPMTAG_VERSION = 1001
_RPMTAG_RELEASE = 1002
_RPMTAG_EPOCH = 1003

_RPMTAG_TYPE_STRING = 6
_RPMTAG_TYPE_INT32 = 4


def parse_rpm_sqlite(content: bytes) -> list[InstalledPackage]:
    """Parse ``var/lib/rpm/rpmdb.sqlite``.

    The DB has a ``Packages`` table whose ``blob`` column holds
    serialised RPM header structures. Each header is:
      * 8-byte header magic + reserved
      * 4-byte index entry count (big-endian)
      * 4-byte data section length (big-endian)
      * <count> × 16-byte index entries (tag, type, offset, count)
      * data section

    We walk the index, find the entries we want (NAME, VERSION,
    RELEASE, EPOCH), and pull their string values from the data
    section. The version we emit is ``[<epoch>:]<version>-<release>``
    matching what OSV expects for RPM ecosystem entries.

    SQLite is parsed via stdlib ``sqlite3`` against a tempfile
    copy of the bytes — sqlite3 wants a path, not bytes. The
    tempfile is auto-cleaned on context exit.
    """
    out: list[InstalledPackage] = []
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix="raptor-rpm-", suffix=".sqlite", delete=False,
        ) as fp:
            tmp_path = Path(fp.name)
            fp.write(content)
        # ``mode=ro`` URI open guards against any accidental writes.
        conn = sqlite3.connect(
            f"file:{tmp_path}?mode=ro", uri=True,
        )
        try:
            # The database bytes come from an image layer, so the engine
            # runs in its least-trusting configuration: no extension
            # loading, no SQL from the schema itself (a view named
            # ``Packages`` would otherwise execute its author's
            # expressions when selected), cell-size validation against
            # corrupt pages, and a heap ceiling so a crafted DB can't
            # balloon the host process.
            with contextlib.suppress(AttributeError):
                conn.enable_load_extension(False)
            cur = conn.cursor()
            try:
                cur.execute("PRAGMA trusted_schema=OFF")
                cur.execute("PRAGMA cell_size_check=ON")
                cur.execute("PRAGMA hard_heap_limit=268435456")  # 256 MB
                row = cur.execute(
                    "SELECT type, sql FROM sqlite_master "
                    "WHERE name = 'Packages'",
                ).fetchone()
                if row is None:
                    logger.debug(
                        "core.oci.sbom: rpmdb.sqlite has no Packages "
                        "object; skipping",
                    )
                    return out
                obj_type, obj_sql = row[0], row[1] or ""
                if obj_type != "table" or re.match(
                    r"\s*CREATE\s+VIRTUAL\s+TABLE", obj_sql, re.IGNORECASE,
                ):
                    # Only a plain table is acceptable — views and
                    # virtual tables evaluate schema-author SQL/module
                    # code on SELECT.
                    logger.debug(
                        "core.oci.sbom: Packages is %s, not a plain "
                        "table; skipping", obj_type,
                    )
                    return out
                cur.execute("SELECT blob FROM Packages")
            except sqlite3.Error as e:
                logger.debug(
                    "core.oci.sbom: rpmdb.sqlite unreadable (%s); "
                    "skipping", e,
                )
                return out
            for (blob,) in cur:
                if not isinstance(blob, (bytes, bytearray)):
                    continue
                pkg = _parse_rpm_header(bytes(blob))
                if pkg is not None:
                    _check_record_cap(out, "rpmdb.sqlite")
                    out.append(pkg)
        finally:
            conn.close()
    finally:
        if tmp_path is not None:
            try:
                tmp_path.unlink()
            except OSError:
                pass
    return out


def _parse_rpm_header(blob: bytes) -> InstalledPackage | None:
    """Parse one RPM header blob → InstalledPackage.

    Tolerant: malformed / truncated headers return None rather
    than raising, so a single corrupt row in rpmdb.sqlite doesn't
    abort the whole layer's SBOM.
    """
    # Header structure:
    #   bytes  0..2    magic 0x8e 0xad 0xe8
    #   byte   3       version (== 1)
    #   bytes  4..7    reserved
    #   bytes  8..11   index entry count (uint32 big-endian)
    #   bytes 12..15   data section length (uint32 big-endian)
    #   bytes 16..16+count*16   index entries
    #   <data section follows>
    if len(blob) < 16:
        return None
    if blob[0:3] != b"\x8e\xad\xe8":
        return None
    try:
        count = struct.unpack(">I", blob[8:12])[0]
        data_len = struct.unpack(">I", blob[12:16])[0]
    except struct.error:
        return None
    index_end = 16 + count * 16
    data_start = index_end
    data_end = data_start + data_len
    if data_end > len(blob):
        return None

    fields: dict = {}
    for i in range(count):
        entry_off = 16 + i * 16
        try:
            tag, typ, off, _cnt = struct.unpack(
                ">IIII", blob[entry_off:entry_off + 16],
            )
        except struct.error:
            continue
        if tag in (_RPMTAG_NAME, _RPMTAG_VERSION, _RPMTAG_RELEASE) \
                and typ == _RPMTAG_TYPE_STRING:
            value = _read_rpm_string(blob, data_start + off, data_end)
            if value is not None:
                fields[tag] = value
        elif tag == _RPMTAG_EPOCH and typ == _RPMTAG_TYPE_INT32:
            epoch_off = data_start + off
            if epoch_off + 4 <= len(blob):
                fields[_RPMTAG_EPOCH] = struct.unpack(
                    ">i", blob[epoch_off:epoch_off + 4],
                )[0]

    name = fields.get(_RPMTAG_NAME)
    version = fields.get(_RPMTAG_VERSION)
    release = fields.get(_RPMTAG_RELEASE)
    if not name or not version:
        return None
    epoch = fields.get(_RPMTAG_EPOCH)
    ver_str = f"{version}-{release}" if release else version
    full_version = f"{epoch}:{ver_str}" if epoch else ver_str
    # OSV's "Red Hat" ecosystem covers RHEL / Rocky / Alma / older
    # CentOS. SUSE / openSUSE use a separate ecosystem; we'd need
    # ``/etc/os-release`` parsing to distinguish. For now,
    # everything RPM lands under "Red Hat" — operators scanning
    # SUSE-based images get a debug note that the OSV match might
    # under-cover.
    return InstalledPackage(
        ecosystem="Red Hat", name=name, version=full_version,
    )


def _read_rpm_string(blob: bytes, offset: int, data_end: int) -> str | None:
    """RPM strings are NUL-terminated. Read from ``offset`` until
    NUL or end of data section; decode as UTF-8 (with permissive
    error handling for non-ASCII package descriptions)."""
    if offset < 0 or offset >= data_end:
        return None
    end = blob.find(b"\x00", offset, data_end)
    if end < 0:
        return None
    try:
        return blob[offset:end].decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        return None


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------


# Standard layer paths we look for, mapped to their parser.
LAYER_FILE_PATHS = {
    "var/lib/dpkg/status": parse_dpkg_status,
    "lib/apk/db/installed": parse_apk_installed,
    "var/lib/rpm/rpmdb.sqlite": parse_rpm_sqlite,
}

# Distro-identity files. Not package databases — they resolve WHICH
# OSV ecosystem the package rows belong to: dpkg serves both Debian
# and Ubuntu (disjoint advisory feeds with incompatible version
# streams — an Ubuntu ``…ubuntu2.1~18.04.23`` version held against a
# Debian fixed-range is meaningless), and Alpine's OSV index is
# sharded per release (``Alpine:v3.16``; the unsuffixed ecosystem
# returns nothing). ``etc/os-release`` is the standard location;
# ``usr/lib/os-release`` is the documented fallback.
OS_RELEASE_PATHS = ("etc/os-release", "usr/lib/os-release")

# Every layer path worth extracting — package DBs plus distro
# identity. Consumers drive :func:`extract_files_from_layer` with
# this set.
WANTED_LAYER_PATHS = tuple(LAYER_FILE_PATHS) + OS_RELEASE_PATHS


def parse_os_release(content: bytes) -> dict[str, str]:
    """Parse the ``KEY=value`` lines of an os-release file.

    Values may be double- or single-quoted. Unknown / malformed
    lines are skipped — the file is target-controlled, so this
    parser extracts and never trusts.
    """
    out: dict[str, str] = {}
    for line in content.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key.isidentifier():
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out[key] = value[:200]
    return out


def _resolve_distro_ecosystem(
    pkg: InstalledPackage, os_release: dict[str, str],
) -> str:
    """Map a package row's parser-assigned ecosystem to the OSV
    ecosystem the image's distro actually publishes under."""
    distro_id = (os_release.get("ID") or "").lower()
    if pkg.ecosystem == "Debian":
        family = {"debian": "Debian", "ubuntu": "Ubuntu"}.get(distro_id)
        if family:
            release = os_release.get("VERSION_ID") or os_release.get("VERSION_CODENAME") or ""
            return release_ecosystem(family, release) or family
        # ID_LIKE is not evidence of the parent's package release/origin.
        # Retain inventory, but leave release unknown for advisory consumers.
        return "Debian"
    if pkg.ecosystem == "Alpine":
        version_id = os_release.get("VERSION_ID") or ""
        parts = version_id.split(".")
        if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
            return f"Alpine:v{parts[0]}.{parts[1]}"
        # Release unknown (edge images carry a snapshot VERSION_ID)
        # — keep the bare ecosystem; the query returns nothing
        # rather than wrong-release matches.
        return "Alpine"
    return pkg.ecosystem


@dataclass(frozen=True)
class LayerPackagesResult:
    """Outcome of :func:`packages_from_layer_files`.

    ``failures`` maps package-db path → error summary for every
    known package-state file that was PRESENT but could not be
    parsed (rejected, corrupt, over the record cap). A non-empty
    mapping means the package inventory is PARTIAL — pre-fix these
    failures were logged at debug level and the result was
    indistinguishable from "this image has no such database".
    """
    packages: list[InstalledPackage]
    failures: dict[str, str]

    @property
    def complete(self) -> bool:
        return not self.failures


def packages_from_layer_files(
    layer_files: dict,
) -> LayerPackagesResult:
    """Dispatch each known path through its parser. Used by the
    consumer pipeline as the post-:func:`extract_files_from_layer`
    step.

    Multi-layer images: each layer's call to this helper returns
    its own package set; the caller overlays later-layer packages
    onto earlier-layer ones (later wins on name collision — that's
    Docker's overlay semantics for state files).

    Parser failures are surfaced in the result's ``failures``
    mapping (and logged at WARNING) so callers can distinguish an
    absent database from a rejected or unparseable one.
    """
    os_release: dict[str, str] = {}
    for path in OS_RELEASE_PATHS:
        if path in layer_files:
            os_release = parse_os_release(layer_files[path])
            break

    out: list[InstalledPackage] = []
    failures: dict[str, str] = {}
    for path, parser in LAYER_FILE_PATHS.items():
        if path in layer_files:
            try:
                parsed = parser(layer_files[path])
            except Exception as e:                  # noqa: BLE001
                failures[path] = f"{type(e).__name__}: {e}"
                logger.warning(
                    "core.oci.sbom: parser for %s failed (package "
                    "inventory will be partial): %s", path, e,
                )
                continue
            for pkg in parsed:
                eco = _resolve_distro_ecosystem(pkg, os_release)
                out.append(
                    pkg if eco == pkg.ecosystem
                    else InstalledPackage(
                        ecosystem=eco, name=pkg.name,
                        version=pkg.version,
                    )
                )
    return LayerPackagesResult(packages=out, failures=failures)


__all__ = [
    "LAYER_FILE_PATHS",
    "MAX_PACKAGE_RECORDS",
    "OS_RELEASE_PATHS",
    "WANTED_LAYER_PATHS",
    "InstalledPackage",
    "LayerPackagesResult",
    "PackageDbLimitExceeded",
    "packages_from_layer_files",
    "parse_apk_installed",
    "parse_dpkg_status",
    "parse_os_release",
    "parse_rpm_sqlite",
]
