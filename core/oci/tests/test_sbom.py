"""Tests for ``core.oci.sbom`` — package-state file parsers.

Each format gets fixture data captured from a real image build
(stripped to a few representative entries to keep tests
self-contained). Pinning the parsers via fixtures guards against
regressions when format quirks shift.
"""

from __future__ import annotations

import sqlite3
import struct
from pathlib import Path

from core.oci.sbom import (
    InstalledPackage,
    LAYER_FILE_PATHS,
    packages_from_layer_files,
    parse_apk_installed,
    parse_dpkg_status,
    parse_rpm_sqlite,
)


# ---------------------------------------------------------------------------
# dpkg / Debian status parsing
# ---------------------------------------------------------------------------


_DPKG_FIXTURE = b"""\
Package: libc6
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 12345
Maintainer: GNU Libc Maintainers <[email protected]>
Architecture: amd64
Source: glibc
Version: 2.36-9+deb12u4
Replaces: libc6-i386
Provides: libc6-2.36
Depends: libgcc-s1 (>= 12)
Description: GNU C Library: Shared libraries
 Contains the standard libraries that are used by nearly all programs on
 the system.

Package: openssl
Status: install ok installed
Priority: standard
Section: utils
Installed-Size: 1234
Maintainer: Debian OpenSSL Team
Architecture: amd64
Multi-Arch: foreign
Version: 3.0.11-1~deb12u2
Description: Secure Sockets Layer toolkit

Package: removed-pkg
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0-1
Description: Was removed; only config files remain

Package: half-installed
Status: install reinstreq half-installed
Architecture: amd64
Version: 0.5-1
Description: Half-broken state
"""


def test_parse_dpkg_emits_only_fully_installed():
    """Skip ``deinstall`` (removed but config files retained) and
    ``half-installed`` states. Only ``install ok installed`` →
    real install with versions OSV can match."""
    pkgs = parse_dpkg_status(_DPKG_FIXTURE)
    names = {p.name for p in pkgs}
    assert "libc6" in names
    assert "openssl" in names
    assert "removed-pkg" not in names
    assert "half-installed" not in names


def test_parse_dpkg_extracts_version():
    pkgs = parse_dpkg_status(_DPKG_FIXTURE)
    by_name = {p.name: p for p in pkgs}
    assert by_name["libc6"].version == "2.36-9+deb12u4"
    assert by_name["openssl"].version == "3.0.11-1~deb12u2"


def test_parse_dpkg_ecosystem_is_debian():
    pkgs = parse_dpkg_status(_DPKG_FIXTURE)
    assert all(p.ecosystem == "Debian" for p in pkgs)


def test_parse_dpkg_handles_missing_fields():
    """A stanza missing ``Package`` or ``Version`` is silently
    skipped — defends against partial corruption without aborting
    the whole layer's SBOM."""
    fixture = b"""\
Package: incomplete
Status: install ok installed
Architecture: amd64

Package: complete
Status: install ok installed
Version: 1.0
Architecture: amd64
"""
    pkgs = parse_dpkg_status(fixture)
    assert {p.name for p in pkgs} == {"complete"}


def test_parse_dpkg_empty_input():
    assert parse_dpkg_status(b"") == []


def test_parse_dpkg_continuation_lines_dont_break_other_fields():
    """Multi-line ``Description:`` value (continuation indented)
    must not consume the next field's parsing."""
    fixture = b"""\
Package: foo
Status: install ok installed
Description: A package
 with a multi-line
 description.
Version: 1.0
Architecture: amd64
"""
    pkgs = parse_dpkg_status(fixture)
    assert len(pkgs) == 1
    assert pkgs[0].version == "1.0"


# ---------------------------------------------------------------------------
# apk / Alpine
# ---------------------------------------------------------------------------


_APK_FIXTURE = b"""\
P:musl
V:1.2.4-r2
A:x86_64
S:123456
I:614400
T:the musl c library (libc) implementation
U:https://musl.libc.org/
L:MIT
o:musl
m:Timo Teras <[email protected]>
t:1234567890
c:abc123
F:lib

P:busybox
V:1.36.1-r5
A:x86_64
T:Size optimized toolbox of many common UNIX utilities

P:zlib
V:1.2.13-r1
A:x86_64
"""


def test_parse_apk_simple():
    pkgs = parse_apk_installed(_APK_FIXTURE)
    by_name = {p.name: p for p in pkgs}
    assert by_name["musl"].version == "1.2.4-r2"
    assert by_name["busybox"].version == "1.36.1-r5"
    assert by_name["zlib"].version == "1.2.13-r1"


def test_parse_apk_ecosystem_is_alpine():
    pkgs = parse_apk_installed(_APK_FIXTURE)
    assert all(p.ecosystem == "Alpine" for p in pkgs)


def test_parse_apk_missing_version_skipped():
    """A stanza without a ``V:`` line can't be matched against OSV;
    skip rather than emit a versionless record."""
    fixture = b"P:incomplete\nA:x86_64\n\nP:complete\nV:1.0\n"
    pkgs = parse_apk_installed(fixture)
    assert {p.name for p in pkgs} == {"complete"}


def test_parse_apk_empty_input():
    assert parse_apk_installed(b"") == []


# ---------------------------------------------------------------------------
# RPM (sqlite-backed)
# ---------------------------------------------------------------------------


def _make_rpm_header(name: str, version: str, release: str) -> bytes:
    """Build a minimal RPM header blob for testing.

    Header structure (per ``rpm/lib/header.c``):
      magic 0x8e 0xad 0xe8 + 0x01 + 4 reserved bytes  (8)
      uint32 BE entry count                            (4)
      uint32 BE data section length                    (4)
      <count> × 16-byte index entries                  (16*count)
      data section
    """
    name_b = name.encode("utf-8") + b"\x00"
    ver_b = version.encode("utf-8") + b"\x00"
    rel_b = release.encode("utf-8") + b"\x00"
    data = name_b + ver_b + rel_b
    entries = []
    offset = 0
    for tag, length in (
        (1000, len(name_b)),     # NAME
        (1001, len(ver_b)),      # VERSION
        (1002, len(rel_b)),      # RELEASE
    ):
        entries.append(
            struct.pack(">IIII", tag, 6, offset, 1)
        )    # type=6 (string), count=1
        offset += length
    header = (
        b"\x8e\xad\xe8\x01" + b"\x00" * 4
        + struct.pack(">I", len(entries))
        + struct.pack(">I", len(data))
        + b"".join(entries)
        + data
    )
    return header


def _make_rpmdb_sqlite(packages: list) -> bytes:
    """Build a minimal rpmdb.sqlite with a ``Packages`` table
    holding our test header blobs."""
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite") as fp:
        path = Path(fp.name)
    try:
        conn = sqlite3.connect(str(path))
        conn.execute("CREATE TABLE Packages (hnum INTEGER, blob BLOB)")
        for i, (name, ver, rel) in enumerate(packages):
            blob = _make_rpm_header(name, ver, rel)
            conn.execute(
                "INSERT INTO Packages VALUES (?, ?)", (i, blob),
            )
        conn.commit()
        conn.close()
        return path.read_bytes()
    finally:
        try:
            path.unlink()
        except OSError:
            pass


def test_parse_rpm_sqlite_extracts_packages():
    sqlite_bytes = _make_rpmdb_sqlite([
        ("openssl-libs", "3.0.7", "27.el9_3"),
        ("glibc", "2.34", "100.el9"),
    ])
    pkgs = parse_rpm_sqlite(sqlite_bytes)
    by_name = {p.name: p for p in pkgs}
    assert by_name["openssl-libs"].version == "3.0.7-27.el9_3"
    assert by_name["glibc"].version == "2.34-100.el9"


def test_parse_rpm_sqlite_ecosystem_is_red_hat():
    sqlite_bytes = _make_rpmdb_sqlite([("openssl", "3.0.7", "1.el9")])
    pkgs = parse_rpm_sqlite(sqlite_bytes)
    assert all(p.ecosystem == "Red Hat" for p in pkgs)


def test_parse_rpm_sqlite_no_packages_table_returns_empty():
    """Defensive: a malformed sqlite without ``Packages`` table
    (or a different schema entirely) must not crash."""
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite") as fp:
        path = Path(fp.name)
    try:
        conn = sqlite3.connect(str(path))
        conn.execute("CREATE TABLE Other (x INTEGER)")
        conn.commit()
        conn.close()
        content = path.read_bytes()
    finally:
        try:
            path.unlink()
        except OSError:
            pass
    assert parse_rpm_sqlite(content) == []


def test_parse_rpm_sqlite_invalid_blob_skipped():
    """A row with an invalid header blob is skipped silently;
    other rows still parse."""
    sqlite_bytes = _make_rpmdb_sqlite([("good", "1.0", "1.el9")])
    # Hack: append a bad row by re-opening.
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite") as fp:
        path = Path(fp.name)
        fp.write(sqlite_bytes)
    try:
        conn = sqlite3.connect(str(path))
        conn.execute(
            "INSERT INTO Packages VALUES (?, ?)",
            (99, b"not a valid rpm header"),
        )
        conn.commit()
        conn.close()
        content = path.read_bytes()
    finally:
        try:
            path.unlink()
        except OSError:
            pass
    pkgs = parse_rpm_sqlite(content)
    assert len(pkgs) == 1
    assert pkgs[0].name == "good"


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------


def test_packages_from_layer_files_dispatches_correctly():
    layer_files = {
        "var/lib/dpkg/status":
            b"Package: foo\nStatus: install ok installed\nVersion: 1.0\n",
        "lib/apk/db/installed":
            b"P:bar\nV:2.0\n",
    }
    pkgs = packages_from_layer_files(layer_files)
    by_eco = {p.ecosystem: p.name for p in pkgs}
    assert by_eco["Debian"] == "foo"
    assert by_eco["Alpine"] == "bar"


def test_packages_from_layer_files_unknown_paths_ignored():
    """A layer with only unrelated files yields no packages —
    graceful no-op rather than an error."""
    layer_files = {
        "etc/passwd": b"root:x:0:0\n",
        "var/log/some.log": b"...",
    }
    assert packages_from_layer_files(layer_files) == []


def test_layer_file_paths_constant_lists_all_three():
    """The paths the blob extractor needs to ask for. Pinned so a
    new SBOM source (e.g. NPM lockfile inside an image — out of
    scope for now) doesn't accidentally drop one."""
    assert "var/lib/dpkg/status" in LAYER_FILE_PATHS
    assert "lib/apk/db/installed" in LAYER_FILE_PATHS
    assert "var/lib/rpm/rpmdb.sqlite" in LAYER_FILE_PATHS
