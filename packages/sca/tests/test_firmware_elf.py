"""Tests for packages.sca.firmware_elf — firmware ELF component
version extraction and its Debian-ecosystem Dependency rows."""

from __future__ import annotations

import struct

from packages.sca.firmware_elf import (
    ComponentHit,
    _scan_bytes,
    _upstream_of,
    firmware_components_to_dependencies,
    map_debian_version,
    scan_firmware_components,
)


def _elf_bytes(payload: bytes = b"") -> bytes:
    """Minimal parseable little-endian 32-bit ELF + payload bytes."""
    ident = b"\x7fELF" + bytes([1, 1, 1]) + b"\x00" * 9
    header = struct.pack("<HHIIIIIHHHHHH", 2, 0x28, 1,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return ident + header + payload


class TestScanBytes:
    def test_busybox_and_openssl(self):
        data = (b"\x00BusyBox v1.30.1 (2019-02-14)\x00"
                b"junk OpenSSL 1.0.2k\x00 more")
        found = {p.component: v for p, v in _scan_bytes(data)}
        assert found == {"busybox": "1.30.1", "openssl": "1.0.2k"}

    def test_dropbear_variants(self):
        for blob, want in [
            (b"SSH-2.0-dropbear_2019.78\x00", "2019.78"),
            (b"Dropbear v2022.83\x00", "2022.83"),
        ]:
            found = {p.component: v for p, v in _scan_bytes(blob)}
            assert found.get("dropbear") == want, blob

    def test_most_common_version_wins(self):
        data = (b"BusyBox v1.30.1\x00BusyBox v1.30.1\x00BusyBox v1.24.0\x00")
        found = {p.component: v for p, v in _scan_bytes(data)}
        assert found["busybox"] == "1.30.1"

    def test_binary_noise_yields_nothing(self):
        assert _scan_bytes(bytes(range(256)) * 64) == []


class TestUpstreamOf:
    def test_strip_epoch_revision_suffixes(self):
        assert _upstream_of("1:1.30.1-4+deb10u1") == "1.30.1"
        assert _upstream_of("2022.83-1") == "2022.83"
        assert _upstream_of("1.1.1n-0+deb11u5") == "1.1.1n"
        assert _upstream_of("1.2.11+dfsg-2") == "1.2.11"
        assert _upstream_of("2.9~rc3-1") == "2.9"

    def test_really_marks_the_actual_upstream(self):
        # +really is a downgrade-in-disguise: the packaged upstream is
        # what FOLLOWS the marker.
        assert _upstream_of("1:1.3.5+really1.3.4-1") == "1.3.4"


class _FakeMadison:
    def __init__(self, versions):
        self._versions = versions
        self.queried: list[str] = []

    def list_versions(self, name):
        self.queried.append(name)
        return self._versions


class TestMapDebianVersion:
    def test_oldest_matching_revision_is_the_floor(self):
        """Later Debian revisions carry security patches a vendor
        firmware build lacks — the OLDEST matching revision keeps
        fixed-in-revision advisories applicable."""
        client = _FakeMadison([
            "1:1.35.0-4", "1:1.30.1-6+deb10u1", "1:1.30.1-4", "1:1.22.0-9",
        ])
        assert map_debian_version(client, "busybox", "1.30.1") == "1:1.30.1-4"

    def test_no_match_returns_none(self):
        client = _FakeMadison(["1:1.35.0-4"])
        assert map_debian_version(client, "busybox", "9.9.9") is None

    def test_client_failure_returns_none(self):
        class Boom:
            def list_versions(self, name):
                raise RuntimeError("network refused")
        assert map_debian_version(Boom(), "busybox", "1.30.1") is None


class TestDependencies:
    def _hits(self):
        return [
            ComponentHit("busybox", "busybox", "busybox", "1.30.1", "bin/busybox"),
            ComponentHit("busybox", "busybox", "busybox", "1.30.1", "bin/ash"),
            ComponentHit("zlib", "zlib", "zlib1g", "1.2.11", "lib/libz.so.1"),
        ]

    def test_grouped_rows_with_madison_mapping(self, tmp_path):
        client = _FakeMadison(["1:1.30.1-6+deb10u1"])
        deps = firmware_components_to_dependencies(
            self._hits(), firmware_root=tmp_path, debian_client=client,
        )
        # single matching revision — mapped verbatim
        assert [d.name for d in deps] == ["busybox", "zlib"]
        busybox = deps[0]
        assert busybox.ecosystem == "Debian"
        assert busybox.version == "1:1.30.1-6+deb10u1"
        assert busybox.source_kind == "firmware_elf"
        assert busybox.source_extra["upstream_version"] == "1.30.1"
        assert busybox.source_extra["binaries"] == ["bin/ash", "bin/busybox"]
        assert busybox.purl == "pkg:deb/debian/busybox@1:1.30.1-6+deb10u1"
        # madison keyed on the BINARY package name (zlib1g, not zlib)
        assert client.queried == ["busybox", "zlib1g"]

    def test_offline_uses_raw_upstream(self, tmp_path):
        deps = firmware_components_to_dependencies(
            self._hits(), firmware_root=tmp_path, debian_client=None,
        )
        assert deps[0].version == "1.30.1"
        assert deps[0].source_extra["debian_version"] is None


class TestScanRoot:
    def test_end_to_end_over_fixture_root(self, tmp_path):
        (tmp_path / "bin").mkdir()
        (tmp_path / "bin/busybox").write_bytes(
            _elf_bytes(b"\x00BusyBox v1.30.1 (2019)\x00"))
        (tmp_path / "bin/dropbear").write_bytes(
            _elf_bytes(b"\x00SSH-2.0-dropbear_2019.78\x00"))
        # Non-ELF file with a version string must NOT be scanned.
        (tmp_path / "bin/notes.txt").write_bytes(b"BusyBox v9.9.9\n")
        hits = scan_firmware_components(tmp_path)
        got = {(h.component, h.version, h.binary) for h in hits}
        assert got == {
            ("busybox", "1.30.1", "bin/busybox"),
            ("dropbear", "2019.78", "bin/dropbear"),
        }


class TestPipelineIntegration:
    def test_offline_run_sca_emits_firmware_components(self, tmp_path):
        """Functional pin for the pipeline's 1d stage wiring: an
        offline run over a firmware root must land the extracted
        components in the SBOM (extraction is local; madison mapping
        is online-only enrichment)."""
        import json

        from packages.sca.pipeline import RunOptions, run_sca

        root = tmp_path / "fw"
        (root / "bin").mkdir(parents=True)
        (root / "bin/busybox").write_bytes(
            _elf_bytes(b"\x00BusyBox v1.30.1 (2019)\x00"))
        out = tmp_path / "out"
        opts = RunOptions(
            offline=True, no_cache=True, cache_root=tmp_path / "cache",
            firmware_root=root,
            enable_llm_review=False, enable_triage=False,
            enable_progress=False,
        )
        run_sca(root, out, opts)
        sbom = json.loads((out / "sbom.cdx.json").read_text())
        comps = {(c.get("name"), c.get("version"))
                 for c in sbom.get("components", [])}
        assert ("busybox", "1.30.1") in comps
