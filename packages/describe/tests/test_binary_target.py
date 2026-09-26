"""Tests for the /describe single-binary target arm: magic-keyed
dispatch in the CLI, the facts block renderers, escape-at-render for
target-derived names, and the pre-existing refusal path staying
intact for unrecognised files."""

from __future__ import annotations

import io
import json

import pytest

import core.binary.elf as elf_mod

from core.binary.tests.test_pe_facts import PeSpec, Sec, build_pe
from packages.binary_analysis.tests.test_macho_facts import (
    build_fat,
    build_thin,
    uuid_cmd,
)

from packages.describe.binary_target import (
    build_binary_report,
    format_binary_text,
    is_binary_target,
)
from packages.describe.cli import describe_main


@pytest.fixture(autouse=True)
def _stub_build_id(monkeypatch):
    """Hermetic: no sandboxed readelf spawns from identity probing on
    runners without the toolchain."""
    monkeypatch.setattr(elf_mod, "_read_build_id",
                        lambda p: (None, None))


def _run(target, json_output=False):
    out, err = io.StringIO(), io.StringIO()
    rc = describe_main(str(target), json_output=json_output,
                       stdout=out, stderr=err)
    return rc, out.getvalue(), err.getvalue()


def _pe_file(tmp_path, **spec_overrides):
    defaults = dict(
        dll_characteristics=0x0140,   # DYNAMIC_BASE | NX
        secs=[Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x40)],
    )
    defaults.update(spec_overrides)
    p = tmp_path / "app.exe"
    p.write_bytes(build_pe(PeSpec(**defaults)))
    return p


class TestCliDispatch:
    def test_pe_binary_gets_facts_block(self, tmp_path):
        rc, out, err = _run(_pe_file(tmp_path))
        assert rc == 0, err
        assert "Source: single binary app.exe" in out
        assert "Format: pe x86 64-bit little-endian" in out
        assert "aslr yes" in out
        assert "dep yes" in out
        assert "cfg no" in out
        assert "safeseh unknown" in out       # PE32+: None by definition
        assert "/understand" in out

    def test_macho_binary_gets_facts_block(self, tmp_path):
        p = tmp_path / "tool"
        p.write_bytes(build_thin([uuid_cmd()], flags=0x200000))
        rc, out, err = _run(p)
        assert rc == 0, err
        assert "Format: macho x86_64 64-bit little-endian" in out
        assert "pie yes" in out
        assert "Identity: macho_uuid" in out

    def test_json_mode_carries_derived_from_target(self, tmp_path):
        rc, out, err = _run(_pe_file(tmp_path), json_output=True)
        assert rc == 0, err
        doc = json.loads(out)
        assert doc["target_kind"] == "binary"
        assert doc["binary_facts"]["derived_from_target"] is True
        assert doc["binary_facts"]["mitigations"]["aslr"] is True
        assert doc["identity"]["kind"] == "pe_guid_age" or doc[
            "identity"]["kind"] == "sha256"

    def test_unrecognised_blob_still_refused_as_before(self, tmp_path):
        # The pre-existing refusal path is untouched for files with
        # no binary magic and no archive format.
        blob = tmp_path / "mystery.bin"
        blob.write_bytes(b"\x00\x01\x02RANDOMBYTES\xff" * 100)
        rc, out, err = _run(blob)
        assert rc == 1
        assert "not a recognised archive" in err

    def test_binary_magic_with_broken_headers_errors_clearly(
            self, tmp_path):
        p = tmp_path / "stub.exe"
        blob = bytearray(b"MZ" + b"\x00" * 126)
        blob[0x3C:0x40] = (0xFFFF).to_bytes(4, "little")
        p.write_bytes(bytes(blob))
        rc, out, err = _run(p)
        assert rc == 1
        assert "headers do not parse" in err
        assert "not a recognised archive" not in err

    def test_tar_with_mz_member_name_keeps_archive_path(
            self, tmp_path):
        # The binary magic sets are NOT disjoint from the archive
        # signatures: a tar's first bytes are its first member NAME.
        # A valid tar whose first member starts "MZ" must keep its
        # extraction path — never hard-fail as a malformed PE.
        # Mutation witness: drop the is_archive consult in
        # _describe_binary and this fails with rc=1.
        import tarfile
        data = b"just text, named like a DOS stub\n"
        member = tarfile.TarInfo("MZapp.txt")
        member.size = len(data)
        archive = tmp_path / "src.tar"
        # USTAR format: the default PAX format would prepend an
        # extended-header member, hiding the name-at-offset-0
        # collision this test exists to exercise.
        with tarfile.open(archive, "w",
                          format=tarfile.USTAR_FORMAT) as tf:
            tf.addfile(member, io.BytesIO(data))
        # The collision is real: the raw tar bytes carry the MZ
        # binary magic at offset 0.
        assert archive.read_bytes()[:2] == b"MZ"
        assert is_binary_target(archive) is True
        rc, out, err = _run(archive)
        assert rc == 0, err
        assert "headers do not parse" not in err
        assert "src.tar" in out

    def test_broken_binary_error_escapes_hostile_path(self, tmp_path):
        # The refusal message interpolates the resolved path, which
        # can traverse target-controlled directory names — control
        # bytes must leave stderr escaped, never raw.
        hostile_dir = tmp_path / "e\x1b[31mvil"
        hostile_dir.mkdir()
        p = hostile_dir / "stub.exe"
        blob = bytearray(b"MZ" + b"\x00" * 126)
        blob[0x3C:0x40] = (0xFFFF).to_bytes(4, "little")
        p.write_bytes(bytes(blob))
        rc, out, err = _run(p)
        assert rc == 1
        assert "headers do not parse" in err
        assert "\x1b" not in err
        assert "\\x1b" in err


class TestRenderEscaping:
    def test_hostile_section_name_escaped_in_text(self, tmp_path):
        p = tmp_path / "evil.exe"
        p.write_bytes(build_pe(PeSpec(
            secs=[Sec(name=b".t\x1b[31mx", va=0x1000,
                      data=b"\xcc" * 0x40)],
        )))
        report = build_binary_report(p)
        assert report is not None
        text = format_binary_text(report)
        assert "\x1b" not in text
        assert "\\x1b" in text

    def test_hostile_name_never_raw_in_json(self, tmp_path):
        p = tmp_path / "evil.exe"
        p.write_bytes(build_pe(PeSpec(
            secs=[Sec(name=b".t\x1b[31mx", va=0x1000,
                      data=b"\xcc" * 0x40)],
        )))
        rc, out, err = _run(p, json_output=True)
        assert rc == 0, err
        # ensure_ascii keeps the ESC byte as a ``\u001b`` escape
        # on the wire; the raw control byte never reaches the
        # stream.
        assert "\x1b" not in out
        assert "\\u001b" in out


class TestProbe:
    def test_probe_matches_dispatch_set(self, tmp_path):
        # Full-set agreement with the facts dispatcher: the probe
        # answers True on well-formed fixtures of EVERY format the
        # dispatcher serves (ELF, PE, thin Mach-O, fat Mach-O) — and
        # the dispatcher serves each — so neither surface can grow a
        # format the other silently lacks.
        from core.binary.facts import extract_format_facts
        from core.binary.tests.test_elf_facts import _standard_fixture
        thin = build_thin([uuid_cmd()])
        positives = {
            "app.exe": build_pe(PeSpec(
                secs=[Sec(name=b".text", va=0x1000,
                          data=b"\xcc" * 0x40)])),
            "app.elf": _standard_fixture(),
            "thin.macho": thin,
            "fat.macho": build_fat([thin]),
        }
        for name, blob in positives.items():
            p = tmp_path / name
            p.write_bytes(blob)
            assert is_binary_target(p) is True, name
            assert extract_format_facts(p) is not None, name
        junk = tmp_path / "junk"
        junk.write_bytes(b"PK\x03\x04not-a-binary")
        assert is_binary_target(junk) is False
        assert extract_format_facts(junk) is None
        assert is_binary_target(tmp_path / "absent") is False
