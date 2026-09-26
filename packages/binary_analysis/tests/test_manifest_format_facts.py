"""Tests for the manifest's per-kind format-facts arms: PE kinds
attach a ``pe_facts`` evidence record, Mach-O attaches
``macho_facts``, TE and ELF kinds attach neither (TE is classified
and declined; the ELF facts extractor's build-id probe would spawn a
second sandboxed readelf per manifest for data no consumer reads
yet — a deliberate, pinned absence)."""

from __future__ import annotations

from pathlib import Path

import core.binary.elf as elf_mod
import pytest

from core.binary.tests.test_elf_facts import _standard_fixture
from core.binary.tests.test_pe_facts import PeSpec, Sec, build_pe

from packages.binary_analysis.manifest import build_manifest

from .test_macho_facts import build_thin, uuid_cmd


@pytest.fixture(autouse=True)
def _stub_build_id(monkeypatch):
    """Hermetic: no sandboxed readelf spawns from the ELF identity
    probe on runners without the toolchain."""
    monkeypatch.setattr(elf_mod, "_read_build_id",
                        lambda p: (None, None))


def _facts_records(manifest):
    # Suffix filter, NOT an exact-kind set: the absence pins below
    # (TE, ELF) must stay non-vacuous against any FUTURE facts arm
    # — an exact {"pe_facts", "macho_facts"} set would silently pass
    # while e.g. an "elf_facts" record slipped in unasserted.
    return [item for item in manifest.evidence
            if item.kind.endswith("_facts")]


def test_pe_manifest_attaches_pe_facts(tmp_path: Path) -> None:
    p = tmp_path / "app.exe"
    p.write_bytes(build_pe(PeSpec(
        dll_characteristics=0x0140,   # DYNAMIC_BASE | NX
        secs=[Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x40)],
    )))
    manifest = build_manifest(p)
    assert manifest.target_kind.startswith("pe-")
    records = _facts_records(manifest)
    assert len(records) == 1
    record = records[0]
    assert record.kind == "pe_facts"
    facts = record.data["facts"]
    assert facts["aslr"] is True
    assert facts["dep"] is True
    assert [s["name"] for s in facts["sections"]] == [".text"]


def test_macho_manifest_attaches_macho_facts(tmp_path: Path) -> None:
    p = tmp_path / "app"
    p.write_bytes(build_thin([uuid_cmd()], flags=0x200000))  # MH_PIE
    manifest = build_manifest(p)
    assert manifest.target_kind == "macho"
    records = _facts_records(manifest)
    assert len(records) == 1
    record = records[0]
    assert record.kind == "macho_facts"
    slices = record.data["facts"]["slices"]
    assert len(slices) == 1
    assert slices[0]["pie"] is True
    assert slices[0]["uuid"] == bytes(range(16)).hex()


def test_te_manifest_attaches_no_facts(tmp_path: Path) -> None:
    p = tmp_path / "firmware.efi"
    p.write_bytes(b"VZ" + b"\x00" * 62)
    manifest = build_manifest(p)
    assert manifest.target_kind == "te"
    assert _facts_records(manifest) == []


def test_elf_manifest_attaches_no_facts(tmp_path: Path) -> None:
    # The deliberate absence: ELF kinds have no facts arm (see the
    # module docstring) — this pin makes adding one a conscious,
    # test-visible decision.
    p = tmp_path / "app"
    p.write_bytes(_standard_fixture())
    manifest = build_manifest(p)
    assert manifest.target_kind == "elf-linux"
    assert _facts_records(manifest) == []


def test_unparsable_pe_degrades_facts_free(tmp_path: Path) -> None:
    # MZ magic with e_lfanew past EOF: the detector calls it PE (its
    # own grain), the facts extractor refuses it, and the manifest
    # builds facts-free instead of failing the intake.
    p = tmp_path / "stub.exe"
    blob = bytearray(b"MZ" + b"\x00" * 126)
    blob[0x3C:0x40] = (0xFFFF).to_bytes(4, "little")
    p.write_bytes(bytes(blob))
    manifest = build_manifest(p)
    assert manifest.target_kind.startswith("pe-")
    assert _facts_records(manifest) == []
