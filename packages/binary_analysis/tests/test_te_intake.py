"""TE (Terse Executable) intake: classify-and-decline.

The kind is "te", deliberately NOT a "pe-" kind — these tests pin
the two consumer misfires that spelling avoids (a UEFI image must
not be platform-labelled "windows", and must not receive the
Windows driver-symbol ingress probing), the intake marker that
records the decline, and the PE facts extractor's refusal to parse
the format.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from core.binary.pe import extract_pe_facts, is_pe
from packages.binary_analysis.ingress import recover_external_ingress
from packages.binary_analysis.manifest import (
    BinaryManifest,
    build_manifest,
    platform_label,
)

# "VZ" signature + x86_64 machine + padding.
_TE_BYTES = b"VZ" + (0x8664).to_bytes(2, "little") + b"\x00" * 60


def _te_file(tmp_path: Path) -> Path:
    path = tmp_path / "driver.te"
    path.write_bytes(_TE_BYTES)
    path.chmod(0o755)
    return path


def _manifest(path: Path, target_kind: str) -> BinaryManifest:
    return BinaryManifest(
        schema_version=1,
        binary_path=str(path),
        binary_sha256="a" * 64,
        size_bytes=path.stat().st_size,
        executable=True,
        target_kind=target_kind,
        arch="x86_64",
        bits=64,
        binary_format=target_kind,
        exports=["DriverEntry", "DispatchDeviceControl"],
    )


def test_platform_label_is_generic_not_windows() -> None:
    """The counterfactual "pe-te" spelling would match the
    startswith("pe-") arm and label UEFI firmware "windows"."""
    assert platform_label(SimpleNamespace(target_kind="te")) == "generic"


def test_te_skips_windows_driver_ingress_probing(tmp_path: Path) -> None:
    """Driver-symbol probing is the pe- prefix's other consumer:
    the same export/function surface yields ioctl candidates for a
    Windows driver and NONE for a TE image."""
    te = _te_file(tmp_path)
    context = {
        "interesting_functions": [{
            "id": "BFN-5000",
            "name": "DispatchDeviceControl",
            "address": "0x5000",
        }],
        "surface_details": [],
        "sources": [],
    }

    te_ingress, _ = recover_external_ingress(
        _manifest(te, "te"), context)
    assert not any(item["kind"] == "ioctl_dispatch"
                   for item in te_ingress)
    assert not any(item["kind"] == "driver_initialisation"
                   for item in te_ingress)

    # Control: the identical surface on a real Windows driver kind
    # DOES probe — proving the te result is the kind's doing.
    pe_ingress, _ = recover_external_ingress(
        _manifest(te, "pe-sys"), context)
    assert any(item["kind"] == "ioctl_dispatch"
               for item in pe_ingress)


def test_build_manifest_records_te_not_analysed(tmp_path: Path) -> None:
    manifest = build_manifest(_te_file(tmp_path))
    assert manifest.target_kind == "te"
    assert platform_label(manifest) == "generic"
    # Composed with the identity front door (phase C): TE carries the
    # front door's sha256 fallback identity — no ELF probe engaged,
    # the whole-file content hash stands in as the module identity.
    assert manifest.identity_kind == "sha256"
    assert manifest.build_id == manifest.binary_sha256
    assert manifest.build_id != ""
    intake = next(item for item in manifest.evidence
                  if item.kind == "binary_intake")
    assert intake.data.get("markers") == ["te_not_analysed"]


def test_non_te_manifest_carries_no_te_marker(tmp_path: Path) -> None:
    path = tmp_path / "prog.exe"
    data = bytearray(b"\x00" * 256)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"
    data[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(bytes(data))
    manifest = build_manifest(path)
    intake = next(item for item in manifest.evidence
                  if item.kind == "binary_intake")
    assert "markers" not in intake.data


def test_te_is_not_a_binary_understand_kind() -> None:
    """The radare2-backed binary-understand path is keyed on an
    explicit kind allowlist; "te" must stay off it — the te loader
    is deliberately not engaged against hostile firmware images."""
    from packages.fuzzing.orchestrator import _BINARY_UNDERSTAND_KINDS
    assert "te" not in _BINARY_UNDERSTAND_KINDS


def test_pe_facts_extractor_refuses_te(tmp_path: Path) -> None:
    """extract_pe_facts does not parse TE (no DOS/COFF header) —
    refusal is whole-parse None, and the cheap probe agrees."""
    te = _te_file(tmp_path)
    assert extract_pe_facts(te) is None
    assert is_pe(te) is False
