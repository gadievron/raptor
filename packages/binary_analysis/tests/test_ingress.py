"""Cross-platform external ingress and fuzz-strategy tests."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from packages.binary_analysis.fuzz_suitability import assess_fuzz_suitability
from packages.binary_analysis.ingress import recover_external_ingress
from packages.binary_analysis.topology import build_component_topology


def _write_binary(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    path.chmod(0o755)
    return path


def _manifest(path: Path, *, target_kind: str, exports: list[str] | None = None, app_bundle=None):
    return SimpleNamespace(
        binary_path=str(path),
        binary_sha256="a" * 64,
        target_kind=target_kind,
        exports=list(exports or []),
        app_bundle=app_bundle,
    )


def _pe_fixture() -> bytes:
    data = bytearray(b"\x00" * 256)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"
    data[0x84:0x86] = (0x8664).to_bytes(2, "little")
    return bytes(data)


def test_macos_callback_ingress_drives_harness_extraction_not_whole_app_fuzz(tmp_path: Path) -> None:
    binary = _write_binary(tmp_path / "Demo", b"\xcf\xfa\xed\xfe" + b"\x00" * 128)
    manifest = _manifest(
        binary,
        target_kind="macho",
        app_bundle=SimpleNamespace(
            bundle_path=str(tmp_path / "Demo.app"),
            url_schemes=["demo"],
            document_types=[],
            identifier="com.example.demo",
            privileged_executables=[],
            helper_tools=[],
            xpc_services=[],
        ),
    )
    context = {
        "framework_callback_candidates": [{
            "class_name": "Demo.AppDelegate",
            "method_name": "application:openURLs:",
            "bound_function_id": "BFN-1000",
            "bound_function_name": "method.Demo.AppDelegate.application:openURLs:",
            "address": "0x1000",
            "evidence_ids": ["EV-1"],
        }],
        "interesting_functions": [{
            "id": "BFN-1000",
            "name": "method.Demo.AppDelegate.application:openURLs:",
            "address": "0x1000",
        }],
        "surface_details": [],
        "sources": [],
    }

    ingress, _ = recover_external_ingress(manifest, context)
    topology = build_component_topology(manifest, ingress)
    suitability = assess_fuzz_suitability(manifest, context, ingress, topology)

    assert ingress[0]["kind"] == "url_handler"
    assert ingress[0]["bound_function_id"] == "BFN-1000"
    assert any(item["kind"] == "external_to_process" for item in topology["boundaries"])
    assert suitability["strategy"] == "extract_harness_from_ingress"
    assert suitability["direct_campaign_recommended"] is False


def test_windows_dll_exports_bind_to_recovered_functions(tmp_path: Path) -> None:
    binary = _write_binary(tmp_path / "codec.dll", _pe_fixture())
    manifest = _manifest(binary, target_kind="pe-dll", exports=["DecodePacket"])
    context = {
        "interesting_functions": [{
            "id": "BFN-401000",
            "name": "DecodePacket",
            "address": "0x401000",
        }],
        "surface_details": [],
        "sources": [],
    }

    ingress, _ = recover_external_ingress(manifest, context)
    topology = build_component_topology(manifest, ingress)
    suitability = assess_fuzz_suitability(manifest, context, ingress, topology)

    exported = next(item for item in ingress if item["kind"] == "exported_api")
    assert exported["bound_function_id"] == "BFN-401000"
    assert exported["boundary"] == "caller_to_library"
    assert suitability["strategy"] == "extract_export_harness"


def test_windows_and_linux_driver_symbols_are_treated_as_ioctl_boundaries(tmp_path: Path) -> None:
    pe_binary = _write_binary(tmp_path / "demo.sys", _pe_fixture())
    pe_manifest = _manifest(pe_binary, target_kind="pe-sys")
    pe_context = {
        "interesting_functions": [{
            "id": "BFN-5000",
            "name": "EvtIoDeviceControl",
            "address": "0x5000",
        }],
        "surface_details": [],
        "sources": [],
    }

    pe_ingress, _ = recover_external_ingress(pe_manifest, pe_context)
    pe_topology = build_component_topology(pe_manifest, pe_ingress)
    pe_suitability = assess_fuzz_suitability(pe_manifest, pe_context, pe_ingress, pe_topology)
    assert any(item["kind"] == "ioctl_dispatch" for item in pe_ingress)
    assert pe_suitability["strategy"] == "snapshot_or_ioctl_harness"
    assert pe_suitability["runtime_strategy"] == "kernel_harness_required"

    ko_binary = _write_binary(tmp_path / "demo.ko", b"\x7fELF" + b"\x00" * 128)
    ko_manifest = _manifest(ko_binary, target_kind="elf-kmod")
    ko_context = {
        "interesting_functions": [{
            "id": "BFN-6000",
            "name": "demo_unlocked_ioctl",
            "address": "0x6000",
        }],
        "surface_details": [],
        "sources": [],
    }

    ko_ingress, _ = recover_external_ingress(ko_manifest, ko_context)
    ko_topology = build_component_topology(ko_manifest, ko_ingress)
    ko_suitability = assess_fuzz_suitability(ko_manifest, ko_context, ko_ingress, ko_topology)
    assert any(item["kind"] == "ioctl_dispatch" for item in ko_ingress)
    assert ko_suitability["strategy"] == "snapshot_or_ioctl_harness"
    assert ko_suitability["runtime_strategy"] == "kernel_harness_required"


def test_libfuzzer_entry_is_the_only_direct_campaign_boundary(tmp_path: Path) -> None:
    binary = _write_binary(tmp_path / "harness", b"\x7fELF" + b"\x00" * 128)
    manifest = _manifest(binary, target_kind="elf-linux")
    context = {
        "entry_points": [{
            "id": "BEP-1000",
            "name": "LLVMFuzzerTestOneInput",
            "address": "0x1000",
            "evidence_ids": ["EV-1"],
        }],
        "surface_details": [],
        "sources": [],
        "interesting_functions": [],
    }

    ingress, _ = recover_external_ingress(manifest, context)
    topology = build_component_topology(manifest, ingress)
    suitability = assess_fuzz_suitability(manifest, context, ingress, topology)

    assert suitability["strategy"] == "direct_harness"
    assert suitability["direct_campaign_recommended"] is True
    assert suitability["should_run_fuzz_plan"] is True
