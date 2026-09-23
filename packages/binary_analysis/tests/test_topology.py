"""Direct unit tests for topology.build_component_topology."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from packages.binary_analysis.topology import (
    _find_declared_artifact,
    build_component_topology,
)


@dataclass
class _FakeBundle:
    bundle_path: str
    privileged_executables: list[str] = field(default_factory=list)
    helper_tools: list[str] = field(default_factory=list)
    xpc_services: list[str] = field(default_factory=list)


@dataclass
class _FakeManifest:
    binary_path: str
    target_kind: str = ""
    app_bundle: Optional[_FakeBundle] = None


def test_basic_elf_topology():
    manifest = _FakeManifest(binary_path="/usr/bin/demo", target_kind="elf-linux")
    result = build_component_topology(manifest, ingress=[])
    assert result["platform"] == "linux"
    assert result["target_kind"] == "elf-linux"
    assert len(result["components"]) == 1
    assert result["components"][0]["kind"] == "target_binary"
    assert result["sibling_artifacts"] == []


def test_pe_dll_adds_caller_boundary():
    manifest = _FakeManifest(binary_path="C:\\lib.dll", target_kind="pe-dll")
    result = build_component_topology(manifest, ingress=[])
    assert result["platform"] == "windows"
    boundaries = result["boundaries"]
    assert any(b["kind"] == "caller_to_library" for b in boundaries)


def test_pe_sys_adds_kernel_boundary():
    manifest = _FakeManifest(binary_path="C:\\driver.sys", target_kind="pe-sys")
    result = build_component_topology(manifest, ingress=[])
    assert any(b["kind"] == "kernel_boundary" for b in result["boundaries"])


def test_ingress_boundaries_are_recorded():
    manifest = _FakeManifest(binary_path="/bin/srv", target_kind="elf-linux")
    ingress = [
        {"kind": "network_input", "boundary": "network_to_process",
         "evidence_tier": "header_backed", "confidence": "candidate"},
        {"kind": "file_open_handler", "boundary": "filesystem_to_process",
         "evidence_tier": "header_backed", "confidence": "candidate"},
    ]
    result = build_component_topology(manifest, ingress=ingress)
    boundary_kinds = {b["kind"] for b in result["boundaries"]}
    assert "network_to_process" in boundary_kinds
    assert "filesystem_to_process" in boundary_kinds


def test_duplicate_boundaries_are_deduped():
    manifest = _FakeManifest(binary_path="/bin/srv", target_kind="elf-linux")
    ingress = [
        {"kind": "network_input", "boundary": "network_to_process",
         "evidence_tier": "header_backed", "confidence": "candidate"},
        {"kind": "network_input", "boundary": "network_to_process",
         "evidence_tier": "header_backed", "confidence": "candidate"},
    ]
    result = build_component_topology(manifest, ingress=ingress)
    assert len(result["boundaries"]) == 1


def test_macos_platform():
    manifest = _FakeManifest(binary_path="/App.app/Contents/MacOS/App", target_kind="macho")
    result = build_component_topology(manifest, ingress=[])
    assert result["platform"] == "macos"


# ---------------------------------------------------------------------------
# Path-traversal prevention in _find_declared_artifact
# ---------------------------------------------------------------------------

def test_traversal_name_rejected(tmp_path):
    bundle = tmp_path / "Evil.app"
    (bundle / "Contents" / "MacOS").mkdir(parents=True)
    outside = tmp_path / "secret.txt"
    outside.write_text("sensitive")

    result = _find_declared_artifact(bundle, "../../../secret.txt")
    assert result is None, f"Path traversal escaped bundle root: {result}"


def test_traversal_two_levels(tmp_path):
    bundle = tmp_path / "Test.app"
    (bundle / "Contents" / "Resources").mkdir(parents=True)
    escape_target = tmp_path / "etc" / "passwd"
    escape_target.parent.mkdir(parents=True, exist_ok=True)
    escape_target.write_text("root:x:0:0")

    result = _find_declared_artifact(bundle, "../../etc/passwd")
    assert result is None


def test_legitimate_name_works(tmp_path):
    bundle = tmp_path / "Good.app"
    macos = bundle / "Contents" / "MacOS"
    macos.mkdir(parents=True)
    helper = macos / "com.example.helper"
    helper.write_text("#!/bin/sh\necho hi")
    helper.chmod(0o755)

    result = _find_declared_artifact(bundle, "com.example.helper")
    assert result is not None
    assert result.name == "com.example.helper"


def test_absolute_path_rejected(tmp_path):
    bundle = tmp_path / "Abs.app"
    (bundle / "Contents" / "MacOS").mkdir(parents=True)

    result = _find_declared_artifact(bundle, "/etc/passwd")
    assert result is None


# ---------------------------------------------------------------------------
# platform_label — the shared target_kind -> OS mapping
# ---------------------------------------------------------------------------


def test_platform_label_shared_by_topology_and_ingress():
    """topology and ingress previously each copied the mapping; both
    must delegate to manifest.platform_label so it cannot drift."""
    from packages.binary_analysis import ingress, manifest, topology
    assert topology._platform is manifest.platform_label
    assert ingress._platform is manifest.platform_label


def test_platform_label_mapping():
    from packages.binary_analysis.manifest import platform_label
    from types import SimpleNamespace as NS
    assert platform_label(NS(target_kind="macho")) == "macos"
    assert platform_label(NS(target_kind="pe-exe")) == "windows"
    assert platform_label(NS(target_kind="elf-linux")) == "linux"
    assert platform_label(NS(target_kind="elf-kmod")) == "linux"
    assert platform_label(NS(target_kind="wasm")) == "generic"
    assert platform_label(NS(target_kind=None)) == "generic"
    assert platform_label(object()) == "generic"


# -------------------------------------------------------------------
# Glob metacharacters in plist-declared names
# -------------------------------------------------------------------

def test_glob_metachar_name_binds_nothing(tmp_path):
    """A hostile Info.plist declaring '*' as its helper name must not
    bind an arbitrary bundle file as the declared artifact — the
    lookup is a filename match, never a pattern."""
    bundle = tmp_path / "App.app"
    (bundle / "Contents").mkdir(parents=True)
    (bundle / "Contents" / "random_file").write_bytes(b"\x00")
    assert _find_declared_artifact(bundle, "*") is None
    assert _find_declared_artifact(bundle, "random_fil?") is None
    assert _find_declared_artifact(bundle, "[r]andom_file") is None


def test_literal_name_with_bracket_chars_still_found(tmp_path):
    bundle = tmp_path / "App.app"
    (bundle / "Contents").mkdir(parents=True)
    weird = bundle / "Contents" / "helper[1].bin"
    weird.write_bytes(b"\x00")
    assert _find_declared_artifact(bundle, "helper[1].bin") == weird
