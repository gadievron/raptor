"""Mach-O and macOS app bundle intake.

The binary pipeline should not treat a universal Mach-O as one opaque blob.
This module reads the fat header directly, records every slice, and extracts
bundle-owned metadata from Info.plist / embedded code-signing output when the
binary lives inside an app bundle.

These are byte/tool-backed facts only. None of this claims reachability.
"""

from __future__ import annotations

import plistlib
import struct
import subprocess
import xml.parsers.expat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from core.sandbox import run_trusted

from .evidence import EvidenceRecord, EvidenceTier, make_evidence

_FAT_MAGICS = {
    b"\xca\xfe\xba\xbe": (">", False),
    b"\xbe\xba\xfe\xca": ("<", False),
    b"\xca\xfe\xba\xbf": (">", True),
    b"\xbf\xba\xfe\xca": ("<", True),
}
_THIN_MAGICS = {
    b"\xfe\xed\xfa\xce": (">", 32),
    b"\xce\xfa\xed\xfe": ("<", 32),
    b"\xfe\xed\xfa\xcf": (">", 64),
    b"\xcf\xfa\xed\xfe": ("<", 64),
}
_CPU_TYPES = {
    7: "x86",
    0x01000007: "x86_64",
    12: "arm",
    0x0100000C: "arm64",
    18: "ppc",
    0x01000012: "ppc64",
}
_MAX_SLICES = 64
_MAX_TOOL_OUTPUT = 256 * 1024


@dataclass
class MachOSlice:
    arch: str
    cpu_type: int
    cpu_subtype: int
    offset: int
    size: int
    bits: int
    sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "arch": self.arch,
            "cpu_type": self.cpu_type,
            "cpu_subtype": self.cpu_subtype,
            "offset": self.offset,
            "size": self.size,
            "bits": self.bits,
            "sha256": self.sha256,
        }


@dataclass
class AppBundleMetadata:
    bundle_path: str
    info_plist_path: str
    identifier: str = ""
    executable: str = ""
    display_name: str = ""
    short_version: str = ""
    build_version: str = ""
    package_type: str = ""
    minimum_os: str = ""
    url_schemes: list[str] = field(default_factory=list)
    document_types: list[str] = field(default_factory=list)
    ats_exception_domains: list[str] = field(default_factory=list)
    privileged_executables: list[str] = field(default_factory=list)
    xpc_services: list[str] = field(default_factory=list)
    helper_tools: list[str] = field(default_factory=list)
    entitlements: dict[str, Any] = field(default_factory=dict)
    code_signing: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_path": self.bundle_path,
            "info_plist_path": self.info_plist_path,
            "identifier": self.identifier,
            "executable": self.executable,
            "display_name": self.display_name,
            "short_version": self.short_version,
            "build_version": self.build_version,
            "package_type": self.package_type,
            "minimum_os": self.minimum_os,
            "url_schemes": list(self.url_schemes),
            "document_types": list(self.document_types),
            "ats_exception_domains": list(self.ats_exception_domains),
            "privileged_executables": list(self.privileged_executables),
            "xpc_services": list(self.xpc_services),
            "helper_tools": list(self.helper_tools),
            "entitlements": dict(self.entitlements),
            "code_signing": dict(self.code_signing),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AppBundleMetadata":
        return cls(
            bundle_path=str(data.get("bundle_path") or ""),
            info_plist_path=str(data.get("info_plist_path") or ""),
            identifier=str(data.get("identifier") or ""),
            executable=str(data.get("executable") or ""),
            display_name=str(data.get("display_name") or ""),
            short_version=str(data.get("short_version") or ""),
            build_version=str(data.get("build_version") or ""),
            package_type=str(data.get("package_type") or ""),
            minimum_os=str(data.get("minimum_os") or ""),
            url_schemes=[str(item) for item in data.get("url_schemes") or []],
            document_types=[str(item) for item in data.get("document_types") or []],
            ats_exception_domains=[str(item) for item in data.get("ats_exception_domains") or []],
            privileged_executables=[str(item) for item in data.get("privileged_executables") or []],
            xpc_services=[str(item) for item in data.get("xpc_services") or []],
            helper_tools=[str(item) for item in data.get("helper_tools") or []],
            entitlements=dict(data.get("entitlements") or {}),
            code_signing=dict(data.get("code_signing") or {}),
        )


def _arch_name(cpu_type: int) -> str:
    return _CPU_TYPES.get(cpu_type & 0xFFFFFFFF, f"cpu_{cpu_type:#x}")


def _slice_sha256(path: Path, offset: int, size: int) -> str:
    import hashlib

    digest = hashlib.sha256()
    remaining = size
    with path.open("rb") as handle:
        handle.seek(offset)
        while remaining > 0:
            chunk = handle.read(min(1024 * 1024, remaining))
            if not chunk:
                break
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest() if remaining == 0 else ""


def inspect_macho_slices(path: Path, binary_sha256: str) -> tuple[list[MachOSlice], list[EvidenceRecord]]:
    """Read thin/fat Mach-O slice headers without calling an external tool."""
    path = Path(path)
    try:
        with path.open("rb") as handle:
            header = handle.read(8 + (_MAX_SLICES * 32))
    except OSError:
        return [], []
    if len(header) < 8:
        return [], []

    slices: list[MachOSlice] = []
    magic = header[:4]
    if magic in _FAT_MAGICS:
        endian, is_64 = _FAT_MAGICS[magic]
        count = min(struct.unpack(f"{endian}I", header[4:8])[0], _MAX_SLICES)
        entry_size = 32 if is_64 else 20
        fmt = f"{endian}IIQQII" if is_64 else f"{endian}IIIII"
        for index in range(count):
            start = 8 + (index * entry_size)
            raw = header[start:start + entry_size]
            if len(raw) != entry_size:
                break
            values = struct.unpack(fmt, raw)
            cpu_type, cpu_subtype, offset, size = values[:4]
            arch = _arch_name(cpu_type)
            bits = 64 if arch.endswith("64") else 32
            slices.append(MachOSlice(
                arch=arch,
                cpu_type=cpu_type,
                cpu_subtype=cpu_subtype,
                offset=int(offset),
                size=int(size),
                bits=bits,
                sha256=_slice_sha256(path, int(offset), int(size)),
            ))
    elif magic in _THIN_MAGICS:
        if len(header) < 12:
            return [], []
        endian, bits = _THIN_MAGICS[magic]
        cpu_type, cpu_subtype = struct.unpack(f"{endian}II", header[4:12])
        slices.append(MachOSlice(
            arch=_arch_name(cpu_type),
            cpu_type=cpu_type,
            cpu_subtype=cpu_subtype,
            offset=0,
            size=path.stat().st_size,
            bits=bits,
            sha256=binary_sha256,
        ))

    if not slices:
        return [], []
    record = make_evidence(
        binary_sha256,
        kind="macho_slices",
        source="macho_header",
        summary=f"Mach-O header declares {len(slices)} architecture slice(s)",
        tier=EvidenceTier.HEADER_BACKED,
        confidence="confirmed",
        reproducible=True,
        tool="binary-intake",
        location=str(path),
        data={"slices": [item.to_dict() for item in slices]},
    )
    return slices, [record]


def _find_app_bundle(path: Path) -> Optional[Path]:
    for parent in [path.parent, *path.parents]:
        if parent.suffix == ".app" and (parent / "Contents" / "Info.plist").is_file():
            return parent
    return None


def _run_readonly_tool(argv: list[str]) -> str:
    try:
        result = run_trusted(
            argv,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return (result.stdout or "")[:_MAX_TOOL_OUTPUT] + (result.stderr or "")[:_MAX_TOOL_OUTPUT]


def _extract_entitlements(binary: Path) -> dict[str, Any]:
    output = _run_readonly_tool(["/usr/bin/codesign", "-d", "--entitlements", ":-", str(binary)])
    start = output.find("<?xml")
    end = output.rfind("</plist>")
    if start < 0 or end < 0:
        return {}
    try:
        payload = plistlib.loads(output[start:end + len("</plist>")].encode("utf-8"))
    except (plistlib.InvalidFileException, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _extract_code_signing(binary: Path) -> dict[str, Any]:
    output = _run_readonly_tool(["/usr/bin/codesign", "-dvvv", str(binary)])
    fields: dict[str, Any] = {}
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"Identifier", "TeamIdentifier", "Runtime Version", "Format", "CDHash"}:
            fields[key] = value.strip()
    if "Notarization Ticket=stapled" in output:
        fields["notarized"] = True
    return fields


def inspect_app_bundle(path: Path, binary_sha256: str) -> tuple[Optional[AppBundleMetadata], list[EvidenceRecord]]:
    bundle = _find_app_bundle(Path(path))
    if bundle is None:
        return None, []
    plist_path = bundle / "Contents" / "Info.plist"
    try:
        with plist_path.open("rb") as handle:
            info = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException, xml.parsers.expat.ExpatError):
        return None, []
    if not isinstance(info, dict):
        return None, []

    url_schemes: list[str] = []
    for item in info.get("CFBundleURLTypes") or []:
        if isinstance(item, dict):
            url_schemes.extend(str(value) for value in item.get("CFBundleURLSchemes") or [])
    document_types: list[str] = []
    for item in info.get("CFBundleDocumentTypes") or []:
        if isinstance(item, dict):
            document_types.extend(str(value) for value in item.get("CFBundleTypeExtensions") or [])
            document_types.extend(str(value) for value in item.get("LSItemContentTypes") or [])
    ats = info.get("NSAppTransportSecurity") or {}
    ats_domains = []
    if isinstance(ats, dict):
        exceptions = ats.get("NSExceptionDomains") or {}
        if isinstance(exceptions, dict):
            ats_domains = sorted(str(key) for key in exceptions)
    privileged = info.get("SMPrivilegedExecutables") or {}
    xpc_dir = bundle / "Contents" / "XPCServices"
    helper_dir = bundle / "Contents" / "Library" / "HelperTools"
    metadata = AppBundleMetadata(
        bundle_path=str(bundle),
        info_plist_path=str(plist_path),
        identifier=str(info.get("CFBundleIdentifier") or ""),
        executable=str(info.get("CFBundleExecutable") or ""),
        display_name=str(info.get("CFBundleDisplayName") or info.get("CFBundleName") or ""),
        short_version=str(info.get("CFBundleShortVersionString") or ""),
        build_version=str(info.get("CFBundleVersion") or ""),
        package_type=str(info.get("CFBundlePackageType") or ""),
        minimum_os=str(info.get("LSMinimumSystemVersion") or ""),
        url_schemes=sorted(set(url_schemes)),
        document_types=sorted(set(document_types)),
        ats_exception_domains=ats_domains,
        privileged_executables=sorted(str(key) for key in privileged) if isinstance(privileged, dict) else [],
        xpc_services=sorted(item.name for item in xpc_dir.glob("*.xpc")) if xpc_dir.is_dir() else [],
        helper_tools=sorted(item.name for item in helper_dir.iterdir() if item.is_file()) if helper_dir.is_dir() else [],
        entitlements=_extract_entitlements(Path(path)),
        code_signing=_extract_code_signing(Path(path)),
    )
    record = make_evidence(
        binary_sha256,
        kind="app_bundle_metadata",
        source="Info.plist",
        summary=f"Read macOS app bundle metadata for {metadata.identifier or bundle.name}",
        tier=EvidenceTier.HEADER_BACKED,
        confidence="confirmed",
        reproducible=True,
        tool="plistlib",
        location=str(plist_path),
        data=metadata.to_dict(),
    )
    return metadata, [record]


def select_slice(slices: list[MachOSlice], requested_arch: Optional[str], host_arch: Optional[str]) -> Optional[MachOSlice]:
    if not slices:
        return None
    aliases = {
        "aarch64": "arm64",
        "arm": "arm64",
        "amd64": "x86_64",
        "x64": "x86_64",
        "i386": "x86",
        "armv7": "arm",
    }
    wanted = aliases.get(str(requested_arch or host_arch or ""), str(requested_arch or host_arch or ""))
    for item in slices:
        if item.arch == wanted:
            return item
    return slices[0]


__all__ = [
    "AppBundleMetadata",
    "MachOSlice",
    "inspect_app_bundle",
    "inspect_macho_slices",
    "select_slice",
]
