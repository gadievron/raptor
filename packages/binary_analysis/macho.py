"""Mach-O and macOS app bundle intake.

The binary pipeline should not treat a universal Mach-O as one opaque blob.
This module reads the fat header directly, records every slice, and extracts
bundle-owned metadata from Info.plist / embedded code-signing output when the
binary lives inside an app bundle.

These are byte/tool-backed facts only. None of this claims reachability.
"""

from __future__ import annotations

import logging
import plistlib
import struct
import subprocess
import xml.parsers.expat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

from core.sandbox import run_trusted

# ONE entropy primitive repo-wide — deliberately shared with the ELF
# tier so the number means the same thing on every facts record. Its
# packedness-refusal rationale (entropy is a measurement, never a
# packed/encrypted verdict) travels with it; any change to that
# posture is amended THERE, beside is_packed.
from core.binary.elf import _shannon_entropy

from core.evidence import BinaryEvidenceRecord, EvidenceTier, make_evidence

logger = logging.getLogger(__name__)

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
    def from_dict(cls, data: dict[str, Any]) -> AppBundleMetadata:
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


def inspect_macho_slices(path: Path, binary_sha256: str) -> tuple[list[MachOSlice], list[BinaryEvidenceRecord]]:
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


def _find_app_bundle(path: Path) -> Path | None:
    for parent in [path.parent, *path.parents]:
        if parent.suffix == ".app" and (parent / "Contents" / "Info.plist").is_file():
            return parent
    return None


def _run_readonly_tool(argv: list[str]) -> str:
    # Sandbox seam, documented deliberately: codesign/otool parse
    # attacker-controlled Mach-O bytes under run_trusted (safe env +
    # rlimits) rather than the full mount-ns/Landlock/seccomp sandbox
    # that core.binary.inspect gives its allowlisted tools. These
    # tools exist only on macOS, where the Linux sandbox stack does
    # not apply — the full sandbox would degrade to exactly this
    # posture there. If these invocations ever need to run on a Linux
    # host, route them through the core.binary.inspect allowlist
    # instead of widening run_trusted use.
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


def inspect_app_bundle(path: Path, binary_sha256: str) -> tuple[AppBundleMetadata | None, list[BinaryEvidenceRecord]]:
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


# An explicitly requested arch is taken literally: 'arm' is the
# canonical name of the 32-bit arm slice (cpu_type 12), so remapping
# it to arm64 would make the 32-bit slice unselectable.
_ARCH_ALIASES = {
    "aarch64": "arm64",
    "amd64": "x86_64",
    "x64": "x86_64",
    "i386": "x86",
    "armv7": "arm",
}


def resolve_requested_slice(
    slices: list[MachOSlice],
    requested_arch: str,
) -> MachOSlice | None:
    """The slice matching an explicitly requested arch, or ``None``
    when the binary carries no such slice (alias-normalised). The one
    shared resolution both the manifest and the r2 flag derivation
    consume — they must never disagree about which ISA is analysed."""
    wanted = _ARCH_ALIASES.get(str(requested_arch), str(requested_arch))
    for item in slices:
        if item.arch == wanted:
            return item
    return None


def select_slice(
    slices: list[MachOSlice],
    requested_arch: str | None,
    host_arch: str | None,
    host_bits: int | None = None,
) -> MachOSlice | None:
    if not slices:
        return None
    if requested_arch:
        resolved = resolve_requested_slice(slices, requested_arch)
        if resolved is None:
            # Never fall back on an EXPLICIT request: the r2 lane maps
            # the requested arch to -a/-b unconditionally, so a silent
            # slices[0] here made r2 decode slice-0 bytes as the wrong
            # ISA (functions/sinks/xrefs all garbage) while the
            # manifest reported slice-0's arch as analysed.
            available = sorted({item.arch for item in slices})
            msg = (
                f"requested slice arch {requested_arch!r} matches no "
                f"slice in this binary (available: {available})"
            )
            raise ValueError(msg)
        return resolved
    # Fallback arch names come from coarse analyser output where
    # 'arm'/'x86' cover both widths and bits carries the split
    # (e.g. arm64 reported as arch='arm', bits=64).
    wanted = _ARCH_ALIASES.get(str(host_arch or ""), str(host_arch or ""))
    if host_bits == 64:
        wanted = {"arm": "arm64", "x86": "x86_64"}.get(wanted, wanted)
    for item in slices:
        if item.arch == wanted:
            return item
    return slices[0]


# ---------------------------------------------------------------------------
# Load-command facts (per-slice walk)
# ---------------------------------------------------------------------------
#
# The facts walk trusts NOTHING it did not bound itself. In particular,
# `inspect_macho_slices` above takes the fat header's offset/size values
# on faith (it only hashes whatever bytes they name) — that machinery is
# a shape reader, not a bounds authority, and is deliberately NOT reused
# here: the walk re-reads the fat header and validates every entry
# against the real file end before a single slice byte is touched.
#
# Error contract (matching the ELF/PE facts tiers): the public entry
# points return ``None`` for non-Mach-O / unreadable input and never
# raise past themselves; malformed SUB-structures degrade per field with
# a machine-readable marker in ``caps_hit`` — truncation and refusal are
# record-visible, never silent.

# Offset screen shared with the ELF/PE facts tiers (see
# core.binary.elf._MAX_SEEK_OFFSET for the full both-direction
# rationale: safely below the off_t ceiling and any real file size, so
# a hostile offset is refused before any seek and a surviving kernel
# refusal costs one field, not the record). Value-coupled to the ELF
# module by the cap-parity test.
_MAX_SEEK_OFFSET = 2**62
# Load commands walked per slice. Real binaries carry tens to a few
# hundred load commands (dylib-heavy app frameworks peak around ~500);
# ncmds is an attacker u32, and honouring a larger claim buys a
# four-billion-iteration walk. 4096 is roughly an order of magnitude
# above anything real: lower would truncate genuine linkage facts on
# plugin-heavy images, higher only sells CPU to hostile counts.
_MAX_LOAD_COMMANDS = 4096
# Smallest well-formed load command: cmd(u32) + cmdsize(u32). A cmdsize
# below this cannot advance the cursor past its own header — the walk
# would spin on or re-read the same bytes — so it is a hard walk abort,
# never a skip.
_MIN_LOAD_COMMAND_SIZE = 8
# lc_str names retained per command, in BYTES. Install names and
# rpaths are filesystem paths — macOS bounds a path at MAXPATHLEN
# (1024), so this truncates no real name; anything longer is crafted
# text, and every retained byte is multiplied by the per-kind list
# caps below. The name bytes are bounded within their own command's
# cmdsize either way (walk invariant d) — this cap bounds what the
# RECORD retains, marker-visibly.
_MAX_LC_NAME_BYTES = 1024
# Dylib names retained per linkage kind. Heavyweight real images
# (Qt / Electron app frameworks) link a few hundred dylibs, so a lower
# cap would drop genuine linkage facts; a higher one multiplies
# retained attacker text. Once a kind's list is full its NAME BYTES
# are no longer even read — only the header walk continues — and the
# per-kind COUNT keeps counting, so the record never under-reports how
# much linkage the file claims.
_MAX_DYLIB_NAMES = 512
# Rpath entries retained. Real rpath counts are single digits; two
# orders of headroom, same fan-out and stop-reading logic as the
# dylib cap.
_MAX_RPATHS = 256
# Total lc_str name BYTES one file's walk may retain, shared across
# every slice of a fat container (same value and rationale as the ELF
# import walk's _MAX_TOTAL_NAME_BYTES): the per-kind list caps bound
# each slice, but 64 fat entries aliasing one crafted slice would
# multiply the retained text 64-fold — the worst small-file record
# must stay bounded by a budget the attacker cannot dodge by adding
# slices. Real fat binaries carry a few hundred KB of names across
# 2-5 slices; on breach names stop being retained OR READ (counts
# keep counting) with a marker, never silently.
_MAX_TOTAL_NAME_BYTES = 8 * 1024 * 1024
# Section records retained per slice. Real slices carry well under a
# hundred sections; nsects is an attacker u32 on EVERY segment command
# and the segment count is bounded only by the load-command cap, so
# without a record cap a crafted slice buys thousands of rows per
# segment times thousands of segments.
_MAX_SECTION_RECORDS = 2_048
# ---- Entropy caps: same values and both-direction rationale as the
# ELF facts extractor (core.binary.elf) — the tiers measure the same
# fact and must degrade identically, so a consumer comparing
# elf/pe/macho records never reads a cap difference as a content
# difference. Value-coupled to the ELF module by the cap-parity test.
# The total budget is FILE-level, shared across every slice of a fat
# container: 64 fat entries must not multiply the IO bound the ELF
# tier fixed per file.
_MAX_ENTROPY_SECTION_BYTES = 4 * 1024 * 1024
_MAX_ENTROPY_TOTAL_BYTES = 64 * 1024 * 1024
_MAX_ENTROPY_SECTIONS = 2_048

# Load-command types this walk parses. LC_REQ_DYLD (0x80000000) is
# part of the command value where <mach-o/loader.h> defines it so.
_LC_REQ_DYLD = 0x80000000
_LC_SEGMENT = 0x1
_LC_UNIXTHREAD = 0x5
_LC_DYSYMTAB = 0xB
_LC_LOAD_DYLIB = 0xC
_LC_LOAD_WEAK_DYLIB = 0x18 | _LC_REQ_DYLD
_LC_SEGMENT_64 = 0x19
_LC_UUID = 0x1B
_LC_RPATH = 0x1C | _LC_REQ_DYLD
_LC_REEXPORT_DYLIB = 0x1F | _LC_REQ_DYLD
_LC_CODE_SIGNATURE = 0x1D
_LC_VERSION_MIN_MACOSX = 0x24
_LC_VERSION_MIN_IPHONEOS = 0x25
_LC_MAIN = 0x28 | _LC_REQ_DYLD
_LC_VERSION_MIN_TVOS = 0x2F
_LC_VERSION_MIN_WATCHOS = 0x30
_LC_BUILD_VERSION = 0x32

# The three linkage kinds this record distinguishes; LC_ID_DYLIB and
# lazy/upward variants stay unparsed by design (linkage facts, not a
# loader model).
_DYLIB_KINDS: dict[int, str] = {
    _LC_LOAD_DYLIB: "load",
    _LC_LOAD_WEAK_DYLIB: "weak",
    _LC_REEXPORT_DYLIB: "reexport",
}

# Legacy min-OS commands: the platform is implied by the command.
_LC_VERSION_MIN_PLATFORM: dict[int, str] = {
    _LC_VERSION_MIN_MACOSX: "macos",
    _LC_VERSION_MIN_IPHONEOS: "ios",
    _LC_VERSION_MIN_TVOS: "tvos",
    _LC_VERSION_MIN_WATCHOS: "watchos",
}

# LC_BUILD_VERSION platform enum. Values outside the map FAIL OPEN as
# "platform_<raw>" — the field is attacker-controlled and a new Apple
# platform must never make the fact silently vanish.
_BUILD_VERSION_PLATFORMS: dict[int, str] = {
    1: "macos",
    2: "ios",
    3: "tvos",
    4: "watchos",
    5: "bridgeos",
    6: "maccatalyst",
    7: "ios_simulator",
    8: "tvos_simulator",
    9: "watchos_simulator",
    10: "driverkit",
    11: "visionos",
    12: "visionos_simulator",
}

# Section-type values that occupy no file bytes (S_ZEROFILL,
# S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL) — entropy absence on these
# is truthful, not a gap.
_S_ZEROFILL_TYPES = {0x1, 0x4, 0x12}

# Fixed-header size per PARSED command type. A cmdsize below the fixed
# size of a command this walk decodes means the bytes it would decode
# belong to the NEXT command (the overlap shape) — walk abort, cause
# named (invariant a). Command types absent from this map are skipped
# whole by cmdsize: dozens of LC types exist that these facts never
# read, and an unknown type must not hide the rest of the walk
# (fail-open, mirroring the ELF export-type doctrine).
_LC_PARSED_FIXED_SIZE: dict[int, int] = {
    _LC_SEGMENT: 56,
    _LC_DYSYMTAB: 80,
    _LC_LOAD_DYLIB: 24,
    _LC_LOAD_WEAK_DYLIB: 24,
    _LC_SEGMENT_64: 72,
    _LC_UUID: 24,
    _LC_RPATH: 12,
    _LC_CODE_SIGNATURE: 16,
    _LC_VERSION_MIN_MACOSX: 16,
    _LC_VERSION_MIN_IPHONEOS: 16,
    _LC_MAIN: 24,
    _LC_VERSION_MIN_TVOS: 16,
    _LC_VERSION_MIN_WATCHOS: 16,
    _LC_BUILD_VERSION: 24,
    _LC_REEXPORT_DYLIB: 24,
}

# mach_header is 28 bytes; mach_header_64 appends a reserved u32.
_MACH_HEADER_SIZES = {32: 28, 64: 32}


@dataclass
class _SliceWalkState:
    """Per-slice mutable walk state.

    ``section_records`` mirrors the total section rows retained on
    this slice's record, maintained O(1) at append time. It must
    NEVER be recomputed by summing over ``facts.segments`` per
    segment command: that re-sum is O(segments^2) per slice — at the
    4096-command cap, times 64 aliasing fat entries, it is billions
    of generator steps bought by a sub-MiB file. Note the failure
    mode deliberately: the analytic READ-COUNT ceiling holds on that
    shape while the wall clock explodes — op counts do not price
    CPU-per-op, so per-command work must be O(1) by construction,
    not merely read-bounded.
    """

    section_records: int = 0


@dataclass
class _WalkBudgets:
    """File-level budgets shared across every slice of a fat
    container — a hostile file must not multiply any per-slice bound
    by adding fat entries (defaults read the module constants at
    instantiation so tests can pin the caps)."""

    entropy_remaining: int = field(
        default_factory=lambda: _MAX_ENTROPY_TOTAL_BYTES)
    entropy_measured: int = 0
    name_bytes_remaining: int = field(
        default_factory=lambda: _MAX_TOTAL_NAME_BYTES)


@dataclass
class MachOSectionFact:
    """One section row from a segment command. ``entropy`` is the
    Shannon entropy of the section's leading file bytes (bits per
    byte) — a deterministic measurement, never a packedness verdict
    (see :func:`core.binary.elf.is_packed`'s recorded refusal).
    ``None`` when nothing was measured (no file bytes, unreadable
    data, or a cap fired — the ``caps_hit`` markers say which);
    ``sampled < size`` means the bounded leading window was measured,
    not the whole section. Names come from fixed 16-byte fields in the
    hostile file — escape at render."""

    segment: str
    name: str
    addr: int
    size: int
    offset: int          # file offset RELATIVE to the slice start
    flags: int           # raw value; type bits mask _S_ZEROFILL_TYPES
    entropy: float | None = None
    sampled: int = 0


@dataclass
class MachOSegmentFact:
    """One LC_SEGMENT / LC_SEGMENT_64 row (raw claims as the file
    states them — nothing here is validated against the slice extent
    except the section entropy reads, which bound themselves)."""

    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    maxprot: int
    initprot: int
    nsects_declared: int
    sections: list[MachOSectionFact] = field(default_factory=list)


@dataclass
class MachOSliceFacts:
    """Load-command facts for ONE Mach-O slice.

    Hostile-input contract: every string field originating in the
    parsed file is attacker-controlled text — length-capped at capture,
    NOT escaped here (matching the ELF/PE facts records); consumers
    escape at render before any terminal / report / prompt use.
    ``caps_hit`` is a sorted list of machine-readable markers naming
    every cap, gap, or walk abort that fired (empty = complete walk).

    ``uuid`` is the LC_UUID payload as lowercase hex, recorded verbatim
    even when all-zero — degenerate-identity screening is the identity
    front door's policy, not this fact layer's.
    """

    arch: str = ""
    cpu_type: int = 0
    cpu_subtype: int = 0
    bits: int = 0
    endianness: str = ""          # "little" | "big" (slice header magic)
    offset: int = 0               # absolute file offset of the slice
    size: int = 0                 # slice size as resolved by the walk
    filetype: int = 0             # raw value — fail open on unknown
    flags: int = 0                # raw mach_header flags
    ncmds_declared: int = 0
    ncmds_walked: int = 0
    sizeofcmds_declared: int = 0
    uuid: str | None = None
    # Dylib linkage, split by kind. Lists are capped (marker on
    # breach); the per-kind COUNTS keep counting past the cap, so the
    # record never under-reports claimed linkage.
    load_dylibs: list[str] = field(default_factory=list)
    weak_dylibs: list[str] = field(default_factory=list)
    reexport_dylibs: list[str] = field(default_factory=list)
    dylib_counts: dict[str, int] = field(
        default_factory=lambda: {"load": 0, "weak": 0, "reexport": 0})
    rpaths: list[str] = field(default_factory=list)
    # LC_DYSYMTAB symbol-range counts (export/symbol PRESENCE — the
    # export trie and symbol-table contents stay unparsed by design).
    # Empty dict = no LC_DYSYMTAB seen.
    dysymtab: dict[str, int] = field(default_factory=dict)
    # Min-OS / platform: LC_BUILD_VERSION preferred over the legacy
    # LC_VERSION_MIN_* family regardless of command order;
    # ``min_os_source`` says which one populated the fields.
    platform: str | None = None
    min_os: str | None = None
    sdk: str | None = None          # None when the file says 0 (unset)
    min_os_source: str | None = None   # "build_version" | "version_min"
    entry_offset: int | None = None    # LC_MAIN entryoff
    has_unixthread: bool = False       # presence only, by design
    # LC_CODE_SIGNATURE: presence + DECLARED size only — the blob is
    # never parsed here (a signature skim is its own hostile parser).
    code_signature_present: bool = False
    code_signature_size: int = 0
    segments: list[MachOSegmentFact] = field(default_factory=list)
    caps_hit: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MachOFacts:
    """Per-slice load-command facts for a thin or fat Mach-O file.

    ``caps_hit`` carries FILE-level markers (fat-table problems,
    rejected fat entries); per-slice markers live on each slice record.
    ``declared_slices`` preserves the fat header's claim even when
    entries were capped or rejected, so "N declared, M walked" is
    always reconstructable from the record.
    """

    is_fat: bool = False
    declared_slices: int = 0
    slices: list[MachOSliceFacts] = field(default_factory=list)
    caps_hit: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def extract_macho_facts(path: Path) -> MachOFacts | None:
    """Extract load-command facts from ``path``, or ``None`` when the
    file is not Mach-O / unreadable — the same malformed-input contract
    as the ELF/PE facts extractors (never raises past itself).
    Malformed sub-structures degrade per field or per slice with a
    marker; hostile counts and sizes are capped, marker-visibly.
    """
    try:
        with Path(path).open("rb") as handle:
            return _extract_facts_stream(handle)
    except OSError as exc:
        logger.debug("macho facts: read failed for %s: %s", path, exc)
        return None
    except struct.error as exc:
        logger.debug("macho facts: truncated / malformed %s: %s",
                     path, exc)
        return None
    except (ValueError, OverflowError) as exc:
        # f.seek() rejects offsets that don't fit a C off_t with
        # ValueError or OverflowError depending on the io layer — same
        # "malformed input" contract as struct.error. The 2**62 screen
        # keeps crafted offsets from ever reaching a seek; this net is
        # belt-and-braces.
        logger.debug("macho facts: pathological offsets in %s: %s",
                     path, exc)
        return None


def extract_macho_slice_facts(
    path: Path, *, offset: int, size: int,
) -> MachOSliceFacts | None:
    """Facts for ONE slice named by an explicit ``offset``/``size``
    (e.g. a manifest's analysed-slice selection). The bounds are
    re-validated here — a stale or hostile selection returns ``None``
    rather than steering reads outside the file."""
    try:
        with Path(path).open("rb") as handle:
            handle.seek(0, 2)
            eof = handle.tell()
            if (offset < 0 or size < 4
                    or offset > _MAX_SEEK_OFFSET
                    or size > _MAX_SEEK_OFFSET
                    or offset + size > eof):
                # size < 4 cannot hold a magic — refusing here keeps
                # the walk's first read inside the declared extent
                # (invariant c).
                return None
            return _extract_slice_facts_stream(
                handle, offset, size, eof, _WalkBudgets())
    except OSError:
        return None
    except struct.error:
        return None
    except (ValueError, OverflowError):
        return None


def _extract_facts_stream(f: BinaryIO) -> MachOFacts | None:
    f.seek(0, 2)
    eof = f.tell()
    f.seek(0)
    magic = f.read(4)
    if len(magic) < 4:
        return None
    caps: set[str] = set()
    budgets = _WalkBudgets()
    if magic in _THIN_MAGICS:
        facts = MachOFacts(is_fat=False, declared_slices=1)
        item = _extract_slice_facts_stream(f, 0, eof, eof, budgets)
        if item is not None:
            facts.slices.append(item)
    elif magic in _FAT_MAGICS:
        endian_f, fat64 = _FAT_MAGICS[magic]
        raw = f.read(4)
        if len(raw) < 4:
            return None
        declared = struct.unpack(f"{endian_f}I", raw)[0]
        facts = MachOFacts(is_fat=True, declared_slices=declared)
        count = min(declared, _MAX_SLICES)
        if count < declared:
            caps.add("fat_slices_capped")
        entry_size = 32 if fat64 else 20
        fmt = f"{endian_f}IIQQII" if fat64 else f"{endian_f}IIIII"
        table = f.read(count * entry_size)
        accepted: list[tuple[int, int]] = []
        for index in range(count):
            chunk = table[index * entry_size:(index + 1) * entry_size]
            if len(chunk) < entry_size:
                caps.add("fat_table_truncated")
                break
            values = struct.unpack(fmt, chunk)
            s_off, s_size = int(values[2]), int(values[3])
            # Walk invariant (c): the fat header is attacker data —
            # every entry is screened (house 2**62 offset screen) and
            # its offset+size checked against the real file end BEFORE
            # any slice byte is read. Python ints cannot wrap, so with
            # both terms screened the explicit sum check IS the
            # overflow check.
            if s_off > _MAX_SEEK_OFFSET or s_size > _MAX_SEEK_OFFSET:
                caps.add("fat_entry_offset_screened")
                continue
            if s_off + s_size > eof:
                caps.add("fat_entry_past_eof")
                continue
            if s_size < 4:
                # Too small to hold even a magic: rejecting it HERE
                # keeps invariant (c) airtight — the slice walk's
                # first read is the 4-byte magic, which must never
                # take bytes from beyond the entry's declared extent.
                caps.add("fat_entry_not_macho")
                continue
            accepted.append((s_off, s_size))
        # Entries overlapping each other are malformed (a re-lipo'd or
        # doctored container); each walk below is independently
        # bounded, so overlap endangers nothing — but the shape is
        # recorded, never silent.
        spans = sorted(accepted)
        for prev, cur in zip(spans, spans[1:]):
            if prev[0] + prev[1] > cur[0]:
                caps.add("fat_slices_overlap")
                break
        for s_off, s_size in accepted:
            item = _extract_slice_facts_stream(
                f, s_off, s_size, eof, budgets)
            if item is None:
                caps.add("fat_entry_not_macho")
            else:
                facts.slices.append(item)
    else:
        return None
    facts.caps_hit = sorted(caps)
    return facts


def _extract_slice_facts_stream(
    f: BinaryIO, slice_offset: int, slice_size: int, eof: int,
    budgets: _WalkBudgets,
) -> MachOSliceFacts | None:
    """Walk one slice's mach header + load commands.

    Walk invariant (c): every read this function (and the walk it
    drives) performs stays inside
    ``[slice_offset, slice_offset + slice_size]`` AND the real file
    end — ``slice_end`` folds both bounds together here, and every
    region derived below is clamped to it before being trusted.
    """
    slice_end = min(slice_offset + slice_size, eof)
    f.seek(slice_offset)
    magic = f.read(4)
    if len(magic) < 4 or magic not in _THIN_MAGICS:
        return None
    endian, bits = _THIN_MAGICS[magic]
    facts = MachOSliceFacts(
        bits=bits,
        endianness="little" if endian == "<" else "big",
        offset=slice_offset,
        size=slice_size,
    )
    caps: set[str] = set()
    header_size = _MACH_HEADER_SIZES[bits]
    rest = b""
    if slice_offset + header_size <= slice_end:
        rest = f.read(header_size - 4)
    if len(rest) < header_size - 4:
        facts.caps_hit = ["slice_header_truncated"]
        return facts
    # cputype cpusubtype filetype ncmds sizeofcmds flags [reserved]
    (cpu_type, cpu_subtype, filetype, ncmds, sizeofcmds,
     flags) = struct.unpack(f"{endian}IIIIII", rest[:24])
    facts.arch = _arch_name(cpu_type)
    facts.cpu_type = cpu_type
    facts.cpu_subtype = cpu_subtype
    facts.filetype = filetype          # raw value — fail open
    facts.flags = flags
    facts.ncmds_declared = ncmds
    facts.sizeofcmds_declared = sizeofcmds

    cmds_start = slice_offset + header_size
    region_end = cmds_start + sizeofcmds
    # Walk invariant (b): sizeofcmds is an attacker u32 — the command
    # region is clamped to the slice extent (file EOF already folded
    # into slice_end) before the walk trusts it.
    if region_end > slice_end:
        region_end = slice_end
        caps.add("lc_sizeofcmds_clamped")
    ncmds_walk = ncmds
    if ncmds_walk > _MAX_LOAD_COMMANDS:
        # Walk invariant (b): ncmds capped at the named constant.
        ncmds_walk = _MAX_LOAD_COMMANDS
        caps.add("lc_ncmds_capped")
    _walk_load_commands(
        f, facts, caps, budgets, endian=endian, bits=bits,
        cmds_start=cmds_start, region_end=region_end, ncmds=ncmds_walk,
    )
    _measure_section_entropy(
        f, facts, caps, slice_offset=slice_offset,
        slice_end=slice_end, budgets=budgets,
    )
    facts.caps_hit = sorted(caps)
    return facts


def _walk_load_commands(
    f: BinaryIO, facts: MachOSliceFacts, caps: set[str],
    budgets: _WalkBudgets, *,
    endian: str, bits: int, cmds_start: int, region_end: int,
    ncmds: int,
) -> None:
    """Per-slice load-command traversal.

    Walk invariant (a) — monotonic advance: ``cmdsize`` must be at
    least ``_MIN_LOAD_COMMAND_SIZE`` and the cursor strictly increases
    by exactly ``cmdsize`` each step. A zero / short cmdsize (which
    would spin on or re-read the current header) or a cmdsize smaller
    than the fixed header of a command this walk decodes (which would
    decode the NEXT command's bytes — the overlap shape) ABORTS the
    walk with a cause-named marker; so does a command overrunning the
    bounded region. Aborts keep every fact collected so far. An
    UNALIGNED cmdsize (not a multiple of 4 on 32-bit / 8 on 64-bit)
    is the module's one documented tolerance: marked, never fatal —
    see the inline rationale at the check.

    Walk invariant (c) — every read stays inside
    ``[cmds_start, region_end)``, which the caller already clamped to
    the slice extent and the file end.
    """
    header_fmt = f"{endian}II"
    state = _SliceWalkState()
    cursor = cmds_start
    for _ in range(ncmds):
        if cursor + _MIN_LOAD_COMMAND_SIZE > region_end:
            # Declared ncmds outruns the (clamped) region — the
            # sizeofcmds-lying-small shape. Bounded stop, marked.
            caps.add("lc_walk_abort_region_end")
            break
        f.seek(cursor)
        raw = f.read(_MIN_LOAD_COMMAND_SIZE)
        if len(raw) < _MIN_LOAD_COMMAND_SIZE:
            caps.add("lc_walk_abort_region_end")
            break
        cmd, cmdsize = struct.unpack(header_fmt, raw)
        if cmdsize < _MIN_LOAD_COMMAND_SIZE:
            # Invariant (a): cmdsize 0 (or < 8) cannot advance the
            # cursor past its own header.
            caps.add("lc_walk_abort_cmdsize_underflow")
            break
        if cmdsize % (8 if bits == 64 else 4):
            # DOCUMENTED TOLERANCE (the module's only one): the spec
            # requires cmdsize be a multiple of 4 (32-bit) / 8
            # (64-bit) and dyld refuses violations. A facts reader is
            # not a loader — the walk continues (unaligned cmdsize
            # threatens no bound here; every read stays cmdsize- and
            # region-bounded), but the violation is record-visible,
            # never silent.
            caps.add("lc_cmdsize_unaligned")
        fixed = _LC_PARSED_FIXED_SIZE.get(cmd)
        if fixed is not None and cmdsize < fixed:
            # Invariant (a): the command claims fewer bytes than its
            # own fixed header — decoding would overlap the next
            # command.
            caps.add("lc_walk_abort_fixed_header_truncated")
            break
        if cursor + cmdsize > region_end:
            # Invariant (a)+(c): the command overruns the bounded
            # region — parsing it would read past the slice extent.
            caps.add("lc_walk_abort_bounds")
            break
        _parse_load_command(
            f, facts, caps, budgets, state, cmd=cmd,
            cmdsize=cmdsize, start=cursor, endian=endian,
        )
        facts.ncmds_walked += 1
        cursor += cmdsize    # strictly increasing: cmdsize >= 8 held above


def _read_exact(f: BinaryIO, pos: int, count: int) -> bytes | None:
    """Bounded exact read — callers pass positions already validated
    against the clamped region, so a short read here means the file
    changed underneath us; ``None`` degrades that one field."""
    f.seek(pos)
    data = f.read(count)
    return data if len(data) == count else None


def _read_lc_name(
    f: BinaryIO, start: int, cmdsize: int, name_off: int, fixed: int,
    caps: set[str],
) -> str | None:
    """One lc_str read. Walk invariant (d): the offset is bounded
    within its own command's cmdsize — a hostile offset (past cmdsize,
    a "negative" u32, or pointing back into the cmd/cmdsize/fixed
    fields) never buys a read outside the command's own bytes, and the
    string never crosses into the next command. The retained text is
    additionally byte-capped at capture; hostile names are stored as
    DATA and escaped at render by consumers."""
    if name_off < fixed or name_off >= cmdsize:
        caps.add("lc_str_out_of_bounds")
        return None
    window = min(cmdsize - name_off, _MAX_LC_NAME_BYTES + 1)
    raw = _read_exact(f, start + name_off, window)
    if raw is None:
        caps.add("lc_payload_unreadable")
        return None
    name = raw.split(b"\x00", 1)[0]
    if len(name) > _MAX_LC_NAME_BYTES:
        name = name[:_MAX_LC_NAME_BYTES]
        caps.add("lc_name_truncated")
    return name.decode("utf-8", errors="replace")


def _decode_version(value: int) -> str:
    """Decode the packed xxxx.yy.zz version u32."""
    return (f"{(value >> 16) & 0xFFFF}"
            f".{(value >> 8) & 0xFF}.{value & 0xFF}")


def _fixed_name(raw: bytes) -> str:
    """A fixed 16-byte segname/sectname field: NUL-trimmed, hostile
    text decoded losslessly enough to stay data (escape at render)."""
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def _parse_load_command(
    f: BinaryIO, facts: MachOSliceFacts, caps: set[str],
    budgets: _WalkBudgets, state: _SliceWalkState, *,
    cmd: int, cmdsize: int, start: int, endian: str,
) -> None:
    """Decode one load command's facts. ``cmdsize`` has already been
    validated against the fixed size for this type and against the
    region bound; per-field problems degrade with a marker, never
    abort the walk."""
    if cmd == _LC_UUID:
        payload = _read_exact(f, start + 8, 16)
        if payload is None:
            caps.add("lc_payload_unreadable")
            return
        uuid_hex = payload.hex()
        if facts.uuid is None:
            # All-zero recorded verbatim: the degenerate-identity
            # screen is the identity front door's later policy.
            facts.uuid = uuid_hex
        elif facts.uuid != uuid_hex:
            # First wins; a later LC_UUID carrying a DIFFERENT
            # identity is marked (identical duplicates are silent) — a
            # doctored second command must not silently steer
            # identity, and any fact it could have steered is
            # surfaced.
            caps.add("conflicting_lc_uuid")
    elif cmd in _DYLIB_KINDS:
        kind = _DYLIB_KINDS[cmd]
        facts.dylib_counts[kind] += 1
        target = {
            "load": facts.load_dylibs,
            "weak": facts.weak_dylibs,
            "reexport": facts.reexport_dylibs,
        }[kind]
        if len(target) >= _MAX_DYLIB_NAMES:
            # Counted, not retained — and the name bytes are not even
            # read: past the cap each surplus command costs only its
            # header walk (the inertness the op-count test pins).
            caps.add("dylib_names_capped")
            return
        if budgets.name_bytes_remaining <= 0:
            # File-level retained-name budget (shared across fat
            # slices): exhausted means no further name reads either.
            caps.add("lc_name_budget_exhausted")
            return
        head = _read_exact(f, start + 8, 4)
        if head is None:
            caps.add("lc_payload_unreadable")
            return
        name_off = struct.unpack(f"{endian}I", head)[0]
        name = _read_lc_name(f, start, cmdsize, name_off, 24, caps)
        if name is not None:
            budgets.name_bytes_remaining -= len(name.encode("utf-8"))
            target.append(name)
    elif cmd == _LC_RPATH:
        if len(facts.rpaths) >= _MAX_RPATHS:
            caps.add("rpaths_capped")
            return
        if budgets.name_bytes_remaining <= 0:
            caps.add("lc_name_budget_exhausted")
            return
        head = _read_exact(f, start + 8, 4)
        if head is None:
            caps.add("lc_payload_unreadable")
            return
        name_off = struct.unpack(f"{endian}I", head)[0]
        name = _read_lc_name(f, start, cmdsize, name_off, 12, caps)
        if name is not None:
            budgets.name_bytes_remaining -= len(name.encode("utf-8"))
            facts.rpaths.append(name)
    elif cmd == _LC_DYSYMTAB:
        if facts.dysymtab:
            return                      # first wins
        payload = _read_exact(f, start + 8, 24)
        if payload is None:
            caps.add("lc_payload_unreadable")
            return
        values = struct.unpack(f"{endian}IIIIII", payload)
        facts.dysymtab = {
            "ilocalsym": values[0], "nlocalsym": values[1],
            "iextdefsym": values[2], "nextdefsym": values[3],
            "iundefsym": values[4], "nundefsym": values[5],
        }
    elif cmd == _LC_BUILD_VERSION:
        payload = _read_exact(f, start + 8, 16)
        if payload is None:
            caps.add("lc_payload_unreadable")
            return
        plat_raw, minos, sdk, _ntools = struct.unpack(
            f"{endian}IIII", payload)
        platform = _BUILD_VERSION_PLATFORMS.get(
            plat_raw, f"platform_{plat_raw}")   # fail open, raw kept
        min_os = _decode_version(minos)
        sdk_str = _decode_version(sdk) if sdk else None
        if facts.min_os_source == "build_version":
            # First wins; a later LC_BUILD_VERSION stating something
            # DIFFERENT is marked (zippered images legitimately carry
            # two — the marker records that this fact is one of
            # several, without extending the record).
            if (facts.platform, facts.min_os,
                    facts.sdk) != (platform, min_os, sdk_str):
                caps.add("multiple_build_versions")
            return
        # LC_BUILD_VERSION is preferred over the legacy family
        # regardless of command order.
        facts.platform = platform
        facts.min_os = min_os
        facts.sdk = sdk_str
        facts.min_os_source = "build_version"
    elif cmd in _LC_VERSION_MIN_PLATFORM:
        if facts.min_os_source == "build_version":
            return              # build_version preferred, documented
        payload = _read_exact(f, start + 8, 8)
        if payload is None:
            caps.add("lc_payload_unreadable")
            return
        version, sdk = struct.unpack(f"{endian}II", payload)
        platform = _LC_VERSION_MIN_PLATFORM[cmd]
        min_os = _decode_version(version)
        sdk_str = _decode_version(sdk) if sdk else None
        if facts.min_os_source == "version_min":
            # First wins; a later legacy command stating something
            # DIFFERENT is marked (identical duplicates silent) —
            # the same steering-visibility rule as the LC_UUID and
            # LC_BUILD_VERSION conflicts.
            if (facts.platform, facts.min_os,
                    facts.sdk) != (platform, min_os, sdk_str):
                caps.add("multiple_version_min")
            return
        facts.platform = platform
        facts.min_os = min_os
        facts.sdk = sdk_str
        facts.min_os_source = "version_min"
    elif cmd == _LC_MAIN:
        if facts.entry_offset is not None:
            return                      # first wins
        payload = _read_exact(f, start + 8, 8)
        if payload is None:
            caps.add("lc_payload_unreadable")
            return
        facts.entry_offset = struct.unpack(f"{endian}Q", payload)[0]
    elif cmd == _LC_UNIXTHREAD:
        # Presence only, by design: the thread-state blob is
        # arch-specific register soup this fact layer never decodes.
        facts.has_unixthread = True
    elif cmd == _LC_CODE_SIGNATURE:
        if facts.code_signature_present:
            return                      # first wins
        payload = _read_exact(f, start + 8, 8)
        if payload is None:
            caps.add("lc_payload_unreadable")
            return
        _dataoff, datasize = struct.unpack(f"{endian}II", payload)
        # Presence + DECLARED size only. The signature blob is never
        # read here — parsing it is a separate hostile-parser problem.
        facts.code_signature_present = True
        facts.code_signature_size = datasize
    elif cmd in (_LC_SEGMENT, _LC_SEGMENT_64):
        _parse_segment(f, facts, caps, state, cmd=cmd,
                       cmdsize=cmdsize, start=start, endian=endian)


def _parse_segment(
    f: BinaryIO, facts: MachOSliceFacts, caps: set[str],
    state: _SliceWalkState, *,
    cmd: int, cmdsize: int, start: int, endian: str,
) -> None:
    is64 = cmd == _LC_SEGMENT_64
    fixed = 72 if is64 else 56
    fmt = f"{endian}16sQQQQiiII" if is64 else f"{endian}16sIIIIiiII"
    payload = _read_exact(f, start + 8, fixed - 8)
    if payload is None:
        caps.add("lc_payload_unreadable")
        return
    (segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot,
     nsects, _segflags) = struct.unpack(fmt, payload)
    segment = MachOSegmentFact(
        name=_fixed_name(segname),
        vmaddr=vmaddr, vmsize=vmsize,
        fileoff=fileoff, filesize=filesize,
        maxprot=maxprot, initprot=initprot,
        nsects_declared=nsects,
    )
    facts.segments.append(segment)
    sec_size = 80 if is64 else 68
    # Walk invariant (d) applied to the section array: nsects is an
    # attacker u32, but the rows live inside THIS command's bytes —
    # only as many rows as cmdsize actually holds are read.
    take = min(nsects, (cmdsize - fixed) // sec_size)
    if take < nsects:
        caps.add("segment_sections_clamped")
    # O(1) maintained counter (see _SliceWalkState): a per-command
    # re-sum over facts.segments here is quadratic in the segment
    # count and invisible to the read-count pin.
    allowance = _MAX_SECTION_RECORDS - state.section_records
    if take > allowance:
        take = allowance
        caps.add("section_records_capped")
    if take <= 0:
        return
    rows = _read_exact(f, start + fixed, take * sec_size)
    if rows is None:
        caps.add("lc_payload_unreadable")
        return
    row_fmt = (f"{endian}16s16sQQIIIIIIII" if is64
               else f"{endian}16s16sIIIIIIIII")
    for index in range(take):
        row = rows[index * sec_size:(index + 1) * sec_size]
        values = struct.unpack(row_fmt, row)
        segment.sections.append(MachOSectionFact(
            segment=_fixed_name(values[1]),
            name=_fixed_name(values[0]),
            addr=values[2],
            size=values[3],
            offset=values[4],
            flags=values[8],
        ))
    state.section_records += take


def _measure_section_entropy(
    f: BinaryIO, facts: MachOSliceFacts, caps: set[str], *,
    slice_offset: int, slice_end: int, budgets: _WalkBudgets,
) -> None:
    """Per-section entropy over each section's leading file bytes.

    Walk invariant (c) again: the section ``offset`` is an attacker
    u32 relative to the slice start — every read is bounded to the
    slice extent (which the caller already clamped to file EOF), the
    per-section sample window, and the FILE-level IO budget. The row
    survives every degradation; only the measurement is skipped,
    marker-visibly."""
    for segment in facts.segments:
        for section in segment.sections:
            if (section.size == 0
                    or (section.flags & 0xFF) in _S_ZEROFILL_TYPES):
                continue    # no file bytes — truthful absence
            if budgets.entropy_measured >= _MAX_ENTROPY_SECTIONS:
                caps.add("entropy_sections_capped")
                continue
            if budgets.entropy_remaining <= 0:
                caps.add("entropy_budget_exhausted")
                continue
            absolute = slice_offset + section.offset
            if absolute > _MAX_SEEK_OFFSET or absolute >= slice_end:
                caps.add("section_data_unreadable")
                continue
            count = min(section.size, _MAX_ENTROPY_SECTION_BYTES,
                        budgets.entropy_remaining,
                        slice_end - absolute)
            try:
                f.seek(absolute)
                data = f.read(count)
            except OSError:
                # Belt-and-braces behind the offset screen: a kernel
                # refusal costs this measurement, not the walk.
                caps.add("section_data_unreadable")
                continue
            if not data:
                caps.add("section_data_unreadable")
                continue
            budgets.entropy_remaining -= len(data)
            budgets.entropy_measured += 1
            section.sampled = len(data)
            section.entropy = _shannon_entropy(data)


def macho_facts_evidence(
    binary_sha256: str, path: Path, facts: MachOFacts,
) -> BinaryEvidenceRecord:
    """Wrap one facts record as HEADER_BACKED evidence — the same
    ``make_evidence`` shape the slice/bundle intake above emits."""
    return make_evidence(
        binary_sha256,
        kind="macho_facts",
        source="macho_load_commands",
        summary=(f"Mach-O load-command facts: "
                 f"{len(facts.slices)} slice(s) walked"),
        tier=EvidenceTier.HEADER_BACKED,
        confidence="confirmed",
        reproducible=True,
        tool="binary-intake",
        location=str(path),
        data={"facts": facts.to_dict()},
    )


__all__ = [
    "AppBundleMetadata",
    "MachOFacts",
    "MachOSectionFact",
    "MachOSegmentFact",
    "MachOSlice",
    "MachOSliceFacts",
    "extract_macho_facts",
    "extract_macho_slice_facts",
    "inspect_app_bundle",
    "inspect_macho_slices",
    "macho_facts_evidence",
    "resolve_requested_slice",
    "select_slice",
]
