"""Evidence-backed intake for compiled targets.

This stage answers only questions the bytes can answer cheaply and
deterministically: what file we were given, which format/runtime markers are
actually present, and which import capabilities are visible. It does not claim
reachability or exploitability.
"""

from __future__ import annotations

import logging
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TYPE_CHECKING

from core.binary.addrmap import image_base as _addrmap_image_base
from core.binary.fingerprint import bucket_imports
from core.hash import sha256_file
from packages.fuzzing.target_detector import detect

from ._symbols import strip_import_prefix
from core.evidence import BinaryEvidenceRecord, EvidenceTier, make_evidence
from .macho import AppBundleMetadata, MachOSlice, inspect_app_bundle, inspect_macho_slices, select_slice

if TYPE_CHECKING:
    from collections.abc import Iterable

_SCAN_CAP = 64 * 1024 * 1024
_CHUNK = 1024 * 1024

logger = logging.getLogger(__name__)


def _module_identity(
    binary: Path,
    target_kind: str,
    analysed_slice: MachOSlice | None,
) -> tuple[str, str]:
    """``(identity_kind, value)`` via the kind-aware front door.

    The front door sniffs the format itself, so the sandboxed
    build-id probe only ever runs on ELF bytes (and its sandbox
    refusal degrades to the content hash inside the door, loudly).
    Mach-O identity follows the ANALYSED slice — the same selection
    the rest of the manifest describes.  Identity is enrichment: any
    probe failure leaves the manifest identity-free rather than
    failing the intake.
    """
    selection = analysed_slice if target_kind == "macho" else None
    try:
        from core.binary.identity import content_identity
        ident = content_identity(binary, slice_selection=selection)
    except Exception:  # noqa: BLE001 — enrichment only; the manifest stays identity-free
        logger.debug("module identity extraction failed", exc_info=True)
        return "", ""
    if ident is None:
        return "", ""
    return ident.kind, ident.value


@dataclass
class RuntimeSignal:
    family: str
    marker: str
    confidence: str
    evidence_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "marker": self.marker,
            "confidence": self.confidence,
            "evidence_id": self.evidence_id,
        }


@dataclass
class BinaryManifest:
    schema_version: int
    binary_path: str
    binary_sha256: str
    size_bytes: int
    executable: bool
    target_kind: str
    arch: str
    bits: int
    binary_format: str
    analysis_depth: str = "full"
    # Module identity legs for normalized function ids
    # (core.binary.addrmap / core.binary.identity): ``build_id``
    # holds the module identity VALUE for ``identity_kind`` — GNU
    # build-id (elf_build_id), analysed-slice LC_UUID (macho_uuid),
    # canonical RSDS GUID+age (pe_guid_age), or the whole-file hash
    # (sha256); "" when no identity could be derived. ``identity_kind``
    # "" on records predating the field means elf-or-unknown — readers
    # apply the prefix anchor rule, never an error. The analysis-time
    # image base stays None when never recorded — fid consumers
    # refuse, they never substitute 0.
    build_id: str = ""
    identity_kind: str = ""
    image_base: int | None = None
    imports: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    # Symbol type per export name (FUNC, OBJ, ...) from the radare2
    # export table. Names with no reported type are absent.
    export_types: dict[str, str] = field(default_factory=dict)
    capability_buckets: dict[str, list[str]] = field(default_factory=dict)
    runtime_signals: list[RuntimeSignal] = field(default_factory=list)
    slices: list[MachOSlice] = field(default_factory=list)
    analysed_slice: MachOSlice | None = None
    app_bundle: AppBundleMetadata | None = None
    evidence: list[BinaryEvidenceRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "binary_path": self.binary_path,
            "binary_sha256": self.binary_sha256,
            "size_bytes": self.size_bytes,
            "executable": self.executable,
            "target_kind": self.target_kind,
            "arch": self.arch,
            "bits": self.bits,
            "binary_format": self.binary_format,
            "analysis_depth": self.analysis_depth,
            "build_id": self.build_id,
            "identity_kind": self.identity_kind,
            "image_base": self.image_base,
            "imports": list(self.imports),
            "exports": list(self.exports),
            "export_types": {
                name: self.export_types[name]
                for name in sorted(self.export_types)
            },
            "capability_buckets": {
                key: sorted(value)
                for key, value in sorted(self.capability_buckets.items())
            },
            "runtime_signals": [item.to_dict() for item in self.runtime_signals],
            "slices": [item.to_dict() for item in self.slices],
            "analysed_slice": self.analysed_slice.to_dict() if self.analysed_slice else None,
            "analysis_scope": {
                "selected_arch": self.analysed_slice.arch if self.analysed_slice else self.arch,
                "deep_analysis_arch": (
                    self.analysed_slice.arch if self.analysed_slice else self.arch
                ) if self.analysis_depth == "full" else None,
                "analysis_depth": self.analysis_depth,
                "all_slices_analysed": self.analysis_depth == "full" and len(self.slices) <= 1,
                "slice_count": len(self.slices),
            },
            "app_bundle": self.app_bundle.to_dict() if self.app_bundle else None,
            "evidence": [item.to_dict() for item in self.evidence],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BinaryManifest:
        return cls(
            schema_version=int(data.get("schema_version", 1)),
            binary_path=str(data.get("binary_path") or ""),
            binary_sha256=str(data.get("binary_sha256") or ""),
            size_bytes=int(data.get("size_bytes") or 0),
            executable=bool(data.get("executable")),
            target_kind=str(data.get("target_kind") or ""),
            arch=str(data.get("arch") or ""),
            bits=int(data.get("bits") or 0),
            binary_format=str(data.get("binary_format") or ""),
            analysis_depth=str(data.get("analysis_depth") or "full"),
            build_id=str(data.get("build_id") or ""),
            identity_kind=str(data.get("identity_kind") or ""),
            # Tolerant of every wire shape (int / hex string / absent)
            # via the single base parser; absent stays None.
            image_base=_addrmap_image_base(data),
            imports=[str(item) for item in data.get("imports") or []],
            exports=[str(item) for item in data.get("exports") or []],
            export_types={
                str(key): str(value)
                for key, value in (data.get("export_types") or {}).items()
                if value
            },
            capability_buckets={
                str(key): [str(item) for item in value]
                for key, value in (data.get("capability_buckets") or {}).items()
                if isinstance(value, list)
            },
            runtime_signals=[
                RuntimeSignal(
                    family=str(item.get("family") or ""),
                    marker=str(item.get("marker") or ""),
                    confidence=str(item.get("confidence") or "candidate"),
                    evidence_id=str(item.get("evidence_id") or ""),
                )
                for item in data.get("runtime_signals") or []
                if isinstance(item, dict)
            ],
            slices=[
                MachOSlice(
                    arch=str(item.get("arch") or ""),
                    cpu_type=int(item.get("cpu_type") or 0),
                    cpu_subtype=int(item.get("cpu_subtype") or 0),
                    offset=int(item.get("offset") or 0),
                    size=int(item.get("size") or 0),
                    bits=int(item.get("bits") or 0),
                    sha256=str(item.get("sha256") or ""),
                )
                for item in data.get("slices") or []
                if isinstance(item, dict)
            ],
            analysed_slice=(
                MachOSlice(
                    arch=str((data.get("analysed_slice") or {}).get("arch") or ""),
                    cpu_type=int((data.get("analysed_slice") or {}).get("cpu_type") or 0),
                    cpu_subtype=int((data.get("analysed_slice") or {}).get("cpu_subtype") or 0),
                    offset=int((data.get("analysed_slice") or {}).get("offset") or 0),
                    size=int((data.get("analysed_slice") or {}).get("size") or 0),
                    bits=int((data.get("analysed_slice") or {}).get("bits") or 0),
                    sha256=str((data.get("analysed_slice") or {}).get("sha256") or ""),
                )
                if isinstance(data.get("analysed_slice"), dict) else None
            ),
            app_bundle=(
                AppBundleMetadata.from_dict(data["app_bundle"])
                if isinstance(data.get("app_bundle"), dict) else None
            ),
            evidence=[],  # populated by pipeline after construction
        )


def platform_label(manifest: Any) -> str:
    """Coarse OS label derived from ``target_kind`` — the shared
    mapping topology and ingress previously each copied. Accepts any
    manifest-shaped object (``target_kind`` attribute); unknown or
    missing kinds land on ``"generic"``."""
    kind = str(getattr(manifest, "target_kind", "") or "")
    if kind == "macho":
        return "macos"
    if kind.startswith("pe-"):
        return "windows"
    if kind in {"elf-linux", "elf-kmod"}:
        return "linux"
    return "generic"


def _normalise_symbol(name: str) -> str:
    return strip_import_prefix(name)


def _iter_markers(path: Path, markers: Iterable[bytes]) -> set[bytes]:
    wanted = set(markers)
    found: set[bytes] = set()
    carry = b""
    read_total = 0
    try:
        with path.open("rb") as f:
            while read_total < _SCAN_CAP and wanted - found:
                chunk = f.read(min(_CHUNK, _SCAN_CAP - read_total))
                if not chunk:
                    break
                read_total += len(chunk)
                haystack = carry + chunk
                for marker in wanted - found:
                    if marker in haystack:
                        found.add(marker)
                max_marker = max((len(m) for m in wanted), default=1)
                carry = haystack[-max_marker:]
    except OSError:
        return set()
    return found


_MAX_ZIP_MEMBERS = 10000
# Central-directory byte ceiling for the probe. Real bundles stay far
# under (10k entries x ~100-400 B records); a crafted archive whose
# EOCD understates its entry count still cannot make ZipFile buffer an
# oversized directory past this gate.
_MAX_ZIP_CDIR_BYTES = 8 * 1024 * 1024
_EOCD_SIG = b"PK\x05\x06"


def _zip_central_directory_bounds(path: Path) -> tuple[int, int] | None:
    """(entry_count, central_directory_bytes) from the end-of-central-
    directory record, or ``None`` when no EOCD exists (not a zip).
    Reads only the file tail — never the directory itself. A zip64
    sentinel (0xFFFF / 0xFFFFFFFF) is returned as-is: anything needing
    zip64 is far beyond the probe's member cap anyway."""
    try:
        size = path.stat().st_size
        tail_len = min(size, 65536 + 22)   # max comment + EOCD record
        with path.open("rb") as fh:
            fh.seek(size - tail_len)
            tail = fh.read(tail_len)
    except OSError:
        return None
    idx = tail.rfind(_EOCD_SIG)
    if idx < 0 or len(tail) - idx < 22:
        return None
    total = int.from_bytes(tail[idx + 10:idx + 12], "little")
    cd_size = int.from_bytes(tail[idx + 12:idx + 16], "little")
    return total, cd_size


def _zip_members(path: Path) -> set[str]:
    # Gate BEFORE parsing: ZipFile(path) materialises the whole
    # central directory at open (a crafted 200k-entry zip drove ~6x
    # its file size in peak allocation), so slicing namelist() after
    # the fact bounded nothing. The EOCD header carries the counts
    # cheaply; oversize archives are refused up front — this is a
    # best-effort runtime-signal probe, not an inventory.
    bounds = _zip_central_directory_bounds(path)
    if bounds is None:
        return set()
    total, cd_size = bounds
    if total > _MAX_ZIP_MEMBERS or cd_size > _MAX_ZIP_CDIR_BYTES:
        return set()
    try:
        with zipfile.ZipFile(path) as zf:
            return set(zf.namelist()[:_MAX_ZIP_MEMBERS])
    except (OSError, zipfile.BadZipFile, RuntimeError):
        return set()


def _runtime_signals(
    path: Path,
    digest: str,
    *,
    target_kind: str,
) -> tuple[list[RuntimeSignal], list[BinaryEvidenceRecord]]:
    records: list[BinaryEvidenceRecord] = []
    signals: list[RuntimeSignal] = []
    try:
        with path.open("rb") as f:
            head = f.read(8)
    except OSError:
        head = b""

    def add(family: str, marker: str, *, confidence: str, source: str, summary: str) -> None:
        record = make_evidence(
            digest,
            kind="runtime_signal",
            source=source,
            summary=summary,
            tier=EvidenceTier.HEADER_BACKED,
            confidence=confidence,
            reproducible=True,
            tool="binary-intake",
            data={"family": family, "marker": marker},
        )
        records.append(record)
        signals.append(RuntimeSignal(family, marker, confidence, record.id))

    # 0xCAFEBABE is also the big-endian fat Mach-O magic. Only call it
    # Java when the earlier format detector did not already prove Mach-O.
    if head.startswith(b"\xca\xfe\xba\xbe") and target_kind != "macho":
        add("java", "CAFEBABE", confidence="confirmed", source="file_magic",
            summary="Java class file magic present")

    members = _zip_members(path)
    if members:
        if "AndroidManifest.xml" in members and any(name.endswith(".dex") for name in members):
            add("android", "AndroidManifest.xml + classes.dex", confidence="confirmed",
                source="zip_members", summary="APK structure present in archive")
        elif "META-INF/MANIFEST.MF" in members and any(name.endswith(".class") for name in members):
            add("java", "META-INF/MANIFEST.MF + .class", confidence="high",
                source="zip_members", summary="JAR-like archive structure present")

    markers = _iter_markers(
        path,
        (
            b"BSJB",
            b"_CorExeMain",
            b"mscoree.dll",
            b"Go buildinf:",
            b".gopclntab",
            b"rust_eh_personality",
            b"core::panicking",
        ),
    )
    if b"BSJB" in markers or b"_CorExeMain" in markers or b"mscoree.dll" in markers:
        marker = next(
            item for item in ("BSJB", "_CorExeMain", "mscoree.dll")
            if item.encode() in markers
        )
        add(".net", marker, confidence="high", source="byte_marker",
            summary=f".NET runtime marker {marker!r} present")
    if b"Go buildinf:" in markers or b".gopclntab" in markers:
        marker = "Go buildinf:" if b"Go buildinf:" in markers else ".gopclntab"
        add("go", marker, confidence="high", source="byte_marker",
            summary=f"Go runtime marker {marker!r} present")
    if b"rust_eh_personality" in markers or b"core::panicking" in markers:
        marker = "rust_eh_personality" if b"rust_eh_personality" in markers else "core::panicking"
        add("rust", marker, confidence="candidate", source="byte_marker",
            summary=f"Rust runtime marker {marker!r} present")
    return signals, records


def build_manifest(
    binary_path: Path,
    context: Any | None = None,
    *,
    requested_slice_arch: str | None = None,
) -> BinaryManifest:
    binary = Path(binary_path).resolve()
    digest = sha256_file(binary)
    target = detect(binary)
    stat = binary.stat()
    imports = sorted({_normalise_symbol(item) for item in getattr(context, "imports", []) if item})
    exports = sorted({str(item) for item in getattr(context, "exports", []) if item})
    export_types = {
        str(key): str(value)
        for key, value in (getattr(context, "export_types", {}) or {}).items()
        if key and value
    }
    runtime_signals, signal_evidence = _runtime_signals(
        binary,
        digest,
        target_kind=target.kind,
    )
    slices: list[MachOSlice] = []
    slice_evidence: list[BinaryEvidenceRecord] = []
    app_bundle: AppBundleMetadata | None = None
    bundle_evidence: list[BinaryEvidenceRecord] = []
    if target.kind == "macho":
        slices, slice_evidence = inspect_macho_slices(binary, digest)
        app_bundle, bundle_evidence = inspect_app_bundle(binary, digest)
    analysed_slice = select_slice(
        slices,
        requested_slice_arch,
        getattr(context, "arch", None),
        getattr(context, "bits", None),
    )
    identity_kind, identity_value = _module_identity(
        binary, target.kind, analysed_slice,
    )
    intake_evidence = make_evidence(
        digest,
        kind="binary_intake",
        source="file_header",
        summary=f"Read {target.kind} target metadata from file bytes",
        tier=EvidenceTier.HEADER_BACKED,
        confidence="confirmed",
        reproducible=True,
        tool="target_detector",
        location=str(binary),
        data={
            "target_kind": target.kind,
            "arch": target.arch,
            "size_bytes": stat.st_size,
            "executable": bool(stat.st_mode & 0o111),
        },
    )
    return BinaryManifest(
        schema_version=1,
        binary_path=str(binary),
        binary_sha256=digest,
        size_bytes=stat.st_size,
        executable=bool(stat.st_mode & 0o111),
        target_kind=target.kind,
        arch=str((analysed_slice.arch if analysed_slice else "") or getattr(context, "arch", "") or target.arch),
        bits=int((analysed_slice.bits if analysed_slice else 0) or getattr(context, "bits", 0) or 0),
        binary_format=str(getattr(context, "binary_format", "") or target.kind),
        analysis_depth=str(getattr(context, "analysis_depth", "") or "full"),
        build_id=identity_value,
        identity_kind=identity_kind,
        # Only an analysis-RECORDED base is carried; the context's
        # int default 0 without the recorded flag would mint wrong
        # identities for non-zero-based binaries.
        image_base=(
            int(getattr(context, "image_base", 0))
            if getattr(context, "image_base_recorded", False) else None
        ),
        imports=imports,
        exports=exports,
        export_types=export_types,
        capability_buckets={
            key: sorted(value)
            for key, value in bucket_imports(set(imports)).items()
        },
        runtime_signals=runtime_signals,
        slices=slices,
        analysed_slice=analysed_slice,
        app_bundle=app_bundle,
        evidence=[intake_evidence, *signal_evidence, *slice_evidence, *bundle_evidence],
    )


__all__ = ["BinaryManifest", "RuntimeSignal", "build_manifest"]
