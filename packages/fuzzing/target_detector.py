"""Target binary / source detection.

Given a path, work out what we're looking at and which fuzzer (if any)
can sensibly attack it on the host system. Designed so the orchestrator
gives clear, actionable feedback before a campaign starts rather than
a cryptic failure six commands deep.

Supported target kinds:
  - elf-linux      : Linux ELF binary (any arch)
  - elf-kmod       : Linux kernel module (.ko)
  - macho          : macOS Mach-O binary
  - pe-exe         : Windows PE executable
  - pe-dll         : Windows DLL
  - pe-sys         : Windows kernel driver (.sys)
  - te             : TE (Terse Executable) UEFI image — classified,
                     deliberately not analysed

  - java-class     : Java class file
  - java-archive   : Java JAR archive
  - apk            : Android APK archive
  - source-c       : C/C++ source files (need harness)
  - source-cpp     : C++ source files (need harness)
  - rust-crate     : Rust crate (Cargo.toml present)
  - python-pkg     : Python package (setup.py / pyproject.toml)
  - unknown        : Unrecognised
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

logger = logging.getLogger(__name__)

_THIN_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
}
_FAT_MACHO_MAGICS = {
    b"\xca\xfe\xba\xbe": (">", False),
    b"\xbe\xba\xfe\xca": ("<", False),
    b"\xca\xfe\xba\xbf": (">", True),
    b"\xbf\xba\xfe\xca": ("<", True),
}
_KNOWN_MACHO_CPU_TYPES = {
    7,
    12,
    18,
    0x01000007,
    0x0100000C,
    0x01000012,
}


# C-family source extensions — ONE set consumed by BOTH the file-mode
# branches and the directory walk. These were hand-copied per mode and
# drifted: the directory set lacked .cxx/.hh/.hxx, so a pure-.cxx tree
# detected `unknown` while any single such file detected `source-cpp`.
_C_SOURCE_EXTS = frozenset({".c", ".h"})
_CPP_SOURCE_EXTS = frozenset({".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"})
_C_FAMILY_EXTS = _C_SOURCE_EXTS | _CPP_SOURCE_EXTS


@dataclass
class TargetInfo:
    """What we determined about a target."""

    path: Path
    kind: str
    arch: str = "unknown"
    description: str = ""
    can_fuzz_here: bool = False
    recommended_fuzzer: str | None = None
    blockers: list[str] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)

    def summary(self) -> str:
        out = [f"Target: {self.path}", f"Kind: {self.kind}", f"Arch: {self.arch}"]
        if self.description:
            out.append(f"Description: {self.description}")
        out.append(f"Fuzzable on this host: {'yes' if self.can_fuzz_here else 'no'}")
        if self.recommended_fuzzer:
            out.append(f"Recommended fuzzer: {self.recommended_fuzzer}")
        if self.blockers:
            out.append("Blockers:")
            out.extend(f"  - {b}" for b in self.blockers)
        if self.hints:
            out.append("Hints:")
            out.extend(f"  - {h}" for h in self.hints)
        return "\n".join(out)


def detect(path: Path) -> TargetInfo:
    """Detect what kind of target a path represents."""
    path = Path(path).resolve()
    if not path.exists():
        return TargetInfo(
            path=path, kind="unknown",
            description=f"Path does not exist: {path}",
        )

    if path.is_dir():
        return _detect_directory(path)

    return _detect_file(path)


def _detect_file(path: Path) -> TargetInfo:
    """Detect a single file by reading its magic bytes and extension."""
    try:
        with Path(path).open("rb") as f:
            magic = f.read(64)
    except OSError as e:
        return TargetInfo(
            path=path, kind="unknown",
            description=f"Could not read file: {e}",
        )

    suffix = path.suffix.lower()
    sys_platform = platform.system()

    # ELF (Linux, BSD, etc)
    if magic[:4] == b"\x7fELF":
        return _detect_elf(path, magic, sys_platform)

    # Mach-O (macOS, including fat binaries). 0xCAFEBABE is also the
    # Java class-file magic, so only call it fat Mach-O when the header
    # has a structurally valid architecture table.
    if magic[:4] in _THIN_MACHO_MAGICS or _looks_like_fat_macho(path, magic):
        return _detect_macho(path, magic, sys_platform)

    # PE (Windows): MZ header at offset 0
    if magic[:2] == b"MZ":
        return _detect_pe(path, magic, suffix, sys_platform)

    # TE (Terse Executable, UEFI PI firmware): "VZ" at offset 0 — a
    # stripped-down PE relative with NO DOS stub and NO COFF header,
    # so nothing on the MZ path above ever sees one and the PE facts
    # extractor does not parse it. The kind is "te", deliberately
    # NOT a "pe-" kind: downstream consumers key Windows behavior
    # off the "pe-" prefix (the target_kind -> OS platform label,
    # the Windows driver-symbol ingress probing), and a UEFI image
    # must inherit neither.
    if magic[:2] == b"VZ":
        return _detect_te(path, magic)

    if magic[:4] == b"\xca\xfe\xba\xbe":
        return TargetInfo(
            path=path,
            kind="java-class",
            description="Java class file",
            can_fuzz_here=False,
            hints=["Use /binary or /understand --map for intake; JVM harnessing is not orchestrated yet."],
        )

    if magic[:4] == b"PK\x03\x04":
        archive = _detect_zip_artifact(path)
        if archive is not None:
            return archive

    # Source code by extension
    if suffix in _C_SOURCE_EXTS:
        return TargetInfo(
            path=path, kind="source-c",
            description="C source/header file",
            can_fuzz_here=False,
            hints=[
                "Use --harness mode to generate a libFuzzer harness from this file.",
                "Or pass the directory containing this file to fuzz the whole library.",
            ],
        )
    if suffix in _CPP_SOURCE_EXTS:
        return TargetInfo(
            path=path, kind="source-cpp",
            description="C++ source/header file",
            can_fuzz_here=False,
            hints=["Use --harness mode to generate a libFuzzer harness."],
        )

    # Cargo.toml / pyproject.toml on a file path -- treat as crate/package marker
    if path.name == "Cargo.toml":
        return _detect_rust_crate(path.parent)
    if path.name in ("pyproject.toml", "setup.py"):
        return _detect_python_pkg(path.parent)

    return TargetInfo(
        path=path, kind="unknown",
        description=f"Unrecognised file format. Magic: {magic[:8].hex()}",
        hints=["Run 'file <path>' for more info."],
    )


def _looks_like_fat_macho(path: Path, magic: bytes) -> bool:
    spec = _FAT_MACHO_MAGICS.get(magic[:4])
    if spec is None or len(magic) < 28:
        return False
    endian, is_64 = spec
    try:
        count = struct.unpack(f"{endian}I", magic[4:8])[0]
    except struct.error:
        return False
    if count < 1 or count > 64:
        return False
    entry_size = 32 if is_64 else 20
    if len(magic) < 8 + entry_size:
        return False
    try:
        values = struct.unpack(
            f"{endian}IIQQII" if is_64 else f"{endian}IIIII",
            magic[8:8 + entry_size],
        )
    except struct.error:
        return False
    cpu_type, _cpu_subtype, offset, size = values[:4]
    if cpu_type not in _KNOWN_MACHO_CPU_TYPES:
        return False
    header_size = 8 + (count * entry_size)
    try:
        file_size = path.stat().st_size
    except OSError:
        return False
    return int(offset) >= header_size and int(size) > 0 and int(offset) + int(size) <= file_size


def _detect_zip_artifact(path: Path) -> TargetInfo | None:
    try:
        with zipfile.ZipFile(path) as zf:
            # Slice the (already-parsed) infolist rather than calling
            # namelist(), which materialises a name list for EVERY
            # entry before the slice — a zip with millions of entries
            # is attacker-supplied input here.
            members = {zi.filename for zi in zf.infolist()[:10000]}
    except (OSError, zipfile.BadZipFile, RuntimeError):
        return None
    if "AndroidManifest.xml" in members and any(name.endswith(".dex") for name in members):
        return TargetInfo(
            path=path,
            kind="apk",
            description="Android APK archive",
            can_fuzz_here=False,
            hints=["Use /binary or /understand --map for intake; APK runtime harnessing is not orchestrated yet."],
        )
    if "META-INF/MANIFEST.MF" in members and any(name.endswith(".class") for name in members):
        return TargetInfo(
            path=path,
            kind="java-archive",
            description="Java JAR archive",
            can_fuzz_here=False,
            hints=["Use /binary or /understand --map for intake; JVM harnessing is not orchestrated yet."],
        )
    return None


def _tree_has_extension(root: Path, extensions: frozenset[str]) -> bool:
    """Single recursive walk with early exit on the first match.

    One ``glob('**/pat')`` per extension meant up to five COMPLETE
    recursive walks (node_modules-scale included) when a large non-C
    tree matched nothing; one walk checking every extension per file
    bounds the no-match case at a single traversal.
    """
    for _dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            if os.path.splitext(name)[1].lower() in extensions:
                return True
    return False


def _detect_directory(path: Path) -> TargetInfo:
    """Inspect a directory for project markers."""
    if (path / "Cargo.toml").exists():
        return _detect_rust_crate(path)
    if (path / "pyproject.toml").exists() or (path / "setup.py").exists():
        return _detect_python_pkg(path)
    if _tree_has_extension(path, _C_FAMILY_EXTS):
        return TargetInfo(
            path=path, kind="source-c",
            description="Directory containing C/C++ sources",
            can_fuzz_here=False,
            hints=[
                "Use harness generation to create libFuzzer harnesses for "
                "specific functions in this library.",
            ],
        )
    return TargetInfo(
        path=path, kind="unknown",
        description="Directory with no recognised project marker",
        hints=["RAPTOR currently fuzzes individual binaries, harness generation, or recognised package types."],
    )


def _detect_elf(path: Path, magic: bytes, sys_platform: str) -> TargetInfo:
    arch = "unknown"
    if len(magic) >= 20:
        ei_class = magic[4]   # 1=32-bit, 2=64-bit
        # e_machine uses the file's own byte order (EI_DATA: 1=LSB,
        # 2=MSB) — reading it little-endian unconditionally byte-swaps
        # the arch label for every big-endian ELF (s390x, MIPS BE,
        # ppc32).
        ei_data = magic[5]
        byteorder: Literal["little", "big"] = (
            "big" if ei_data == 2 else "little"
        )
        machine = int.from_bytes(magic[18:20], byteorder)
        machine_map = {
            0x03: "i386", 0x3E: "x86_64",
            0x28: "arm", 0xB7: "aarch64",
            0xF3: "riscv",
        }
        arch = machine_map.get(machine, f"machine_{machine:#x}")
        if ei_class == 1 and machine not in machine_map:
            arch = "32-bit"

    if path.suffix.lower() == ".ko":
        return TargetInfo(
            path=path,
            kind="elf-kmod",
            arch=arch,
            description=f"Linux kernel module ({arch})",
            can_fuzz_here=False,
            recommended_fuzzer="kafl-or-snapchange",
            blockers=[
                "Linux kernel modules need a kernel harness or snapshot fuzzing setup; "
                "RAPTOR does not load or fuzz them in-process.",
            ],
            hints=[
                "Recover ioctl/file_operations entry points first, then build a narrow "
                "kernel harness or use kAFL/Snapchange.",
            ],
        )

    is_executable = path.stat().st_mode & 0o111 != 0
    can_fuzz = sys_platform == "Linux" and is_executable

    info = TargetInfo(
        path=path, kind="elf-linux", arch=arch,
        description=f"Linux ELF binary ({arch})",
        can_fuzz_here=can_fuzz,
        recommended_fuzzer="afl" if can_fuzz else None,
    )
    if not can_fuzz:
        if sys_platform != "Linux":
            info.blockers.append(
                f"Linux ELF binaries do not run on {sys_platform}. "
                "Run inside a Linux VM, container (Docker), or WSL."
            )
        if not is_executable:
            info.blockers.append("File is not executable. Run 'chmod +x' first.")
    return info


def _detect_macho(path: Path, magic: bytes, sys_platform: str) -> TargetInfo:
    arch = "fat" if magic[:4] in (
        b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
    ) else "unknown"
    if magic[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"):
        arch = "32-bit"
    elif magic[:4] in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        arch = "64-bit"

    is_executable = path.stat().st_mode & 0o111 != 0
    can_fuzz = sys_platform == "Darwin" and is_executable

    info = TargetInfo(
        path=path, kind="macho", arch=arch,
        description=f"macOS Mach-O binary ({arch})",
        can_fuzz_here=can_fuzz,
        recommended_fuzzer="libfuzzer" if can_fuzz else None,
    )
    if not can_fuzz:
        if sys_platform != "Darwin":
            info.blockers.append(
                f"Mach-O binaries do not run on {sys_platform}. "
                "Run on macOS or under qemu-darwin."
            )
        if not is_executable:
            info.blockers.append("File is not executable. Run 'chmod +x' first.")
    if can_fuzz:
        info.hints.append(
            "On macOS, libFuzzer is generally more reliable than AFL++. "
            "If the binary is not libFuzzer-instrumented, recompile with "
            "'-fsanitize=fuzzer,address'."
        )
    return info


def _detect_pe(
    path: Path,
    _magic: bytes,
    suffix: str,
    sys_platform: str,
) -> TargetInfo:
    """Windows PE: .exe, .dll, .sys, .ocx, etc."""
    arch = _pe_arch(path)
    # Determine subtype from suffix and DLL flag
    kind = "pe-exe"
    description = "Windows PE executable"
    fuzzer = "winafl"

    if suffix == ".sys":
        kind = "pe-sys"
        description = "Windows kernel driver (.sys)"
        fuzzer = "kafl-or-snapchange"
    elif suffix == ".dll":
        kind = "pe-dll"
        description = "Windows DLL"
        fuzzer = "winafl"

    is_windows_host = sys_platform == "Windows"
    has_wsl = sys_platform == "Linux" and shutil.which("cmd.exe") is not None

    info = TargetInfo(
        path=path, kind=kind, arch=arch,
        description=f"{description} ({arch})",
        can_fuzz_here=False,
        recommended_fuzzer=fuzzer,
    )

    if kind == "pe-sys":
        # Kernel driver fuzzing
        if is_windows_host:
            info.hints.extend([
                "Windows kernel driver fuzzing is genuinely hard. The "
                "production-grade options are:",
                "  - kAFL: snapshot fuzzer using Intel PT + KVM (Linux host, Windows guest VM)",
                "  - Snapchange: AWS snapshot fuzzer (Linux host, KVM-based)",
                "  - HEVD-style IOCTL harness: write a user-mode harness that opens the device "
                "handle and fuzzes IOCTLs via DeviceIoControl. RAPTOR can scaffold this with --harness-ioctl.",
            ])
            info.blockers.extend([
                "RAPTOR does not orchestrate kernel-mode fuzzing in-process. "
                "You will need to set up the snapshot infrastructure separately.",
            ])
        else:
            info.blockers.extend([
                f"Cannot fuzz Windows kernel drivers from {sys_platform}.",
                "Realistic options:",
                "  - Set up a Linux host with KVM + a Windows VM, then use kAFL/Snapchange.",
                "  - Or write a user-mode IOCTL harness on a Windows machine and fuzz that.",
                "  - For purely static analysis of the driver, use /codeql or /scan against the source.",
            ])
        info.hints.append(
            "If you have the driver source, pass that instead of the .sys binary "
            "and use the harness generator to wrap individual IOCTL handlers."
        )
    elif kind in ("pe-exe", "pe-dll"):
        if is_windows_host:
            info.can_fuzz_here = True
            info.hints.extend([
                "WinAFL is the standard tool for fuzzing Windows PE binaries.",
                "It uses DynamoRIO or Intel PT for instrumentation.",
                "Install: https://github.com/googleprojectzero/winafl",
            ])
        elif has_wsl:
            info.hints.append(
                "On WSL: WinAFL can be invoked from the Windows side. "
                "RAPTOR does not orchestrate WSL/Windows handoff yet."
            )
            info.blockers.append(
                "Cross-host fuzzing (WSL to Windows binary) needs manual setup."
            )
        else:
            info.blockers.append(
                f"Windows PE binaries do not run on {sys_platform}. "
                "Run on a Windows host with WinAFL, or under Wine/Crossover for "
                "limited cases (no instrumentation)."
            )

    return info


# COFF machine value -> arch label, shared by the PE header probe
# and the TE header probe (TE reuses the COFF machine vocabulary at
# its own fixed offset).
_COFF_MACHINE_ARCH = {
    0x014C: "i386",
    0x8664: "x86_64",
    0x01C0: "arm",
    0x01C4: "armv7",
    0xAA64: "arm64",
    0x0200: "ia64",
}


def _detect_te(path: Path, magic: bytes) -> TargetInfo:
    """TE (Terse Executable) UEFI image: classify and decline.

    The machine field sits at offset 2, directly behind the "VZ"
    signature — already inside the magic bytes read, so
    classification costs no further IO. Nothing else is parsed:
    there is no DOS/COFF header for the PE facts path, and
    radare2's te loader is deliberately not engaged either — a
    low-mileage parser pointed at hostile firmware images is a poor
    trade for facts nothing downstream consumes yet; revisit with a
    dedicated firmware lane.
    """
    arch = "unknown"
    if len(magic) >= 4:
        machine = int.from_bytes(magic[2:4], "little")
        arch = _COFF_MACHINE_ARCH.get(machine,
                                      f"machine_{machine:#x}")
    return TargetInfo(
        path=path,
        kind="te",
        arch=arch,
        description=f"TE (Terse Executable) UEFI image ({arch})",
        can_fuzz_here=False,
        blockers=[
            "te_not_analysed: TE images are classified but not "
            "analysed — no DOS/COFF header for the PE facts path, "
            "and the radare2 te loader is deliberately not engaged "
            "against hostile firmware images.",
        ],
        hints=[
            "Use a firmware analysis toolchain (e.g. UEFITool) to "
            "unpack and inspect the image.",
        ],
    )


def _pe_arch(path: Path) -> str:
    """Read the PE COFF machine field rather than guessing x86_64."""
    try:
        with path.open("rb") as f:
            dos = f.read(64)
            if len(dos) < 64 or dos[:2] != b"MZ":
                return "unknown"
            pe_offset = int.from_bytes(dos[0x3C:0x40], "little")
            f.seek(pe_offset)
            header = f.read(6)
    except OSError:
        return "unknown"
    if len(header) < 6 or header[:4] != b"PE\x00\x00":
        return "unknown"
    machine = int.from_bytes(header[4:6], "little")
    return _COFF_MACHINE_ARCH.get(machine, f"machine_{machine:#x}")


# cargo-fuzz layout detection ------------------------------------------

# Fuzz-target names double as cargo bin names and path components on
# the run side; the enumeration vets them to this charset so a scanned
# repo's file names stay inert in hints, globs, and command lines.
_CARGO_FUZZ_TARGET_NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
# Enumeration bound — fuzz_targets/ is scanned-repo content, so a
# planted directory with millions of entries must not balloon hints or
# plan output. Real projects carry a handful of targets.
_MAX_CARGO_FUZZ_TARGETS = 256


def find_cargo_fuzz_dir(crate_dir: Path) -> Path | None:
    """Locate the cargo-fuzz workspace for *crate_dir*.

    The conventional layout is a ``fuzz/`` child holding its own
    ``Cargo.toml`` plus a ``fuzz_targets/`` directory (what
    ``cargo fuzz init`` scaffolds). The crate directory itself also
    qualifies, so an operator can point /fuzz straight at the fuzz
    workspace. Returns the RESOLVED path, or None when neither
    matches.

    Containment: a candidate — or its ``fuzz_targets`` directory —
    that resolves OUTSIDE the resolved crate directory is refused with
    a logged reason. The fuzz workspace receives a build-phase write
    grant downstream and the target enumeration walks ``fuzz_targets``,
    so a repo-planted symlink at either level would otherwise steer
    the grant or the enumeration at an arbitrary tree elsewhere on the
    host.
    """
    base = Path(crate_dir)
    try:
        base_resolved = base.resolve()
    except OSError:
        return None

    def _escapes(path: Path) -> Path | None:
        """The resolved path when it escapes the crate, else None."""
        try:
            resolved = path.resolve()
        except OSError:
            return path
        if resolved != base_resolved and \
                base_resolved not in resolved.parents:
            return resolved
        return None

    for candidate in (base / "fuzz", base):
        if not ((candidate / "Cargo.toml").is_file()
                and (candidate / "fuzz_targets").is_dir()):
            continue
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        for level, escaped_to in (
            (candidate, _escapes(candidate)),
            (candidate / "fuzz_targets",
             _escapes(candidate / "fuzz_targets")),
        ):
            if escaped_to is not None:
                logger.warning(
                    "cargo-fuzz layout at %s refused: %s resolves to "
                    "%s, outside the crate %s — a symlinked workspace "
                    "or fuzz_targets dir would steer the build's "
                    "write grant or the target enumeration off the "
                    "crate",
                    candidate, level, escaped_to, base_resolved,
                )
                break
        else:
            return resolved
    return None


def list_cargo_fuzz_targets(fuzz_dir: Path) -> list[str]:
    """Fuzz-target names under ``<fuzz_dir>/fuzz_targets`` (``.rs``
    stems), sorted, charset-vetted, symlink-refusing, and bounded —
    the tree is the scanned repo's own content."""
    targets: list[str] = []
    try:
        entries = sorted((Path(fuzz_dir) / "fuzz_targets").iterdir())
    except OSError:
        return []
    for entry in entries:
        if len(targets) >= _MAX_CARGO_FUZZ_TARGETS:
            break
        if entry.suffix != ".rs" or entry.is_symlink() or not entry.is_file():
            continue
        if _CARGO_FUZZ_TARGET_NAME_RE.fullmatch(entry.stem):
            targets.append(entry.stem)
    return targets


def _detect_rust_crate(crate_dir: Path) -> TargetInfo:
    has_cargo = shutil.which("cargo") is not None
    has_cargo_fuzz = shutil.which("cargo-fuzz") is not None
    can_fuzz = has_cargo and has_cargo_fuzz
    info = TargetInfo(
        path=crate_dir,
        kind="rust-crate",
        description="Rust crate (Cargo.toml present)",
        can_fuzz_here=can_fuzz,
        recommended_fuzzer="cargo-fuzz" if can_fuzz else None,
    )
    if not has_cargo:
        info.blockers.append("cargo not installed. Install Rust: https://rustup.rs")
    if not has_cargo_fuzz:
        info.blockers.append(
            "cargo-fuzz not installed. Install with: cargo install cargo-fuzz"
        )
    fuzz_dir = find_cargo_fuzz_dir(crate_dir)
    targets = list_cargo_fuzz_targets(fuzz_dir) if fuzz_dir else []
    if targets:
        shown = ", ".join(targets[:8]) + (", ..." if len(targets) > 8 else "")
        info.hints.append(
            f"cargo-fuzz layout detected ({len(targets)} fuzz "
            f"target(s)): {shown}. Select one with --fuzz-target "
            "<name>; a single target is auto-selected."
        )
    else:
        info.hints.append(
            "No fuzz targets found. cargo-fuzz scaffolds harnesses in "
            "fuzz/fuzz_targets/ — use 'cargo fuzz init' (and "
            "'cargo fuzz add <name>') if not already set up."
        )
    return info


def _detect_python_pkg(pkg_dir: Path) -> TargetInfo:
    try:
        import atheris    # noqa: F401
        has_atheris = True
    except ImportError:
        has_atheris = False

    info = TargetInfo(
        path=pkg_dir,
        kind="python-pkg",
        description="Python package",
        can_fuzz_here=has_atheris,
        recommended_fuzzer="atheris" if has_atheris else None,
    )
    if not has_atheris:
        info.blockers.append("atheris not installed. Install with: pip install atheris")
    info.hints.append(
        "Atheris fuzzes Python code (and Python C extensions) using libFuzzer. "
        "Pass --py-harness <file> for an operator-written TestOneInput "
        "harness, or --py-entry module:function to scaffold the simple "
        "bytes/str case."
    )
    return info
