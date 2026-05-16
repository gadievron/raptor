"""Target binary / source detection.

Given a path, work out what we're looking at and which fuzzer (if any)
can sensibly attack it on the host system. Designed so the orchestrator
gives clear, actionable feedback before a campaign starts rather than
a cryptic failure six commands deep.

Supported target kinds:
  - elf-linux      : Linux ELF binary (any arch)
  - macho          : macOS Mach-O binary
  - pe-exe         : Windows PE executable
  - pe-dll         : Windows DLL
  - pe-sys         : Windows kernel driver (.sys)
  - source-c       : C/C++ source files (need harness)
  - source-cpp     : C++ source files (need harness)
  - rust-crate     : Rust crate (Cargo.toml present)
  - python-pkg     : Python package (setup.py / pyproject.toml)
  - unknown        : Unrecognised
"""

from __future__ import annotations

import logging
import platform
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class TargetInfo:
    """What we determined about a target."""

    path: Path
    kind: str
    arch: str = "unknown"
    description: str = ""
    can_fuzz_here: bool = False
    recommended_fuzzer: Optional[str] = None
    blockers: List[str] = field(default_factory=list)
    hints: List[str] = field(default_factory=list)

    def summary(self) -> str:
        out = [f"Target: {self.path}", f"Kind: {self.kind}", f"Arch: {self.arch}"]
        if self.description:
            out.append(f"Description: {self.description}")
        out.append(f"Fuzzable on this host: {'yes' if self.can_fuzz_here else 'no'}")
        if self.recommended_fuzzer:
            out.append(f"Recommended fuzzer: {self.recommended_fuzzer}")
        if self.blockers:
            out.append("Blockers:")
            for b in self.blockers:
                out.append(f"  - {b}")
        if self.hints:
            out.append("Hints:")
            for h in self.hints:
                out.append(f"  - {h}")
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
        with open(path, "rb") as f:
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

    # Mach-O (macOS, including fat binaries)
    if magic[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                     b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                     b"\xca\xfe\xba\xbe"):
        return _detect_macho(path, magic, sys_platform)

    # PE (Windows): MZ header at offset 0
    if magic[:2] == b"MZ":
        return _detect_pe(path, magic, suffix, sys_platform)

    # Source code by extension
    if suffix in (".c", ".h"):
        return TargetInfo(
            path=path, kind="source-c",
            description="C source/header file",
            can_fuzz_here=False,
            hints=[
                "Use --harness mode to generate a libFuzzer harness from this file.",
                "Or pass the directory containing this file to fuzz the whole library.",
            ],
        )
    if suffix in (".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"):
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


def _detect_directory(path: Path) -> TargetInfo:
    """Inspect a directory for project markers."""
    if (path / "Cargo.toml").exists():
        return _detect_rust_crate(path)
    if (path / "pyproject.toml").exists() or (path / "setup.py").exists():
        return _detect_python_pkg(path)
    if any(path.glob("*.h")) or any(path.glob("**/*.h")):
        return TargetInfo(
            path=path, kind="source-c",
            description="Directory containing C/C++ headers",
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
    if len(magic) > 18:
        ei_class = magic[4]   # 1=32-bit, 2=64-bit
        machine = int.from_bytes(magic[18:20], "little")
        machine_map = {
            0x03: "i386", 0x3E: "x86_64",
            0x28: "arm", 0xB7: "aarch64",
            0xF3: "riscv",
        }
        arch = machine_map.get(machine, f"machine_{machine:#x}")
        if ei_class == 1 and arch == "unknown":
            arch = "32-bit"

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
    arch = "fat" if magic[:4] == b"\xca\xfe\xba\xbe" else "unknown"
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
    if not can_fuzz and sys_platform != "Darwin":
        info.blockers.append(
            f"Mach-O binaries do not run on {sys_platform}. "
            "Run on macOS or under qemu-darwin."
        )
    if can_fuzz:
        info.hints.append(
            "On macOS, libFuzzer is generally more reliable than AFL++. "
            "If the binary is not libFuzzer-instrumented, recompile with "
            "'-fsanitize=fuzzer,address'."
        )
    return info


def _detect_pe(
    path: Path,
    magic: bytes,
    suffix: str,
    sys_platform: str,
) -> TargetInfo:
    """Windows PE: .exe, .dll, .sys, .ocx, etc."""
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
        path=path, kind=kind, arch="x86_64",
        description=description,
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


def _detect_rust_crate(crate_dir: Path) -> TargetInfo:
    has_cargo = shutil.which("cargo") is not None
    has_cargo_fuzz = shutil.which("cargo-fuzz") is not None
    info = TargetInfo(
        path=crate_dir,
        kind="rust-crate",
        description="Rust crate (Cargo.toml present)",
        can_fuzz_here=has_cargo and has_cargo_fuzz,
        recommended_fuzzer="cargo-fuzz",
    )
    if not has_cargo:
        info.blockers.append("cargo not installed. Install Rust: https://rustup.rs")
    if not has_cargo_fuzz:
        info.blockers.append(
            "cargo-fuzz not installed. Install with: cargo install cargo-fuzz"
        )
    info.hints.append(
        "cargo-fuzz scaffolds harnesses in fuzz/fuzz_targets/. "
        "Use 'cargo fuzz init' if not already set up."
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
        recommended_fuzzer="atheris",
    )
    if not has_atheris:
        info.blockers.append("atheris not installed. Install with: pip install atheris")
    info.hints.append(
        "Atheris fuzzes Python code (and Python C extensions) using libFuzzer. "
        "RAPTOR's harness generator can scaffold an atheris harness from a "
        "function name."
    )
    return info
