"""Binary lifting — extract targets from fleet members for analysis elsewhere.

A *lift* pulls a binary (APK, EXE, ELF, .so, .dll) from a source system
to local staging, optionally unpacks it, then hands it off to the task
router which ships it to the best-suited analysis system.

Typical flows:

    Pixel → local staging → linux-arm (AFL++ fuzzing of native .so)
    Windows → local staging → linux-arm (Ghidra headless, radare2)
    linux-arm → local staging → win-desktop (IDA Pro)

The ``lift()`` function does the download + optional unpack.
The ``lift_and_route()`` function combines lift → route → execute/launch.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Optional, Sequence

from core.broker.broker import _build_transport
from core.broker.capabilities import OperatingSystem
from core.broker.inventory import Inventory
from core.broker.transport import RemoteSystemEntry, TransportError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LiftedBinary:
    """Result of pulling a binary from a remote system."""
    source_alias: str
    remote_path: str
    local_path: str
    original_name: str
    unpacked_dir: Optional[str] = None
    file_type: Optional[str] = None
    size_bytes: int = 0


@dataclass(frozen=True)
class LiftSpec:
    """What to pull and from where."""
    source_alias: str
    remote_path: str
    unpack: bool = True


def _staging_dir() -> Path:
    """Resolve local staging directory for lifted binaries."""
    raptor_dir = os.environ.get("RAPTOR_DIR")
    base = Path(raptor_dir) if raptor_dir else Path.cwd()
    return base / "out" / "lifted"


def _detect_file_type(path: str) -> Optional[str]:
    """Use ``file`` command to identify a binary."""
    try:
        result = subprocess.run(
            ["file", "-b", path],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def _unpack_apk(apk_path: str, dest_dir: str) -> list[str]:
    """Extract native libraries from an APK.

    Returns paths to extracted .so files.  Falls back to plain
    ``unzip`` if ``apktool`` isn't available.
    """
    os.makedirs(dest_dir, exist_ok=True)
    extracted: list[str] = []

    if shutil.which("apktool"):
        subprocess.run(
            ["apktool", "d", "-f", "-o", dest_dir, apk_path],
            capture_output=True, timeout=120,
        )
    else:
        subprocess.run(
            ["unzip", "-o", "-q", apk_path, "-d", dest_dir],
            capture_output=True, timeout=60,
        )

    for root, _dirs, files in os.walk(dest_dir):
        for f in files:
            if f.endswith(".so"):
                extracted.append(os.path.join(root, f))

    return extracted


def _unpack_pe(pe_path: str, dest_dir: str) -> list[str]:
    """Extract embedded resources from a PE using 7z if available."""
    os.makedirs(dest_dir, exist_ok=True)
    if shutil.which("7z"):
        subprocess.run(
            ["7z", "x", f"-o{dest_dir}", pe_path, "-y"],
            capture_output=True, timeout=60,
        )
    shutil.copy2(pe_path, dest_dir)
    return [os.path.join(dest_dir, os.path.basename(pe_path))]


def lift(
    spec: LiftSpec,
    inventory: Inventory,
    *,
    staging_dir: Optional[str] = None,
) -> LiftedBinary:
    """Pull a binary from a fleet member to local staging.

    Connects to the source system, downloads the file, optionally
    unpacks it (APK → native .so, PE → resources), and returns a
    ``LiftedBinary`` with the local path.
    """
    entry = inventory.get(spec.source_alias)
    if not entry:
        raise LiftError(
            f"source system '{spec.source_alias}' not in inventory"
        )

    stage = Path(staging_dir) if staging_dir else _staging_dir()
    stage.mkdir(parents=True, exist_ok=True)

    filename = os.path.basename(spec.remote_path)
    local_path = str(stage / filename)

    transport = _build_transport(entry)
    try:
        transport.connect()

        if not transport.path_exists(spec.remote_path):
            raise LiftError(
                f"remote path does not exist on {spec.source_alias}: "
                f"{spec.remote_path}"
            )

        logger.info(
            "lifting %s from %s", spec.remote_path, spec.source_alias,
        )
        transport.download(spec.remote_path, local_path)

    except TransportError as exc:
        raise LiftError(f"download failed: {exc}") from exc
    finally:
        try:
            transport.disconnect()
        except Exception:
            pass

    size = os.path.getsize(local_path) if os.path.exists(local_path) else 0
    file_type = _detect_file_type(local_path)

    unpacked_dir = None
    if spec.unpack and file_type:
        unpack_dest = str(stage / f"{filename}_unpacked")

        if "Android" in (file_type or "") or filename.endswith(".apk"):
            natives = _unpack_apk(local_path, unpack_dest)
            if natives:
                unpacked_dir = unpack_dest
                logger.info(
                    "extracted %d native libraries from APK", len(natives),
                )

        elif "PE32" in (file_type or "") or filename.endswith((".exe", ".dll")):
            _unpack_pe(local_path, unpack_dest)
            unpacked_dir = unpack_dest

    return LiftedBinary(
        source_alias=spec.source_alias,
        remote_path=spec.remote_path,
        local_path=local_path,
        original_name=filename,
        unpacked_dir=unpacked_dir,
        file_type=file_type,
        size_bytes=size,
    )


def list_native_libs(lifted: LiftedBinary) -> list[str]:
    """List .so files from an unpacked APK lift."""
    if not lifted.unpacked_dir:
        return []
    result: list[str] = []
    for root, _dirs, files in os.walk(lifted.unpacked_dir):
        for f in files:
            if f.endswith(".so"):
                result.append(os.path.join(root, f))
    return sorted(result)


def choose_fuzz_target(lifted: LiftedBinary) -> str:
    """Pick the best fuzzing target from a lifted binary.

    For APKs: prefers the largest arm64-v8a .so (most attack surface).
    For everything else: returns the original file.
    """
    natives = list_native_libs(lifted)
    if not natives:
        return lifted.local_path

    arm64_libs = [n for n in natives if "arm64-v8a" in n]
    candidates = arm64_libs if arm64_libs else natives

    return max(candidates, key=lambda p: os.path.getsize(p))


class LiftError(Exception):
    """Binary lift operation failed."""
