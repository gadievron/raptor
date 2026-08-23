"""Host architecture detection + image-platform decision.

Covers host arch detection, Rosetta presence check, and manifest inspection
for the image-arch decision. Uses subprocess (no docker-py dependency); no
Colima sizing preflight or emulation-mode YAML loading.
"""

from __future__ import annotations

import json
import platform as _platform
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

_DARWIN_ROSETTA_PATH = "/Library/Apple/usr/libexec/oah/libRosettaRuntime"


@dataclass(frozen=True)
class HostArch:
    """Observed host architecture + emulation availability."""

    arch: str  # 'arm64' | 'amd64' | 'unknown'
    os: str  # 'darwin' | 'linux' | 'windows' | ...
    rosetta_available: bool = False

    @property
    def docker_platform(self) -> str:
        """Canonical ``linux/<arch>`` string for ``docker --platform``."""
        arch_to_docker = {"arm64": "linux/arm64", "amd64": "linux/amd64"}
        return arch_to_docker.get(self.arch, "linux/amd64")


@lru_cache(maxsize=1)
def detect_host_arch() -> HostArch:
    """Best-effort host detection.

    Uses :mod:`platform` for OS + arch; checks for the Rosetta runtime
    on darwin so the decision logic can tell native-on-arm64 from
    translate-capable arm64.
    """
    machine = _platform.machine().lower()
    if machine in {"arm64", "aarch64"}:
        arch = "arm64"
    elif machine in {"x86_64", "amd64"}:
        arch = "amd64"
    else:
        arch = "unknown"
    os_name = _platform.system().lower()
    rosetta = False
    if os_name == "darwin" and arch == "arm64":
        rosetta = Path(_DARWIN_ROSETTA_PATH).exists()
    return HostArch(arch=arch, os=os_name, rosetta_available=rosetta)


@dataclass
class ArchDecision:
    """Decision about whether an image can run on the current host."""

    image_ref: str
    host_arch: str
    decision: str  # 'native' | 'rosetta_ok' | 'build_from_source_required' | 'error'
    supported_platforms: list[str] = field(default_factory=list)
    reason: str = ""


def _manifest_inspect(image_ref: str, *, timeout_seconds: int = 30) -> list[str] | None:
    """Return the list of ``os/arch`` platforms the manifest advertises.

    Uses ``docker manifest inspect``. ``None`` means the manifest could
    not be fetched (private registry, nonexistent image, docker-cli
    unavailable) -- caller should treat that as ambiguous.
    """
    # run_with_timeout collapses timeout / missing-binary / OSError all to
    # returncode is None → return None (= unknown), matching the docstring
    # contract. (A bare subprocess.run would instead let TimeoutExpired
    # propagate to the caller rather than treating it as "platforms unknown".)
    from cve_env.utils.run import run_with_timeout

    outcome = run_with_timeout(
        ["docker", "manifest", "inspect", image_ref],
        timeout=timeout_seconds,
    )
    if outcome.returncode != 0 or not outcome.stdout.strip():
        return None
    try:
        data = json.loads(outcome.stdout)
    except json.JSONDecodeError:
        return None
    platforms: list[str] = []
    if isinstance(data, dict):
        manifests = data.get("manifests")
        if isinstance(manifests, list):
            for m in manifests:
                if not isinstance(m, dict):
                    continue
                plat = m.get("platform")
                if not isinstance(plat, dict):
                    continue
                os_name = plat.get("os")
                arch = plat.get("architecture")
                if isinstance(os_name, str) and isinstance(arch, str):
                    platforms.append(f"{os_name}/{arch}")
        elif "config" in data and "architecture" in data:
            # Single-arch manifest.
            os_name = data.get("os", "linux")
            arch = data["architecture"]
            if isinstance(os_name, str) and isinstance(arch, str):
                platforms.append(f"{os_name}/{arch}")
    return platforms or None


def arch_decide(image_ref: str, *, host: HostArch | None = None) -> ArchDecision:
    """Decide how ``image_ref`` runs on this host.

    * ``native`` -- manifest advertises a matching host platform.
    * ``rosetta_ok`` -- host is darwin/arm64 with Rosetta and the
      manifest has ``linux/amd64``.
    * ``build_from_source_required`` -- no native or rosetta path.
    * ``error`` -- manifest fetch failed; caller can retry or escalate.
    """
    h = host or detect_host_arch()
    platforms = _manifest_inspect(image_ref)
    if platforms is None:
        return ArchDecision(
            image_ref=image_ref,
            host_arch=h.arch,
            decision="error",
            reason="docker manifest inspect failed or returned empty",
        )

    if h.docker_platform in platforms:
        return ArchDecision(
            image_ref=image_ref,
            host_arch=h.arch,
            decision="native",
            supported_platforms=platforms,
        )

    # Rosetta path: darwin+arm64 host + linux/amd64 manifest.
    if (
        h.os == "darwin"
        and h.arch == "arm64"
        and h.rosetta_available
        and "linux/amd64" in platforms
    ):
        return ArchDecision(
            image_ref=image_ref,
            host_arch=h.arch,
            decision="rosetta_ok",
            supported_platforms=platforms,
        )

    return ArchDecision(
        image_ref=image_ref,
        host_arch=h.arch,
        decision="build_from_source_required",
        supported_platforms=platforms,
        reason=(f"no matching platform; host={h.docker_platform} image={platforms}"),
    )
