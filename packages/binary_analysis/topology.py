"""Deployment topology recovery for black-box binary investigation.

The security boundary is often larger than one executable. A macOS app can
ship helpers and XPC services; a Windows driver sits behind a kernel/user-mode
boundary; a DLL is called by another process; an ELF daemon may expose network
or IPC ingress. This module records those components and boundaries without
pretending the relationship is exploitable.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def _find_declared_artifact(bundle_root: Path, name: str) -> Path | None:
    preferred = [
        bundle_root / "Contents" / "Library" / "HelperTools" / name,
        bundle_root / "Contents" / "Resources" / name,
        bundle_root / "Contents" / "MacOS" / name,
    ]
    for path in preferred:
        if path.is_file():
            return path
    resolved_root = bundle_root.resolve()
    try:
        for path in bundle_root.rglob(name):
            if path.is_file() and path.resolve().is_relative_to(resolved_root):
                return path
    except OSError:
        return None
    return None


def discover_sibling_artifacts(manifest: Any) -> list[dict[str, Any]]:
    """Resolve deployment siblings we can prove from local artefacts."""
    bundle = getattr(manifest, "app_bundle", None)
    if bundle is None:
        return []
    bundle_root = Path(bundle.bundle_path)
    target = Path(manifest.binary_path).resolve()
    found: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(path: Path | None, *, name: str, kind: str, declared_by: str) -> None:
        resolved = str(path.resolve()) if path and path.exists() else ""
        key = resolved or f"{kind}:{name}"
        if key in seen:
            return
        seen.add(key)
        found.append({
            "name": name,
            "kind": kind,
            "declared_by": declared_by,
            "path": resolved,
            "present": bool(resolved),
            "executable": bool(path and path.exists() and os.access(path, os.X_OK)),
            "evidence_tier": "header_backed",
            "claim": "declared_or_present_sibling_only",
        })

    for name in bundle.privileged_executables:
        add(
            _find_declared_artifact(bundle_root, name),
            name=name,
            kind="privileged_helper",
            declared_by="SMPrivilegedExecutables",
        )
    for name in bundle.helper_tools:
        add(
            _find_declared_artifact(bundle_root, name),
            name=name,
            kind="helper_tool",
            declared_by="Contents/Library/HelperTools",
        )
    for xpc_name in bundle.xpc_services:
        xpc_root = bundle_root / "Contents" / "XPCServices" / xpc_name
        candidate = None
        macos_dir = xpc_root / "Contents" / "MacOS"
        if macos_dir.is_dir():
            for path in sorted(macos_dir.iterdir()):
                if path.is_file() and os.access(path, os.X_OK):
                    candidate = path
                    break
        add(candidate, name=xpc_name, kind="xpc_service", declared_by="Contents/XPCServices")

    macos_dir = bundle_root / "Contents" / "MacOS"
    if macos_dir.is_dir():
        for path in sorted(macos_dir.iterdir()):
            if not path.is_file() or not os.access(path, os.X_OK):
                continue
            if path.resolve() == target:
                continue
            add(path, name=path.name, kind="sibling_executable", declared_by="Contents/MacOS")
    return found


def build_component_topology(
    manifest: Any,
    ingress: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a small platform-neutral component/boundary map."""
    siblings = discover_sibling_artifacts(manifest)
    components = [{
        "id": "BCOMP-TARGET",
        "kind": "target_binary",
        "name": Path(manifest.binary_path).name,
        "path": manifest.binary_path,
        "platform": _platform(manifest),
        "privilege": "unknown",
        "evidence_tier": "header_backed",
    }]
    for index, item in enumerate(siblings, start=1):
        components.append({
            "id": f"BCOMP-SIBLING-{index:03d}",
            "kind": item["kind"],
            "name": item["name"],
            "path": item["path"],
            "platform": _platform(manifest),
            "privilege": "elevated_candidate" if item["kind"] == "privileged_helper" else "unknown",
            "evidence_tier": item["evidence_tier"],
        })

    boundaries: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in ingress:
        boundary = str(item.get("boundary") or "")
        if not boundary:
            continue
        key = (boundary, str(item.get("kind") or ""))
        if key in seen:
            continue
        seen.add(key)
        boundaries.append({
            "id": f"BBOUNDARY-{len(boundaries) + 1:03d}",
            "kind": boundary,
            "ingress_kind": item.get("kind"),
            "description": _boundary_description(boundary),
            "evidence_tier": item.get("evidence_tier"),
            "confidence": item.get("confidence"),
            "claim": "boundary_candidate_only",
        })

    target_kind = str(getattr(manifest, "target_kind", "") or "")
    if target_kind in {"pe-sys", "elf-kmod"} and not any(
        item["kind"] == "kernel_boundary" for item in boundaries
    ):
        boundaries.append({
            "id": f"BBOUNDARY-{len(boundaries) + 1:03d}",
            "kind": "kernel_boundary",
            "ingress_kind": "driver",
            "description": "User/kernel transition around driver dispatch and ioctl handling.",
            "evidence_tier": "header_backed",
            "confidence": "confirmed",
            "claim": "boundary_candidate_only",
        })
    elif target_kind == "pe-dll" and not any(
        item["kind"] == "caller_to_library" for item in boundaries
    ):
        boundaries.append({
            "id": f"BBOUNDARY-{len(boundaries) + 1:03d}",
            "kind": "caller_to_library",
            "ingress_kind": "exported_api",
            "description": "External process calls into exported library APIs.",
            "evidence_tier": "header_backed",
            "confidence": "candidate",
            "claim": "boundary_candidate_only",
        })

    return {
        "platform": _platform(manifest),
        "target_kind": target_kind,
        "components": components,
        "boundaries": boundaries,
        "sibling_artifacts": siblings,
        "analysis_note": (
            "Topology records deployment structure and externally drivable boundaries. "
            "It is not proof that data crosses them unsafely."
        ),
    }


def _platform(manifest: Any) -> str:
    kind = str(getattr(manifest, "target_kind", "") or "")
    if kind == "macho":
        return "macos"
    if kind.startswith("pe-"):
        return "windows"
    if kind in {"elf-linux", "elf-kmod"}:
        return "linux"
    return "generic"


def _boundary_description(kind: str) -> str:
    return {
        "external_to_process": "External user-controlled input delivered into the process.",
        "process_boundary": "Another process can initiate an IPC interaction.",
        "network_to_process": "Remote or local network bytes enter the process.",
        "filesystem_to_process": "Filesystem content or path state enters the process.",
        "stream_to_process": "Stream bytes enter the process.",
        "process_environment": "Process environment influences behaviour.",
        "web_to_process": "Web content or navigation state crosses into native code.",
        "caller_to_library": "An external caller invokes an exported library API.",
        "kernel_boundary": "User/kernel or kernel/driver boundary.",
        "harness_boundary": "Fuzzer-owned bytes are passed into a harness entry point.",
        "process_start": "Process startup boundary.",
    }.get(kind, "Externally visible boundary candidate.")


__all__ = ["build_component_topology", "discover_sibling_artifacts"]
