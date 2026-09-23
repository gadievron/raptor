"""Platform-neutral external ingress recovery for black-box binaries.

The low-level radare2 layer can recover functions and imports, but an analyst
does not start from every function named ``main`` or every imported parser.
They start from externally drivable interfaces: URL handlers, XPC listeners,
exported DLL APIs, driver dispatchers, socket readers, file open handlers and
real process entry symbols.

This module keeps those ideas separate from vulnerability claims. Every record
is still a candidate until runtime, replay or another mechanical oracle proves
the interface is exercised with attacker-controlled data.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Any

from core.evidence import BinaryEvidenceRecord, EvidenceTier, make_evidence

from .manifest import platform_label

logger = logging.getLogger(__name__)


def _addr(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, int):
        return hex(v)
    return str(v)


@dataclass(frozen=True)
class ExternalIngressCandidate:
    id: str
    kind: str
    name: str
    platform: str
    source: str
    external_control: str
    boundary: str
    score: int
    confidence: str
    evidence_tier: str
    evidence_ids: list[str]
    bound_function_id: str = ""
    bound_function_name: str = ""
    address: str = ""
    details: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "name": self.name,
            "platform": self.platform,
            "source": self.source,
            "external_control": self.external_control,
            "boundary": self.boundary,
            "score": self.score,
            "confidence": self.confidence,
            "evidence_tier": self.evidence_tier,
            "evidence_ids": list(self.evidence_ids),
            "bound_function_id": self.bound_function_id,
            "bound_function_name": self.bound_function_name,
            "address": self.address,
            "details": dict(self.details or {}),
            "claim": "external_ingress_candidate_only",
        }


_CALLBACK_INGRESS = {
    "application:openFile:": ("file_open_handler", "user_supplied_file", "external_to_process", 95),
    "application:openFiles:": ("file_open_handler", "user_supplied_file", "external_to_process", 95),
    "application:openURLs:": ("url_handler", "user_supplied_url", "external_to_process", 100),
    "application:openURL:options:": ("url_handler", "user_supplied_url", "external_to_process", 100),
    "application:continueUserActivity:restorationHandler:": ("user_activity_handler", "user_supplied_activity", "external_to_process", 85),
    "application:handleOpenURL:": ("url_handler", "user_supplied_url", "external_to_process", 100),
    "handleAppleEvent:withReplyEvent:": ("apple_event_handler", "user_supplied_event", "external_to_process", 90),
    "listener:shouldAcceptNewConnection:": ("ipc_listener", "peer_process", "process_boundary", 105),
    "userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:": ("notification_handler", "user_supplied_notification", "external_to_process", 75),
    "webView:decidePolicyForNavigationAction:decisionHandler:": ("web_navigation_handler", "web_content", "web_to_process", 90),
    "webView:didReceiveAuthenticationChallenge:completionHandler:": ("web_auth_challenge_handler", "remote_peer", "web_to_process", 80),
}

_DRIVER_SYMBOLS = {
    "DriverEntry": ("driver_initialisation", "kernel_loader", "kernel_boundary", 40),
    "EvtIoDeviceControl": ("ioctl_dispatch", "user_mode_ioctl", "kernel_boundary", 120),
    "EvtIoInternalDeviceControl": ("ioctl_dispatch", "kernel_peer_ioctl", "kernel_boundary", 115),
    "DispatchDeviceControl": ("ioctl_dispatch", "user_mode_ioctl", "kernel_boundary", 120),
    "IRP_MJ_DEVICE_CONTROL": ("ioctl_dispatch", "user_mode_ioctl", "kernel_boundary", 120),
    "IRP_MJ_INTERNAL_DEVICE_CONTROL": ("ioctl_dispatch", "kernel_peer_ioctl", "kernel_boundary", 115),
}

_LINUX_DRIVER_SYMBOLS = {
    "module_init": ("driver_initialisation", "kernel_loader", "kernel_boundary", 40),
    "init_module": ("driver_initialisation", "kernel_loader", "kernel_boundary", 40),
    "unlocked_ioctl": ("ioctl_dispatch", "user_mode_ioctl", "kernel_boundary", 120),
    "compat_ioctl": ("ioctl_dispatch", "user_mode_ioctl", "kernel_boundary", 115),
    "proc_ioctl": ("ioctl_dispatch", "user_mode_ioctl", "kernel_boundary", 110),
}

_PE_EXPORT_SKIP = {
    "DllMain",
    "DllRegisterServer",
    "DllUnregisterServer",
    "DllCanUnloadNow",
    "DllGetClassObject",
}

# Export-table symbol types (radare2 iEj, upper-cased) that mark a
# data export. A global length-limit constant exported as OBJ is real
# surface information, but it is not an API an external caller can
# invoke — ranking it as ``exported_api`` pushes genuine function
# exports down the ingress queue. Data-typed exports are DEMOTED to
# the low-score ``exported_data`` kind, never dropped: the type byte
# is attacker-controlled (a 2-byte st_info patch relabels a callable
# export OBJECT while it stays dlopen/dlsym-callable), so suppression
# would hand the binary an operator-invisible surface-hiding lever —
# demotion keeps every export visible in candidates, graph and report.
# Unknown or missing types stay ``exported_api`` (fail-open):
# symbol-type coverage varies by binary format and r2 version, and
# demoting a real API is worse than ranking a constant.
_DATA_EXPORT_TYPES = frozenset({"OBJ", "OBJECT", "TLS", "COMMON"})

# Score for demoted data exports — below every callable-API surface
# (exported_api is 70/75) so a data export can never outrank a
# function export, while staying present in the ranked output.
_DATA_EXPORT_SCORE = 10


def _id(*parts: Any) -> str:
    raw = "::".join(str(part) for part in parts)
    return f"BINGRESS-{hashlib.sha256(raw.encode('utf-8', 'surrogateescape')).hexdigest()[:12]}"


# Shared target_kind -> OS mapping (kept under the module-local name
# the call sites use).
_platform = platform_label


def recover_external_ingress(
    manifest: Any,
    context_map: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[BinaryEvidenceRecord]]:
    """Recover externally drivable interfaces without claiming reachability."""
    records: list[BinaryEvidenceRecord] = []
    candidates: list[ExternalIngressCandidate] = []
    seen: set[tuple[str, str, str]] = set()
    platform = _platform(manifest)
    functions = {
        str(item.get("name") or ""): item
        for item in context_map.get("interesting_functions", [])
        if isinstance(item, dict) and item.get("name")
    }

    # Base-name fallback index, built once. Pre-fix every export not
    # found by exact name linearly rescanned all interesting functions
    # (2000+ PE-DLL exports x 10k functions = ~20M splits/compares —
    # a multi-minute pure-CPU stall in recover_external_ingress).
    # setdefault keeps the FIRST function per base name, matching the
    # old scan's first-in-iteration-order semantics exactly.
    functions_by_base: dict[str, dict[str, Any]] = {}
    for function_name, item in functions.items():
        functions_by_base.setdefault(function_name.split(".")[-1], item)

    def bind_function(name: str) -> tuple[str, str, str]:
        exact = functions.get(name)
        if exact is None:
            base = name.rsplit(".", maxsplit=1)[-1]
            exact = functions_by_base.get(base)
        if exact is None:
            return "", "", ""
        return (
            str(exact.get("id") or ""),
            str(exact.get("name") or ""),
            _addr(exact.get("address")),
        )

    def add(
        *,
        kind: str,
        name: str,
        source: str,
        external_control: str,
        boundary: str,
        score: int,
        tier: EvidenceTier,
        confidence: str,
        bound_function_id: str = "",
        bound_function_name: str = "",
        address: str = "",
        details: dict[str, Any] | None = None,
        existing_evidence_ids: list[str] | None = None,
    ) -> None:
        key = (kind, name, bound_function_id)
        if key in seen:
            return
        seen.add(key)
        evidence_ids = list(existing_evidence_ids or [])
        if not evidence_ids:
            record = make_evidence(
                manifest.binary_sha256,
                kind="external_ingress_candidate",
                source=source,
                summary=f"Recovered {kind} candidate {name!r}",
                tier=tier,
                confidence=confidence,
                reproducible=True,
                tool="binary-ingress",
                location=f"{manifest.binary_path}@{address}" if address else manifest.binary_path,
                data={
                    "kind": kind,
                    "name": name,
                    "external_control": external_control,
                    "boundary": boundary,
                    "bound_function_id": bound_function_id,
                },
            )
            records.append(record)
            evidence_ids = [record.id]
        candidates.append(ExternalIngressCandidate(
            id=_id(kind, name, bound_function_id or address),
            kind=kind,
            name=name,
            platform=platform,
            source=source,
            external_control=external_control,
            boundary=boundary,
            score=score,
            confidence=confidence,
            evidence_tier=tier.value,
            evidence_ids=evidence_ids,
            bound_function_id=bound_function_id,
            bound_function_name=bound_function_name,
            address=address,
            details=details,
        ))

    # Conventional process entry symbols are useful orientation, but they are
    # not automatically attacker-controlled.
    for item in context_map.get("entry_points", []):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        kind = "process_entry"
        control = "process_invocation"
        boundary = "process_start"
        score = 25
        if name == "LLVMFuzzerTestOneInput":
            kind = "libfuzzer_entry"
            control = "fuzzer_bytes"
            boundary = "harness_boundary"
            score = 120
        elif name in {"DriverEntry"}:
            kind = "driver_initialisation"
            control = "kernel_loader"
            boundary = "kernel_boundary"
            score = 40
        add(
            kind=kind,
            name=name,
            source="radare2_function_name",
            external_control=control,
            boundary=boundary,
            score=score,
            tier=EvidenceTier.HEURISTIC,
            confidence="candidate",
            bound_function_id=str(item.get("id") or ""),
            bound_function_name=name,
            address=_addr(item.get("address")),
            existing_evidence_ids=list(item.get("evidence_ids") or []),
        )

    # Mach-O / Objective-C / Swift callback contracts are much more useful than
    # raw ``main`` because they describe concrete framework-delivered input.
    for item in context_map.get("framework_callback_candidates", []):
        if not isinstance(item, dict):
            continue
        selector = str(item.get("method_name") or "")
        spec = _CALLBACK_INGRESS.get(selector)
        if spec is None:
            continue
        kind, control, boundary, score = spec
        add(
            kind=kind,
            name=f"{item.get('class_name')}.{selector}",
            source="radare2_icj_selector",
            external_control=control,
            boundary=boundary,
            score=score,
            tier=EvidenceTier.HEADER_BACKED,
            confidence="candidate",
            bound_function_id=str(item.get("bound_function_id") or ""),
            bound_function_name=str(item.get("bound_function_name") or ""),
            address=_addr(item.get("address")),
            details={"selector": selector, "class_name": item.get("class_name")},
            existing_evidence_ids=list(item.get("evidence_ids") or []),
        )

    bundle = getattr(manifest, "app_bundle", None)
    if bundle:
        for scheme in bundle.url_schemes:
            add(
                kind="url_scheme",
                name=scheme,
                source="Info.plist",
                external_control="user_supplied_url",
                boundary="external_to_process",
                score=90,
                tier=EvidenceTier.HEADER_BACKED,
                confidence="confirmed",
                details={"bundle_identifier": bundle.identifier},
            )
        for document_type in bundle.document_types:
            add(
                kind="document_type",
                name=document_type,
                source="Info.plist",
                external_control="user_supplied_file",
                boundary="external_to_process",
                score=80,
                tier=EvidenceTier.HEADER_BACKED,
                confidence="confirmed",
                details={"bundle_identifier": bundle.identifier},
            )

    # Imported input channels are capability-level ingress only. They matter on
    # stripped ELF/PE binaries where framework metadata does not exist, but we
    # keep their score below bound callbacks and exported APIs.
    for item in context_map.get("sources", []):
        if not isinstance(item, dict):
            continue
        channel_type = str(item.get("type") or "").replace("binary_", "").replace("_input", "")
        boundary = {
            "network": "network_to_process",
            "file": "filesystem_to_process",
            "stream": "stream_to_process",
            "ipc": "process_boundary",
            "environment": "process_environment",
        }.get(channel_type, "external_to_process")
        add(
            kind=f"{channel_type}_input",
            name=str(item.get("entry") or f"{channel_type} input"),
            source="import_table",
            external_control=f"{channel_type}_bytes",
            boundary=boundary,
            score=55 if channel_type in {"network", "ipc"} else 40,
            tier=EvidenceTier.HEADER_BACKED,
            confidence=str(item.get("confidence") or "candidate"),
            details={"observed": bool(item.get("observed"))},
            existing_evidence_ids=list(item.get("evidence_ids") or []),
        )

    exports = [str(item) for item in getattr(manifest, "exports", []) if item]
    export_names = set(exports)
    export_types = {
        str(name): str(value).upper()
        for name, value in (getattr(manifest, "export_types", {}) or {}).items()
    }
    data_export_names: list[str] = []

    def symbol_provenance(name: str) -> tuple[str, EvidenceTier]:
        if name in export_names:
            return "export_table", EvidenceTier.HEADER_BACKED
        return "radare2_function_name", EvidenceTier.HEURISTIC

    def is_data_export(name: str) -> bool:
        return export_types.get(name, "") in _DATA_EXPORT_TYPES

    def add_data_export(name: str) -> None:
        """Demote a data-typed export: visible low-score candidate,
        never an ``exported_api`` peer (see _DATA_EXPORT_TYPES)."""
        data_export_names.append(name)
        function_id, function_name, address = bind_function(name)
        add(
            kind="exported_data",
            name=name,
            source="export_table",
            external_control="external_caller",
            boundary="caller_to_library",
            score=_DATA_EXPORT_SCORE,
            tier=EvidenceTier.HEADER_BACKED,
            confidence="candidate",
            bound_function_id=function_id,
            bound_function_name=function_name,
            address=address,
            details={"symbol_type": export_types.get(name, "")},
        )

    if str(getattr(manifest, "target_kind", "")).startswith("pe-"):
        for symbol, (kind, control, boundary, score) in _DRIVER_SYMBOLS.items():
            matches = sorted({
                name
                for name in [*exports, *functions]
                if name.endswith((symbol, symbol.lower()))
            })
            for name in matches:
                function_id, function_name, address = bind_function(name)
                source, tier = symbol_provenance(name)
                add(
                    kind=kind,
                    name=name,
                    source=source,
                    external_control=control,
                    boundary=boundary,
                    score=score,
                    tier=tier,
                    confidence="candidate",
                    bound_function_id=function_id,
                    bound_function_name=function_name,
                    address=address,
                )
        if getattr(manifest, "target_kind", "") == "pe-dll":
            if len(exports) > 2000:
                logger.info("PE DLL has %d exports", len(exports))
            for name in exports:
                if name.split(".")[-1] in _PE_EXPORT_SKIP:
                    continue
                if is_data_export(name):
                    add_data_export(name)
                    continue
                function_id, function_name, address = bind_function(name)
                add(
                    kind="exported_api",
                    name=name,
                    source="export_table",
                    external_control="external_caller",
                    boundary="caller_to_library",
                    score=75,
                    tier=EvidenceTier.HEADER_BACKED,
                    confidence="candidate",
                    bound_function_id=function_id,
                    bound_function_name=function_name,
                    address=address,
                )
    elif getattr(manifest, "target_kind", "") == "elf-kmod":
        for symbol, (kind, control, boundary, score) in _LINUX_DRIVER_SYMBOLS.items():
            matches = sorted({
                name
                for name in [*exports, *functions]
                if name.endswith((symbol, symbol.lower()))
            })
            for name in matches:
                function_id, function_name, address = bind_function(name)
                source, tier = symbol_provenance(name)
                add(
                    kind=kind,
                    name=name,
                    source=source,
                    external_control=control,
                    boundary=boundary,
                    score=score,
                    tier=tier,
                    confidence="candidate",
                    bound_function_id=function_id,
                    bound_function_name=function_name,
                    address=address,
                )
    elif getattr(manifest, "target_kind", "") == "elf-linux":
        if len(exports) > 2000:
            logger.info("ELF binary has %d exports", len(exports))
        for name in exports:
            if name.split(".")[-1] in {"main", "_start"}:
                continue
            if is_data_export(name):
                add_data_export(name)
                continue
            function_id, function_name, address = bind_function(name)
            add(
                kind="exported_api",
                name=name,
                source="export_table",
                external_control="external_caller",
                boundary="caller_to_library",
                score=70,
                tier=EvidenceTier.HEADER_BACKED,
                confidence="candidate",
                bound_function_id=function_id,
                bound_function_name=function_name,
                address=address,
            )

    if data_export_names:
        # One aggregated record of the demotion decision, on top of
        # the per-candidate evidence add() already emitted — the full
        # count survives even when the name list is truncated, so a
        # padded export table cannot push a demoted name out of the
        # audit trail unnoticed.
        truncated = len(data_export_names) > 200
        records.append(make_evidence(
            manifest.binary_sha256,
            kind="exported_data_symbol",
            source="export_table",
            summary=(
                f"{len(data_export_names)} exported data symbol(s) "
                "demoted from exported_api to exported_data ingress"
            ),
            tier=EvidenceTier.HEADER_BACKED,
            confidence="confirmed",
            reproducible=True,
            tool="binary-ingress",
            location=manifest.binary_path,
            data={
                "kind": "exported_data",
                "count": len(data_export_names),
                # Bounded: a hostile export table must not balloon the
                # evidence store through this record.
                "names": sorted(data_export_names)[:200],
                "names_truncated": truncated,
            },
        ))

    return [
        item.to_dict()
        for item in sorted(candidates, key=lambda candidate: (-candidate.score, candidate.kind, candidate.name))
    ], records


__all__ = ["ExternalIngressCandidate", "recover_external_ingress"]
