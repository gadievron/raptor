"""Black-box binary understanding pipeline.

This is the first-class binary sibling of source `/understand`. It keeps the
existing `context-map.json` contract for downstream consumers, but adds richer
binary artefacts and a queryable SQLite graph. Static recovery, runtime
observation, fuzz witnesses and SMT checks all meet here without flattening
their evidence strength.
"""

from __future__ import annotations

import bisect
import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from core.json import load_json, save_json
from core.hash import sha256_file

from ._symbols import symbol_base_name
from .constraints import validate_constraint_file
from .diff import diff_manifests
from .evidence import EvidenceRecord, EvidenceTier, make_evidence
from .fuzz_evidence import CrashEvidence, FuzzEvidenceBundle, load_fuzz_evidence
from .fuzz_suitability import assess_fuzz_suitability
from .graph_store import BinaryGraphStore, graph_path_for_run, graph_summary, stable_node_id
from .ingress import recover_external_ingress
from .input_channels import InputChannel, event_channel_kind, merge_observed_channels, recover_static_channels
from .manifest import BinaryManifest, build_manifest
from .parser_boundary import extract_parser_boundaries
from .radare2_understand import BinaryContextMap, FunctionInfo, analyse_binary_context
from .runtime_evidence import load_runtime_evidence
from .surface_classification import classify_security_api
from .topology import build_component_topology
from .validation_handoff import build_validation_handoff

logger = logging.getLogger(__name__)

_RUNTIME_SUPPORT_PREFIXES = (
    "sym.___afl_",
    "sym.___asan_",
    "sym.___cmplog_",
    "sym.___sanitizer_",
    "sym._sancov.",
    "sym._ijon_",
)
_RUNTIME_SUPPORT_EXACT_NAMES = {
    "sym.___early_forkserver",
    "sym._area_is_valid",
    "sym._send_forkserver_error",
    "sym._write_error_with_location",
}
_FRAMEWORK_CALLBACK_SELECTORS = {
    "applicationDidFinishLaunching:",
    "applicationWillFinishLaunching:",
    "applicationWillTerminate:",
    "application:openFile:",
    "application:openFiles:",
    "application:openURLs:",
    "application:openURL:options:",
    "application:continueUserActivity:restorationHandler:",
    "application:handleOpenURL:",
    "applicationSupportsSecureRestorableState:",
    "handleAppleEvent:withReplyEvent:",
    "listener:shouldAcceptNewConnection:",
    "userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:",
    "webView:decidePolicyForNavigationAction:decisionHandler:",
    "webView:didReceiveAuthenticationChallenge:completionHandler:",
}


@dataclass
class BinaryAnalysisResult:
    manifest: BinaryManifest
    context_map: dict[str, Any]
    evidence: list[EvidenceRecord]
    input_channels: list[InputChannel]
    graph_path: Path
    fuzz: FuzzEvidenceBundle = field(default_factory=FuzzEvidenceBundle)
    constraints: Optional[dict[str, Any]] = None
    diff: Optional[dict[str, Any]] = None
    decompilations: dict[str, Any] = field(default_factory=dict)
    validation_handoff: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest": self.manifest.to_dict(),
            "context_map": self.context_map,
            "evidence": [record.to_dict() for record in self.evidence],
            "input_channels": [channel.to_dict() for channel in self.input_channels],
            "graph_path": str(self.graph_path),
            "fuzz": self.fuzz.to_dict(),
            "constraints": self.constraints,
            "diff": self.diff,
            "decompilations": self.decompilations,
            "validation_handoff": self.validation_handoff,
        }


def _address(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return hex(int(value))
    except (TypeError, ValueError):
        return ""


def _fn_id(prefix: str, fn: Any) -> str:
    address = getattr(fn, "address", None)
    if address:
        return f"{prefix}-{int(address):x}"
    name = getattr(fn, "name", "unknown")
    digest = hashlib.sha256(str(name).encode("utf-8", "surrogateescape")).hexdigest()[:12]
    return f"{prefix}-{digest}"


def _sorted_functions(functions: list[Any]) -> tuple[list[int], list[Any]]:
    valid = [fn for fn in functions if fn.address is not None and fn.size > 0]
    valid.sort(key=lambda fn: int(fn.address))
    addrs = [int(fn.address) for fn in valid]
    return addrs, valid


def _find_containing_function(address: int, sorted_addrs: list[int], sorted_fns: list[Any]) -> Any:
    idx = bisect.bisect_right(sorted_addrs, address) - 1
    if idx < 0:
        return None
    fn = sorted_fns[idx]
    if int(fn.address) <= address < int(fn.address) + fn.size:
        return fn
    return None


def _import_candidate_id(prefix: str, name: str) -> str:
    digest = hashlib.sha256(str(name).encode("utf-8", "surrogateescape")).hexdigest()[:12]
    return f"{prefix}-{digest}"


def _metadata_item_id(prefix: str, *parts: Any) -> str:
    raw = "::".join(str(part) for part in parts)
    digest = hashlib.sha256(raw.encode("utf-8", "surrogateescape")).hexdigest()[:12]
    return f"{prefix}-{digest}"


def _is_runtime_support_name(name: str) -> bool:
    normalised = str(name or "")
    return normalised in _RUNTIME_SUPPORT_EXACT_NAMES or normalised.startswith(_RUNTIME_SUPPORT_PREFIXES)


def _is_graph_worthy_method(name: str) -> bool:
    """Keep the graph useful when Swift metadata contains numeric thunks."""
    normalised = str(name or "")
    if not normalised or normalised.isdigit():
        return False
    if normalised.startswith("func.") and normalised[5:].replace("_", "").isalnum():
        return False
    return True


def _static_evidence(manifest: BinaryManifest, context: BinaryContextMap) -> list[EvidenceRecord]:
    evidence: list[EvidenceRecord] = []
    digest = manifest.binary_sha256
    if context.imports:
        evidence.append(make_evidence(
            digest,
            kind="import_table",
            source="radare2_iij",
            summary=f"radare2 recovered {len(context.imports)} imported symbols",
            tier=EvidenceTier.HEADER_BACKED,
            confidence="confirmed",
            reproducible=True,
            tool="radare2",
            data={"imports": sorted(context.imports)},
        ))
    if context.interesting_functions:
        evidence.append(make_evidence(
            digest,
            kind="function_inventory",
            source="radare2_aflj",
            summary=f"radare2 recovered {len(context.interesting_functions)} code functions",
            tier=EvidenceTier.XREF_BACKED,
            confidence="high",
            reproducible=True,
            tool="radare2",
            data={"function_count": len(context.interesting_functions)},
        ))
    if context.classes:
        methods = sum(len(item.methods) for item in context.classes)
        fields = sum(len(item.fields) for item in context.classes)
        evidence.append(make_evidence(
            digest,
            kind="class_metadata_inventory",
            source="radare2_icj",
            summary=(
                f"radare2 recovered {len(context.classes)} class metadata records "
                f"with {methods} methods"
            ),
            tier=EvidenceTier.HEADER_BACKED,
            confidence="confirmed",
            reproducible=True,
            tool="radare2",
            data={
                "class_count": len(context.classes),
                "method_count": methods,
                "field_count": fields,
                "languages": sorted({item.language for item in context.classes if item.language}),
            },
        ))
    return evidence


def _runtime_observation_summary(
    events: list[dict[str, Any]],
    evidence_ids: list[str],
) -> list[dict[str, Any]]:
    counts: dict[tuple[str, str], int] = {}
    for event in events:
        category = str(event.get("category") or "unknown")
        fn = str(event.get("fn") or "unknown")
        counts[(category, fn)] = counts.get((category, fn), 0) + 1
    return [
        {
            "id": f"BRT-OBS-{index:03d}",
            "category": category,
            "function": fn,
            "count": count,
            "confidence": "confirmed",
            "evidence_tier": EvidenceTier.OBSERVED_RUNTIME.value,
            "evidence_ids": list(evidence_ids),
        }
        for index, ((category, fn), count) in enumerate(sorted(counts.items()), start=1)
    ]


def _decompilation_artifact(
    manifest: BinaryManifest,
    context: BinaryContextMap,
) -> tuple[dict[str, Any], list[EvidenceRecord]]:
    records: list[EvidenceRecord] = []
    functions: list[dict[str, Any]] = []
    for fn in context.interesting_functions:
        if not fn.decompiled:
            continue
        body = fn.decompiled
        body_sha256 = hashlib.sha256(body.encode("utf-8", "surrogateescape")).hexdigest()
        record = make_evidence(
            manifest.binary_sha256,
            kind="decompiled_function",
            source=str(context.decompiler or "radare2_pdc"),
            summary=f"Decompiler recovered pseudocode for {fn.name!r}",
            tier=EvidenceTier.DECOMPILER_INFERRED,
            confidence="candidate",
            reproducible=True,
            tool=str(context.decompiler or "radare2"),
            location=f"{manifest.binary_path}@{_address(fn.address)}",
            data={
                "name": fn.name,
                "address": _address(fn.address),
                "size": fn.size,
                "body_sha256": body_sha256,
                "decompiler": context.decompiler,
            },
        )
        records.append(record)
        functions.append({
            "id": f"BDEC-{int(fn.address or 0):x}",
            "function_id": _fn_id("BFN", fn),
            "name": fn.name,
            "address": _address(fn.address),
            "size": fn.size,
            "decompiler": context.decompiler,
            "body_sha256": body_sha256,
            "body": body,
            "evidence_id": record.id,
            "evidence_tier": EvidenceTier.DECOMPILER_INFERRED.value,
            "confidence": "candidate",
        })
    coverage = {
        "recovered_functions": len(context.interesting_functions),
        "decompiled_functions": len(functions),
        "attempted_functions": int(context.decompilation_attempted or 0),
        "configured_limit": int(context.decompilation_limit or 0),
        "decompiler": context.decompiler or "",
        "complete": bool(context.interesting_functions) and len(functions) == len(context.interesting_functions),
        "note": "Pseudocode is a prioritisation aid and an operator artefact, not proof of attacker control.",
    }
    return {"coverage": coverage, "functions": functions}, records


def _runtime_input_flows(
    manifest: BinaryManifest,
    context: BinaryContextMap,
    channels: list[InputChannel],
    runtime_events: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[EvidenceRecord]]:
    channel_by_kind = {channel.kind: channel for channel in channels}
    raw_functions = [
        fn for fn in context.interesting_functions
        if fn.address is not None and fn.size > 0 and not _is_runtime_support_name(fn.name)
    ]
    sorted_addrs, sorted_fns = _sorted_functions(raw_functions)
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for event in runtime_events:
        kind = event_channel_kind(event)
        caller = str(event.get("caller") or "")
        caller_offset = str(event.get("caller_offset") or "")
        if kind is None or (not caller and not caller_offset):
            continue
        try:
            if caller_offset and context.image_base:
                caller_addr = int(context.image_base) + int(caller_offset, 16)
            else:
                caller_addr = int(caller, 16)
        except ValueError:
            continue
        fn = _find_containing_function(caller_addr, sorted_addrs, sorted_fns)
        if fn is None or kind not in channel_by_kind:
            continue
        key = (kind, _fn_id("BFN", fn))
        item = grouped.setdefault(key, {
            "channel": channel_by_kind[kind],
            "function": fn,
            "events": [],
        })
        item["events"].append(event)

    flows: list[dict[str, Any]] = []
    evidence: list[EvidenceRecord] = []
    for index, ((kind, fn_id), item) in enumerate(sorted(grouped.items()), start=1):
        channel = item["channel"]
        fn = item["function"]
        events = item["events"]
        record = make_evidence(
            manifest.binary_sha256,
            kind="runtime_input_callsite",
            source="frida_callsite",
            summary=f"Frida observed {fn.name!r} calling a {kind} input API",
            tier=EvidenceTier.OBSERVED_RUNTIME,
            confidence="confirmed",
            reproducible=False,
            tool="frida",
            location=f"{manifest.binary_path}@{_address(fn.address)}",
            data={
                "channel": kind,
                "function": fn.name,
                "function_id": fn_id,
                "event_count": len(events),
                "callers": sorted({str(event.get("caller")) for event in events}),
                "caller_offsets": sorted({str(event.get("caller_offset")) for event in events if event.get("caller_offset")}),
            },
        )
        evidence.append(record)
        flows.append({
            "id": f"BRT-FLOW-{index:03d}",
            "channel_id": channel.id,
            "channel_kind": kind,
            "function_id": fn_id,
            "function_name": fn.name,
            "address": _address(fn.address),
            "event_count": len(events),
            "callers": sorted({str(event.get("caller")) for event in events}),
            "caller_offsets": sorted({str(event.get("caller_offset")) for event in events if event.get("caller_offset")}),
            "confidence": "confirmed",
            "evidence_tier": EvidenceTier.OBSERVED_RUNTIME.value,
            "evidence_ids": [record.id],
            "evidence_note": "Runtime callsite proof only; it does not prove those bytes reach a later sink.",
        })
    return flows, evidence


def _runtime_parser_flows(
    manifest: BinaryManifest,
    context: BinaryContextMap,
    surface_details: list[dict[str, Any]],
    runtime_events: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[EvidenceRecord]]:
    """Bind observed parser API callsites back to recovered functions."""
    parser_surfaces = {
        symbol_base_name(str(item.get("name") or "")): item
        for item in surface_details
        if isinstance(item, dict) and item.get("category") == "parser"
    }
    raw_functions = [
        fn for fn in context.interesting_functions
        if fn.address is not None and fn.size > 0 and not _is_runtime_support_name(fn.name)
    ]
    sorted_addrs, sorted_fns = _sorted_functions(raw_functions)
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    target_module_name = Path(manifest.binary_path).name

    def map_backtrace_functions(event: dict[str, Any]) -> tuple[list[str], list[str]]:
        ids: list[str] = []
        names: list[str] = []
        for frame in event.get("backtrace_frames") or []:
            if not isinstance(frame, dict):
                continue
            if frame.get("module") and str(frame.get("module")) != target_module_name:
                continue
            try:
                if frame.get("module_offset") and context.image_base:
                    address = int(context.image_base) + int(str(frame["module_offset"]), 16)
                else:
                    address = int(str(frame.get("address") or ""), 16)
            except ValueError:
                continue
            function = _find_containing_function(address, sorted_addrs, sorted_fns)
            if function is None:
                continue
            function_id = _fn_id("BFN", function)
            if function_id in ids:
                continue
            ids.append(function_id)
            names.append(function.name)
        return ids, names

    for event in runtime_events:
        if str(event.get("category") or "") != "parser":
            continue
        parser_name = symbol_base_name(str(event.get("fn") or ""))
        parser_surface = parser_surfaces.get(parser_name)
        caller = str(event.get("caller") or "")
        caller_offset = str(event.get("caller_offset") or "")
        if parser_surface is None or (not caller and not caller_offset):
            continue
        try:
            if caller_offset and context.image_base:
                caller_addr = int(context.image_base) + int(caller_offset, 16)
            else:
                caller_addr = int(caller, 16)
        except ValueError:
            continue
        fn = _find_containing_function(caller_addr, sorted_addrs, sorted_fns)
        if fn is None:
            continue
        key = (str(parser_surface["id"]), _fn_id("BFN", fn))
        item = grouped.setdefault(key, {
            "surface": parser_surface,
            "function": fn,
            "events": [],
            "backtrace_function_ids": [],
            "backtrace_function_names": [],
        })
        item["events"].append(event)
        backtrace_ids, backtrace_names = map_backtrace_functions(event)
        for function_id, function_name in zip(backtrace_ids, backtrace_names):
            if function_id in item["backtrace_function_ids"]:
                continue
            item["backtrace_function_ids"].append(function_id)
            item["backtrace_function_names"].append(function_name)

    flows: list[dict[str, Any]] = []
    evidence: list[EvidenceRecord] = []
    for index, ((_surface_id, fn_id), item) in enumerate(sorted(grouped.items()), start=1):
        surface = item["surface"]
        fn = item["function"]
        events = item["events"]
        record = make_evidence(
            manifest.binary_sha256,
            kind="runtime_parser_callsite",
            source="frida_callsite",
            summary=f"Frida observed {fn.name!r} calling parser surface {surface['name']!r}",
            tier=EvidenceTier.OBSERVED_RUNTIME,
            confidence="confirmed",
            reproducible=False,
            tool="frida",
            location=f"{manifest.binary_path}@{_address(fn.address)}",
            data={
                "parser_surface_id": surface["id"],
                "parser_surface_name": surface["name"],
                "function": fn.name,
                "function_id": fn_id,
                "event_count": len(events),
                "callers": sorted({str(event.get("caller")) for event in events}),
                "caller_offsets": sorted({str(event.get("caller_offset")) for event in events if event.get("caller_offset")}),
                "backtrace_function_ids": item["backtrace_function_ids"],
                "backtrace_function_names": item["backtrace_function_names"],
            },
        )
        evidence.append(record)
        flows.append({
            "id": f"BRT-PARSER-{index:03d}",
            "parser_surface_id": surface["id"],
            "parser_surface_name": surface["name"],
            "function_id": fn_id,
            "function_name": fn.name,
            "address": _address(fn.address),
            "event_count": len(events),
            "callers": sorted({str(event.get("caller")) for event in events}),
            "caller_offsets": sorted({str(event.get("caller_offset")) for event in events if event.get("caller_offset")}),
            "backtrace_function_ids": item["backtrace_function_ids"],
            "backtrace_function_names": item["backtrace_function_names"],
            "confidence": "confirmed",
            "evidence_tier": EvidenceTier.OBSERVED_RUNTIME.value,
            "evidence_ids": [record.id],
            "evidence_note": "Runtime parser callsite proof only; it does not prove attacker-controlled bytes reached the parser.",
        })
    return flows, evidence


def _call_graph_edges(
    context: BinaryContextMap,
    surface_details: list[dict[str, Any]],
    external_ingress: list[dict[str, Any]],
    *,
    max_depth: int = 6,
) -> list[dict[str, Any]]:
    """Persist the bounded call subgraph needed for boundary extraction.

    Large Swift/ObjC applications can contain tens of thousands of recovered
    functions. Persisting the entire radare2 call graph would turn a focused
    harness aid into a huge disassembler dump, so we retain only paths rooted
    at bound external ingress and stop after a small fixed depth.
    """
    functions_by_name = {
        str(fn.name): fn
        for fn in context.interesting_functions
        if not _is_runtime_support_name(fn.name)
    }
    functions_by_base = {
        symbol_base_name(name): fn
        for name, fn in functions_by_name.items()
    }
    surfaces_by_base = {
        symbol_base_name(str(item.get("name") or "")): item
        for item in surface_details
        if isinstance(item, dict) and item.get("name")
    }
    edges: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    functions_by_id = {
        _fn_id("BFN", fn): fn
        for fn in functions_by_name.values()
    }

    def resolve_ingress_function(ingress: dict[str, Any]) -> Optional[FunctionInfo]:
        bound_id = str(ingress.get("bound_function_id") or "")
        if bound_id in functions_by_id:
            return functions_by_id[bound_id]
        address = str(ingress.get("address") or "")
        name = str(ingress.get("bound_function_name") or ingress.get("name") or "")
        return next(
            (
                fn for fn in functions_by_name.values()
                if (address and _address(fn.address) == address) or (name and fn.name == name)
            ),
            None,
        )

    queue: list[tuple[FunctionInfo, int]] = []
    queued: set[str] = set()
    for ingress in external_ingress:
        fn = resolve_ingress_function(ingress)
        if fn is None:
            continue
        fn_id = _fn_id("BFN", fn)
        if fn_id in queued:
            continue
        queued.add(fn_id)
        queue.append((fn, 0))

    index = 0
    while index < len(queue):
        fn, depth = queue[index]
        index += 1
        source_id = _fn_id("BFN", fn)
        for callee in fn.direct_callees:
            target_fn = functions_by_name.get(str(callee)) or functions_by_base.get(symbol_base_name(str(callee)))
            target_surface = surfaces_by_base.get(symbol_base_name(str(callee)))
            if target_fn is not None:
                key = (source_id, "function", _fn_id("BFN", target_fn))
                if key in seen:
                    continue
                seen.add(key)
                edges.append({
                    "id": f"BCALL-{len(edges) + 1:04d}",
                    "source_function": source_id,
                    "source_name": fn.name,
                    "target_function": _fn_id("BFN", target_fn),
                    "target_name": target_fn.name,
                    "relationship": "calls",
                    "confidence": "high",
                    "evidence_tier": EvidenceTier.XREF_BACKED.value,
                    "evidence_note": "Direct radare2 call-graph edge; this is not taint proof.",
                })
                target_id = _fn_id("BFN", target_fn)
                if depth < max_depth and target_id not in queued:
                    queued.add(target_id)
                    queue.append((target_fn, depth + 1))
            elif target_surface is not None:
                key = (source_id, "surface", str(target_surface["id"]))
                if key in seen:
                    continue
                seen.add(key)
                edges.append({
                    "id": f"BCALL-{len(edges) + 1:04d}",
                    "source_function": source_id,
                    "source_name": fn.name,
                    "target_surface": target_surface["id"],
                    "target_name": target_surface["name"],
                    "target_category": target_surface["category"],
                    "relationship": "calls",
                    "confidence": "high",
                    "evidence_tier": EvidenceTier.XREF_BACKED.value,
                    "evidence_note": "Direct radare2 call-graph edge into an imported surface; this is not taint proof.",
                })
    return edges


def _build_entry_points(
    manifest: BinaryManifest,
    context: BinaryContextMap,
) -> tuple[list[dict[str, Any]], list[EvidenceRecord]]:
    entry_points: list[dict[str, Any]] = []
    evidence: list[EvidenceRecord] = []
    for fn in context.entry_points:
        if _is_runtime_support_name(fn.name):
            continue
        record = make_evidence(
            manifest.binary_sha256,
            kind="entry_point_candidate",
            source="radare2_function_name",
            summary=f"Function name {fn.name!r} matches an entry-point heuristic",
            tier=EvidenceTier.HEURISTIC,
            confidence="candidate",
            reproducible=True,
            tool="radare2",
            location=f"{manifest.binary_path}@{_address(fn.address)}",
            data={"name": fn.name, "address": _address(fn.address), "size": fn.size},
        )
        evidence.append(record)
        entry_points.append({
            "id": _fn_id("BEP", fn),
            "name": fn.name,
            "entry": fn.name,
            "file": manifest.binary_path,
            "address": _address(fn.address),
            "size": fn.size,
            "type": "binary_entry_point_candidate",
            "auth_required": None,
            "confidence": "candidate",
            "evidence_tier": EvidenceTier.HEURISTIC.value,
            "evidence_note": "Name-based entry point recovery; not proof of attacker control.",
            "evidence_ids": [record.id],
        })
    return entry_points, evidence


def _build_surfaces_and_sinks(
    manifest: BinaryManifest,
    context: BinaryContextMap,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[EvidenceRecord]]:
    surface_details: list[dict[str, Any]] = []
    sink_details: list[dict[str, Any]] = []
    evidence: list[EvidenceRecord] = []

    for fn in context.dangerous_sinks:
        classification = classify_security_api(fn.name)
        if classification is None:
            continue
        record = make_evidence(
            manifest.binary_sha256,
            kind="dangerous_import_sink",
            source="radare2_import_table",
            summary=f"Imported {classification.category} API {fn.name!r} is present",
            tier=EvidenceTier.HEADER_BACKED,
            confidence="high",
            reproducible=True,
            tool="radare2",
            location=f"{manifest.binary_path}@{_address(fn.address)}",
            data={"name": fn.name, "address": _address(fn.address), "size": fn.size},
        )
        evidence.append(record)
        item = {
            "id": _fn_id("BSINK", fn),
            "name": fn.name,
            "operation": fn.name,
            "file": manifest.binary_path,
            "address": _address(fn.address),
            "size": fn.size,
            "type": "binary_sink_candidate" if classification.is_sink else "binary_surface_candidate",
            "confidence": "candidate",
            "presence_confidence": "confirmed",
            "role": classification.role,
            "category": classification.category,
            "is_sink": classification.is_sink,
            "evidence_tier": EvidenceTier.HEADER_BACKED.value,
            "evidence_note": classification.rationale,
            "evidence_ids": [record.id],
        }
        surface_details.append(item)
        if classification.is_sink:
            sink_details.append(item)

    known_surface_names = {symbol_base_name(item["name"]) for item in surface_details}
    for import_name in manifest.imports:
        if symbol_base_name(import_name) in known_surface_names:
            continue
        classification = classify_security_api(import_name)
        if classification is None:
            continue
        record = make_evidence(
            manifest.binary_sha256,
            kind="security_surface",
            source="radare2_import_table",
            summary=f"Imported {classification.category} surface {import_name!r} is present",
            tier=EvidenceTier.HEADER_BACKED,
            confidence="candidate",
            reproducible=True,
            tool="radare2",
            location=manifest.binary_path,
            data={"name": import_name, "category": classification.category, "role": classification.role},
        )
        evidence.append(record)
        item = {
            "id": _import_candidate_id("BSINK-IMP" if classification.is_sink else "BSURF", import_name),
            "name": import_name,
            "operation": import_name,
            "file": manifest.binary_path,
            "address": "",
            "size": 0,
            "type": "binary_sink_candidate" if classification.is_sink else "binary_surface_candidate",
            "confidence": "candidate",
            "presence_confidence": "confirmed",
            "role": classification.role,
            "category": classification.category,
            "is_sink": classification.is_sink,
            "evidence_tier": EvidenceTier.HEADER_BACKED.value,
            "evidence_note": classification.rationale,
            "evidence_ids": [record.id],
        }
        surface_details.append(item)
        if classification.is_sink:
            sink_details.append(item)

    return surface_details, sink_details, evidence


def _build_candidate_flows(
    manifest: BinaryManifest,
    context: BinaryContextMap,
    sink_details: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[EvidenceRecord]]:
    candidate_flows: list[dict[str, Any]] = []
    evidence: list[EvidenceRecord] = []
    sink_by_name = {symbol_base_name(item["name"]): item["id"] for item in sink_details}
    for fn in context.interesting_functions:
        if _is_runtime_support_name(fn.name):
            continue
        for sink_name in sorted(set(fn.calls_dangerous)):
            sink_id = sink_by_name.get(sink_name)
            if not sink_id:
                continue
            record = make_evidence(
                manifest.binary_sha256,
                kind="candidate_flow",
                source="radare2_axffj",
                summary=f"Direct xref from {fn.name!r} to dangerous import {sink_name!r}",
                tier=EvidenceTier.XREF_BACKED,
                confidence="high",
                reproducible=True,
                tool="radare2",
                location=f"{manifest.binary_path}@{_address(fn.address)}",
                data={"source_function": fn.name, "sink": sink_name, "relationship": "calls"},
            )
            evidence.append(record)
            candidate_flows.append({
                "id": f"BCFLOW-{len(candidate_flows) + 1:03d}",
                "source_function": _fn_id("BFN", fn),
                "source_name": fn.name,
                "sink": sink_id,
                "relationship": "calls",
                "confidence": "high",
                "evidence_tier": EvidenceTier.XREF_BACKED.value,
                "evidence_note": "radare2 cross-reference shows a direct call edge; this is not proof attacker bytes reach the sink.",
                "evidence_ids": [record.id],
            })
        for sink_name in sorted(set(fn.transitively_reaches_dangerous) - set(fn.calls_dangerous)):
            sink_id = sink_by_name.get(sink_name)
            if not sink_id:
                continue
            record = make_evidence(
                manifest.binary_sha256,
                kind="candidate_flow",
                source="radare2_aflcj",
                summary=f"Call graph from {fn.name!r} may reach dangerous import {sink_name!r}",
                tier=EvidenceTier.XREF_BACKED,
                confidence="candidate",
                reproducible=True,
                tool="radare2",
                location=f"{manifest.binary_path}@{_address(fn.address)}",
                data={
                    "source_function": fn.name,
                    "sink": sink_name,
                    "relationship": "may_reach",
                    "distance": fn.transitive_distance,
                },
            )
            evidence.append(record)
            candidate_flows.append({
                "id": f"BCFLOW-{len(candidate_flows) + 1:03d}",
                "source_function": _fn_id("BFN", fn),
                "source_name": fn.name,
                "sink": sink_id,
                "relationship": "may_reach",
                "distance": fn.transitive_distance,
                "confidence": "candidate",
                "evidence_tier": EvidenceTier.XREF_BACKED.value,
                "evidence_note": "Call-graph reachability only; no taint or boundary proof.",
                "evidence_ids": [record.id],
            })
    return candidate_flows, evidence


def _context_map(
    manifest: BinaryManifest,
    context: BinaryContextMap,
    channels: list[InputChannel],
    runtime_events: list[dict[str, Any]],
    runtime_records: list[EvidenceRecord],
    fuzz: FuzzEvidenceBundle,
    constraints: Optional[dict[str, Any]],
    graph_path: Path,
    static_records: list[EvidenceRecord],
    decompilations: dict[str, Any],
    runtime_input_flows: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[EvidenceRecord]]:
    generated_evidence: list[EvidenceRecord] = []
    class_inventory_evidence_ids = [
        record.id for record in static_records
        if record.kind == "class_metadata_inventory"
    ]

    entry_points, ep_evidence = _build_entry_points(manifest, context)
    generated_evidence.extend(ep_evidence)

    surface_details, sink_details, surf_evidence = _build_surfaces_and_sinks(manifest, context)
    generated_evidence.extend(surf_evidence)

    candidate_flows, flow_evidence = _build_candidate_flows(manifest, context, sink_details)
    generated_evidence.extend(flow_evidence)

    class_inventory: list[dict[str, Any]] = []
    framework_callback_candidates: list[dict[str, Any]] = []
    for class_info in context.classes:
        class_id = _metadata_item_id("BCLASS", class_info.name, class_info.address)
        methods: list[dict[str, Any]] = []
        for method in class_info.methods:
            method_id = _metadata_item_id("BMETHOD", class_info.name, method.name, method.address)
            function_id = (
                f"BFN-{int(method.bound_function_address):x}"
                if method.bound_function_address is not None else ""
            )
            method_item = {
                "id": method_id,
                "name": method.name,
                "address": _address(method.address),
                "language": method.language,
                "flag": method.flag,
                "is_class_method": method.is_class_method,
                "bound_function_id": function_id,
                "bound_function_name": method.bound_function_name,
                "graph_worthy": _is_graph_worthy_method(method.name),
                "evidence_tier": EvidenceTier.HEADER_BACKED.value,
                "evidence_ids": list(class_inventory_evidence_ids),
            }
            methods.append(method_item)
            if method.name not in _FRAMEWORK_CALLBACK_SELECTORS:
                continue
            record = make_evidence(
                manifest.binary_sha256,
                kind="framework_callback_candidate",
                source="radare2_icj_selector",
                summary=(
                    f"Class metadata declares framework callback selector "
                    f"{class_info.name}.{method.name}"
                ),
                tier=EvidenceTier.HEADER_BACKED,
                confidence="candidate",
                reproducible=True,
                tool="radare2",
                location=f"{manifest.binary_path}@{_address(method.address)}",
                data={
                    "class": class_info.name,
                    "method": method.name,
                    "address": _address(method.address),
                    "bound_function_id": function_id,
                },
            )
            generated_evidence.append(record)
            framework_callback_candidates.append({
                "id": _metadata_item_id("BCALLBACK", class_info.name, method.name, method.address),
                "class_id": class_id,
                "class_name": class_info.name,
                "method_id": method_id,
                "method_name": method.name,
                "address": _address(method.address),
                "bound_function_id": function_id,
                "bound_function_name": method.bound_function_name,
                "confidence": "candidate",
                "evidence_tier": EvidenceTier.HEADER_BACKED.value,
                "evidence_note": (
                    "Class metadata proves the callback implementation exists; "
                    "it does not prove the framework invoked it or that attacker "
                    "controlled data reached it."
                ),
                "evidence_ids": [record.id],
            })
        class_inventory.append({
            "id": class_id,
            "name": class_info.name,
            "address": _address(class_info.address),
            "language": class_info.language,
            "superclasses": list(class_info.superclasses),
            "fields": list(class_info.fields),
            "methods": methods,
            "evidence_tier": EvidenceTier.HEADER_BACKED.value,
            "evidence_ids": list(class_inventory_evidence_ids),
        })
    class_summary = {
        "class_count": len(class_inventory),
        "method_count": sum(len(item["methods"]) for item in class_inventory),
        "field_count": sum(len(item["fields"]) for item in class_inventory),
        "bound_method_count": sum(
            1
            for item in class_inventory
            for method in item["methods"]
            if method["bound_function_id"]
        ),
        "graph_method_count": sum(
            1
            for item in class_inventory
            for method in item["methods"]
            if method["graph_worthy"]
        ),
        "languages": sorted({item["language"] for item in class_inventory if item["language"]}),
        "evidence_note": (
            "Objective-C / Swift class metadata is a recovered program structure, "
            "not a reachability or attacker-control claim."
        ),
    }

    return {
        "meta": {
            "target": manifest.binary_path,
            "target_kind": "blackbox_binary",
            "binary_sha256": manifest.binary_sha256,
            "binary_format": manifest.binary_format,
            "arch": manifest.arch,
            "bits": manifest.bits,
            "analysis_mode": "blackbox_binary",
            "graph_db": str(graph_path),
            "evidence_policy": "Claims are limited to mechanically observed or xref-backed facts.",
        },
        "binary": manifest.binary_path,
        "target_path": manifest.binary_path,
        "image_base": _address(context.image_base),
        "binary_slices": [item.to_dict() for item in manifest.slices],
        "analysis_scope": {
            "selected_arch": manifest.analysed_slice.arch if manifest.analysed_slice else manifest.arch,
            "deep_analysis_arch": (
                manifest.analysed_slice.arch if manifest.analysed_slice else manifest.arch
            ) if manifest.analysis_depth == "full" else None,
            "analysis_depth": manifest.analysis_depth,
            "all_slices_analysed": manifest.analysis_depth == "full" and len(manifest.slices) <= 1,
            "slice_count": len(manifest.slices),
            "decompilation": decompilations.get("coverage", {}),
            "notes": list(context.notes),
        },
        "app_bundle": manifest.app_bundle.to_dict() if manifest.app_bundle else None,
        "entry_points": entry_points,
        "framework_callback_candidates": framework_callback_candidates,
        "class_inventory": {
            "summary": class_summary,
            "classes": class_inventory,
        },
        "sources": [
            {
                "id": channel.id,
                "type": f"binary_{channel.kind}_input",
                "entry": channel.name,
                "observed": channel.observed,
                "confidence": channel.confidence,
                "evidence_ids": channel.evidence_ids,
            }
            for channel in channels
        ],
        "trust_boundaries": [],
        "boundary_details": [],
        "sinks": [
            {
                "id": item["id"],
                "type": item["type"],
                "location": item["operation"],
                "file": item["file"],
                "address": item["address"],
                "confidence": item["confidence"],
            }
            for item in sink_details
        ],
        "sink_details": sink_details,
        "surface_details": surface_details,
        "interesting_functions": [
            {
                "id": _fn_id("BFN", fn),
                "name": fn.name,
                "file": manifest.binary_path,
                "address": _address(fn.address),
                "size": fn.size,
                "calls_dangerous": list(fn.calls_dangerous),
                "transitively_reaches_dangerous": list(fn.transitively_reaches_dangerous),
                "transitive_distance": fn.transitive_distance,
                "confidence": "high" if fn.calls_dangerous else "candidate",
                "evidence_tier": EvidenceTier.XREF_BACKED.value,
            }
            for fn in context.interesting_functions
            if not _is_runtime_support_name(fn.name)
        ],
        "runtime_support_functions": [
            {
                "id": _fn_id("BRT", fn),
                "name": fn.name,
                "file": manifest.binary_path,
                "address": _address(fn.address),
                "size": fn.size,
                "evidence_tier": EvidenceTier.XREF_BACKED.value,
            }
            for fn in context.interesting_functions
            if _is_runtime_support_name(fn.name)
        ],
        "candidate_flows": candidate_flows,
        "unchecked_flows": [],
        "runtime_signals": [signal.to_dict() for signal in manifest.runtime_signals],
        "runtime_observations": _runtime_observation_summary(
            runtime_events,
            [record.id for record in runtime_records],
        ),
        "runtime_input_flows": runtime_input_flows,
        # Patched by the caller after external_ingress recovery (depends on
        # this context_map, so can't be computed here).
        "runtime_parser_flows": [],
        "call_graph_edges": [],
        "parser_boundary_candidates": [],
        "decompilations": {
            "coverage": decompilations.get("coverage", {}),
            "functions": [
                {key: value for key, value in item.items() if key != "body"}
                for item in decompilations.get("functions", [])
            ],
        },
        "fuzz_witnesses": [crash.to_dict() for crash in fuzz.crashes],
        "constraints": constraints,
        "fuzz_priorities": list(context.fuzz_priorities),
        "notes": list(context.notes),
        "analysis_limits": [
            "A recovered import or call edge is not proof that attacker-controlled bytes reach it.",
            "No trust boundary or unchecked flow is emitted without runtime or trace evidence.",
            "Name-based entry points are candidates until a runtime observation or format-specific contract confirms them.",
            "Framework callback selectors are metadata-backed candidates until a runtime observation proves they fire.",
            "Only the selected Mach-O slice receives deep analysis; other slices remain header-backed inventory until separately mapped.",
            "Decompiler output is persisted for operator review but remains decompiler-inferred evidence.",
        ],
        "evidence": [record.to_dict() for record in [*static_records, *generated_evidence]],
    }, generated_evidence


def _write_report(result: BinaryAnalysisResult, out_dir: Path) -> None:
    context = result.context_map
    coverage = result.decompilations.get("coverage", {})
    scope = context.get("analysis_scope", {})
    class_summary = (context.get("class_inventory") or {}).get("summary") or {}
    lines = [
        "# RAPTOR Black-box Binary Understanding",
        "",
        f"Target: `{result.manifest.binary_path}`",
        f"SHA-256: `{result.manifest.binary_sha256}`",
        f"Format: `{result.manifest.binary_format}`  Arch: `{result.manifest.arch}`  Bits: `{result.manifest.bits}`",
        "",
        "## Evidence Summary",
        "",
        f"- Entry point candidates: {len(context.get('entry_points', []))}",
        f"- Input channel candidates: {len(result.input_channels)}",
        f"- Security-relevant imported primitive candidates: {len(context.get('sink_details', []))}",
        f"- Security-relevant non-sink surfaces: {len(context.get('surface_details', [])) - len(context.get('sink_details', []))}",
        f"- Candidate call-graph flows: {len(context.get('candidate_flows', []))}",
        f"- Decompiled functions persisted: {coverage.get('decompiled_functions', 0)} / {coverage.get('recovered_functions', 0)}",
        f"- Runtime observation summaries: {len(context.get('runtime_observations', []))}",
        f"- Runtime input callsites bound to recovered functions: {len(context.get('runtime_input_flows', []))}",
        f"- Runtime parser callsites bound to recovered functions: {len(context.get('runtime_parser_flows', []))}",
        f"- Runtime evidence records ingested: {sum(1 for item in result.evidence if item.tier == EvidenceTier.OBSERVED_RUNTIME)}",
        f"- Fuzz crash witnesses ingested: {len(result.fuzz.crashes)}",
        f"- Recovered Objective-C / Swift classes: {class_summary.get('class_count', 0)}",
        f"- Recovered class methods: {class_summary.get('method_count', 0)}",
        f"- Framework callback candidates: {len(context.get('framework_callback_candidates', []))}",
        f"- External ingress candidates: {len(context.get('external_ingress_candidates', []))}",
        f"- Parser boundary candidates: {len(context.get('parser_boundary_candidates', []))}",
        "",
        "## Analysis Scope",
        "",
        f"- Selected architecture: {scope.get('selected_arch', result.manifest.arch)}",
        f"- Analysis depth: {scope.get('analysis_depth', result.manifest.analysis_depth)}",
        f"- Deep-analysis architecture: {scope.get('deep_analysis_arch') or 'not run'}",
        f"- Mach-O slices inventoried: {scope.get('slice_count', 0)}",
        f"- All slices deeply analysed: {'yes' if scope.get('all_slices_analysed') else 'no'}",
        f"- Decompiler: {coverage.get('decompiler') or 'none'}",
    ]
    if result.manifest.app_bundle:
        bundle = result.manifest.app_bundle
        lines.extend([
            "",
            "## App Bundle",
            "",
            f"- Identifier: `{bundle.identifier or 'unknown'}`",
            f"- Version: `{bundle.short_version or 'unknown'}` build `{bundle.build_version or 'unknown'}`",
            f"- Privileged executables: {', '.join(bundle.privileged_executables) or 'none declared'}",
            f"- XPC services: {', '.join(bundle.xpc_services) or 'none declared'}",
            f"- ATS exception domains: {', '.join(bundle.ats_exception_domains) or 'none declared'}",
        ])
    if context.get("notes"):
        lines.extend([
            "",
            "## Analysis Notes",
            "",
        ])
        lines.extend(f"- {note}" for note in context["notes"])
    callbacks = context.get("framework_callback_candidates", [])
    if callbacks:
        lines.extend([
            "",
            "## Framework Callback Candidates",
            "",
        ])
        lines.extend(
            f"- `{item['class_name']}.{item['method_name']}` @ `{item['address']}`"
            for item in callbacks[:10]
        )
        lines.append("")
        lines.append("These selectors are metadata-backed candidates, not proof that the framework invoked them.")
    ingress = context.get("external_ingress_candidates", [])
    if ingress:
        lines.extend([
            "",
            "## External Ingress Candidates",
            "",
        ])
        lines.extend(
            f"- `{item['kind']}` `{item['name']}` via `{item['boundary']}` "
            f"(control: `{item['external_control']}`)"
            for item in ingress[:10]
        )
        lines.append("")
        lines.append("Ingress candidates describe externally drivable interfaces, not proven vulnerable paths.")
    parser_boundaries = context.get("parser_boundary_candidates", [])
    if parser_boundaries:
        lines.extend([
            "",
            "## Parser Boundary Candidates",
            "",
        ])
        lines.extend(
            f"- `{item['boundary_function_name']}` behind `{item['ingress_name']}` calls "
            f"`{item['parser_surface_name']}` (depth {item['path']['depth']}, tier `{item['evidence_tier']}`)"
            for item in parser_boundaries[:10]
        )
        lines.append("")
        lines.append("Parser boundaries are bounded call-graph candidates, not proof that attacker bytes reach the parser.")
    suitability = context.get("fuzz_suitability") or {}
    if suitability:
        lines.extend([
            "",
            "## Fuzz Strategy",
            "",
            f"- Strategy: `{suitability.get('strategy')}`",
            f"- Direct campaign recommended: {'yes' if suitability.get('direct_campaign_recommended') else 'no'}",
            f"- Runtime collection: `{suitability.get('runtime_strategy', 'direct_process')}`",
            f"- Runtime reason: {suitability.get('runtime_reason')}",
            f"- Reason: {suitability.get('reason')}",
            f"- Next step: {suitability.get('next_step')}",
        ])
    lines.extend([
        "",
        "## What RAPTOR Is Not Claiming",
        "",
        "- This output does not call a source-to-sink path vulnerable just because an import exists.",
        "- This output does not invent trust boundaries for stripped code.",
        "- A candidate flow becomes stronger only when runtime, replay, SMT or a format-specific oracle adds evidence.",
        "",
        f"Validation handoff: `{Path(out_dir) / 'binary-validation-handoff.json'}`",
        f"Graph: `{result.graph_path}`",
    ])
    (Path(out_dir) / "binary-analysis-report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _ingest_graph(result: BinaryAnalysisResult, out_dir: Path) -> None:
    with BinaryGraphStore(result.graph_path) as store, store.batch():
        _ingest_graph_body(store, result, out_dir)


_STATUS_MAP = {
    "binary_entry_point_candidate": "entry_point",
    "binary_sink_candidate": "sink",
    "binary_surface_candidate": "flow_step",
}


def _synthesise_annotations(result: BinaryAnalysisResult, out_dir: Path) -> None:
    try:
        from core.annotations.models import Annotation
        from core.annotations.storage import write_annotation
    except ImportError:
        return
    ann_dir = out_dir / "annotations"
    binary_file = Path(result.manifest.binary_path).name
    count = 0

    for ep in result.context_map.get("entry_points", []):
        if not ep.get("name"):
            continue
        ann = Annotation(
            file=binary_file,
            function=ep["name"],
            body=ep.get("evidence_note", ""),
            metadata={
                "status": "entry_point",
                "source": "llm",
                "evidence_tier": ep.get("evidence_tier", ""),
            },
        )
        if write_annotation(ann_dir, ann, overwrite="respect-manual"):
            count += 1

    for sink in result.context_map.get("sink_details", []):
        if not sink.get("name"):
            continue
        status = _STATUS_MAP.get(sink.get("type", ""), "flow_step")
        ann = Annotation(
            file=binary_file,
            function=sink["name"],
            body=sink.get("evidence_note", ""),
            metadata={
                "status": status,
                "source": "llm",
                "category": sink.get("category", ""),
                "evidence_tier": sink.get("evidence_tier", ""),
            },
        )
        if write_annotation(ann_dir, ann, overwrite="respect-manual"):
            count += 1

    for boundary in result.context_map.get("boundary_details", []):
        boundary_name = boundary.get("name") or boundary.get("id", "")
        if not boundary_name:
            continue
        ann = Annotation(
            file=binary_file,
            function=boundary_name,
            body=boundary.get("description", ""),
            metadata={
                "status": "trust_boundary",
                "source": "llm",
                "evidence_tier": boundary.get("evidence_tier", ""),
            },
        )
        if write_annotation(ann_dir, ann, overwrite="respect-manual"):
            count += 1

    for ingress in result.context_map.get("external_ingress_candidates", []):
        if not ingress.get("name"):
            continue
        ann = Annotation(
            file=binary_file,
            function=ingress["name"],
            body=ingress.get("evidence_note", ""),
            metadata={
                "status": "entry_point",
                "source": "llm",
                "kind": ingress.get("kind", ""),
                "evidence_tier": ingress.get("evidence_tier", ""),
            },
        )
        if write_annotation(ann_dir, ann, overwrite="respect-manual"):
            count += 1

    if count:
        logger.info("synthesised %d annotations in %s", count, ann_dir)


def _ingest_graph_body(store: BinaryGraphStore, result: BinaryAnalysisResult, out_dir: Path) -> None:
    manifest = result.manifest
    snapshot_id = store.begin_snapshot(
        manifest.binary_sha256,
        manifest.binary_path,
        out_dir,
        props={"target_kind": manifest.target_kind, "binary_format": manifest.binary_format},
    )
    for record in result.evidence:
        store.add_evidence(snapshot_id, record)
    binary_node = store.add_node(
        snapshot_id,
        manifest.binary_sha256,
        "binary",
        manifest.binary_sha256,
        name=Path(manifest.binary_path).name,
        props=manifest.to_dict(),
        evidence_ids=[record.id for record in manifest.evidence],
    )
    for signal in manifest.runtime_signals:
        node = store.add_node(
            snapshot_id,
            manifest.binary_sha256,
            "runtime_signal",
            f"{signal.family}:{signal.marker}",
            name=f"{signal.family}:{signal.marker}",
            props=signal.to_dict(),
            evidence_ids=[signal.evidence_id],
        )
        store.add_edge(snapshot_id, manifest.binary_sha256, "HAS_RUNTIME_SIGNAL", binary_node, node,
                       confidence=signal.confidence, evidence_ids=[signal.evidence_id])
    for slice_info in manifest.slices:
        node = store.add_node(
            snapshot_id,
            manifest.binary_sha256,
            "binary_slice",
            f"{slice_info.arch}:{slice_info.offset}:{slice_info.size}",
            name=slice_info.arch,
            props=slice_info.to_dict(),
        )
        store.add_edge(snapshot_id, manifest.binary_sha256, "HAS_SLICE", binary_node, node, confidence="confirmed")
    if manifest.app_bundle:
        bundle_node = store.add_node(
            snapshot_id,
            manifest.binary_sha256,
            "app_bundle",
            manifest.app_bundle.bundle_path,
            name=manifest.app_bundle.identifier or Path(manifest.app_bundle.bundle_path).name,
            props=manifest.app_bundle.to_dict(),
            evidence_ids=[record.id for record in manifest.evidence if record.kind == "app_bundle_metadata"],
        )
        store.add_edge(snapshot_id, manifest.binary_sha256, "BELONGS_TO_APP", binary_node, bundle_node, confidence="confirmed")
    component_nodes: dict[str, str] = {}
    for component in (result.context_map.get("component_topology") or {}).get("components", []):
        node = store.add_node(
            snapshot_id,
            manifest.binary_sha256,
            "component",
            component["id"],
            name=component["name"],
            props=component,
        )
        component_nodes[component["id"]] = node
        store.add_edge(
            snapshot_id,
            manifest.binary_sha256,
            "HAS_COMPONENT",
            binary_node,
            node,
            confidence="confirmed",
        )
    ingress_nodes: dict[str, str] = {}
    for ingress in result.context_map.get("external_ingress_candidates", []):
        node = store.add_node(
            snapshot_id,
            manifest.binary_sha256,
            "external_ingress",
            ingress["id"],
            name=ingress["name"],
            address=ingress.get("address") or "",
            props=ingress,
            evidence_ids=ingress.get("evidence_ids") or [],
        )
        ingress_nodes[ingress["id"]] = node
        store.add_edge(
            snapshot_id,
            manifest.binary_sha256,
            "EXPOSES_INGRESS",
            binary_node,
            node,
            confidence=ingress.get("confidence") or "candidate",
            evidence_ids=ingress.get("evidence_ids") or [],
        )
    for boundary in (result.context_map.get("component_topology") or {}).get("boundaries", []):
        node = store.add_node(
            snapshot_id,
            manifest.binary_sha256,
            "boundary",
            boundary["id"],
            name=boundary["kind"],
            props=boundary,
        )
        store.add_edge(
            snapshot_id,
            manifest.binary_sha256,
            "HAS_BOUNDARY",
            binary_node,
            node,
            confidence=boundary.get("confidence") or "candidate",
        )
    channel_nodes: dict[str, str] = {}
    for channel in result.input_channels:
        node = store.add_node(
            snapshot_id,
            manifest.binary_sha256,
            "input_channel",
            channel.id,
            name=channel.name,
            props=channel.to_dict(),
            evidence_ids=channel.evidence_ids,
        )
        channel_nodes[channel.id] = node
        store.add_edge(snapshot_id, manifest.binary_sha256, "HAS_INPUT_CHANNEL", binary_node, node,
                       confidence=channel.confidence, evidence_ids=channel.evidence_ids)
    for observation in result.context_map.get("runtime_observations", []):
        node = store.add_node(
            snapshot_id,
            manifest.binary_sha256,
            "runtime_observation",
            observation["id"],
            name=f"{observation['category']}:{observation['function']}",
            props=observation,
            evidence_ids=observation.get("evidence_ids") or [],
        )
        store.add_edge(
            snapshot_id,
            manifest.binary_sha256,
            "OBSERVED_RUNTIME",
            binary_node,
            node,
            confidence="confirmed",
            evidence_ids=observation.get("evidence_ids") or [],
        )
    function_nodes: dict[str, str] = {}
    function_nodes_by_address: dict[str, str] = {}
    for fn in result.context_map.get("interesting_functions", []):
        node = store.add_node(
            snapshot_id,
            manifest.binary_sha256,
            "function",
            fn["id"],
            name=fn["name"],
            address=fn.get("address") or "",
            props=fn,
            evidence_ids=fn.get("evidence_ids") or [],
        )
        function_nodes[fn["id"]] = node
        if fn.get("address"):
            function_nodes_by_address[str(fn["address"])] = node
        store.add_edge(snapshot_id, manifest.binary_sha256, "CONTAINS", binary_node, node, confidence="high")
    for fn in result.context_map.get("runtime_support_functions", []):
        node = store.add_node(
            snapshot_id,
            manifest.binary_sha256,
            "runtime_support_function",
            fn["id"],
            name=fn["name"],
            address=fn.get("address") or "",
            props=fn,
        )
        store.add_edge(snapshot_id, manifest.binary_sha256, "CONTAINS", binary_node, node, confidence="high")
    for ingress in result.context_map.get("external_ingress_candidates", []):
        ingress_node = ingress_nodes.get(ingress.get("id") or "")
        function_node = function_nodes.get(ingress.get("bound_function_id") or "")
        if function_node is None and ingress.get("address"):
            function_node = function_nodes_by_address.get(str(ingress["address"]))
        if ingress_node and function_node:
            store.add_edge(
                snapshot_id,
                manifest.binary_sha256,
                "BACKED_BY_FUNCTION",
                ingress_node,
                function_node,
                confidence=ingress.get("confidence") or "candidate",
                evidence_ids=ingress.get("evidence_ids") or [],
            )
    class_nodes: dict[str, str] = {}
    method_nodes: dict[str, str] = {}
    callback_by_method_id = {
        item["method_id"]: item
        for item in result.context_map.get("framework_callback_candidates", [])
        if isinstance(item, dict) and item.get("method_id")
    }
    for class_info in (result.context_map.get("class_inventory") or {}).get("classes", []):
        node = store.add_node(
            snapshot_id,
            manifest.binary_sha256,
            "class",
            class_info["id"],
            name=class_info["name"],
            address=class_info.get("address") or "",
            props={key: value for key, value in class_info.items() if key != "methods"},
            evidence_ids=class_info.get("evidence_ids") or [],
        )
        class_nodes[class_info["id"]] = node
        store.add_edge(
            snapshot_id,
            manifest.binary_sha256,
            "DECLARES_CLASS",
            binary_node,
            node,
            confidence="confirmed",
            evidence_ids=class_info.get("evidence_ids") or [],
        )
        for method in class_info.get("methods", []):
            if not method.get("graph_worthy"):
                continue
            method_node = store.add_node(
                snapshot_id,
                manifest.binary_sha256,
                "method",
                method["id"],
                name=f"{class_info['name']}.{method['name']}",
                address=method.get("address") or "",
                props=method,
                evidence_ids=method.get("evidence_ids") or [],
            )
            method_nodes[method["id"]] = method_node
            store.add_edge(
                snapshot_id,
                manifest.binary_sha256,
                "DECLARES_METHOD",
                node,
                method_node,
                confidence="confirmed",
                evidence_ids=method.get("evidence_ids") or [],
            )
            function_node = function_nodes.get(method.get("bound_function_id") or "")
            if function_node:
                store.add_edge(
                    snapshot_id,
                    manifest.binary_sha256,
                    "BACKED_BY_FUNCTION",
                    method_node,
                    function_node,
                    confidence="confirmed",
                    evidence_ids=method.get("evidence_ids") or [],
                )
            callback = callback_by_method_id.get(method["id"])
            if callback:
                store.add_edge(
                    snapshot_id,
                    manifest.binary_sha256,
                    "FRAMEWORK_CALLBACK_CANDIDATE",
                    binary_node,
                    method_node,
                    confidence="candidate",
                    props=callback,
                    evidence_ids=callback.get("evidence_ids") or [],
                )
    for decomp in result.decompilations.get("functions", []):
        node = store.add_node(
            snapshot_id,
            manifest.binary_sha256,
            "decompilation",
            decomp["id"],
            name=decomp["name"],
            address=decomp.get("address") or "",
            props={key: value for key, value in decomp.items() if key != "body"},
            evidence_ids=[decomp["evidence_id"]],
        )
        function_node = function_nodes.get(decomp["function_id"])
        if function_node:
            store.add_edge(
                snapshot_id,
                manifest.binary_sha256,
                "DECOMPILED_AS",
                function_node,
                node,
                confidence="candidate",
                evidence_ids=[decomp["evidence_id"]],
            )
    for runtime_flow in result.context_map.get("runtime_input_flows", []):
        channel_node = channel_nodes.get(runtime_flow["channel_id"])
        function_node = function_nodes.get(runtime_flow["function_id"])
        if channel_node and function_node:
            store.add_edge(
                snapshot_id,
                manifest.binary_sha256,
                "OBSERVED_CALLSITE",
                channel_node,
                function_node,
                confidence="confirmed",
                props=runtime_flow,
                evidence_ids=runtime_flow.get("evidence_ids") or [],
            )
    surface_nodes: dict[str, str] = {}
    for surface in result.context_map.get("surface_details", []):
        if surface.get("is_sink"):
            continue
        node = store.add_node(
            snapshot_id,
            manifest.binary_sha256,
            "surface",
            surface["id"],
            name=surface["name"],
            address=surface.get("address") or "",
            props=surface,
            evidence_ids=surface.get("evidence_ids") or [],
        )
        surface_nodes[surface["id"]] = node
        store.add_edge(snapshot_id, manifest.binary_sha256, "IMPORTS_SURFACE", binary_node, node, confidence="confirmed")
    sink_nodes: dict[str, str] = {}
    for sink in result.context_map.get("sink_details", []):
        node = store.add_node(
            snapshot_id,
            manifest.binary_sha256,
            "sink",
            sink["id"],
            name=sink["name"],
            address=sink.get("address") or "",
            props=sink,
            evidence_ids=sink.get("evidence_ids") or [],
        )
        sink_nodes[sink["id"]] = node
        store.add_edge(snapshot_id, manifest.binary_sha256, "IMPORTS", binary_node, node, confidence="confirmed")
    for flow in result.context_map.get("candidate_flows", []):
        src = function_nodes.get(flow["source_function"])
        dst = sink_nodes.get(flow["sink"])
        if src and dst:
            store.add_edge(
                snapshot_id,
                manifest.binary_sha256,
                "CALLS" if flow["relationship"] == "calls" else "MAY_REACH",
                src,
                dst,
                confidence=flow["confidence"],
                props=flow,
                evidence_ids=flow.get("evidence_ids") or [],
            )
    all_surface_nodes = {**surface_nodes, **sink_nodes}
    for flow in result.context_map.get("runtime_parser_flows", []):
        surface_node = all_surface_nodes.get(flow["parser_surface_id"])
        function_node = function_nodes.get(flow["function_id"])
        if surface_node and function_node:
            store.add_edge(
                snapshot_id,
                manifest.binary_sha256,
                "OBSERVED_PARSER_CALLSITE",
                function_node,
                surface_node,
                confidence="confirmed",
                props=flow,
                evidence_ids=flow.get("evidence_ids") or [],
            )
    for edge in result.context_map.get("call_graph_edges", []):
        source_node = function_nodes.get(edge.get("source_function") or "")
        target_node = function_nodes.get(edge.get("target_function") or "")
        if source_node and target_node:
            store.add_edge(
                snapshot_id,
                manifest.binary_sha256,
                "CALLS_FUNCTION",
                source_node,
                target_node,
                confidence=edge.get("confidence") or "high",
                props=edge,
            )
        target_surface_node = all_surface_nodes.get(edge.get("target_surface") or "")
        if source_node and target_surface_node:
            store.add_edge(
                snapshot_id,
                manifest.binary_sha256,
                "CALLS_SURFACE",
                source_node,
                target_surface_node,
                confidence=edge.get("confidence") or "high",
                props=edge,
            )
    for boundary in result.context_map.get("parser_boundary_candidates", []):
        boundary_node = store.add_node(
            snapshot_id,
            manifest.binary_sha256,
            "parser_boundary",
            boundary["id"],
            name=boundary["boundary_function_name"],
            address=boundary.get("address") or "",
            props=boundary,
            evidence_ids=boundary.get("evidence_ids") or [],
        )
        ingress_node = ingress_nodes.get(boundary.get("ingress_id") or "")
        function_node = function_nodes.get(boundary.get("boundary_function_id") or "")
        surface_node = surface_nodes.get(boundary.get("parser_surface_id") or "")
        store.add_edge(
            snapshot_id,
            manifest.binary_sha256,
            "HAS_PARSER_BOUNDARY",
            binary_node,
            boundary_node,
            confidence=boundary.get("confidence") or "candidate",
            evidence_ids=boundary.get("evidence_ids") or [],
        )
        if ingress_node:
            store.add_edge(
                snapshot_id,
                manifest.binary_sha256,
                "PARSER_BOUNDARY_FOR_INGRESS",
                ingress_node,
                boundary_node,
                confidence=boundary.get("confidence") or "candidate",
                props=boundary.get("path") or {},
                evidence_ids=boundary.get("evidence_ids") or [],
            )
        if function_node:
            store.add_edge(
                snapshot_id,
                manifest.binary_sha256,
                "BACKED_BY_FUNCTION",
                boundary_node,
                function_node,
                confidence=boundary.get("confidence") or "candidate",
                evidence_ids=boundary.get("evidence_ids") or [],
            )
        if surface_node:
            store.add_edge(
                snapshot_id,
                manifest.binary_sha256,
                "PARSER_BOUNDARY_CALLS_SURFACE",
                boundary_node,
                surface_node,
                confidence=boundary.get("confidence") or "candidate",
                evidence_ids=boundary.get("evidence_ids") or [],
            )
    for crash in result.fuzz.crashes:
        crash_evidence_ids = [crash.evidence_id, *crash.replay_evidence_ids]
        node = store.add_node(
            snapshot_id,
            manifest.binary_sha256,
            "crash_witness",
            crash.id,
            name=crash.id,
            props=crash.to_dict(),
            evidence_ids=crash_evidence_ids,
        )
        store.add_edge(snapshot_id, manifest.binary_sha256, "CRASHED_WITH", binary_node, node,
                       confidence="confirmed", evidence_ids=crash_evidence_ids)
        for replay in crash.replays:
            replay_evidence_id = str(replay.get("evidence_id") or "")
            replay_binary = str(replay.get("binary") or "")
            if not replay_evidence_id or not replay_binary:
                continue
            replay_node = store.add_node(
                snapshot_id,
                manifest.binary_sha256,
                "replay_binary",
                replay_binary,
                name=Path(replay_binary).name,
                props=replay,
                evidence_ids=[replay_evidence_id],
            )
            store.add_edge(
                snapshot_id,
                manifest.binary_sha256,
                "REPLAYED_ON",
                node,
                replay_node,
                confidence="confirmed",
                evidence_ids=[replay_evidence_id],
            )
    if result.constraints:
        node = store.add_node(
            snapshot_id,
            manifest.binary_sha256,
            "constraint_check",
            result.constraints["evidence_id"],
            name="SMT constraint check",
            props=result.constraints,
            evidence_ids=[result.constraints["evidence_id"]],
        )
        store.add_edge(snapshot_id, manifest.binary_sha256, "CHECKED_BY", binary_node, node,
                       confidence="confirmed", evidence_ids=[result.constraints["evidence_id"]])
    if result.diff:
        base = result.diff.get("base") or {}
        evidence_id = str(result.diff.get("evidence_id") or "")
        node = store.add_node(
            snapshot_id,
            manifest.binary_sha256,
            "comparison_binary",
            str(base.get("binary_sha256") or base.get("binary_path") or "unknown"),
            name=Path(str(base.get("binary_path") or "comparison-binary")).name,
            props=base,
            evidence_ids=[evidence_id] if evidence_id else [],
        )
        store.add_edge(
            snapshot_id,
            manifest.binary_sha256,
            "DIFFED_AGAINST",
            binary_node,
            node,
            confidence="confirmed",
            props=result.diff,
            evidence_ids=[evidence_id] if evidence_id else [],
        )
    if result.validation_handoff:
        node = store.add_node(
            snapshot_id,
            manifest.binary_sha256,
            "validation_handoff",
            "binary-validation-handoff",
            name="binary validation handoff",
            props=result.validation_handoff,
        )
        store.add_edge(snapshot_id, manifest.binary_sha256, "REQUIRES_VALIDATION", binary_node, node, confidence="confirmed")
    for kind, path in (
        ("binary_manifest", Path(out_dir) / "binary-manifest.json"),
        ("context_map", Path(out_dir) / "context-map.json"),
        ("binary_context_map", Path(out_dir) / "binary-context-map.json"),
        ("binary_evidence", Path(out_dir) / "binary-evidence.json"),
        ("binary_fuzz_evidence", Path(out_dir) / "binary-fuzz-evidence.json"),
        ("binary_constraints", Path(out_dir) / "binary-constraints.json"),
        ("binary_diff", Path(out_dir) / "binary-diff.json"),
        ("binary_decompilations", Path(out_dir) / "binary-decompilations.json"),
        ("binary_validation_handoff", Path(out_dir) / "binary-validation-handoff.json"),
    ):
        if path.exists():
            store.add_artifact(snapshot_id, kind, path)


def analyse_blackbox_binary(
    binary_path: Path,
    *,
    out_dir: Path,
    llm: Any = None,
    quick: bool = False,
    max_decompile: int = 20,
    slice_arch: Optional[str] = None,
    runtime_dir: Optional[Path] = None,
    fuzz_dir: Optional[Path] = None,
    constraint_file: Optional[Path] = None,
    compare_binary: Optional[Path] = None,
) -> BinaryAnalysisResult:
    binary = Path(binary_path).resolve()
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        context = analyse_binary_context(
            binary,
            llm=llm,
            quick=quick,
            max_decompile=max_decompile,
            slice_arch=slice_arch,
        )
    except Exception as exc:
        logger.warning("radare2 analysis failed for %s: %s", binary, exc, exc_info=True)
        context = BinaryContextMap(binary_path=binary)
        context.analysis_depth = "unavailable"
        context.notes.append(f"radare2 analysis unavailable: {exc}")

    manifest = build_manifest(binary, context, requested_slice_arch=slice_arch)
    evidence = list(manifest.evidence)
    static_records = _static_evidence(manifest, context)
    evidence.extend(static_records)
    decompilations, decompilation_evidence = _decompilation_artifact(manifest, context)
    evidence.extend(decompilation_evidence)
    channels, channel_evidence = recover_static_channels(manifest.binary_sha256, manifest.imports)
    evidence.extend(channel_evidence)

    runtime_events: list[dict[str, Any]] = []
    runtime_records: list[EvidenceRecord] = []
    if runtime_dir is not None:
        runtime_events, runtime_records = load_runtime_evidence(
            Path(runtime_dir),
            target_path=manifest.binary_path,
            binary_sha256=manifest.binary_sha256,
        )
        evidence.extend(runtime_records)
        channels, observed_channel_evidence = merge_observed_channels(
            manifest.binary_sha256,
            channels,
            runtime_events,
        )
        evidence.extend(observed_channel_evidence)
    runtime_input_flows, runtime_flow_evidence = _runtime_input_flows(
        manifest,
        context,
        channels,
        runtime_events,
    )
    evidence.extend(runtime_flow_evidence)

    fuzz = FuzzEvidenceBundle()
    if fuzz_dir is not None:
        fuzz = load_fuzz_evidence(
            Path(fuzz_dir),
            binary_sha256=manifest.binary_sha256,
            target_path=manifest.binary_path,
        )
        evidence.extend(fuzz.evidence)

    constraints = None
    if constraint_file is not None:
        constraints, constraint_evidence = validate_constraint_file(
            Path(constraint_file),
            binary_sha256=manifest.binary_sha256,
        )
        evidence.extend(constraint_evidence)

    diff = None
    if compare_binary is not None:
        try:
            compare_context = analyse_binary_context(Path(compare_binary), quick=True)
        except Exception:
            logger.warning("radare2 analysis failed for comparison binary %s", compare_binary, exc_info=True)
            compare_context = BinaryContextMap(binary_path=Path(compare_binary).resolve())
        compare_manifest = build_manifest(Path(compare_binary), compare_context)
        diff = diff_manifests(compare_manifest, manifest)
        diff_record = make_evidence(
            manifest.binary_sha256,
            kind="binary_diff",
            source="manifest_diff",
            summary=f"Compared binary manifest against {Path(compare_manifest.binary_path).name}",
            tier=EvidenceTier.HEADER_BACKED,
            confidence="confirmed",
            reproducible=True,
            tool="binary-intake",
            location=compare_manifest.binary_path,
            data={
                "base_sha256": compare_manifest.binary_sha256,
                "head_sha256": manifest.binary_sha256,
                "bytes_changed": diff["bytes_changed"],
                "metadata_changed": diff["metadata_changed"],
                "imports": diff["imports"],
                "runtime_signals": diff["runtime_signals"],
            },
        )
        evidence.append(diff_record)
        diff["evidence_id"] = diff_record.id

    graph_path = graph_path_for_run(out_dir)
    context_map, context_evidence = _context_map(
        manifest,
        context,
        channels,
        runtime_events,
        runtime_records,
        fuzz,
        constraints,
        graph_path,
        static_records,
        decompilations,
        runtime_input_flows,
    )
    evidence.extend(context_evidence)
    external_ingress, ingress_evidence = recover_external_ingress(manifest, context_map)
    evidence.extend(ingress_evidence)
    context_map["external_ingress_candidates"] = external_ingress
    call_graph_edges = _call_graph_edges(
        context,
        context_map.get("surface_details", []),
        external_ingress,
    )
    runtime_parser_flows, runtime_parser_evidence = _runtime_parser_flows(
        manifest,
        context,
        context_map.get("surface_details", []),
        runtime_events,
    )
    evidence.extend(runtime_parser_evidence)
    context_map["call_graph_edges"] = call_graph_edges
    context_map["runtime_parser_flows"] = runtime_parser_flows
    component_topology = build_component_topology(manifest, external_ingress)
    fuzz_suitability = assess_fuzz_suitability(
        manifest,
        context_map,
        external_ingress,
        component_topology,
    )
    parser_boundaries, parser_boundary_evidence = extract_parser_boundaries(
        binary_sha256=manifest.binary_sha256,
        binary_path=manifest.binary_path,
        context_map=context_map,
    )
    evidence.extend(parser_boundary_evidence)
    context_map["parser_boundary_candidates"] = parser_boundaries
    context_map["component_topology"] = component_topology
    context_map["fuzz_suitability"] = fuzz_suitability
    context_map["boundary_details"] = component_topology.get("boundaries", [])
    context_map["trust_boundaries"] = [
        {
            "id": item["id"],
            "type": item["kind"],
            "description": item["description"],
            "confidence": item["confidence"],
            "evidence_tier": item["evidence_tier"],
        }
        for item in component_topology.get("boundaries", [])
    ]
    validation_handoff = build_validation_handoff(
        target_path=manifest.binary_path,
        binary_sha256=manifest.binary_sha256,
        context_map=context_map,
        evidence=evidence,
        decompilations=decompilations,
    )
    result = BinaryAnalysisResult(
        manifest=manifest,
        context_map=context_map,
        evidence=evidence,
        input_channels=channels,
        graph_path=graph_path,
        fuzz=fuzz,
        constraints=constraints,
        diff=diff,
        decompilations=decompilations,
        validation_handoff=validation_handoff,
    )

    save_json(out_dir / "binary-manifest.json", manifest.to_dict())
    save_json(out_dir / "binary-evidence.json", {"evidence": [record.to_dict() for record in evidence]})
    save_json(out_dir / "binary-context-map.json", context_map)
    save_json(out_dir / "context-map.json", context_map)
    save_json(out_dir / "binary-decompilations.json", decompilations)
    save_json(out_dir / "binary-validation-handoff.json", validation_handoff)
    save_json(out_dir / "binary-checklist.json", {
        "target_path": manifest.binary_path,
        "target_kind": "blackbox_binary",
        "binary_sha256": manifest.binary_sha256,
        "evidence_policy": context_map["meta"]["evidence_policy"],
        "binary_slices": context_map.get("binary_slices", []),
        "analysis_scope": context_map.get("analysis_scope", {}),
        "app_bundle": context_map.get("app_bundle"),
        "items": [
            {
                "id": item["id"],
                "kind": "function",
                "name": item["name"],
                "address": item["address"],
                "size": item["size"],
                "evidence_tier": item["evidence_tier"],
            }
            for item in context_map.get("interesting_functions", [])
        ],
        "entry_point_candidates": context_map.get("entry_points", []),
        "framework_callback_candidates": context_map.get("framework_callback_candidates", []),
        "external_ingress_candidates": context_map.get("external_ingress_candidates", []),
        "component_topology": context_map.get("component_topology", {}),
        "fuzz_suitability": context_map.get("fuzz_suitability", {}),
        "class_inventory": context_map.get("class_inventory", {}),
        "input_channels": [channel.to_dict() for channel in channels],
        "sensitive_import_candidates": context_map.get("sink_details", []),
        "security_surface_candidates": context_map.get("surface_details", []),
        "candidate_flows": context_map.get("candidate_flows", []),
        "runtime_observations": context_map.get("runtime_observations", []),
        "runtime_input_flows": context_map.get("runtime_input_flows", []),
        "runtime_parser_flows": context_map.get("runtime_parser_flows", []),
        "call_graph_edges": context_map.get("call_graph_edges", []),
        "parser_boundary_candidates": context_map.get("parser_boundary_candidates", []),
        "decompilations": context_map.get("decompilations", {}),
        "fuzz_witnesses": context_map.get("fuzz_witnesses", []),
        "constraints": constraints,
        "binary_diff": diff,
        "validation_handoff": validation_handoff,
    })
    if fuzz_dir is not None:
        save_json(out_dir / "binary-fuzz-evidence.json", fuzz.to_dict())
    if constraints is not None:
        save_json(out_dir / "binary-constraints.json", constraints)
    if diff is not None:
        save_json(out_dir / "binary-diff.json", diff)
    _write_report(result, out_dir)
    try:
        _ingest_graph(result, out_dir)
    except Exception:
        logger.warning("graph ingest failed; JSON artifacts are intact", exc_info=True)
    _synthesise_annotations(result, out_dir)
    return result


def append_fuzz_evidence_to_run(
    binary_path: Path,
    *,
    out_dir: Path,
    fuzz_dir: Optional[Path] = None,
) -> Optional[FuzzEvidenceBundle]:
    """Append completed fuzz evidence to an existing binary run.

    The fuzz orchestrator uses this after the campaign finishes so the pre-fuzz
    static map does not need to be recomputed. If no binary manifest exists, the
    caller can fall back to a fresh `analyse_blackbox_binary` run.
    """
    out_dir = Path(out_dir).resolve()
    manifest_data = load_json(out_dir / "binary-manifest.json")
    context_map = load_json(out_dir / "binary-context-map.json")
    if not isinstance(manifest_data, dict) or not isinstance(context_map, dict):
        return None
    manifest = BinaryManifest.from_dict(manifest_data)
    if not manifest.binary_sha256:
        return None
    resolved_binary = Path(binary_path).resolve()
    if str(resolved_binary) != str(Path(manifest.binary_path).resolve()):
        return None
    try:
        if sha256_file(resolved_binary) != manifest.binary_sha256:
            return None
    except OSError:
        return None
    bundle = load_fuzz_evidence(
        Path(fuzz_dir or out_dir),
        binary_sha256=manifest.binary_sha256,
        target_path=str(resolved_binary),
    )
    context_map["fuzz_witnesses"] = [crash.to_dict() for crash in bundle.crashes]
    save_json(out_dir / "binary-context-map.json", context_map)
    save_json(out_dir / "context-map.json", context_map)
    save_json(out_dir / "binary-fuzz-evidence.json", bundle.to_dict())
    checklist = load_json(out_dir / "binary-checklist.json")
    if isinstance(checklist, dict):
        checklist["fuzz_witnesses"] = context_map["fuzz_witnesses"]

    evidence_payload = load_json(out_dir / "binary-evidence.json") or {}
    existing = evidence_payload.get("evidence") if isinstance(evidence_payload, dict) else []
    if not isinstance(existing, list):
        existing = []
    seen = {item.get("id") for item in existing if isinstance(item, dict)}
    for record in bundle.evidence:
        if record.id not in seen:
            existing.append(record.to_dict())
    save_json(out_dir / "binary-evidence.json", {"evidence": existing})
    decompilations = load_json(out_dir / "binary-decompilations.json")
    if not isinstance(decompilations, dict):
        decompilations = {}
    all_evidence = _evidence_records_from_payload(existing)
    validation_handoff = build_validation_handoff(
        target_path=manifest.binary_path,
        binary_sha256=manifest.binary_sha256,
        context_map=context_map,
        evidence=all_evidence,
        decompilations=decompilations,
    )
    save_json(out_dir / "binary-validation-handoff.json", validation_handoff)
    if isinstance(checklist, dict):
        checklist["validation_handoff"] = validation_handoff
        save_json(out_dir / "binary-checklist.json", checklist)

    with BinaryGraphStore(graph_path_for_run(out_dir)) as store, store.batch():
        snapshot_id = store.latest_snapshot_id()
        if snapshot_id:
            binary_node = stable_node_id(manifest.binary_sha256, "binary", manifest.binary_sha256)
            for record in bundle.evidence:
                store.add_evidence(snapshot_id, record)
            for crash in bundle.crashes:
                crash_evidence_ids = [crash.evidence_id, *crash.replay_evidence_ids]
                node = store.add_node(
                    snapshot_id,
                    manifest.binary_sha256,
                    "crash_witness",
                    crash.id,
                    name=crash.id,
                    props=crash.to_dict(),
                    evidence_ids=crash_evidence_ids,
                )
                store.add_edge(
                    snapshot_id,
                    manifest.binary_sha256,
                    "CRASHED_WITH",
                    binary_node,
                    node,
                    confidence="confirmed",
                    evidence_ids=crash_evidence_ids,
                )
                for replay in crash.replays:
                    replay_evidence_id = str(replay.get("evidence_id") or "")
                    replay_binary = str(replay.get("binary") or "")
                    if not replay_evidence_id or not replay_binary:
                        continue
                    replay_node = store.add_node(
                        snapshot_id,
                        manifest.binary_sha256,
                        "replay_binary",
                        replay_binary,
                        name=Path(replay_binary).name,
                        props=replay,
                        evidence_ids=[replay_evidence_id],
                    )
                    store.add_edge(
                        snapshot_id,
                        manifest.binary_sha256,
                        "REPLAYED_ON",
                        node,
                        replay_node,
                        confidence="confirmed",
                        evidence_ids=[replay_evidence_id],
                    )
            handoff_node = store.add_node(
                snapshot_id,
                manifest.binary_sha256,
                "validation_handoff",
                "binary-validation-handoff",
                name="binary validation handoff",
                props=validation_handoff,
            )
            store.add_edge(
                snapshot_id,
                manifest.binary_sha256,
                "REQUIRES_VALIDATION",
                binary_node,
                handoff_node,
                confidence="confirmed",
            )
            store.add_artifact(snapshot_id, "binary_fuzz_evidence", out_dir / "binary-fuzz-evidence.json")
            store.add_artifact(snapshot_id, "binary_validation_handoff", out_dir / "binary-validation-handoff.json")
    return bundle


def _evidence_records_from_payload(items: list[dict[str, Any]]) -> list[EvidenceRecord]:
    records: list[EvidenceRecord] = []
    for item in items:
        if not isinstance(item, dict) or not item.get("id") or not item.get("tier"):
            continue
        try:
            tier = EvidenceTier(str(item["tier"]))
        except ValueError:
            logger.warning("skipping evidence record with unrecognised tier %r", item.get("tier"))
            continue
        records.append(EvidenceRecord(
            id=str(item.get("id") or ""),
            kind=str(item.get("kind") or ""),
            source=str(item.get("source") or ""),
            summary=str(item.get("summary") or ""),
            tier=tier,
            confidence=str(item.get("confidence") or "candidate"),
            reproducible=bool(item.get("reproducible")),
            tool=str(item.get("tool") or ""),
            location=item.get("location"),
            data=dict(item.get("data") or {}),
        ))
    return records


def _fuzz_bundle_from_payload(payload: Any) -> FuzzEvidenceBundle:
    if not isinstance(payload, dict):
        return FuzzEvidenceBundle()
    evidence = payload.get("evidence")
    crashes = payload.get("crashes")
    return FuzzEvidenceBundle(
        summary=dict(payload.get("summary") or {}),
        crashes=[
            CrashEvidence(
                id=str(item.get("id") or ""),
                input_path=str(item.get("input_path") or ""),
                input_sha256=str(item.get("input_sha256") or ""),
                signal=item.get("signal"),
                stack_hash=item.get("stack_hash"),
                evidence_id=str(item.get("evidence_id") or ""),
                replays=[dict(replay) for replay in item.get("replays") or [] if isinstance(replay, dict)],
                replay_evidence_ids=[str(value) for value in item.get("replay_evidence_ids") or []],
            )
            for item in crashes or []
            if isinstance(item, dict) and item.get("id")
        ],
        evidence=_evidence_records_from_payload(evidence if isinstance(evidence, list) else []),
    )


def _saved_context_for_runtime(manifest: BinaryManifest, context_map: dict[str, Any]) -> BinaryContextMap:
    try:
        image_base = int(str(context_map.get("image_base") or "0"), 16)
    except ValueError:
        image_base = 0
    context = BinaryContextMap(
        binary_path=Path(manifest.binary_path),
        arch=manifest.arch,
        bits=manifest.bits,
        binary_format=manifest.binary_format,
        image_base=image_base,
        analysis_depth=str((context_map.get("analysis_scope") or {}).get("analysis_depth") or "full"),
    )
    for item in context_map.get("interesting_functions", []):
        if not isinstance(item, dict):
            continue
        try:
            address = int(str(item.get("address") or "0"), 16)
        except ValueError:
            address = 0
        context.interesting_functions.append(FunctionInfo(
            name=str(item.get("name") or ""),
            address=address,
            size=int(item.get("size") or 0),
        ))
    return context


def _channels_from_checklist(checklist: dict[str, Any]) -> list[InputChannel]:
    channels: list[InputChannel] = []
    for item in checklist.get("input_channels", []):
        if not isinstance(item, dict):
            continue
        channels.append(InputChannel(
            id=str(item.get("id") or ""),
            kind=str(item.get("kind") or ""),
            name=str(item.get("name") or ""),
            observed=bool(item.get("observed")),
            confidence=str(item.get("confidence") or "candidate"),
            evidence_ids=list(item.get("evidence_ids") or []),
            details=dict(item.get("details") or {}),
        ))
    return channels


def append_runtime_evidence_to_run(
    binary_path: Path,
    *,
    out_dir: Path,
    runtime_dir: Path,
) -> Optional[BinaryAnalysisResult]:
    """Append parser/input runtime evidence to an existing binary run.

    This is used by `/binary trace-parser`: it preserves the original static
    map, adds new Frida observations, refreshes parser-boundary candidates and
    updates the graph/handoff in place.
    """
    out_dir = Path(out_dir).resolve()
    manifest_data = load_json(out_dir / "binary-manifest.json")
    context_map = load_json(out_dir / "binary-context-map.json")
    checklist = load_json(out_dir / "binary-checklist.json")
    if not isinstance(manifest_data, dict) or not isinstance(context_map, dict) or not isinstance(checklist, dict):
        return None
    manifest = BinaryManifest.from_dict(manifest_data)
    resolved_binary = Path(binary_path).resolve()
    if str(resolved_binary) != str(Path(manifest.binary_path).resolve()):
        return None
    try:
        if sha256_file(resolved_binary) != manifest.binary_sha256:
            return None
    except OSError:
        return None

    saved_context = _saved_context_for_runtime(manifest, context_map)
    channels = _channels_from_checklist(checklist)
    runtime_events, runtime_records = load_runtime_evidence(
        Path(runtime_dir),
        target_path=manifest.binary_path,
        binary_sha256=manifest.binary_sha256,
    )
    channels, observed_channel_evidence = merge_observed_channels(
        manifest.binary_sha256,
        channels,
        runtime_events,
    )
    runtime_input_flows, runtime_flow_evidence = _runtime_input_flows(
        manifest,
        saved_context,
        channels,
        runtime_events,
    )
    runtime_parser_flows, runtime_parser_evidence = _runtime_parser_flows(
        manifest,
        saved_context,
        context_map.get("surface_details", []),
        runtime_events,
    )
    context_map["sources"] = [
        {
            "id": channel.id,
            "type": f"binary_{channel.kind}_input",
            "entry": channel.name,
            "observed": channel.observed,
            "confidence": channel.confidence,
            "evidence_ids": channel.evidence_ids,
        }
        for channel in channels
    ]
    context_map["runtime_observations"] = _runtime_observation_summary(
        runtime_events,
        [record.id for record in runtime_records],
    )
    context_map["runtime_input_flows"] = runtime_input_flows
    context_map["runtime_parser_flows"] = runtime_parser_flows
    parser_boundaries, parser_boundary_evidence = extract_parser_boundaries(
        binary_sha256=manifest.binary_sha256,
        binary_path=manifest.binary_path,
        context_map=context_map,
    )
    context_map["parser_boundary_candidates"] = parser_boundaries

    evidence_payload = load_json(out_dir / "binary-evidence.json") or {}
    existing = evidence_payload.get("evidence") if isinstance(evidence_payload, dict) else []
    if not isinstance(existing, list):
        existing = []
    seen = {item.get("id") for item in existing if isinstance(item, dict)}
    new_records = [
        *runtime_records,
        *observed_channel_evidence,
        *runtime_flow_evidence,
        *runtime_parser_evidence,
        *parser_boundary_evidence,
    ]
    for record in new_records:
        if record.id not in seen:
            existing.append(record.to_dict())
            seen.add(record.id)
    all_evidence = _evidence_records_from_payload(existing)
    decompilations = load_json(out_dir / "binary-decompilations.json")
    if not isinstance(decompilations, dict):
        decompilations = {}
    fuzz = _fuzz_bundle_from_payload(load_json(out_dir / "binary-fuzz-evidence.json"))
    constraints = load_json(out_dir / "binary-constraints.json")
    if not isinstance(constraints, dict):
        constraints = None
    diff = load_json(out_dir / "binary-diff.json")
    if not isinstance(diff, dict):
        diff = None
    validation_handoff = build_validation_handoff(
        target_path=manifest.binary_path,
        binary_sha256=manifest.binary_sha256,
        context_map=context_map,
        evidence=all_evidence,
        decompilations=decompilations,
    )
    context_map["evidence"] = existing
    save_json(out_dir / "binary-context-map.json", context_map)
    save_json(out_dir / "context-map.json", context_map)
    save_json(out_dir / "binary-evidence.json", {"evidence": existing})
    save_json(out_dir / "binary-validation-handoff.json", validation_handoff)
    checklist["input_channels"] = [channel.to_dict() for channel in channels]
    checklist["runtime_observations"] = context_map["runtime_observations"]
    checklist["runtime_input_flows"] = runtime_input_flows
    checklist["runtime_parser_flows"] = runtime_parser_flows
    checklist["parser_boundary_candidates"] = parser_boundaries
    checklist["validation_handoff"] = validation_handoff
    save_json(out_dir / "binary-checklist.json", checklist)

    result = BinaryAnalysisResult(
        manifest=manifest,
        context_map=context_map,
        evidence=all_evidence,
        input_channels=channels,
        graph_path=graph_path_for_run(out_dir),
        fuzz=fuzz,
        constraints=constraints,
        diff=diff,
        decompilations=decompilations,
        validation_handoff=validation_handoff,
    )
    _write_report(result, out_dir)
    with BinaryGraphStore(result.graph_path) as store, store.batch():
        snapshot_id = store.latest_snapshot_id()
        if snapshot_id:
            binary_node = stable_node_id(manifest.binary_sha256, "binary", manifest.binary_sha256)
            function_nodes = {
                item["id"]: stable_node_id(manifest.binary_sha256, "function", item["id"])
                for item in context_map.get("interesting_functions", [])
                if isinstance(item, dict) and item.get("id")
            }
            channel_nodes = {
                channel.id: stable_node_id(manifest.binary_sha256, "input_channel", channel.id)
                for channel in channels
            }
            surface_nodes = {
                item["id"]: stable_node_id(manifest.binary_sha256, "surface", item["id"])
                for item in context_map.get("surface_details", [])
                if isinstance(item, dict) and item.get("id")
            }
            ingress_nodes = {
                item["id"]: stable_node_id(manifest.binary_sha256, "external_ingress", item["id"])
                for item in context_map.get("external_ingress_candidates", [])
                if isinstance(item, dict) and item.get("id")
            }
            for record in new_records:
                store.add_evidence(snapshot_id, record)
            for observation in context_map["runtime_observations"]:
                node = store.add_node(
                    snapshot_id,
                    manifest.binary_sha256,
                    "runtime_observation",
                    observation["id"],
                    name=f"{observation['category']}:{observation['function']}",
                    props=observation,
                    evidence_ids=observation.get("evidence_ids") or [],
                )
                store.add_edge(snapshot_id, manifest.binary_sha256, "OBSERVED_RUNTIME", binary_node, node,
                               confidence="confirmed", evidence_ids=observation.get("evidence_ids") or [])
            for flow in runtime_input_flows:
                if flow["channel_id"] in channel_nodes and flow["function_id"] in function_nodes:
                    store.add_edge(snapshot_id, manifest.binary_sha256, "OBSERVED_CALLSITE",
                                   channel_nodes[flow["channel_id"]], function_nodes[flow["function_id"]],
                                   confidence="confirmed", props=flow, evidence_ids=flow.get("evidence_ids") or [])
            for flow in runtime_parser_flows:
                if flow["parser_surface_id"] in surface_nodes and flow["function_id"] in function_nodes:
                    store.add_edge(snapshot_id, manifest.binary_sha256, "OBSERVED_PARSER_CALLSITE",
                                   function_nodes[flow["function_id"]], surface_nodes[flow["parser_surface_id"]],
                                   confidence="confirmed", props=flow, evidence_ids=flow.get("evidence_ids") or [])
            for boundary in parser_boundaries:
                node = store.add_node(
                    snapshot_id,
                    manifest.binary_sha256,
                    "parser_boundary",
                    boundary["id"],
                    name=boundary["boundary_function_name"],
                    address=boundary.get("address") or "",
                    props=boundary,
                    evidence_ids=boundary.get("evidence_ids") or [],
                )
                store.add_edge(snapshot_id, manifest.binary_sha256, "HAS_PARSER_BOUNDARY", binary_node, node,
                               confidence=boundary.get("confidence") or "candidate", evidence_ids=boundary.get("evidence_ids") or [])
                if boundary.get("ingress_id") in ingress_nodes:
                    store.add_edge(snapshot_id, manifest.binary_sha256, "PARSER_BOUNDARY_FOR_INGRESS",
                                   ingress_nodes[boundary["ingress_id"]], node,
                                   confidence=boundary.get("confidence") or "candidate",
                                   props=boundary.get("path") or {}, evidence_ids=boundary.get("evidence_ids") or [])
                if boundary.get("boundary_function_id") in function_nodes:
                    store.add_edge(snapshot_id, manifest.binary_sha256, "BACKED_BY_FUNCTION", node,
                                   function_nodes[boundary["boundary_function_id"]],
                                   confidence=boundary.get("confidence") or "candidate", evidence_ids=boundary.get("evidence_ids") or [])
                if boundary.get("parser_surface_id") in surface_nodes:
                    store.add_edge(snapshot_id, manifest.binary_sha256, "PARSER_BOUNDARY_CALLS_SURFACE", node,
                                   surface_nodes[boundary["parser_surface_id"]],
                                   confidence=boundary.get("confidence") or "candidate", evidence_ids=boundary.get("evidence_ids") or [])
            store.add_artifact(snapshot_id, "binary_validation_handoff", out_dir / "binary-validation-handoff.json")
            store.add_artifact(snapshot_id, "binary_context_map", out_dir / "binary-context-map.json")
            for kind, path in (
                ("parser_runtime_metadata", Path(runtime_dir) / "metadata.json"),
                ("parser_runtime_events", Path(runtime_dir) / "events.jsonl"),
            ):
                if path.exists():
                    store.add_artifact(snapshot_id, kind, path)
    return result


def _load_investigation_summary(out_dir: Path) -> dict[str, Any]:
    inv_path = out_dir / "binary-investigation.json"
    if not inv_path.is_file():
        return {}
    data = load_json(inv_path)
    if not isinstance(data, dict):
        return {}
    return {
        "ranked_surfaces": data.get("ranked_surfaces", [])[:10],
        "ranked_ingress": data.get("ranked_ingress", [])[:10],
        "hypotheses": data.get("hypotheses", []),
        "priority_queue": data.get("priority_queue", []),
        "summary": data.get("summary", {}),
    }


def map_result_payload(result: BinaryAnalysisResult, out_dir: Path) -> dict[str, Any]:
    context = result.context_map
    class_summary = (context.get("class_inventory") or {}).get("summary") or {}
    return {
        "mode": "map",
        "target": result.manifest.binary_path,
        "models": [],
        "items": context.get("entry_points", []),
        "failed_models": [],
        "correlation": {
            "summary": {
                "entry_point_candidates": len(context.get("entry_points", [])),
                "input_channels": len(result.input_channels),
                "sensitive_import_candidates": len(context.get("sink_details", [])),
                "security_surface_candidates": len(context.get("surface_details", [])),
                "candidate_flows": len(context.get("candidate_flows", [])),
                "fuzz_witnesses": len(result.fuzz.crashes),
                "recovered_classes": int(class_summary.get("class_count", 0)),
                "framework_callback_candidates": len(context.get("framework_callback_candidates", [])),
                "decompiled_functions": int(
                    (context.get("decompilations") or {}).get("coverage", {}).get("decompiled_functions", 0)
                ),
            },
        },
        "artifacts": {
            "context_map": str(out_dir / "context-map.json"),
            "binary_context_map": str(out_dir / "binary-context-map.json"),
            "binary_manifest": str(out_dir / "binary-manifest.json"),
            "binary_evidence": str(out_dir / "binary-evidence.json"),
            "binary_decompilations": str(out_dir / "binary-decompilations.json"),
            "binary_validation_handoff": str(out_dir / "binary-validation-handoff.json"),
            "binary_investigation": str(out_dir / "binary-investigation.json"),
            "binary_graph": str(result.graph_path),
        },
        "investigation": _load_investigation_summary(out_dir),
    }


__all__ = [
    "BinaryAnalysisResult",
    "analyse_blackbox_binary",
    "append_fuzz_evidence_to_run",
    "append_runtime_evidence_to_run",
    "graph_summary",
    "map_result_payload",
]
