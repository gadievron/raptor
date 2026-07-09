"""Decide whether fuzzing is the next sensible binary experiment.

This is intentionally not the same question as "is AFL installed?". A GUI app
with parser imports may be runnable on the host but still be a poor direct fuzz
target. A DLL, driver or IPC handler may be very interesting, but only after
RAPTOR extracts a harness or chooses snapshot infrastructure.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from packages.fuzzing.target_detector import detect


def assess_fuzz_suitability(
    manifest: Any,
    context_map: dict[str, Any],
    ingress: list[dict[str, Any]],
    topology: dict[str, Any],
) -> dict[str, Any]:
    """Return an evidence-led fuzz strategy, not a campaign verdict."""
    target_info = detect(Path(manifest.binary_path))
    target_kind = str(getattr(manifest, "target_kind", "") or "")
    parser_surfaces = [
        item for item in context_map.get("surface_details", [])
        if isinstance(item, dict) and item.get("category") == "parser"
    ]
    has_libfuzzer_entry = any(item.get("kind") == "libfuzzer_entry" for item in ingress)
    high_value_ingress = [
        item for item in ingress
        if item.get("kind") in {
            "url_handler", "file_open_handler", "ipc_listener",
            "ioctl_dispatch", "exported_api", "network_input",
            "web_navigation_handler",
        }
    ]
    app_like = bool(getattr(manifest, "app_bundle", None)) or any(
        item.get("kind") in {"url_handler", "ipc_listener", "web_navigation_handler"}
        for item in ingress
    )
    driver_like = target_kind in {"pe-sys", "elf-kmod"} or any(item.get("kind") == "ioctl_dispatch" for item in ingress)
    library_like = target_kind in {"pe-dll"} or any(item.get("kind") == "exported_api" for item in ingress)

    strategy = "runtime_first"
    runtime_strategy = "direct_process"
    runtime_reason = "The target can be observed as a process before stronger claims are made."
    direct_campaign_recommended = False
    should_run_fuzz_plan = False
    reason = "No mechanically identified harness boundary or parser-driven input contract yet."
    next_step = "Collect runtime evidence around the highest-ranked external ingress."

    if has_libfuzzer_entry:
        strategy = "direct_harness"
        direct_campaign_recommended = True
        should_run_fuzz_plan = True
        reason = "The binary exports LLVMFuzzerTestOneInput, which is a concrete harness boundary."
        next_step = "Run the fuzzer capability plan, then start a campaign if the host can execute it."
    elif driver_like:
        strategy = "snapshot_or_ioctl_harness"
        runtime_strategy = "kernel_harness_required"
        runtime_reason = "Kernel drivers need a driver harness, VM trace or kernel debugger rather than direct Frida process tracing."
        reason = "Driver targets need IOCTL/dispatch harnessing or snapshot fuzzing, not a direct user-mode campaign."
        next_step = "Recover dispatch handlers and build an IOCTL or snapshot-fuzzer harness."
    elif app_like:
        strategy = "extract_harness_from_ingress"
        reason = "This is an application-style target with framework or IPC ingress; fuzz the handler behind the boundary, not the whole GUI process."
        next_step = "Trace a concrete URL/file/IPC handler and extract the narrow parser or protocol harness it reaches."
    elif library_like:
        strategy = "extract_export_harness"
        runtime_strategy = "caller_harness_required"
        runtime_reason = "A bare library needs a caller harness or host process before runtime tracing is meaningful."
        reason = "The target exposes callable APIs, but a harness must define arguments and ownership before fuzzing is meaningful."
        next_step = "Select an exported API with parser reachability and scaffold a harness around it."
    elif parser_surfaces and context_map.get("sources"):
        strategy = "campaign_plan_required"
        should_run_fuzz_plan = True
        reason = "Parser surfaces and input channels exist, but RAPTOR still needs the host/fuzzer plan before claiming a direct campaign is sensible."
        next_step = "Run the fuzzer plan and only launch a campaign if the binary accepts a known input mode."

    harness_candidates: list[dict[str, Any]] = []
    for item in high_value_ingress[:8]:
        harness_candidates.append({
            "ingress_id": item.get("id"),
            "kind": item.get("kind"),
            "name": item.get("name"),
            "bound_function_id": item.get("bound_function_id"),
            "why": _harness_reason(str(item.get("kind") or "")),
            "evidence_tier": item.get("evidence_tier"),
        })

    return {
        "strategy": strategy,
        "direct_campaign_recommended": direct_campaign_recommended,
        "should_run_fuzz_plan": should_run_fuzz_plan,
        "reason": reason,
        "next_step": next_step,
        "runtime_strategy": runtime_strategy,
        "runtime_reason": runtime_reason,
        "target_kind": target_kind,
        "target_detector": {
            "kind": target_info.kind,
            "arch": target_info.arch,
            "can_fuzz_here": target_info.can_fuzz_here,
            "recommended_fuzzer": target_info.recommended_fuzzer,
            "blockers": list(target_info.blockers),
            "hints": list(target_info.hints),
        },
        "signals": {
            "parser_surface_count": len(parser_surfaces),
            "external_ingress_count": len(ingress),
            "high_value_ingress_count": len(high_value_ingress),
            "sibling_artifact_count": len(topology.get("sibling_artifacts") or []),
            "has_libfuzzer_entry": has_libfuzzer_entry,
            "app_like": app_like,
            "driver_like": driver_like,
            "library_like": library_like,
        },
        "harness_candidates": harness_candidates,
        "claim": "fuzz_strategy_candidate_only",
    }


def _harness_reason(kind: str) -> str:
    return {
        "url_handler": "URL handlers are often narrow, reproducible parser/protocol boundaries.",
        "file_open_handler": "File-open handlers can often be isolated behind a file corpus harness.",
        "ipc_listener": "IPC handlers are better fuzzed at the message boundary than through the whole app.",
        "ioctl_dispatch": "IOCTL handlers are the meaningful driver fuzz boundary.",
        "exported_api": "Exported APIs can be wrapped with a typed harness.",
        "network_input": "Network parsers are good harness candidates once the message framing is known.",
        "web_navigation_handler": "Native web navigation policy handlers can often be driven with controlled URLs.",
    }.get(kind, "Potentially narrow externally drivable boundary.")


__all__ = ["assess_fuzz_suitability"]
