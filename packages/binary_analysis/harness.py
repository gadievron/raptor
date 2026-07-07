"""Evidence-backed harness planning for black-box binary investigation.

This module sits between `/binary investigate` and `/binary fuzz`. It does not
pretend a selector, export or driver dispatch symbol is enough to write a safe
harness. Instead it writes a harness spec that separates:

- what the binary map proved
- what the operator supplied explicitly
- what RAPTOR still needs before a generated harness can be trusted

Runnable source is emitted only for mechanically defined contracts:

- an already-present libFuzzer entry point
- an exported API with an operator-supplied ABI shape
- an ioctl boundary with an operator-supplied device path and ioctl code

App callbacks and IPC handlers remain planning artefacts until runtime evidence
identifies the narrow parser/protocol boundary behind them.
"""

from __future__ import annotations

import hashlib

import re
import shlex
from pathlib import Path
from typing import Any, Optional

from core.json import load_json, save_json

from .graph_store import BinaryGraphStore, graph_path_for_run, stable_node_id

_ABI_CHOICES = {"buffer-size", "cstring"}
_APP_INGRESS_KINDS = {
    "url_handler",
    "file_open_handler",
    "ipc_listener",
    "web_navigation_handler",
    "web_auth_challenge_handler",
    "apple_event_handler",
    "notification_handler",
    "user_activity_handler",
    "url_scheme",
    "document_type",
}


def _slug(value: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "")).strip("._")
    return clean[:80] or "harness"


def _c_string(value: str) -> str:
    out = ['"']
    for ch in str(value):
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        elif ch == '\0':
            out.append('\\0')
        elif 0x20 <= ord(ch) <= 0x7e:
            out.append(ch)
        else:
            out.append(f'\\x{ord(ch):02x}')
    out.append('"')
    return ''.join(out)


def _evidence_ref(ingress: dict[str, Any]) -> dict[str, Any]:
    return {
        "ingress_id": ingress.get("id"),
        "kind": ingress.get("kind"),
        "name": ingress.get("name"),
        "bound_function_id": ingress.get("bound_function_id"),
        "bound_function_name": ingress.get("bound_function_name"),
        "address": ingress.get("address"),
        "evidence_tier": ingress.get("evidence_tier"),
        "evidence_ids": list(ingress.get("evidence_ids") or []),
        "claim": ingress.get("claim"),
    }


def _load_run(run_dir: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    run_dir = Path(run_dir).resolve()
    manifest_data = load_json(run_dir / "binary-manifest.json")
    context = load_json(run_dir / "context-map.json")
    investigation = load_json(run_dir / "binary-investigation.json")
    if not isinstance(manifest_data, dict):
        raise FileNotFoundError(f"missing binary-manifest.json in {run_dir}")
    if not isinstance(context, dict):
        raise FileNotFoundError(f"missing context-map.json in {run_dir}")
    return manifest_data, context, investigation if isinstance(investigation, dict) else {}


def _select_ingress(
    context: dict[str, Any],
    investigation: dict[str, Any],
    ingress_id: Optional[str],
) -> dict[str, Any]:
    ingress = [
        item for item in context.get("external_ingress_candidates", [])
        if isinstance(item, dict)
    ]
    if ingress_id:
        match = next((item for item in ingress if item.get("id") == ingress_id), None)
        if match is None:
            raise ValueError(f"unknown ingress id: {ingress_id}")
        return match
    ranked = [
        item for item in investigation.get("ranked_ingress", [])
        if isinstance(item, dict)
    ]
    parser_boundary_ingress_ids = {
        str(item.get("ingress_id") or "")
        for item in context.get("parser_boundary_candidates", [])
        if isinstance(item, dict) and item.get("ingress_id")
    }
    for ranked_item in ranked:
        if str(ranked_item.get("id") or "") not in parser_boundary_ingress_ids:
            continue
        match = next((item for item in ingress if item.get("id") == ranked_item.get("id")), None)
        if match is not None:
            return match
    actionable_kinds = {"libfuzzer_entry", "exported_api", "ioctl_dispatch", *_APP_INGRESS_KINDS}
    for ranked_item in ranked:
        match = next((item for item in ingress if item.get("id") == ranked_item.get("id")), None)
        if match is None:
            continue
        if match.get("kind") in actionable_kinds and (
            match.get("bound_function_id") or match.get("kind") in {"libfuzzer_entry", "exported_api", "ioctl_dispatch"}
        ):
            return match
    if ranked:
        top_id = ranked[0].get("id")
        match = next((item for item in ingress if item.get("id") == top_id), None)
        if match is not None:
            return match
    if ingress:
        return sorted(
            ingress,
            key=lambda item: (-int(item.get("score") or 0), str(item.get("name") or "")),
        )[0]
    raise ValueError("no external ingress candidates exist in this run")


def _verification_contract() -> list[dict[str, str]]:
    return [
        {
            "step": "build",
            "proof": "Harness source compiles with the intended sanitiser/fuzzer runtime.",
        },
        {
            "step": "smoke_replay",
            "proof": "Known-good seed input reaches the intended boundary without failing in harness glue.",
        },
        {
            "step": "determinism",
            "proof": "The same seed produces the same path/exit behaviour across repeated runs.",
        },
        {
            "step": "coverage",
            "proof": "Coverage increases beyond harness initialisation and reaches target code.",
        },
        {
            "step": "crash_replay",
            "proof": "Any crash reproduces against the bound debug/ASAN build or debugger witness.",
        },
    ]


def _source_exported_api(
    *,
    target_path: str,
    symbol: str,
    platform: str,
    abi: str,
) -> tuple[str, str, str]:
    if platform == "windows":
        platform_include = "#include <windows.h>\n"
        load = (
            f"    static HMODULE lib = NULL;\n"
            f"    static target_fn target = NULL;\n"
            f"    if (!lib) {{\n"
            f"        lib = LoadLibraryA({_c_string(target_path)});\n"
            f"        if (!lib) return 0;\n"
            f"        target = (target_fn)GetProcAddress(lib, {_c_string(symbol)});\n"
            f"        if (!target) return 0;\n"
            f"    }}\n"
        )
        compile_command = "clang -fsanitize=fuzzer,address,undefined -g -O1 fuzz_export.c -o fuzz_export.exe"
    else:
        platform_include = "#include <dlfcn.h>\n"
        load = (
            f"    static void *lib = NULL;\n"
            f"    static target_fn target = NULL;\n"
            f"    if (!lib) {{\n"
            f"        lib = dlopen({_c_string(target_path)}, RTLD_NOW | RTLD_LOCAL);\n"
            f"        if (!lib) return 0;\n"
            f"        target = (target_fn)dlsym(lib, {_c_string(symbol)});\n"
            f"        if (!target) return 0;\n"
            f"    }}\n"
        )
        compile_command = "clang -fsanitize=fuzzer,address,undefined -g -O1 fuzz_export.c -ldl -o fuzz_export"

    if abi == "cstring":
        typedef = "typedef int (*target_fn)(const char *);"
        invoke = (
            "    char *buf = (char *)malloc(size + 1);\n"
            "    if (!buf) return 0;\n"
            "    memcpy(buf, data, size);\n"
            "    buf[size] = '\\0';\n"
            "    (void)target(buf);\n"
            "    free(buf);\n"
        )
    else:
        typedef = "typedef int (*target_fn)(const uint8_t *, size_t);"
        invoke = "    (void)target(data, size);\n"

    source = (
        "/* RAPTOR generated candidate harness.\n"
        " * Contract source: operator-supplied ABI shape, not recovered proof.\n"
        " * Verify this reaches the intended export before fuzzing.\n"
        " */\n"
        "#include <stdint.h>\n"
        "#include <stddef.h>\n"
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        f"{platform_include}"
        f"{typedef}\n\n"
        "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
        "    if (size == 0) return 0;\n"
        f"{load}"
        f"{invoke}"
        "    return 0;\n"
        "}\n"
    )
    return source, compile_command, "fuzz_export.c"


def _source_ioctl(
    *,
    platform: str,
    device: str,
    ioctl_code: str,
) -> tuple[str, str, str]:
    if platform == "windows":
        source = (
            "/* RAPTOR generated candidate IOCTL harness.\n"
            " * Device path and IOCTL code are operator-supplied contracts.\n"
            " */\n"
            "#include <windows.h>\n"
            "#include <stdint.h>\n"
            "#include <stddef.h>\n\n"
            "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
            f"    static HANDLE dev = INVALID_HANDLE_VALUE;\n"
            "    if (dev == INVALID_HANDLE_VALUE) {\n"
            f"        dev = CreateFileA({_c_string(device)}, GENERIC_READ | GENERIC_WRITE,\n"
            "                          0, NULL, OPEN_EXISTING, 0, NULL);\n"
            "        if (dev == INVALID_HANDLE_VALUE) return 0;\n"
            "    }\n"
            "    DWORD returned = 0;\n"
            f"    (void)DeviceIoControl(dev, {ioctl_code}, (LPVOID)data, (DWORD)size,\n"
            "                          NULL, 0, &returned, NULL);\n"
            "    return 0;\n"
            "}\n"
        )
        return source, "clang -fsanitize=fuzzer,address -g -O1 fuzz_ioctl.c -o fuzz_ioctl.exe", "fuzz_ioctl.c"
    source = (
        "/* RAPTOR generated candidate ioctl harness.\n"
        " * Device path and ioctl code are operator-supplied contracts.\n"
        " */\n"
        "#include <stdint.h>\n"
        "#include <stddef.h>\n"
        "#include <fcntl.h>\n"
        "#include <sys/ioctl.h>\n"
        "#include <unistd.h>\n\n"
        "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
        "    static int fd = -1;\n"
        "    if (fd < 0) {\n"
        f"        fd = open({_c_string(device)}, O_RDWR);\n"
        "        if (fd < 0) return 0;\n"
        "    }\n"
        f"    (void)ioctl(fd, {ioctl_code}, data);\n"
        "    (void)size;\n"
        "    return 0;\n"
        "}\n"
    )
    return source, "clang -fsanitize=fuzzer,address -g -O1 fuzz_ioctl.c -o fuzz_ioctl", "fuzz_ioctl.c"


def _normalise_ioctl_code(value: str) -> str:
    try:
        number = int(str(value), 0)
    except ValueError as exc:
        raise ValueError("ioctl code must be a numeric literal such as 0x222003") from exc
    if number < 0 or number > 0xFFFFFFFF:
        raise ValueError("ioctl code must fit in an unsigned 32-bit value")
    return hex(number)


def _write_generated_source(
    harness_dir: Path,
    *,
    source: str,
    filename: str,
    compile_command: str,
) -> dict[str, str]:
    harness_dir.mkdir(parents=True, exist_ok=True)
    source_path = harness_dir / filename
    source_path.write_text(source, encoding="utf-8")
    build_path = harness_dir / "build.sh"
    build_path.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        "# Generated by RAPTOR. Review the contract before running.\n"
        "cd \"$(dirname \"$0\")\"\n"
        f"{compile_command}\n",
        encoding="utf-8",
    )
    build_path.chmod(0o755)
    return {
        "source": str(source_path),
        "build_script": str(build_path),
        "compile_command": compile_command,
    }


def generate_binary_harness(
    run_dir: Path,
    *,
    ingress_id: Optional[str] = None,
    abi: Optional[str] = None,
    device: Optional[str] = None,
    ioctl_code: Optional[str] = None,
) -> dict[str, Any]:
    """Write a binary harness plan and optional candidate source."""
    run_dir = Path(run_dir).resolve()
    manifest_data, context, investigation = _load_run(run_dir)
    ingress = _select_ingress(context, investigation, ingress_id)
    kind = str(ingress.get("kind") or "")
    platform = str(ingress.get("platform") or "generic")
    target_path = str(manifest_data.get("binary_path") or context.get("target_path") or "")
    target_kind = str(manifest_data.get("target_kind") or "")
    binary_sha256 = str(manifest_data.get("binary_sha256") or "")
    bound_function_id = str(ingress.get("bound_function_id") or "")
    linked_candidate_flows = [
        item for item in context.get("candidate_flows", [])
        if isinstance(item, dict) and str(item.get("source_function") or "") == bound_function_id
    ]
    linked_runtime_flows = [
        item for item in context.get("runtime_input_flows", [])
        if isinstance(item, dict) and str(item.get("function_id") or "") == bound_function_id
    ]
    linked_parser_boundaries = [
        item for item in context.get("parser_boundary_candidates", [])
        if isinstance(item, dict) and str(item.get("ingress_id") or "") == str(ingress.get("id") or "")
    ]
    selected_abi = str(abi or "")
    if selected_abi and selected_abi not in _ABI_CHOICES:
        raise ValueError(f"unsupported ABI shape {selected_abi!r}; choose one of {sorted(_ABI_CHOICES)}")

    plan_key = f"{binary_sha256}:{ingress.get('id')}"
    plan_id = f"BHARNESS-{hashlib.sha256(plan_key.encode()).hexdigest()[:12]}"
    harness_dir = run_dir / "harness" / _slug(str(ingress.get("id") or ingress.get("name") or "candidate"))
    unknowns: list[str] = []
    operator_inputs: dict[str, Any] = {}
    generated: dict[str, str] = {}
    status = "blocked"
    family = "unknown"
    reason = "RAPTOR does not have enough evidence to emit a harness for this ingress."
    next_step = "Collect stronger runtime or ABI evidence."

    if kind == "libfuzzer_entry":
        family = "existing_libfuzzer"
        status = "ready_existing_harness"
        reason = "The binary already exposes LLVMFuzzerTestOneInput."
        next_step = f"/binary fuzz {shlex.quote(target_path)} --plan-only"
    elif kind == "exported_api":
        family = "dynamic_export"
        unknowns = [
            "parameter types and calling convention",
            "ownership and lifetime rules",
            "whether the artefact can be loaded in-process",
        ]
        if not selected_abi:
            status = "needs_abi_contract"
            reason = "An exported symbol exists, but black-box bytes do not prove its argument contract."
            next_step = (
                f"/binary harness {shlex.quote(str(run_dir))} --ingress {shlex.quote(str(ingress.get('id')))} "
                "--abi buffer-size"
            )
        else:
            operator_inputs["abi"] = selected_abi
            source, compile_command, filename = _source_exported_api(
                target_path=target_path,
                symbol=str(ingress.get("name") or ""),
                platform=platform,
                abi=selected_abi,
            )
            generated = _write_generated_source(
                harness_dir,
                source=source,
                filename=filename,
                compile_command=compile_command,
            )
            status = "generated_candidate"
            reason = "Generated from a proven export plus an operator-supplied ABI shape."
            next_step = f"Review and build {generated['build_script']}"
    elif kind == "ioctl_dispatch":
        family = "ioctl_driver"
        unknowns = [
            "device path",
            "ioctl/control code",
            "buffer direction and structure",
            "driver load/setup requirements",
        ]
        if not device or not ioctl_code:
            status = "needs_driver_contract"
            reason = "The dispatch boundary exists, but the device path and ioctl code are not recoverable from this symbol alone."
            next_step = (
                f"/binary harness {shlex.quote(str(run_dir))} --ingress {shlex.quote(str(ingress.get('id')))} "
                "--device <path> --ioctl-code <code>"
            )
        else:
            operator_inputs["device"] = device
            normalised_ioctl_code = _normalise_ioctl_code(ioctl_code)
            operator_inputs["ioctl_code"] = normalised_ioctl_code
            source, compile_command, filename = _source_ioctl(
                platform=platform,
                device=device,
                ioctl_code=normalised_ioctl_code,
            )
            generated = _write_generated_source(
                harness_dir,
                source=source,
                filename=filename,
                compile_command=compile_command,
            )
            status = "generated_candidate"
            reason = "Generated from a proven dispatch boundary plus operator-supplied device contract."
            next_step = f"Review and build {generated['build_script']}"
    elif linked_parser_boundaries:
        family = "runtime_extracted_parser"
        top_boundary = linked_parser_boundaries[0]
        status = "parser_boundary_candidate"
        reason = (
            f"RAPTOR recovered {top_boundary['boundary_function_name']} as a bounded "
            f"parser boundary behind this ingress."
        )
        unknowns = [
            "callable ABI or object contract for the recovered parser boundary",
            "setup and teardown needed for isolated replay",
        ]
        next_step = (
            f"/binary graph {shlex.quote(str(run_dir))} "
            "--edges --kind PARSER_BOUNDARY_FOR_INGRESS --json"
        )
    elif kind in _APP_INGRESS_KINDS:
        family = "runtime_extracted_handler"
        unknowns = [
            "concrete runtime invocation",
            "message or object schema",
            "setup and teardown needed for isolated replay",
        ]
        if linked_runtime_flows:
            unknowns.append("narrow parser/protocol function behind the framework callback")
            status = "needs_parser_boundary"
            reason = "Runtime evidence reached the bound handler, but a safe harness still needs the narrower parser boundary behind it."
            next_step = f"/binary graph {shlex.quote(str(run_dir))} --edges --kind OBSERVED_CALLSITE --json"
        else:
            unknowns.append("narrow parser/protocol function behind the framework callback")
            status = "needs_runtime_trace"
            reason = "Framework and IPC ingress is real, but a safe harness needs the narrower parser boundary behind it."
            next_step = f"/binary runtime {shlex.quote(target_path)} --duration 30"
    else:
        family = "manual_review"
        unknowns = ["narrow input contract", "callable target boundary"]

    spec = {
        "schema_version": 1,
        "id": plan_id,
        "run_dir": str(run_dir),
        "target": {
            "path": target_path,
            "binary_sha256": binary_sha256,
            "target_kind": target_kind,
            "platform": platform,
            "arch": manifest_data.get("arch"),
            "bits": manifest_data.get("bits"),
        },
        "ingress": _evidence_ref(ingress),
        "linked_evidence": {
            "candidate_flows": linked_candidate_flows,
            "runtime_input_flows": linked_runtime_flows,
            "parser_boundaries": linked_parser_boundaries,
        },
        "family": family,
        "status": status,
        "reason": reason,
        "operator_inputs": operator_inputs,
        "unknowns": unknowns,
        "generated": generated,
        "verification_contract": _verification_contract(),
        "next_step": next_step,
        "evidence_policy": (
            "Generated source is a candidate harness only. It does not become a trusted "
            "fuzz boundary until build, smoke replay, determinism and coverage checks pass."
        ),
    }
    harness_dir.mkdir(parents=True, exist_ok=True)
    spec_path = harness_dir / "harness-spec.json"
    report_path = harness_dir / "harness-report.md"
    report_path.write_text(render_harness_report(spec), encoding="utf-8")
    spec["artifacts"] = {
        "spec": str(spec_path),
        "report": str(report_path),
        **generated,
    }
    save_json(spec_path, spec)
    checklist = load_json(run_dir / "binary-checklist.json")
    if isinstance(checklist, dict):
        plans = [
            item for item in checklist.get("harness_plans", [])
            if isinstance(item, dict) and item.get("id") != spec["id"]
        ]
        plans.append({
            "id": spec["id"],
            "ingress_id": ingress.get("id"),
            "family": spec["family"],
            "status": spec["status"],
            "artifacts": spec["artifacts"],
        })
        checklist["harness_plans"] = plans
        save_json(run_dir / "binary-checklist.json", checklist)
    graph_path = graph_path_for_run(run_dir)
    if graph_path.exists():
        with BinaryGraphStore(graph_path) as store:
            snapshot_id = store.latest_snapshot_id()
            if snapshot_id:
                store.add_artifact(snapshot_id, "binary_harness_spec", spec_path)
                store.add_artifact(snapshot_id, "binary_harness_report", report_path)
                for key in ("source", "build_script"):
                    if generated.get(key):
                        store.add_artifact(snapshot_id, f"binary_harness_{key}", Path(generated[key]))
                plan_node = store.add_node(
                    snapshot_id,
                    binary_sha256,
                    "harness_plan",
                    plan_id,
                    name=f"{spec['family']}:{ingress.get('name')}",
                    props=spec,
                    evidence_ids=list(ingress.get("evidence_ids") or []),
                )
                binary_node = stable_node_id(binary_sha256, "binary", binary_sha256)
                ingress_node = stable_node_id(binary_sha256, "external_ingress", str(ingress.get("id") or ""))
                store.add_edge(
                    snapshot_id,
                    binary_sha256,
                    "HAS_HARNESS_PLAN",
                    binary_node,
                    plan_node,
                    confidence="candidate",
                    evidence_ids=list(ingress.get("evidence_ids") or []),
                )
                store.add_edge(
                    snapshot_id,
                    binary_sha256,
                    "PLANNED_HARNESS_FOR",
                    plan_node,
                    ingress_node,
                    confidence="candidate",
                    evidence_ids=list(ingress.get("evidence_ids") or []),
                )
    return spec


def render_harness_report(spec: dict[str, Any]) -> str:
    ingress = spec["ingress"]
    target = spec["target"]
    lines = [
        "# RAPTOR Binary Harness Plan",
        "",
        f"Target: `{target['path']}`",
        f"SHA-256: `{target['binary_sha256']}`",
        f"Ingress: `{ingress['name']}`",
        f"Family: `{spec['family']}`",
        f"Status: `{spec['status']}`",
        "",
        "## Evidence",
        "",
        f"- Ingress kind: `{ingress['kind']}`",
        f"- Bound function: `{ingress.get('bound_function_name') or 'not bound'}`",
        f"- Evidence tier: `{ingress.get('evidence_tier')}`",
        f"- Evidence ids: `{', '.join(ingress.get('evidence_ids') or []) or 'none'}`",
        f"- Linked candidate flows: {len((spec.get('linked_evidence') or {}).get('candidate_flows') or [])}",
        f"- Linked runtime input flows: {len((spec.get('linked_evidence') or {}).get('runtime_input_flows') or [])}",
        f"- Linked parser boundary candidates: {len((spec.get('linked_evidence') or {}).get('parser_boundaries') or [])}",
        "",
        "## Decision",
        "",
        f"- {spec['reason']}",
        f"- Next step: `{spec['next_step']}`",
    ]
    if spec.get("operator_inputs"):
        lines.extend(["", "## Operator-supplied Contract", ""])
        lines.extend(
            f"- `{key}`: `{value}`"
            for key, value in spec["operator_inputs"].items()
        )
    if spec.get("unknowns"):
        lines.extend(["", "## Still Unknown", ""])
        lines.extend(f"- {item}" for item in spec["unknowns"])
    parser_boundaries = (spec.get("linked_evidence") or {}).get("parser_boundaries") or []
    if parser_boundaries:
        lines.extend(["", "## Recovered Parser Boundary", ""])
        for item in parser_boundaries[:5]:
            lines.append(
                f"- `{item['boundary_function_name']}` -> `{item['parser_surface_name']}` "
                f"(depth {item['path']['depth']}, tier `{item['evidence_tier']}`)"
            )
    if spec.get("generated"):
        lines.extend([
            "",
            "## Generated Candidate",
            "",
            f"- Source: `{spec['generated'].get('source')}`",
            f"- Build script: `{spec['generated'].get('build_script')}`",
            f"- Compile command: `{spec['generated'].get('compile_command')}`",
        ])
    lines.extend(["", "## Verification Contract", ""])
    lines.extend(
        f"- `{item['step']}`: {item['proof']}"
        for item in spec["verification_contract"]
    )
    lines.extend([
        "",
        "## What RAPTOR Is Not Claiming",
        "",
        "- A generated harness is not yet a trusted fuzz boundary.",
        "- An operator-supplied ABI or ioctl contract is not binary-recovered proof.",
        "- A framework callback is not safe to fuzz in isolation until runtime evidence narrows the boundary.",
    ])
    return "\n".join(lines) + "\n"


__all__ = ["generate_binary_harness", "render_harness_report"]
