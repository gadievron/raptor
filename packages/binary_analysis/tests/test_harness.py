"""Tests for evidence-backed black-box harness planning."""

from __future__ import annotations

import json
from pathlib import Path

from packages.binary_analysis.harness import generate_binary_harness


def _write_run(
    tmp_path: Path,
    *,
    target_kind: str,
    platform: str,
    ingress: dict,
) -> Path:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "binary-manifest.json").write_text(json.dumps({
        "binary_path": str(tmp_path / "target"),
        "binary_sha256": "a" * 64,
        "target_kind": target_kind,
        "arch": "x86_64",
        "bits": 64,
    }))
    ingress = {
        "id": "BINGRESS-001",
        "platform": platform,
        "score": 100,
        "evidence_tier": "header_backed",
        "evidence_ids": ["EV-1"],
        "claim": "external_ingress_candidate_only",
        **ingress,
    }
    (run_dir / "context-map.json").write_text(json.dumps({
        "target_path": str(tmp_path / "target"),
        "external_ingress_candidates": [ingress],
    }))
    (run_dir / "binary-investigation.json").write_text(json.dumps({
        "ranked_ingress": [ingress],
    }))
    (run_dir / "binary-checklist.json").write_text(json.dumps({
        "target_path": str(tmp_path / "target"),
    }))
    return run_dir


def test_app_ingress_stops_at_runtime_trace_plan(tmp_path: Path) -> None:
    run_dir = _write_run(
        tmp_path,
        target_kind="macho",
        platform="macos",
        ingress={
            "kind": "ipc_listener",
            "name": "Demo.Listener.listener:shouldAcceptNewConnection:",
            "bound_function_id": "BFN-1000",
            "bound_function_name": "method.Demo.Listener.listener:shouldAcceptNewConnection:",
        },
    )

    spec = generate_binary_harness(run_dir)

    assert spec["family"] == "runtime_extracted_handler"
    assert spec["status"] == "needs_runtime_trace"
    assert spec["generated"] == {}
    assert "message or object schema" in spec["unknowns"]
    assert Path(spec["artifacts"]["spec"]).is_file()
    assert Path(spec["artifacts"]["report"]).is_file()
    checklist = json.loads((run_dir / "binary-checklist.json").read_text())
    assert checklist["harness_plans"][0]["id"] == spec["id"]


def test_exported_api_requires_explicit_abi_before_source_is_emitted(tmp_path: Path) -> None:
    run_dir = _write_run(
        tmp_path,
        target_kind="pe-dll",
        platform="windows",
        ingress={
            "kind": "exported_api",
            "name": "DecodePacket",
            "bound_function_id": "BFN-401000",
            "bound_function_name": "DecodePacket",
        },
    )

    blocked = generate_binary_harness(run_dir)
    assert blocked["status"] == "needs_abi_contract"
    assert blocked["generated"] == {}

    generated = generate_binary_harness(run_dir, abi="buffer-size")
    assert generated["status"] == "generated_candidate"
    assert generated["operator_inputs"]["abi"] == "buffer-size"
    source = Path(generated["generated"]["source"]).read_text()
    assert "LLVMFuzzerTestOneInput" in source
    assert "LoadLibraryA" in source
    assert "GetProcAddress" in source
    assert "DecodePacket" in source
    assert source.index("#include <windows.h>") < source.index("int LLVMFuzzerTestOneInput")
    assert Path(generated["generated"]["build_script"]).is_file()


def test_ioctl_harness_requires_device_contract_then_emits_linux_candidate(tmp_path: Path) -> None:
    run_dir = _write_run(
        tmp_path,
        target_kind="elf-kmod",
        platform="linux",
        ingress={
            "kind": "ioctl_dispatch",
            "name": "demo_unlocked_ioctl",
            "bound_function_id": "BFN-6000",
            "bound_function_name": "demo_unlocked_ioctl",
        },
    )

    blocked = generate_binary_harness(run_dir)
    assert blocked["status"] == "needs_driver_contract"

    generated = generate_binary_harness(run_dir, device="/dev/demo", ioctl_code="0x1234")
    assert generated["status"] == "generated_candidate"
    assert generated["operator_inputs"]["ioctl_code"] == "0x1234"
    source = Path(generated["generated"]["source"]).read_text()
    assert "ioctl(fd, 0x1234, data)" in source
    assert 'open("/dev/demo", O_RDWR)' in source


def test_ioctl_code_rejects_non_numeric_source_injection(tmp_path: Path) -> None:
    run_dir = _write_run(
        tmp_path,
        target_kind="pe-sys",
        platform="windows",
        ingress={
            "kind": "ioctl_dispatch",
            "name": "EvtIoDeviceControl",
        },
    )

    try:
        generate_binary_harness(
            run_dir,
            device=r"\\.\Demo",
            ioctl_code="0x222003); system(\"calc\");",
        )
    except ValueError as exc:
        assert "numeric literal" in str(exc)
    else:
        raise AssertionError("non-numeric ioctl code should be rejected")


def test_existing_libfuzzer_entry_does_not_generate_duplicate_source(tmp_path: Path) -> None:
    run_dir = _write_run(
        tmp_path,
        target_kind="elf-linux",
        platform="linux",
        ingress={
            "kind": "libfuzzer_entry",
            "name": "LLVMFuzzerTestOneInput",
            "bound_function_id": "BEP-1000",
            "bound_function_name": "LLVMFuzzerTestOneInput",
        },
    )

    spec = generate_binary_harness(run_dir)

    assert spec["status"] == "ready_existing_harness"
    assert spec["generated"] == {}
    assert "/binary fuzz" in spec["next_step"]


def test_app_ingress_with_runtime_binding_moves_to_parser_boundary(tmp_path: Path) -> None:
    run_dir = _write_run(
        tmp_path,
        target_kind="macho",
        platform="macos",
        ingress={
            "kind": "url_handler",
            "name": "Demo.AppDelegate.application:openURLs:",
            "bound_function_id": "BFN-1000",
            "bound_function_name": "method.Demo.AppDelegate.application:openURLs:",
        },
    )
    context = json.loads((run_dir / "context-map.json").read_text())
    context["runtime_input_flows"] = [{
        "id": "BRT-FLOW-001",
        "function_id": "BFN-1000",
        "function_name": "method.Demo.AppDelegate.application:openURLs:",
    }]
    (run_dir / "context-map.json").write_text(json.dumps(context))

    spec = generate_binary_harness(run_dir)

    assert spec["status"] == "needs_parser_boundary"
    assert len(spec["linked_evidence"]["runtime_input_flows"]) == 1
    assert "OBSERVED_CALLSITE" in spec["next_step"]


def test_app_ingress_with_recovered_parser_boundary_surfaces_that_in_plan(tmp_path: Path) -> None:
    run_dir = _write_run(
        tmp_path,
        target_kind="macho",
        platform="macos",
        ingress={
            "kind": "url_handler",
            "name": "Demo.AppDelegate.application:openURLs:",
            "bound_function_id": "BFN-1000",
            "bound_function_name": "method.Demo.AppDelegate.application:openURLs:",
        },
    )
    context = json.loads((run_dir / "context-map.json").read_text())
    context["parser_boundary_candidates"] = [{
        "id": "BPARSER-001",
        "ingress_id": "BINGRESS-001",
        "boundary_function_id": "BFN-1100",
        "boundary_function_name": "parse_url_payload",
        "parser_surface_name": "sym.imp.XML_Parse",
        "path": {"depth": 1},
        "evidence_tier": "xref_backed",
    }]
    (run_dir / "context-map.json").write_text(json.dumps(context))

    spec = generate_binary_harness(run_dir)

    assert spec["status"] == "parser_boundary_candidate"
    assert len(spec["linked_evidence"]["parser_boundaries"]) == 1
    assert "parse_url_payload" in spec["reason"]
    assert "PARSER_BOUNDARY_FOR_INGRESS" in spec["next_step"]
