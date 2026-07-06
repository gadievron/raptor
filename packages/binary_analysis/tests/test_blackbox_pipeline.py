"""Tests for the evidence-first black-box binary substrate."""

from __future__ import annotations

import json
import plistlib
import struct
from pathlib import Path
from unittest.mock import patch

from packages.binary_analysis.constraints import validate_constraint_file
from packages.binary_analysis.diff import diff_manifests
from packages.binary_analysis.graph_store import graph_summary, query_edges, query_evidence
from packages.binary_analysis.input_channels import merge_observed_channels, recover_static_channels
from packages.binary_analysis.manifest import build_manifest
from packages.binary_analysis.pipeline import analyse_blackbox_binary, append_fuzz_evidence_to_run, append_runtime_evidence_to_run
from packages.binary_analysis.radare2_understand import (
    BinaryContextMap,
    FunctionInfo,
    RecoveredClassInfo,
    RecoveredMethodInfo,
)
from packages.binary_analysis.surface_classification import classify_security_api


def _write_binary(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    path.chmod(0o755)
    return path


def _write_frida_run(run_dir: Path, binary: Path) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "metadata.json").write_text(json.dumps({
        "ok": True,
        "target": {
            "raw": str(binary),
            "kind": "binary",
            "binary": str(binary),
        },
    }))
    (run_dir / "events.jsonl").write_text(
        json.dumps({
            "type": "send",
            "payload": {
                "category": "network",
                "fn": "recv",
                "args": {"fd": 4},
                "tid": 1,
            },
        }) + "\n"
    )
    return run_dir


def test_manifest_records_runtime_markers_without_claiming_reachability(tmp_path: Path) -> None:
    binary = _write_binary(tmp_path / "sample.exe", b"MZ" + b"\x00" * 64 + b"BSJB")
    ctx = BinaryContextMap(binary_path=binary, arch="x86", bits=64, binary_format="pe")
    ctx.imports = ["sym.imp.recv", "sym.imp.strcpy"]

    manifest = build_manifest(binary, ctx)

    assert manifest.binary_sha256
    assert manifest.binary_format == "pe"
    assert manifest.capability_buckets["network"] == ["recv"]
    assert any(signal.family == ".net" for signal in manifest.runtime_signals)
    assert all(record.reproducible for record in manifest.evidence)


def test_fat_macho_magic_is_not_mislabelled_as_java(tmp_path: Path) -> None:
    binary = _write_binary(tmp_path / "fat-macho", b"\xca\xfe\xba\xbe" + b"\x00" * 64)
    ctx = BinaryContextMap(binary_path=binary, arch="fat", bits=64, binary_format="mach0")

    manifest = build_manifest(binary, ctx)

    assert manifest.target_kind == "macho"
    assert not any(signal.family == "java" for signal in manifest.runtime_signals)


def test_fat_macho_manifest_records_slices_and_bundle_metadata(tmp_path: Path) -> None:
    app = tmp_path / "JamfCheck.app" / "Contents"
    binary = app / "MacOS" / "JamfCheck"
    binary.parent.mkdir(parents=True)
    plist_path = app / "Info.plist"
    plist_path.write_bytes(plistlib.dumps({
        "CFBundleIdentifier": "com.example.JamfCheck",
        "CFBundleExecutable": "JamfCheck",
        "CFBundleShortVersionString": "2.2.1",
        "CFBundleVersion": "20",
        "NSAppTransportSecurity": {
            "NSExceptionDomains": {"example.test": {"NSExceptionAllowsInsecureHTTPLoads": True}},
        },
        "SMPrivilegedExecutables": {"com.example.JamfCheck.helper": "anchor apple"},
    }))
    payload = bytearray(b"\x00" * 0x240)
    payload[:8] = b"\xca\xfe\xba\xbe" + struct.pack(">I", 2)
    payload[8:28] = struct.pack(">IIIII", 0x01000007, 3, 0x100, 0x20, 0)
    payload[28:48] = struct.pack(">IIIII", 0x0100000C, 0, 0x200, 0x20, 0)
    payload[0x100:0x120] = b"x86-slice" + b"\x00" * 23
    payload[0x200:0x220] = b"arm-slice" + b"\x00" * 23
    _write_binary(binary, bytes(payload))
    ctx = BinaryContextMap(binary_path=binary, arch="arm", bits=64, binary_format="mach0")

    manifest = build_manifest(binary, ctx)

    assert [item.arch for item in manifest.slices] == ["x86_64", "arm64"]
    assert manifest.analysed_slice is not None
    assert manifest.analysed_slice.arch == "arm64"
    assert manifest.arch == "arm64"
    assert manifest.app_bundle is not None
    assert manifest.app_bundle.identifier == "com.example.JamfCheck"
    assert manifest.app_bundle.ats_exception_domains == ["example.test"]
    assert manifest.app_bundle.privileged_executables == ["com.example.JamfCheck.helper"]
    assert any(record.kind == "macho_slices" for record in manifest.evidence)
    assert any(record.kind == "app_bundle_metadata" for record in manifest.evidence)


def test_quick_binary_map_does_not_claim_deep_analysis(tmp_path: Path) -> None:
    binary = _write_binary(tmp_path / "sample", b"\x7fELF" + b"\x00" * 128)
    out = tmp_path / "out"
    ctx = BinaryContextMap(
        binary_path=binary,
        arch="x86",
        bits=64,
        binary_format="elf",
        analysis_depth="metadata_only",
    )

    with patch("packages.binary_analysis.pipeline.analyse_binary_context", return_value=ctx):
        result = analyse_blackbox_binary(binary, out_dir=out, quick=True)

    assert result.manifest.analysis_depth == "metadata_only"
    assert result.context_map["analysis_scope"]["selected_arch"] == "x86"
    assert result.context_map["analysis_scope"]["deep_analysis_arch"] is None
    assert result.context_map["analysis_scope"]["analysis_depth"] == "metadata_only"
    assert result.context_map["analysis_scope"]["all_slices_analysed"] is False


def test_radare2_failure_is_reported_as_unavailable_not_empty_success(tmp_path: Path) -> None:
    binary = _write_binary(tmp_path / "sample", b"\x7fELF" + b"\x00" * 128)
    out = tmp_path / "out"

    with patch(
        "packages.binary_analysis.pipeline.analyse_binary_context",
        side_effect=TimeoutError("r2 command 'aaa' exceeded 600s"),
    ):
        result = analyse_blackbox_binary(binary, out_dir=out)

    assert result.manifest.analysis_depth == "unavailable"
    assert result.context_map["analysis_scope"]["deep_analysis_arch"] is None
    assert result.context_map["analysis_scope"]["analysis_depth"] == "unavailable"
    assert "radare2 analysis unavailable" in result.context_map["notes"][0]
    report = (out / "binary-analysis-report.md").read_text()
    assert "## Analysis Notes" in report
    assert "radare2 analysis unavailable" in report


def test_input_channels_upgrade_only_when_runtime_observed() -> None:
    channels, static_evidence = recover_static_channels("a" * 64, ["recv", "getenv"])
    assert {channel.kind for channel in channels} == {"network", "environment"}
    assert all(channel.confidence == "candidate" for channel in channels)
    assert static_evidence

    channels, runtime_evidence = merge_observed_channels(
        "a" * 64,
        channels,
        [{"category": "network", "fn": "accept", "args": {"fd": 4}}],
    )
    network = next(channel for channel in channels if channel.kind == "network")
    env = next(channel for channel in channels if channel.kind == "environment")
    assert network.observed is True
    assert network.confidence == "confirmed"
    assert env.observed is False
    assert runtime_evidence[0].tier.value == "observed_runtime"


def test_pipeline_writes_graph_and_candidate_flows(tmp_path: Path) -> None:
    binary = _write_binary(tmp_path / "sample", b"\x7fELF" + b"\x00" * 128)
    out = tmp_path / "out"
    ctx = BinaryContextMap(binary_path=binary, arch="x86", bits=64, binary_format="elf")
    main = FunctionInfo(name="main", address=0x401000, size=64, is_entry=True)
    parser = FunctionInfo(
        name="parse_request",
        address=0x401100,
        size=128,
        calls_dangerous=["strcpy"],
    )
    sink = FunctionInfo(name="sym.imp.strcpy", address=0x402000, size=16, is_imported=True)
    ctx.entry_points = [main]
    ctx.interesting_functions = [main, parser]
    ctx.dangerous_sinks = [sink]
    ctx.imports = ["sym.imp.recv", "sym.imp.strcpy"]

    with patch("packages.binary_analysis.pipeline.analyse_binary_context", return_value=ctx):
        result = analyse_blackbox_binary(binary, out_dir=out)

    assert (out / "binary-manifest.json").exists()
    assert (out / "binary-evidence.json").exists()
    assert (out / "context-map.json").exists()
    assert (out / "binary-analysis-report.md").exists()
    assert result.context_map["unchecked_flows"] == []
    assert result.context_map["candidate_flows"][0]["relationship"] == "calls"
    assert "not proof" in result.context_map["candidate_flows"][0]["evidence_note"]
    assert result.context_map["sink_details"][0]["presence_confidence"] == "confirmed"
    assert result.context_map["sink_details"][0]["confidence"] == "candidate"

    summary = graph_summary(result.graph_path)
    assert summary["nodes"]["binary"] == 1
    assert summary["edges"]["CALLS"] == 1
    assert query_edges(result.graph_path, kind="CALLS")[0]["target"]["name"] == "sym.imp.strcpy"
    assert any(item["tier"] == "xref_backed" for item in query_evidence(result.graph_path))


def test_pipeline_recovers_bounded_parser_boundary_behind_ingress(tmp_path: Path) -> None:
    binary = _write_binary(tmp_path / "sample", b"\x7fELF" + b"\x00" * 128)
    out = tmp_path / "out"
    ctx = BinaryContextMap(binary_path=binary, arch="x86", bits=64, binary_format="elf")
    main = FunctionInfo(
        name="main",
        address=0x401000,
        size=64,
        is_entry=True,
        direct_callees=["parse_request"],
    )
    parser = FunctionInfo(
        name="parse_request",
        address=0x401100,
        size=128,
        direct_callees=["sym.imp.XML_Parse"],
    )
    ctx.entry_points = [main]
    ctx.interesting_functions = [main, parser]
    ctx.imports = ["sym.imp.XML_Parse"]

    with patch("packages.binary_analysis.pipeline.analyse_binary_context", return_value=ctx):
        result = analyse_blackbox_binary(binary, out_dir=out)

    boundaries = result.context_map["parser_boundary_candidates"]
    assert len(boundaries) == 1
    assert boundaries[0]["boundary_function_name"] == "parse_request"
    assert boundaries[0]["ingress_name"] == "main"
    assert boundaries[0]["parser_surface_name"] == "XML_Parse"
    assert boundaries[0]["path"]["function_names"] == ["main", "parse_request"]
    assert boundaries[0]["path"]["depth"] == 1
    assert boundaries[0]["evidence_tier"] == "xref_backed"
    summary = graph_summary(result.graph_path)
    assert summary["nodes"]["parser_boundary"] == 1
    assert summary["edges"]["PARSER_BOUNDARY_FOR_INGRESS"] == 1
    assert summary["edges"]["PARSER_BOUNDARY_CALLS_SURFACE"] == 1


def test_pipeline_persists_decompilation_and_validation_handoff(tmp_path: Path) -> None:
    binary = _write_binary(tmp_path / "sample", b"\x7fELF" + b"\x00" * 128)
    out = tmp_path / "out"
    ctx = BinaryContextMap(binary_path=binary, arch="x86", bits=64, binary_format="elf")
    ctx.decompiler = "pdc"
    ctx.decompilation_limit = 20
    ctx.decompilation_attempted = 1
    parser = FunctionInfo(
        name="parse_request",
        address=0x401100,
        size=128,
        calls_dangerous=["strcpy"],
        decompiled="void parse_request(char *s) { strcpy(buf, s); }",
    )
    sink = FunctionInfo(name="sym.imp.strcpy", address=0x402000, size=16, is_imported=True)
    ctx.interesting_functions = [parser]
    ctx.dangerous_sinks = [sink]
    ctx.imports = ["sym.imp.strcpy"]

    with patch("packages.binary_analysis.pipeline.analyse_binary_context", return_value=ctx):
        result = analyse_blackbox_binary(binary, out_dir=out)

    decomp = json.loads((out / "binary-decompilations.json").read_text())
    assert decomp["coverage"]["decompiled_functions"] == 1
    assert decomp["functions"][0]["body"].startswith("void parse_request")
    handoff = json.loads((out / "binary-validation-handoff.json").read_text())
    assert handoff["status"] == "static_only"
    assert handoff["candidate_flows"][0]["can_promote_to_finding"] is False
    assert "runtime_input_callsite" in handoff["candidate_flows"][0]["missing_evidence"]
    assert handoff["next_actions"][0]["command"] == "/binary trace-parser <run-dir> --duration 30"
    assert handoff["next_actions"][1]["kind"] == "harness_strategy"
    assert handoff["next_actions"][1]["command"] == "/binary harness <run-dir>"
    assert handoff["next_actions"][2]["command"].startswith("/binary map ")
    summary = graph_summary(result.graph_path)
    assert summary["nodes"]["decompilation"] == 1
    assert summary["nodes"]["validation_handoff"] == 1
    assert summary["edges"]["DECOMPILED_AS"] == 1
    assert summary["edges"]["REQUIRES_VALIDATION"] == 1


def test_pipeline_persists_class_metadata_without_promoting_callbacks_to_entry_points(tmp_path: Path) -> None:
    binary = _write_binary(tmp_path / "sample", b"\xcf\xfa\xed\xfe" + b"\x00" * 128)
    out = tmp_path / "out"
    ctx = BinaryContextMap(binary_path=binary, arch="arm64", bits=64, binary_format="mach0")
    main = FunctionInfo(name="main", address=0x100001000, size=64, is_entry=True)
    callback_fn = FunctionInfo(
        name="method.AppDelegate.applicationDidFinishLaunching:",
        address=0x100001100,
        size=96,
    )
    ctx.entry_points = [main]
    ctx.interesting_functions = [main, callback_fn]
    ctx.classes = [
        RecoveredClassInfo(
            name="Example.AppDelegate",
            address=0x100100000,
            language="objc",
            superclasses=["NSObject"],
            methods=[
                RecoveredMethodInfo(
                    name="applicationDidFinishLaunching:",
                    address=callback_fn.address,
                    language="objc",
                    bound_function_address=callback_fn.address,
                    bound_function_name=callback_fn.name,
                ),
                RecoveredMethodInfo(name="init", address=0x100001200, language="objc"),
            ],
            fields=[{"name": "helper", "kind": "var", "address": "0x100100100"}],
        ),
    ]

    with patch("packages.binary_analysis.pipeline.analyse_binary_context", return_value=ctx):
        result = analyse_blackbox_binary(binary, out_dir=out)

    assert [item["name"] for item in result.context_map["entry_points"]] == ["main"]
    class_inventory = result.context_map["class_inventory"]
    assert class_inventory["summary"]["class_count"] == 1
    assert class_inventory["summary"]["method_count"] == 2
    assert class_inventory["summary"]["bound_method_count"] == 1
    callback = result.context_map["framework_callback_candidates"][0]
    assert callback["class_name"] == "Example.AppDelegate"
    assert callback["method_name"] == "applicationDidFinishLaunching:"
    assert callback["bound_function_id"] == "BFN-100001100"
    assert "does not prove" in callback["evidence_note"]
    checklist = json.loads((out / "binary-checklist.json").read_text())
    assert checklist["class_inventory"]["summary"]["class_count"] == 1
    summary = graph_summary(result.graph_path)
    assert summary["nodes"]["class"] == 1
    assert summary["nodes"]["method"] == 2
    assert summary["edges"]["DECLARES_CLASS"] == 1
    assert summary["edges"]["DECLARES_METHOD"] == 2
    assert summary["edges"]["BACKED_BY_FUNCTION"] == 2
    assert summary["edges"]["FRAMEWORK_CALLBACK_CANDIDATE"] == 1


def test_native_surfaces_are_not_all_reported_as_sinks() -> None:
    assert classify_security_api("sym.imp.memcpy").is_sink is True
    assert classify_security_api("sym.imp.NSTask").is_sink is True
    assert classify_security_api("sym.imp.Foundation.JSONDecoder.decode").is_sink is False
    assert classify_security_api("sym.imp.Foundation.URL.fileURLWithPath").is_sink is False
    assert classify_security_api("sym.imp.NSLog").is_sink is False
    assert classify_security_api("sym.imp.readlink").is_sink is False


def test_runtime_scaffolding_is_not_presented_as_entry_point(tmp_path: Path) -> None:
    binary = _write_binary(tmp_path / "sample", b"\x7fELF" + b"\x00" * 128)
    out = tmp_path / "out"
    ctx = BinaryContextMap(binary_path=binary, arch="x86", bits=64, binary_format="elf")
    ctx.entry_points = [
        FunctionInfo(name="main", address=0x401000, size=64, is_entry=True),
        FunctionInfo(name="sym.___afl_manual_init", address=0x401100, size=64, is_entry=True),
        FunctionInfo(name="sym.___sanitizer_cov_trace_pc_guard_init", address=0x401200, size=64, is_entry=True),
        FunctionInfo(name="sym.___early_forkserver", address=0x401300, size=64, is_entry=True),
        FunctionInfo(name="sym._write_error_with_location", address=0x401400, size=64, is_entry=True),
    ]
    ctx.interesting_functions = list(ctx.entry_points)

    with patch("packages.binary_analysis.pipeline.analyse_binary_context", return_value=ctx):
        result = analyse_blackbox_binary(binary, out_dir=out)

    assert [item["name"] for item in result.context_map["entry_points"]] == ["main"]
    assert {item["name"] for item in result.context_map["runtime_support_functions"]} == {
        "sym.___afl_manual_init",
        "sym.___sanitizer_cov_trace_pc_guard_init",
        "sym.___early_forkserver",
        "sym._write_error_with_location",
    }


def test_append_fuzz_evidence_updates_json_and_graph_without_reanalysis(tmp_path: Path) -> None:
    binary = _write_binary(tmp_path / "sample", b"\x7fELF" + b"\x00" * 128)
    out = tmp_path / "out"
    ctx = BinaryContextMap(binary_path=binary, arch="x86", bits=64, binary_format="elf")
    ctx.entry_points = [FunctionInfo(name="main", address=0x401000, size=64, is_entry=True)]
    ctx.interesting_functions = list(ctx.entry_points)

    with patch("packages.binary_analysis.pipeline.analyse_binary_context", return_value=ctx):
        result = analyse_blackbox_binary(binary, out_dir=out)

    crashes_dir = out / "afl" / "main" / "crashes"
    crashes_dir.mkdir(parents=True)
    crash_path = crashes_dir / "id:000000,sig:11,src:000000,op:havoc"
    crash_path.write_bytes(b"boom")
    replay_binary = _write_binary(tmp_path / "sample_asan", b"\x7fELF" + b"\x00" * 128)
    replay_dir = out / "crash_analysis" / "replay"
    replay_dir.mkdir(parents=True)
    (replay_dir / "replay-summary.json").write_text(json.dumps({
        str(crash_path): [{
            "binary": str(replay_binary),
            "returncode": -11,
            "stdout": str(replay_dir / "stdout.log"),
            "stderr": str(replay_dir / "stderr.log"),
            "reproduced": True,
        }],
    }))
    (out / "fuzz-summary.json").write_text(json.dumps({
        "fuzzer": "afl++",
        "target": str(binary),
        "crashes": 1,
        "crashes_dir": str(crashes_dir),
        "total_executions": 1234,
        "coverage_percent": 12.5,
    }))

    bundle = append_fuzz_evidence_to_run(binary, out_dir=out)

    assert bundle is not None
    assert len(bundle.crashes) == 1
    assert bundle.crashes[0].signal == "11"
    assert bundle.crashes[0].replay_evidence_ids
    context_map = json.loads((out / "context-map.json").read_text())
    assert context_map["fuzz_witnesses"][0]["id"] == "BIN-CRASH-000000"
    checklist = json.loads((out / "binary-checklist.json").read_text())
    assert checklist["fuzz_witnesses"][0]["id"] == "BIN-CRASH-000000"
    evidence = json.loads((out / "binary-evidence.json").read_text())["evidence"]
    assert any(item["kind"] == "fuzz_crash" for item in evidence)
    assert any(item["kind"] == "crash_replay" and item["tier"] == "replayed_crash" for item in evidence)
    summary = graph_summary(result.graph_path)
    assert summary["nodes"]["crash_witness"] == 1
    assert summary["nodes"]["replay_binary"] == 1
    assert summary["edges"]["CRASHED_WITH"] == 1
    assert summary["edges"]["REPLAYED_ON"] == 1


def test_pipeline_surfaces_frida_observations_without_inventing_taint(tmp_path: Path) -> None:
    binary = _write_binary(tmp_path / "sample", b"\x7fELF" + b"\x00" * 128)
    out = tmp_path / "out"
    runtime_dir = _write_frida_run(tmp_path / "frida-run", binary)
    ctx = BinaryContextMap(binary_path=binary, arch="x86", bits=64, binary_format="elf")
    ctx.imports = ["sym.imp.recv"]

    with patch("packages.binary_analysis.pipeline.analyse_binary_context", return_value=ctx):
        result = analyse_blackbox_binary(binary, out_dir=out, runtime_dir=runtime_dir)

    assert result.context_map["unchecked_flows"] == []
    observation = result.context_map["runtime_observations"][0]
    assert observation["id"] == "BRT-OBS-001"
    assert observation["category"] == "network"
    assert observation["function"] == "recv"
    assert observation["count"] == 1
    assert observation["evidence_tier"] == "observed_runtime"
    assert observation["evidence_ids"]
    network = next(channel for channel in result.input_channels if channel.kind == "network")
    assert network.observed is True
    summary = graph_summary(result.graph_path)
    assert summary["nodes"]["runtime_observation"] == 1
    assert summary["edges"]["OBSERVED_RUNTIME"] == 1


def test_pipeline_binds_aslr_relative_runtime_callsites_to_functions(tmp_path: Path) -> None:
    binary = _write_binary(tmp_path / "sample", b"\x7fELF" + b"\x00" * 128)
    out = tmp_path / "out"
    runtime_dir = tmp_path / "frida-run"
    runtime_dir.mkdir()
    (runtime_dir / "metadata.json").write_text(json.dumps({
        "ok": True,
        "target": {"raw": str(binary), "kind": "binary", "binary": str(binary)},
    }))
    (runtime_dir / "events.jsonl").write_text(json.dumps({
        "type": "send",
        "payload": {
            "category": "network",
            "fn": "recv",
            "args": {"fd": 4},
            "caller": "0x700001005",
            "caller_offset": "0x1005",
        },
    }) + "\n")
    ctx = BinaryContextMap(binary_path=binary, arch="x86", bits=64, binary_format="elf", image_base=0x100000000)
    ctx.imports = ["sym.imp.recv"]
    ctx.interesting_functions = [FunctionInfo(name="parse_packet", address=0x100001000, size=0x40)]

    with patch("packages.binary_analysis.pipeline.analyse_binary_context", return_value=ctx):
        result = analyse_blackbox_binary(binary, out_dir=out, runtime_dir=runtime_dir)

    assert result.context_map["runtime_input_flows"][0]["function_name"] == "parse_packet"
    assert result.context_map["runtime_input_flows"][0]["caller_offsets"] == ["0x1005"]
    summary = graph_summary(result.graph_path)
    assert summary["edges"]["OBSERVED_CALLSITE"] == 1


def test_runtime_parser_callsite_strengthens_parser_boundary_candidate(tmp_path: Path) -> None:
    binary = _write_binary(tmp_path / "sample", b"\x7fELF" + b"\x00" * 128)
    out = tmp_path / "out"
    runtime_dir = tmp_path / "frida-run"
    runtime_dir.mkdir()
    (runtime_dir / "metadata.json").write_text(json.dumps({
        "ok": True,
        "target": {"raw": str(binary), "kind": "binary", "binary": str(binary)},
    }))
    (runtime_dir / "events.jsonl").write_text(json.dumps({
        "type": "send",
        "payload": {
            "category": "parser",
            "fn": "XML_Parse",
            "args": {"len": 42},
            "caller": "0x700001105",
            "caller_offset": "0x1105",
        },
    }) + "\n")
    ctx = BinaryContextMap(binary_path=binary, arch="x86", bits=64, binary_format="elf", image_base=0x100000000)
    main = FunctionInfo(name="main", address=0x100001000, size=0x40, is_entry=True, direct_callees=["parse_packet"])
    parser = FunctionInfo(name="parse_packet", address=0x100001100, size=0x40, direct_callees=["sym.imp.XML_Parse"])
    ctx.entry_points = [main]
    ctx.interesting_functions = [main, parser]
    ctx.imports = ["sym.imp.XML_Parse"]

    with patch("packages.binary_analysis.pipeline.analyse_binary_context", return_value=ctx):
        result = analyse_blackbox_binary(binary, out_dir=out, runtime_dir=runtime_dir)

    assert result.context_map["runtime_parser_flows"][0]["function_name"] == "parse_packet"
    boundary = result.context_map["parser_boundary_candidates"][0]
    assert boundary["boundary_function_name"] == "parse_packet"
    assert boundary["evidence_tier"] == "observed_runtime"
    assert boundary["confidence"] == "confirmed"
    summary = graph_summary(result.graph_path)
    assert summary["edges"]["OBSERVED_PARSER_CALLSITE"] == 1


def test_append_runtime_evidence_refreshes_existing_parser_boundary_run(tmp_path: Path) -> None:
    binary = _write_binary(tmp_path / "sample", b"\x7fELF" + b"\x00" * 128)
    out = tmp_path / "out"
    ctx = BinaryContextMap(binary_path=binary, arch="x86", bits=64, binary_format="elf", image_base=0x100000000)
    main = FunctionInfo(name="main", address=0x100001000, size=0x40, is_entry=True, direct_callees=["parse_packet"])
    parser = FunctionInfo(name="parse_packet", address=0x100001100, size=0x40, direct_callees=["sym.imp.XML_Parse"])
    ctx.entry_points = [main]
    ctx.interesting_functions = [main, parser]
    ctx.imports = ["sym.imp.XML_Parse"]

    with patch("packages.binary_analysis.pipeline.analyse_binary_context", return_value=ctx):
        initial = analyse_blackbox_binary(binary, out_dir=out)

    assert initial.context_map["parser_boundary_candidates"][0]["evidence_tier"] == "xref_backed"
    runtime_dir = tmp_path / "parser-runtime"
    runtime_dir.mkdir()
    (runtime_dir / "metadata.json").write_text(json.dumps({
        "ok": True,
        "target": {"raw": str(binary), "kind": "binary", "binary": str(binary)},
    }))
    (runtime_dir / "events.jsonl").write_text(json.dumps({
        "type": "send",
        "payload": {
            "category": "parser",
            "fn": "XML_Parse",
            "args": {"len": 42},
            "caller": "0x700001105",
            "caller_offset": "0x1105",
        },
    }) + "\n")

    refreshed = append_runtime_evidence_to_run(binary, out_dir=out, runtime_dir=runtime_dir)

    assert refreshed is not None
    assert refreshed.context_map["runtime_parser_flows"][0]["function_name"] == "parse_packet"
    assert refreshed.context_map["parser_boundary_candidates"][0]["confidence"] == "confirmed"
    assert refreshed.context_map["parser_boundary_candidates"][0]["evidence_tier"] == "observed_runtime"
    summary = graph_summary(refreshed.graph_path)
    assert summary["edges"]["OBSERVED_PARSER_CALLSITE"] == 1
    assert "Runtime parser callsites bound to recovered functions: 1" in (out / "binary-analysis-report.md").read_text()


def test_runtime_parser_backtrace_recovers_boundary_when_static_dispatch_is_missing(tmp_path: Path) -> None:
    binary = _write_binary(tmp_path / "sample", b"\xcf\xfa\xed\xfe" + b"\x00" * 128)
    out = tmp_path / "out"
    runtime_dir = tmp_path / "frida-run"
    runtime_dir.mkdir()
    (runtime_dir / "metadata.json").write_text(json.dumps({
        "ok": True,
        "target": {"raw": str(binary), "kind": "binary", "binary": str(binary)},
    }))
    (runtime_dir / "events.jsonl").write_text(json.dumps({
        "type": "send",
        "payload": {
            "category": "parser",
            "fn": "XML_Parse",
            "args": {"len": 42},
            "caller": "0x700001205",
            "caller_offset": "0x1205",
            "backtrace_frames": [
                {"address": "0x700001205", "module": "sample", "module_offset": "0x1205"},
                {"address": "0x700001005", "module": "sample", "module_offset": "0x1005"},
            ],
        },
    }) + "\n")
    ctx = BinaryContextMap(binary_path=binary, arch="arm64", bits=64, binary_format="mach0", image_base=0x100000000)
    callback = FunctionInfo(name="method.AppDelegate.application:openURLs:", address=0x100001000, size=0x40)
    parser = FunctionInfo(name="parse_payload", address=0x100001200, size=0x40, direct_callees=["sym.imp.XML_Parse"])
    ctx.interesting_functions = [callback, parser]
    ctx.imports = ["sym.imp.XML_Parse"]
    ctx.classes = [
        RecoveredClassInfo(
            name="Example.AppDelegate",
            address=0x100100000,
            methods=[
                RecoveredMethodInfo(
                    name="application:openURLs:",
                    address=callback.address,
                    bound_function_address=callback.address,
                    bound_function_name=callback.name,
                ),
            ],
        ),
    ]

    with patch("packages.binary_analysis.pipeline.analyse_binary_context", return_value=ctx):
        result = analyse_blackbox_binary(binary, out_dir=out, runtime_dir=runtime_dir)

    boundary = result.context_map["parser_boundary_candidates"][0]
    assert boundary["ingress_name"] == "Example.AppDelegate.application:openURLs:"
    assert boundary["boundary_function_name"] == "parse_payload"
    assert boundary["path"]["function_names"] == ["method.AppDelegate.application:openURLs:", "parse_payload"]
    assert boundary["evidence_tier"] == "observed_runtime"


def test_diff_is_explicitly_not_a_reachability_claim(tmp_path: Path) -> None:
    base_path = _write_binary(tmp_path / "base", b"\x7fELF" + b"\x00" * 80)
    head_path = _write_binary(tmp_path / "head", b"\x7fELF" + b"\x00" * 81)
    base_ctx = BinaryContextMap(binary_path=base_path, binary_format="elf")
    head_ctx = BinaryContextMap(binary_path=head_path, binary_format="elf")
    base_ctx.imports = ["sym.imp.read"]
    head_ctx.imports = ["sym.imp.read", "sym.imp.execve"]

    diff = diff_manifests(build_manifest(base_path, base_ctx), build_manifest(head_path, head_ctx))

    assert diff["bytes_changed"] is True
    assert diff["imports"]["added"] == ["execve"]
    assert "does not claim" in diff["interpretation"]


def test_pipeline_records_binary_diff_as_graph_evidence(tmp_path: Path) -> None:
    base_path = _write_binary(tmp_path / "base", b"\x7fELF" + b"\x00" * 80)
    head_path = _write_binary(tmp_path / "head", b"\x7fELF" + b"\x00" * 81)
    out = tmp_path / "out"
    base_ctx = BinaryContextMap(binary_path=base_path, binary_format="elf")
    head_ctx = BinaryContextMap(binary_path=head_path, binary_format="elf")
    base_ctx.imports = ["sym.imp.read"]
    head_ctx.imports = ["sym.imp.read", "sym.imp.execve"]

    def fake_context(path: Path, *args, **kwargs) -> BinaryContextMap:
        return base_ctx if Path(path).resolve() == base_path.resolve() else head_ctx

    with patch("packages.binary_analysis.pipeline.analyse_binary_context", side_effect=fake_context):
        result = analyse_blackbox_binary(head_path, out_dir=out, compare_binary=base_path)

    assert result.diff is not None
    assert result.diff["evidence_id"]
    evidence = json.loads((out / "binary-evidence.json").read_text())["evidence"]
    assert any(item["kind"] == "binary_diff" for item in evidence)
    summary = graph_summary(result.graph_path)
    assert summary["nodes"]["comparison_binary"] == 1
    assert summary["edges"]["DIFFED_AGAINST"] == 1


def test_constraint_file_only_checks_explicit_conditions(tmp_path: Path) -> None:
    path = tmp_path / "conditions.json"
    path.write_text(json.dumps({
        "profile": "int64",
        "conditions": ["declared_len > 2147483647"],
    }))
    with patch(
        "packages.binary_analysis.constraints.validate_path",
        return_value={"feasible": True, "model": {"declared_len": 2147483648}},
    ) as mocked:
        result, evidence = validate_constraint_file(path, binary_sha256="b" * 64)

    mocked.assert_called_once()
    assert result is not None
    assert result["result"]["feasible"] is True
    assert evidence[0].tool == "z3"
    assert evidence[0].tier.value == "smt_proved"


def test_append_fuzz_evidence_rejects_wrong_binary_binding(tmp_path: Path) -> None:
    binary = _write_binary(tmp_path / "sample", b"\x7fELF" + b"\x00" * 128)
    other = _write_binary(tmp_path / "other", b"\x7fELF" + b"\x01" * 128)
    out = tmp_path / "out"
    ctx = BinaryContextMap(binary_path=binary, arch="x86", bits=64, binary_format="elf")
    with patch("packages.binary_analysis.pipeline.analyse_binary_context", return_value=ctx):
        analyse_blackbox_binary(binary, out_dir=out)

    assert append_fuzz_evidence_to_run(other, out_dir=out) is None
