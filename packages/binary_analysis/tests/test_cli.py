"""Tests for the /binary operator surface."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

from core.hash import sha256_file
from packages.binary_analysis.cli import _build_parser, _normalise_argv, _print_report, main
from packages.binary_analysis.manifest import BinaryManifest
from packages.binary_analysis.pipeline import BinaryAnalysisResult


REPO_ROOT = Path(__file__).resolve().parents[3]
WRAPPER = REPO_ROOT / "libexec" / "raptor-binary"


def _make_result(
    binary: Path,
    context_map: dict,
    *,
    graph_path: Path | None = None,
) -> BinaryAnalysisResult:
    manifest = BinaryManifest(
        schema_version=1,
        binary_path=str(binary),
        binary_sha256="a" * 64,
        size_bytes=binary.stat().st_size,
        executable=True,
        target_kind="elf",
        arch="x86",
        bits=64,
        binary_format="elf",
    )
    return BinaryAnalysisResult(
        manifest=manifest,
        context_map=context_map,
        evidence=[],
        input_channels=[],
        graph_path=graph_path or binary.parent / "graph" / "binary-graph.sqlite",
    )


def test_normalise_defaults_bare_path_to_investigate() -> None:
    assert _normalise_argv(["/tmp/app"]) == ["investigate", "/tmp/app"]
    assert _normalise_argv([]) == ["help"]


def test_fuzz_subcommand_keeps_follow_on_args() -> None:
    args = _build_parser().parse_args(["fuzz", "/tmp/app", "--duration", "60", "--plan-only"])
    assert args.target == "/tmp/app"
    assert args.fuzz_args == ["--duration", "60", "--plan-only"]


def test_harness_subcommand_accepts_contract_flags() -> None:
    args = _build_parser().parse_args([
        "harness",
        "/tmp/run",
        "--ingress",
        "BINGRESS-001",
        "--abi",
        "buffer-size",
        "--device",
        "/dev/demo",
        "--ioctl-code",
        "0x1234",
    ])
    assert args.run_dir == "/tmp/run"
    assert args.ingress == "BINGRESS-001"
    assert args.abi == "buffer-size"
    assert args.device == "/dev/demo"
    assert args.ioctl_code == "0x1234"


def test_investigate_accepts_explicit_active_flags() -> None:
    args = _build_parser().parse_args([
        "investigate",
        "/tmp/app",
        "--active",
        "--runtime-duration",
        "12",
        "--fuzz-duration",
        "34",
    ])
    assert args.active is True
    assert args.runtime_duration == 12
    assert args.fuzz_duration == 34


def test_trace_parser_subcommand_accepts_runtime_flags() -> None:
    args = _build_parser().parse_args([
        "trace-parser",
        "/tmp/run",
        "--duration",
        "12",
        "--spawn",
        "--unsafe-attach",
        "--host",
        "127.0.0.1:27042",
    ])
    assert args.run_dir == "/tmp/run"
    assert args.duration == 12
    assert args.spawn is True
    assert args.unsafe_attach is True
    assert args.host == "127.0.0.1:27042"


def test_map_writes_operator_result_and_lifecycle(tmp_path: Path, capsys) -> None:
    binary = tmp_path / "sample"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 32)
    binary.chmod(0o755)
    out = tmp_path / "out"
    result = _make_result(binary, {
        "entry_points": [{"id": "BEP-1", "name": "main"}],
        "sink_details": [],
        "surface_details": [],
        "candidate_flows": [],
        "framework_callback_candidates": [],
        "class_inventory": {"summary": {"class_count": 0}},
        "decompilations": {"coverage": {"decompiled_functions": 0}},
    }, graph_path=out / "graph" / "binary-graph.sqlite")

    with (
        patch("packages.binary_analysis.cli.analyse_blackbox_binary", return_value=result),
        patch("packages.binary_analysis.cli.start_run") as start_run,
        patch("packages.binary_analysis.cli.complete_run") as complete_run,
    ):
        rc = main(["map", str(binary), "--out", str(out)])

    assert rc == 0
    start_run.assert_called_once_with(out.resolve(), "understand", target=str(binary.resolve()))
    complete_run.assert_called_once_with(out.resolve())
    payload = json.loads((out / "map-result.json").read_text())
    assert payload["mode"] == "map"
    assert payload["correlation"]["summary"]["entry_point_candidates"] == 1
    stdout = capsys.readouterr().out
    assert "mechanical binary substrate" in stdout
    assert "Handoff:" in stdout


def test_trace_parser_refreshes_existing_investigation_run(tmp_path: Path, capsys) -> None:
    binary = tmp_path / "sample"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 32)
    binary.chmod(0o755)
    run_dir = tmp_path / "out"
    run_dir.mkdir()
    manifest = BinaryManifest(
        schema_version=1,
        binary_path=str(binary.resolve()),
        # Real digest: trace-parser verifies content identity before
        # executing the mapped binary.
        binary_sha256=sha256_file(binary),
        size_bytes=binary.stat().st_size,
        executable=True,
        target_kind="elf",
        arch="x86",
        bits=64,
        binary_format="elf",
    )
    (run_dir / "binary-manifest.json").write_text(json.dumps(manifest.to_dict()))
    (run_dir / "map-result.json").write_text(json.dumps({"mode": "investigate"}))
    (run_dir / "binary-investigation.json").write_text(json.dumps({
        "active_phases": [{"kind": "runtime", "status": "completed"}],
    }))
    result = BinaryAnalysisResult(
        manifest=manifest,
        context_map={
            "entry_points": [],
            "sink_details": [],
            "surface_details": [],
            "candidate_flows": [],
            "framework_callback_candidates": [],
            "runtime_parser_flows": [{"id": "BRPF-1"}],
            "parser_boundary_candidates": [{"id": "BPARSER-1"}],
            "class_inventory": {"summary": {"class_count": 0}},
            "decompilations": {"coverage": {"decompiled_functions": 0}},
        },
        evidence=[],
        input_channels=[],
        graph_path=run_dir / "graph" / "binary-graph.sqlite",
    )
    phase = {
        "kind": "parser_trace",
        "status": "completed",
        "returncode": 0,
        "output_dir": str(run_dir / "parser-runtime"),
        "stdout": str(run_dir / "parser-runtime" / "stdout.log"),
        "stderr": str(run_dir / "parser-runtime" / "stderr.log"),
        "command": ["raptor-frida"],
    }
    investigation = {"status": "runtime_observed_but_not_validated"}

    with (
        patch("packages.binary_analysis.cli._run_active_phase", return_value=phase) as run_active,
        patch("packages.binary_analysis.cli.append_runtime_evidence_to_run", return_value=result) as append_runtime,
        patch("packages.binary_analysis.cli.write_investigation", return_value=investigation) as write_investigation,
    ):
        rc = main(["trace-parser", str(run_dir), "--duration", "12"])

    assert rc == 0
    cmd = run_active.call_args.kwargs["cmd"]
    assert cmd[:5] == [
        str(REPO_ROOT / "libexec" / "raptor-frida"),
        "--target",
        str(binary.resolve()),
        "--template",
        "binary-flow-trace",
    ]
    assert "--out" in cmd
    append_runtime.assert_called_once_with(
        binary.resolve(),
        out_dir=run_dir.resolve(),
        runtime_dir=run_dir.resolve() / "parser-runtime",
    )
    assert write_investigation.call_args.kwargs["active_phases"] == [
        {"kind": "runtime", "status": "completed"},
        phase,
    ]
    payload = json.loads((run_dir / "map-result.json").read_text())
    assert payload["mode"] == "investigate"
    assert "binary_investigation" in payload["artifacts"]
    stdout = capsys.readouterr().out
    assert "Mode: trace-parser" in stdout
    assert "Parser boundary candidates: 1" in stdout


def _write_trace_parser_run(tmp_path: Path, *, sha: str) -> tuple[Path, Path]:
    binary = tmp_path / "sample"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 32)
    binary.chmod(0o755)
    run_dir = tmp_path / "out"
    run_dir.mkdir()
    manifest = BinaryManifest(
        schema_version=1,
        binary_path=str(binary.resolve()),
        binary_sha256=sha,
        size_bytes=binary.stat().st_size,
        executable=True,
        target_kind="elf",
        arch="x86",
        bits=64,
        binary_format="elf",
    )
    (run_dir / "binary-manifest.json").write_text(json.dumps(manifest.to_dict()))
    return binary, run_dir


def test_trace_parser_refuses_swapped_binary_before_execution(
    tmp_path: Path, capsys,
) -> None:
    # The file at the manifest path changed since the map run: refuse
    # BEFORE the Frida phase would spawn it — the post-hoc evidence gate
    # is too late to prevent execution.
    _, run_dir = _write_trace_parser_run(tmp_path, sha="b" * 64)

    with patch("packages.binary_analysis.cli._run_active_phase") as run_active:
        rc = main(["trace-parser", str(run_dir)])

    assert rc == 2
    run_active.assert_not_called()
    err = capsys.readouterr().err
    assert "refusing to execute" in err


def test_trace_parser_matching_hash_reaches_frida_phase(tmp_path: Path) -> None:
    binary, run_dir = _write_trace_parser_run(tmp_path, sha="")
    manifest_payload = json.loads((run_dir / "binary-manifest.json").read_text())
    manifest_payload["binary_sha256"] = sha256_file(binary)
    (run_dir / "binary-manifest.json").write_text(json.dumps(manifest_payload))
    failed_phase = {
        "kind": "parser_trace",
        "status": "failed",
        "returncode": 1,
        "output_dir": str(run_dir / "parser-runtime"),
        "stdout": str(run_dir / "parser-runtime" / "stdout.log"),
        "stderr": str(run_dir / "parser-runtime" / "stderr.log"),
        "command": ["raptor-frida"],
    }

    with patch(
        "packages.binary_analysis.cli._run_active_phase",
        return_value=failed_phase,
    ) as run_active:
        rc = main(["trace-parser", str(run_dir)])

    # The gate passed (phase invoked); the stubbed phase failure is the
    # exit path — no real execution happens in this test.
    run_active.assert_called_once()
    assert rc == 1


def test_corpus_subcommand_accepts_flags() -> None:
    args = _build_parser().parse_args([
        "corpus",
        "/tmp/samples",
        "--family",
        "*.sys",
        "--max-samples",
        "100",
        "--max-bytes-per-sample",
        "4096",
        "--out",
        "/tmp/out",
    ])
    assert args.samples_dir == "/tmp/samples"
    assert args.family == "*.sys"
    assert args.max_samples == 100
    assert args.max_bytes_per_sample == 4096
    assert args.out == "/tmp/out"


def test_corpus_writes_profile_and_lifecycle(tmp_path: Path, capsys) -> None:
    corpus = tmp_path / "samples"
    corpus.mkdir()
    for i in range(4):
        (corpus / f"s{i}.dat").write_bytes(b"MAGX" + bytes([i]) * 40)
    out = tmp_path / "out"

    with (
        patch("packages.binary_analysis.cli.start_run") as start_run,
        patch("packages.binary_analysis.cli.complete_run") as complete_run,
    ):
        rc = main(["corpus", str(corpus), "--out", str(out)])

    assert rc == 0
    start_run.assert_called_once_with(out.resolve(), "understand", target=str(corpus.resolve()))
    complete_run.assert_called_once_with(out.resolve())
    payload = json.loads((out / "format-profile.json").read_text())
    assert payload["summary"]["samples_profiled"] == 4
    assert (out / "format-profile.md").is_file()
    stdout = capsys.readouterr().out
    assert "Mode: corpus" in stdout
    assert "mechanical byte statistics" in stdout


def test_corpus_rejects_missing_directory(tmp_path: Path) -> None:
    rc = main(["corpus", str(tmp_path / "nope")])
    assert rc == 2


def test_corpus_summary_scrubs_hostile_family_keys(tmp_path: Path, capsys) -> None:
    corpus = tmp_path / "samples"
    corpus.mkdir()
    # Attacker-chosen names ride into the family key (extension +
    # template) — the terminal summary must render them inert.
    for i in range(3):
        (corpus / f"evil\x1b]0;pwn{i}\x07.b\x1bd").write_bytes(b"MAGY" + bytes([i]) * 30)
    out = tmp_path / "out"
    with (
        patch("packages.binary_analysis.cli.start_run"),
        patch("packages.binary_analysis.cli.complete_run"),
    ):
        rc = main(["corpus", str(corpus), "--out", str(out)])
    assert rc == 0
    stdout = capsys.readouterr().out
    assert "\x1b" not in stdout
    assert "\x07" not in stdout


def test_wrapper_help_is_available() -> None:
    env = os.environ.copy()
    env["_RAPTOR_TRUSTED"] = "1"
    proc = subprocess.run(
        [sys.executable, str(WRAPPER), "--help"],
        capture_output=True,
        text=True,
        timeout=15,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    assert "raptor-binary" in proc.stdout
    assert "investigate" in proc.stdout
    assert "runtime" in proc.stdout
    assert "trace-parser" in proc.stdout
    assert "harness" in proc.stdout
    assert "handoff" in proc.stdout


def test_report_prefers_investigation_report(tmp_path: Path, capsys) -> None:
    (tmp_path / "binary-analysis-report.md").write_text("map report\n")
    (tmp_path / "binary-investigation-report.md").write_text("investigation report\n")

    assert _print_report(str(tmp_path)) == 0
    assert capsys.readouterr().out == "investigation report\n"


def test_report_print_scrubs_terminal_escapes(tmp_path: Path, capsys) -> None:
    # Last line of defence: even if a report artifact carries raw
    # control bytes (older run, hand-edited file), the terminal print
    # must escape them.
    (tmp_path / "binary-analysis-report.md").write_text(
        "before\x1b]0;pwn\x07after\n",
    )
    assert _print_report(str(tmp_path)) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out
    assert "before" in out and "after" in out
    assert out.endswith("\n")


def test_investigation_summary_scrubs_hostile_names_and_commands(capsys) -> None:
    """Every summary field derived from the analysed binary — names AND
    the priority-queue commands (which embed shlex.quote()d artifact
    paths; quoting preserves control bytes) — must reach the terminal
    scrubbed."""
    from packages.binary_analysis.cli import _print_investigation_summary

    investigation = {
        "status": "static_only",
        "summary": {
            "surface_candidates": 1,
            "candidate_flows": 0,
            "ranked_ingress": 1,
            "runtime_input_flows": 0,
            "fuzz_witnesses": 0,
            "discovered_artifacts": 0,
        },
        "ranked_surfaces": [{
            "name": "parse\x1b[2Jbuf", "category": "parser",
            "direct_callers": 2,
        }],
        "ranked_ingress": [{
            "name": "recv\x1b]0;pwn\x07loop", "kind": "socket",
            "boundary": "network\x1b[8m",
        }],
        "ranked_parser_boundaries": [{
            "boundary_function_name": "read\x1bcfg",
            "parser_surface_name": "parse\x07hdr",
            "ingress_name": "recv\x1b[1mloop",
            "path": {"depth": 2},
        }],
        "priority_queue": [{
            "command": "raptor-binary fuzz 'evil\x1b]0;pwned\x07.bin'",
        }],
    }
    _print_investigation_summary(investigation, Path("/nonexistent-out"))
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out
    assert "raptor-binary fuzz" in out


def test_investigate_active_does_not_fuzz_whole_app_without_harness_boundary(tmp_path: Path) -> None:
    binary = tmp_path / "sample"
    binary.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 32)
    binary.chmod(0o755)
    out = tmp_path / "out"
    result = _make_result(binary, {
        "entry_points": [],
        "sink_details": [],
        "surface_details": [],
        "candidate_flows": [],
        "framework_callback_candidates": [],
        "class_inventory": {"summary": {"class_count": 0}},
        "decompilations": {"coverage": {"decompiled_functions": 0}},
        "fuzz_suitability": {
            "strategy": "extract_harness_from_ingress",
            "reason": "Whole GUI process is not a sensible fuzz boundary.",
            "direct_campaign_recommended": False,
            "should_run_fuzz_plan": False,
        },
    }, graph_path=out / "graph" / "binary-graph.sqlite")
    investigation = {
        "status": "static_only",
        "summary": {
            "surface_candidates": 0,
            "candidate_flows": 0,
            "ranked_ingress": 0,
            "runtime_input_flows": 0,
            "fuzz_witnesses": 0,
            "discovered_artifacts": 0,
        },
        "ranked_surfaces": [],
        "ranked_ingress": [],
        "priority_queue": [],
    }

    with (
        patch("packages.binary_analysis.cli.analyse_blackbox_binary", return_value=result),
        patch("packages.binary_analysis.cli.write_investigation", return_value=investigation) as write_investigation,
        patch("packages.binary_analysis.cli._run_active_phase") as run_active,
        patch("packages.binary_analysis.cli.start_run"),
        patch("packages.binary_analysis.cli.complete_run"),
    ):
        rc = main(["investigate", str(binary), "--fuzz", "--out", str(out)])

    assert rc == 0
    run_active.assert_not_called()
    active_phases = write_investigation.call_args.kwargs["active_phases"]
    assert active_phases[0]["kind"] == "fuzz"
    assert active_phases[0]["status"] == "skipped"


def test_investigate_active_does_not_try_frida_against_driver_file(tmp_path: Path) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ" + b"\x00" * 32)
    binary.chmod(0o755)
    out = tmp_path / "out"
    result = _make_result(binary, {
        "entry_points": [],
        "sink_details": [],
        "surface_details": [],
        "candidate_flows": [],
        "framework_callback_candidates": [],
        "class_inventory": {"summary": {"class_count": 0}},
        "decompilations": {"coverage": {"decompiled_functions": 0}},
        "fuzz_suitability": {
            "strategy": "snapshot_or_ioctl_harness",
            "runtime_strategy": "kernel_harness_required",
            "runtime_reason": "Drivers need a kernel harness.",
            "reason": "Drivers need a snapshot or IOCTL harness.",
            "direct_campaign_recommended": False,
            "should_run_fuzz_plan": False,
        },
    }, graph_path=out / "graph" / "binary-graph.sqlite")
    investigation = {
        "status": "static_only",
        "summary": {
            "surface_candidates": 0,
            "candidate_flows": 0,
            "ranked_ingress": 0,
            "runtime_input_flows": 0,
            "fuzz_witnesses": 0,
            "discovered_artifacts": 0,
        },
        "ranked_surfaces": [],
        "ranked_ingress": [],
        "priority_queue": [],
    }

    with (
        patch("packages.binary_analysis.cli.analyse_blackbox_binary", return_value=result),
        patch("packages.binary_analysis.cli.write_investigation", return_value=investigation) as write_investigation,
        patch("packages.binary_analysis.cli._run_active_phase") as run_active,
        patch("packages.binary_analysis.cli.start_run"),
        patch("packages.binary_analysis.cli.complete_run"),
    ):
        rc = main(["investigate", str(binary), "--runtime", "--out", str(out)])

    assert rc == 0
    run_active.assert_not_called()
    active_phases = write_investigation.call_args.kwargs["active_phases"]
    assert active_phases[0]["kind"] == "runtime"
    assert active_phases[0]["status"] == "skipped"


def test_print_file_json_lane_ascii_encodes_c1(tmp_path, capsys) -> None:
    """--json artifact relay: bare JSON escapes C0 but passes C1
    terminal controls (single-byte CSI/OSC) raw — the lane must
    ASCII-encode while staying valid JSON."""
    from packages.binary_analysis.cli import _print_file

    hostile = "sym\x9b2J\x9d0;pwn\x1b]t\x07‮x"
    (tmp_path / "graph.json").write_text(
        json.dumps({"nodes": [{"name": hostile}]}, ensure_ascii=False),
        encoding="utf-8",
    )
    rc = _print_file(str(tmp_path), "graph.json", json_output=True)
    assert rc == 0
    out = capsys.readouterr().out
    for raw in ("\x1b", "\x07", "\x9b", "\x9d", "‮"):
        assert raw not in out
    assert json.loads(out)["nodes"][0]["name"] == hostile  # intact


class TestRunActivePhaseStreaming:
    """_run_active_phase streams child output to the log files —
    capture_output buffered an hour-long fuzz/frida child's whole
    stdout+stderr in this process's memory before writing them."""

    def test_output_streams_to_log_files(self, tmp_path):
        from packages.binary_analysis.cli import _run_active_phase

        phase = _run_active_phase(
            kind="probe",
            cmd=[sys.executable, "-c",
                 "import sys; print('to-out'); print('to-err', file=sys.stderr)"],
            output_dir=tmp_path / "phase",
        )
        assert phase["status"] == "completed"
        assert "to-out" in Path(phase["stdout"]).read_text()
        assert "to-err" in Path(phase["stderr"]).read_text()

    def test_child_output_never_buffered_in_memory(self, tmp_path):
        import packages.binary_analysis.cli as cli_mod
        from packages.binary_analysis.cli import _run_active_phase

        seen = {}
        real_run = cli_mod.subprocess.run

        def spying_run(cmd, **kwargs):
            seen.update(kwargs)
            return real_run(cmd, **kwargs)

        with patch.object(cli_mod.subprocess, "run", spying_run):
            _run_active_phase(
                kind="probe",
                cmd=[sys.executable, "-c", "print('x')"],
                output_dir=tmp_path / "phase",
            )
        assert not seen.get("capture_output"), (
            "child output must stream to the log files, not buffer "
            "in memory")
        assert hasattr(seen.get("stdout"), "write")
        assert hasattr(seen.get("stderr"), "write")

    def test_failure_appends_error_after_partial_output(self, tmp_path):
        import packages.binary_analysis.cli as cli_mod
        from packages.binary_analysis.cli import _run_active_phase

        def exploding_run(cmd, **kwargs):
            kwargs["stderr"].write("partial diagnostics\n")
            raise subprocess.TimeoutExpired(cmd, 1)

        with patch.object(cli_mod.subprocess, "run", exploding_run):
            phase = _run_active_phase(
                kind="probe",
                cmd=["whatever"],
                output_dir=tmp_path / "phase",
            )
        assert phase["status"] == "failed"
        text = Path(phase["stderr"]).read_text()
        assert "partial diagnostics" in text
        assert "TimeoutExpired" in text

    def test_failure_message_scrubs_target_influenced_bytes(self, tmp_path):
        """Exception text echoes the child's argv/paths — a hostile
        filename rides e.g. TimeoutExpired's message, so the appended
        error line gets the terminal-grade scrub like every other exc
        interpolation in this module."""
        import packages.binary_analysis.cli as cli_mod

        def exploding_run(cmd, **kwargs):
            raise subprocess.TimeoutExpired(
                ["fuzz", "/tmp/evil\x1b]0;pwn\x07.bin"], 1)

        with patch.object(cli_mod.subprocess, "run", exploding_run):
            phase = cli_mod._run_active_phase(
                kind="probe",
                cmd=["whatever"],
                output_dir=tmp_path / "phase",
            )
        text = Path(phase["stderr"]).read_text()
        assert "\x1b" not in text and "\x07" not in text
        assert "\x1b" not in phase["error"]
        assert "TimeoutExpired" in text
