"""Operator CLI for evidence-backed black-box binary work.

This is the human-facing router behind ``/binary`` and ``raptor.py binary``.
It keeps the substrate mechanical:

- ``map`` reads bytes and radare2 output only.
- ``runtime`` is an explicit Frida run.
- ``harness`` turns one evidence-backed ingress into a harness plan.
- ``fuzz`` is an explicit handoff to the existing fuzz workflow.
- ``graph`` / ``report`` / ``handoff`` / ``diagram`` are read-only views.

The CLI does not silently execute an unknown target during ``map``.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

sys.path.insert(0, os.environ.get("RAPTOR_DIR", str(Path(__file__).resolve().parents[2])))

from core.config import RaptorConfig
from core.json import load_json, save_json
from core.run.metadata import complete_run, fail_run, start_run
from core.run.output import TargetMismatchError, get_output_dir

from packages.binary_analysis.investigation import write_investigation
from packages.binary_analysis.harness import generate_binary_harness
from packages.binary_analysis.manifest import BinaryManifest
from packages.binary_analysis.pipeline import map_result_payload
from packages.binary_analysis.pipeline import analyse_blackbox_binary, append_runtime_evidence_to_run

_COMMANDS = {
    "investigate",
    "map",
    "runtime",
    "trace-parser",
    "harness",
    "fuzz",
    "graph",
    "report",
    "handoff",
    "diagram",
    "help",
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _normalise_argv(argv: Sequence[str]) -> list[str]:
    args = list(argv)
    if not args:
        return ["help"]
    if args[0] in {"-h", "--help"}:
        return ["help"]
    if args[0] not in _COMMANDS and not args[0].startswith("-"):
        return ["investigate", *args]
    return args


def _positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return number


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="raptor-binary",
        description="Evidence-backed black-box binary understanding and follow-on evidence collection.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("help", help="Show this help")

    investigate_p = sub.add_parser("investigate", help="Run an autonomous evidence-first binary investigation")
    _add_map_args(investigate_p)
    investigate_p.add_argument("--runtime", action="store_true", help="Explicitly run a Frida evidence phase before the final map")
    investigate_p.add_argument("--fuzz", action="store_true", help="Explicitly run a short fuzz phase before the final map")
    investigate_p.add_argument("--active", action="store_true", help="Explicitly allow both runtime and fuzz phases")
    investigate_p.add_argument("--runtime-duration", type=_positive_int, default=30, help="Seconds for --runtime/--active Frida phase")
    investigate_p.add_argument("--fuzz-duration", type=_positive_int, default=60, help="Seconds for --fuzz/--active fuzz phase")

    map_p = sub.add_parser("map", help="Build a static binary map and graph")
    _add_map_args(map_p)

    runtime_p = sub.add_parser("runtime", help="Collect explicit Frida input-callsite evidence")
    runtime_p.add_argument("target", help="Binary, process name, bundle id or PID")
    _add_trace_args(runtime_p, include_out=True)

    trace_parser_p = sub.add_parser(
        "trace-parser",
        help="Run parser-focused Frida tracing and refresh an existing binary run",
    )
    trace_parser_p.add_argument("run_dir", help="Existing /binary investigate or map output directory")
    _add_trace_args(trace_parser_p, include_out=False)

    harness_p = sub.add_parser("harness", help="Plan or generate a candidate harness for one recovered ingress")
    harness_p.add_argument("run_dir", help="Existing /binary investigate or map output directory")
    harness_p.add_argument("--ingress", help="Ingress id to target; defaults to the highest-ranked ingress")
    harness_p.add_argument("--abi", choices=["buffer-size", "cstring"], help="Operator-supplied ABI shape for exported APIs")
    harness_p.add_argument("--device", help="Operator-supplied device path for ioctl harnesses")
    harness_p.add_argument("--ioctl-code", help="Operator-supplied ioctl/control code, for example 0x222003")
    harness_p.add_argument("--json", action="store_true", help="Emit compact JSON")

    fuzz_p = sub.add_parser("fuzz", help="Hand off to RAPTOR's existing fuzz workflow")
    fuzz_p.add_argument("target", help="Binary to fuzz")
    fuzz_p.add_argument("fuzz_args", nargs=argparse.REMAINDER, help="Additional /fuzz arguments")

    graph_p = sub.add_parser("graph", help="Query the binary graph")
    graph_p.add_argument("run_dir", help="Binary map output directory")
    graph_p.add_argument("--edges", action="store_true", help="List graph edges")
    graph_p.add_argument("--evidence", action="store_true", help="List evidence records")
    graph_p.add_argument("--kind", help="Filter graph edges by kind")
    graph_p.add_argument("--tier", help="Filter evidence by tier")
    graph_p.add_argument("--json", action="store_true", help="Emit JSON")

    report_p = sub.add_parser("report", help="Print the investigation report, or the map report when no investigation exists")
    report_p.add_argument("run_dir", help="Binary map output directory")

    handoff_p = sub.add_parser("handoff", help="Print the validation handoff JSON")
    handoff_p.add_argument("run_dir", help="Binary map output directory")
    handoff_p.add_argument("--json", action="store_true", help="Emit compact JSON instead of pretty JSON")

    diagram_p = sub.add_parser("diagram", help="Render diagrams from a binary map run")
    diagram_p.add_argument("run_dir", help="Binary map output directory")
    diagram_p.add_argument("--target", help="Display name to use in the diagram heading")
    diagram_p.add_argument("--stdout", action="store_true", help="Print diagrams rather than writing diagrams.md")
    diagram_p.add_argument("--force", action="store_true", help="Overwrite an existing diagrams.md")

    return parser


def _add_map_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("target", help="Binary or compiled application executable")
    parser.add_argument("--out", help="Explicit output directory")
    parser.add_argument("--quick", action="store_true", help="Header/import intake only; skip deep radare2 analysis")
    parser.add_argument("--slice-arch", help="Mach-O slice to deeply analyse, for example arm64 or x86_64")
    parser.add_argument("--max-decompile", type=_positive_int, default=20, help="Maximum functions to decompile and persist")
    parser.add_argument("--decompile-all", action="store_true", help="Persist pseudocode for every recovered function")
    parser.add_argument("--runtime-dir", help="Existing /binary runtime or /frida run to ingest")
    parser.add_argument("--fuzz-dir", help="Existing /binary fuzz or /fuzz run to ingest")
    parser.add_argument("--constraint-file", help="JSON file containing explicit SMT path conditions")
    parser.add_argument("--compare", help="Older compiled artefact to compare against")


def _add_trace_args(parser: argparse.ArgumentParser, *, include_out: bool) -> None:
    parser.add_argument("--duration", type=_positive_int, default=30, help="Seconds to trace (default: 30)")
    if include_out:
        parser.add_argument("--out", help="Explicit Frida output directory")
    parser.add_argument("--spawn", action="store_true", help="Force spawn-and-attach")
    parser.add_argument("--unsafe-attach", action="store_true", help="Allow attach mode outside the sandbox")
    parser.add_argument("--host", help="Remote frida-server host[:port]")
    parser.add_argument("--usb", action="store_true", help="Use the first USB-connected device")



def _print_map_summary(payload: dict[str, Any], output_path: Path) -> None:
    summary = payload["correlation"]["summary"]
    print("Mode: map")
    print("Models: none (mechanical binary substrate)")
    print(f"Items: {len(payload['items'])}")
    print("Summary: " + " | ".join(f"{key}={summary[key]}" for key in sorted(summary)))
    print(f"Output: {output_path}")
    print(f"Report: {output_path.parent / 'binary-analysis-report.md'}")
    print(f"Handoff: {payload['artifacts']['binary_validation_handoff']}")
    print(f"Graph: {payload['artifacts']['binary_graph']}")


def _resolve_target_and_out(args: argparse.Namespace) -> tuple[Path, Path] | None:
    target = Path(args.target).expanduser().resolve()
    if not target.exists() or not target.is_file():
        print(f"raptor-binary: target is not a file: {target}", file=sys.stderr)
        return None
    try:
        out_dir = get_output_dir(
            "understand",
            target_name=target.stem,
            explicit_out=args.out,
            target_path=str(target),
        )
    except TargetMismatchError as exc:
        print(f"raptor-binary: {exc}", file=sys.stderr)
        return None
    return target, out_dir


def _analyse_for_args(args: argparse.Namespace, target: Path, out_dir: Path) -> Any:
    return analyse_blackbox_binary(
        target,
        out_dir=out_dir,
        quick=bool(args.quick),
        max_decompile=(1_000_000 if args.decompile_all else args.max_decompile),
        slice_arch=args.slice_arch,
        runtime_dir=Path(args.runtime_dir).expanduser().resolve() if args.runtime_dir else None,
        fuzz_dir=Path(args.fuzz_dir).expanduser().resolve() if args.fuzz_dir else None,
        constraint_file=Path(args.constraint_file).expanduser().resolve() if args.constraint_file else None,
        compare_binary=Path(args.compare).expanduser().resolve() if args.compare else None,
    )


def _run_map(args: argparse.Namespace) -> int:
    resolved = _resolve_target_and_out(args)
    if resolved is None:
        return 2
    target, out_dir = resolved

    start_run(out_dir, "understand", target=str(target))
    try:
        result = _analyse_for_args(args, target, out_dir)
        payload = map_result_payload(result, out_dir)
        output_path = out_dir / "map-result.json"
        save_json(output_path, payload)
        complete_run(out_dir)
    except KeyboardInterrupt:
        fail_run(out_dir, "binary map interrupted")
        raise
    except Exception as exc:  # noqa: BLE001 - operator-facing clean failure
        fail_run(out_dir, f"binary map failed: {type(exc).__name__}: {exc}")
        print(f"raptor-binary: map failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    _print_map_summary(payload, output_path)
    return 0


def _run_active_phase(
    *,
    kind: str,
    cmd: list[str],
    output_dir: Path,
    trusted: bool = False,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = output_dir / "stdout.log"
    stderr_path = output_dir / "stderr.log"
    try:
        env = RaptorConfig.get_safe_env()
        if trusted:
            env.setdefault("_RAPTOR_TRUSTED", "1")
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        stdout_path.write_text(proc.stdout or "", encoding="utf-8")
        stderr_path.write_text(proc.stderr or "", encoding="utf-8")
        return {
            "kind": kind,
            "status": "completed" if proc.returncode == 0 else "failed",
            "returncode": proc.returncode,
            "output_dir": str(output_dir),
            "stdout": str(stdout_path),
            "stderr": str(stderr_path),
            "command": cmd,
        }
    except Exception as exc:  # noqa: BLE001 - report phase failure, keep static map useful
        stderr_path.write_text(f"{type(exc).__name__}: {exc}\n", encoding="utf-8")
        return {
            "kind": kind,
            "status": "failed",
            "returncode": None,
            "output_dir": str(output_dir),
            "stdout": str(stdout_path),
            "stderr": str(stderr_path),
            "command": cmd,
            "error": f"{type(exc).__name__}: {exc}",
        }


def _print_investigation_summary(investigation: dict[str, Any], out_dir: Path) -> None:
    summary = investigation["summary"]
    print("Mode: investigate")
    print(f"Status: {investigation['status']}")
    print(
        "Summary: "
        f"surfaces={summary['surface_candidates']} | "
        f"flows={summary['candidate_flows']} | "
        f"ingress={summary['ranked_ingress']} | "
        f"parser_boundaries={summary.get('parser_boundary_candidates', 0)} | "
        f"runtime_flows={summary['runtime_input_flows']} | "
        f"fuzz_witnesses={summary['fuzz_witnesses']} | "
        f"sibling_artifacts={summary['discovered_artifacts']}"
    )
    leads = investigation.get("ranked_surfaces") or []
    ingress = investigation.get("ranked_ingress") or []
    parser_boundaries = investigation.get("ranked_parser_boundaries") or []
    if ingress:
        print("Top ingress:")
        for item in ingress[:3]:
            print(
                f"  - {item['name']} "
                f"({item['kind']}, boundary={item['boundary']})"
            )
    if leads:
        print("Top leads:")
        for item in leads[:3]:
            print(
                f"  - {item['name']} "
                f"({item['category']}, direct_callers={item['direct_callers']})"
            )
    if parser_boundaries:
        print("Top parser boundaries:")
        for item in parser_boundaries[:3]:
            print(
                f"  - {item['boundary_function_name']} -> {item['parser_surface_name']} "
                f"(ingress={item['ingress_name']}, depth={item['path']['depth']})"
            )
    actions = investigation.get("priority_queue") or []
    if actions:
        print("Next actions:")
        for item in actions[:3]:
            print(f"  - {item['command']}")
    print(f"Output: {out_dir}")
    print(f"Investigation report: {out_dir / 'binary-investigation-report.md'}")
    print(f"Investigation JSON: {out_dir / 'binary-investigation.json'}")


def _skipped_phase(kind: str, output_dir: Path, reason: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "status": "skipped",
        "returncode": None,
        "output_dir": str(output_dir),
        "stdout": "",
        "stderr": "",
        "command": [],
        "reason": reason,
    }


def _run_investigate(args: argparse.Namespace) -> int:
    resolved = _resolve_target_and_out(args)
    if resolved is None:
        return 2
    target, out_dir = resolved
    if args.runtime_dir and (args.runtime or args.active):
        print("raptor-binary: --runtime-dir cannot be combined with --runtime/--active", file=sys.stderr)
        return 2
    if args.fuzz_dir and (args.fuzz or args.active):
        print("raptor-binary: --fuzz-dir cannot be combined with --fuzz/--active", file=sys.stderr)
        return 2

    start_run(out_dir, "understand", target=str(target))
    active_phases: list[dict[str, Any]] = []
    try:
        # Always map first. Agentic follow-on work needs a mechanical view of
        # the artefact before it decides whether runtime or fuzzing is sensible.
        result = _analyse_for_args(args, target, out_dir)
        if args.runtime or args.active:
            runtime_dir = out_dir / "runtime"
            suitability = result.context_map.get("fuzz_suitability") or {}
            if suitability.get("runtime_strategy", "direct_process") == "direct_process":
                active_phases.append(_run_active_phase(
                    kind="runtime",
                    output_dir=runtime_dir,
                    trusted=True,
                    cmd=[
                        str(_repo_root() / "libexec" / "raptor-frida"),
                        "--target",
                        str(target),
                        "--template",
                        "binary-flow-trace",
                        "--duration",
                        str(args.runtime_duration),
                        "--out",
                        str(runtime_dir),
                    ],
                ))
                if active_phases[-1]["status"] == "completed":
                    args.runtime_dir = str(runtime_dir)
                    result = _analyse_for_args(args, target, out_dir)
            else:
                active_phases.append(_skipped_phase(
                    "runtime",
                    runtime_dir,
                    str(
                        suitability.get("runtime_reason")
                        or "This artefact needs a harness before runtime tracing is meaningful."
                    ),
                ))
        if args.fuzz or args.active:
            fuzz_dir = out_dir / "fuzz"
            suitability = result.context_map.get("fuzz_suitability") or {}
            strategy = str(suitability.get("strategy") or "")
            if strategy == "direct_harness":
                active_phases.append(_run_active_phase(
                    kind="fuzz",
                    output_dir=fuzz_dir,
                    trusted=True,
                    cmd=[
                        sys.executable,
                        str(_repo_root() / "raptor_fuzzing.py"),
                        "--orchestrator",
                        "--binary",
                        str(target),
                        "--duration",
                        str(args.fuzz_duration),
                        "--out",
                        str(fuzz_dir),
                    ],
                ))
                if active_phases[-1]["status"] == "completed":
                    args.fuzz_dir = str(fuzz_dir)
                    result = _analyse_for_args(args, target, out_dir)
            elif suitability.get("should_run_fuzz_plan"):
                active_phases.append(_run_active_phase(
                    kind="fuzz_plan",
                    output_dir=fuzz_dir,
                    trusted=True,
                    cmd=[
                        sys.executable,
                        str(_repo_root() / "raptor_fuzzing.py"),
                        "--orchestrator",
                        "--binary",
                        str(target),
                        "--duration",
                        str(args.fuzz_duration),
                        "--plan-only",
                        "--out",
                        str(fuzz_dir),
                    ],
                ))
            else:
                active_phases.append(_skipped_phase(
                    "fuzz",
                    fuzz_dir,
                    str(
                        suitability.get("reason")
                        or "No evidence-backed whole-target fuzzing boundary was recovered."
                    ),
                ))

        payload = map_result_payload(result, out_dir)
        payload["mode"] = "investigate"
        payload["artifacts"]["binary_investigation"] = str(out_dir / "binary-investigation.json")
        payload["artifacts"]["binary_investigation_report"] = str(out_dir / "binary-investigation-report.md")
        save_json(out_dir / "map-result.json", payload)
        investigation = write_investigation(result, out_dir, active_phases=active_phases)
        complete_run(out_dir)
    except KeyboardInterrupt:
        fail_run(out_dir, "binary investigation interrupted")
        raise
    except Exception as exc:  # noqa: BLE001 - operator-facing clean failure
        fail_run(out_dir, f"binary investigation failed: {type(exc).__name__}: {exc}")
        print(f"raptor-binary: investigate failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    _print_investigation_summary(investigation, out_dir)
    return 0


def _run_runtime(args: argparse.Namespace) -> int:
    return subprocess.call(_frida_trace_command(
        target=str(args.target),
        duration=args.duration,
        output_dir=Path(args.out).expanduser().resolve() if args.out else None,
        spawn=args.spawn,
        unsafe_attach=args.unsafe_attach,
        host=args.host,
        usb=args.usb,
    ), env=RaptorConfig.get_safe_env())


def _frida_trace_command(
    *,
    target: str,
    duration: int,
    output_dir: Path | None,
    spawn: bool,
    unsafe_attach: bool,
    host: str | None,
    usb: bool,
) -> list[str]:
    cmd = [
        str(_repo_root() / "libexec" / "raptor-frida"),
        "--target",
        target,
        "--template",
        "binary-flow-trace",
        "--duration",
        str(duration),
    ]
    if output_dir is not None:
        cmd.extend(["--out", str(output_dir)])
    if spawn:
        cmd.append("--spawn")
    if unsafe_attach:
        cmd.append("--unsafe-attach")
    if host:
        cmd.extend(["--host", host])
    if usb:
        cmd.append("--usb")
    return cmd


def _load_run_manifest(run_dir: Path) -> BinaryManifest | None:
    payload = load_json(run_dir / "binary-manifest.json")
    if not isinstance(payload, dict):
        print(f"raptor-binary: missing binary-manifest.json: {run_dir / 'binary-manifest.json'}", file=sys.stderr)
        return None
    manifest = BinaryManifest.from_dict(payload)
    if not manifest.binary_path:
        print(f"raptor-binary: invalid binary manifest in {run_dir}", file=sys.stderr)
        return None
    return manifest


def _existing_active_phases(run_dir: Path) -> list[dict[str, Any]]:
    payload = load_json(run_dir / "binary-investigation.json")
    if not isinstance(payload, dict):
        return []
    phases = payload.get("active_phases")
    if not isinstance(phases, list):
        return []
    return [dict(item) for item in phases if isinstance(item, dict)]


def _run_trace_parser(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir).expanduser().resolve()
    if not run_dir.is_dir():
        print(f"raptor-binary: run directory does not exist: {run_dir}", file=sys.stderr)
        return 2
    manifest = _load_run_manifest(run_dir)
    if manifest is None:
        return 2
    binary = Path(manifest.binary_path).expanduser().resolve()
    if not binary.is_file():
        print(f"raptor-binary: mapped binary no longer exists: {binary}", file=sys.stderr)
        return 2

    runtime_dir = run_dir / "parser-runtime"
    phase = _run_active_phase(
        kind="parser_trace",
        output_dir=runtime_dir,
        trusted=True,
        cmd=_frida_trace_command(
            target=str(binary),
            duration=args.duration,
            output_dir=runtime_dir,
            spawn=args.spawn,
            unsafe_attach=args.unsafe_attach,
            host=args.host,
            usb=args.usb,
        ),
    )
    if phase["status"] != "completed":
        print(
            f"raptor-binary: parser trace failed; see {phase['stderr']}",
            file=sys.stderr,
        )
        return 1

    result = append_runtime_evidence_to_run(binary, out_dir=run_dir, runtime_dir=runtime_dir)
    if result is None:
        print(
            "raptor-binary: parser trace completed but the existing run could not be refreshed",
            file=sys.stderr,
        )
        return 1

    payload = map_result_payload(result, run_dir)
    prior_payload = load_json(run_dir / "map-result.json")
    if isinstance(prior_payload, dict) and prior_payload.get("mode") == "investigate":
        payload["mode"] = "investigate"
    payload["artifacts"]["binary_investigation"] = str(run_dir / "binary-investigation.json")
    payload["artifacts"]["binary_investigation_report"] = str(run_dir / "binary-investigation-report.md")
    save_json(run_dir / "map-result.json", payload)
    investigation = write_investigation(
        result,
        run_dir,
        active_phases=[*_existing_active_phases(run_dir), phase],
    )
    print("Mode: trace-parser")
    print(f"Status: {phase['status']}")
    print(f"Runtime output: {runtime_dir}")
    print(f"Runtime parser flows: {len(result.context_map.get('runtime_parser_flows', []))}")
    print(f"Parser boundary candidates: {len(result.context_map.get('parser_boundary_candidates', []))}")
    print(f"Investigation status: {investigation['status']}")
    print(f"Report: {run_dir / 'binary-investigation-report.md'}")
    print(f"Handoff: {run_dir / 'binary-validation-handoff.json'}")
    return 0


def _run_fuzz(args: argparse.Namespace) -> int:
    target = Path(args.target).expanduser().resolve()
    cmd = [
        sys.executable,
        str(_repo_root() / "raptor.py"),
        "fuzz",
        "--orchestrator",
        "--binary",
        str(target),
        *args.fuzz_args,
    ]
    return subprocess.call(cmd, env=RaptorConfig.get_safe_env())


def _run_harness(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir).expanduser().resolve()
    if not run_dir.is_dir():
        print(f"raptor-binary: run directory does not exist: {run_dir}", file=sys.stderr)
        return 2
    try:
        spec = generate_binary_harness(
            run_dir,
            ingress_id=args.ingress,
            abi=args.abi,
            device=args.device,
            ioctl_code=args.ioctl_code,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"raptor-binary: harness failed: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(spec, separators=(",", ":"), sort_keys=True))
        return 0
    print("Mode: harness")
    print(f"Status: {spec['status']}")
    print(f"Family: {spec['family']}")
    print(f"Ingress: {spec['ingress']['name']} ({spec['ingress']['kind']})")
    print(f"Reason: {spec['reason']}")
    print(f"Next step: {spec['next_step']}")
    print(f"Spec: {spec['artifacts']['spec']}")
    print(f"Report: {spec['artifacts']['report']}")
    if spec.get("generated"):
        print(f"Source: {spec['generated']['source']}")
        print(f"Build: {spec['generated']['build_script']}")
    return 0


def _run_graph(args: argparse.Namespace) -> int:
    cmd = [
        str(_repo_root() / "libexec" / "raptor-binary-graph-query"),
        "--run-dir",
        str(Path(args.run_dir).expanduser().resolve()),
    ]
    if args.edges:
        cmd.append("--edges")
    if args.evidence:
        cmd.append("--evidence")
    if args.kind:
        cmd.extend(["--kind", args.kind])
    if args.tier:
        cmd.extend(["--tier", args.tier])
    if args.json:
        cmd.append("--json")
    return subprocess.call(cmd, env=RaptorConfig.get_safe_env())


def _print_file(run_dir: str, filename: str, *, json_output: bool = False) -> int:
    path = Path(run_dir).expanduser().resolve() / filename
    if not path.is_file():
        print(f"raptor-binary: missing {filename}: {path}", file=sys.stderr)
        return 1
    if not json_output:
        print(path.read_text(encoding="utf-8"), end="")
        return 0
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"raptor-binary: invalid JSON in {path}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(payload, separators=(",", ":"), sort_keys=True))
    return 0


def _print_report(run_dir: str) -> int:
    base = Path(run_dir).expanduser().resolve()
    investigation = base / "binary-investigation-report.md"
    if investigation.is_file():
        return _print_file(run_dir, investigation.name)
    return _print_file(run_dir, "binary-analysis-report.md")


def _run_diagram(args: argparse.Namespace) -> int:
    cmd = [
        str(_repo_root() / "libexec" / "raptor-render-diagrams"),
        str(Path(args.run_dir).expanduser().resolve()),
    ]
    if args.target:
        cmd.extend(["--target", args.target])
    if args.stdout:
        cmd.append("--stdout")
    if args.force:
        cmd.append("--force")
    return subprocess.call(cmd, env=RaptorConfig.get_safe_env())


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(_normalise_argv(sys.argv[1:] if argv is None else argv))
    if args.command == "help":
        parser.print_help()
        return 0
    if args.command == "investigate":
        return _run_investigate(args)
    if args.command == "map":
        return _run_map(args)
    if args.command == "runtime":
        return _run_runtime(args)
    if args.command == "trace-parser":
        return _run_trace_parser(args)
    if args.command == "harness":
        return _run_harness(args)
    if args.command == "fuzz":
        return _run_fuzz(args)
    if args.command == "graph":
        return _run_graph(args)
    if args.command == "report":
        return _print_report(args.run_dir)
    if args.command == "handoff":
        return _print_file(args.run_dir, "binary-validation-handoff.json", json_output=args.json)
    if args.command == "diagram":
        return _run_diagram(args)
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
