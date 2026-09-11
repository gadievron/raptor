"""Runtime regression oracle for candidate patches.

Answers one question with dynamic evidence: given a proof-of-concept
input that drives a vulnerable binary into a sink, does the patched
build still reach that sink?  Two sink-watch sessions run with the
same input — one against the unpatched binary, one against the
patched build — and the verdict comes from comparing target-attributed
sink evidence between them.

Verdicts (``verdict`` in the report):

* ``closed`` — the sink fired pre-patch and did not fire post-patch.
  ``confidence`` is ``site`` when the pre-patch firing was
  source-resolved to the finding's location, else ``function``.
* ``still_fires`` — the sink fired in BOTH runs.  Compared at
  function level only: a patch moves source lines, so matching the
  post-patch run against the original finding's line is unsound.
  Note a sink legitimately firing post-patch does NOT always mean the
  patch failed (a patch may sanitise arguments rather than remove the
  call) — this oracle detects call-removal and guard-style patches.
* ``inconclusive`` — the sink never fired pre-patch (the PoC does
  not demonstrate the vulnerable path), or the post-patch session
  produced no events at all (broken session — absence of evidence
  from a session that observed nothing is not evidence). Nothing can
  be concluded about the patch.

With several sinks, the runs are compared on ANY watched sink firing
— per-sink counts are in the report when a finer reading matters.

The target binaries run under frida WITHOUT a sandbox (same trust
stance as the raw runner): only verify patches on binaries you built
yourself.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence

from core.logging import get_logger

log = get_logger("frida.patch_oracle")

__all__ = ["verify_patch"]

# Worst case per side: run duration + the runner's own bounded
# stages (script-load 30s + flush 5s + detach 10s + kill 5s) +
# spawn slack.
_SIDE_TIMEOUT_SLACK = 60.0

_FINDING_ID = "patch-oracle"


def _frida_python() -> str:
    """Interpreter that has frida-python importable.

    The frida CLI is often a pipx/venv install whose bindings are
    not visible to ``sys.executable``; its shebang names the
    interpreter that can actually run ``packages.frida.cli``.
    """
    frida_bin = shutil.which("frida")
    if frida_bin:
        try:
            with open(frida_bin, encoding="utf-8",
                      errors="replace") as f:
                shebang = f.readline(256).strip()
            if shebang.startswith("#!"):
                python = shebang[2:].strip().split()[0]
                if os.path.isfile(python):
                    return python
        except OSError:
            pass
    return sys.executable


def _run_side(binary: Path, script_path: Path, side_dir: Path,
              poc: Path | None, duration: float) -> None:
    """Run one sink-watch session; raises RuntimeError on failure."""
    # Same credential-stripped environment as every other frida
    # launch (active._safe_env): the spawned target inherits this env
    # from the CLI process, runs unsandboxed, and "built yourself"
    # does not mean "audited yourself" — operator credentials must
    # not be readable via getenv from target code. _safe_env keeps
    # RAPTOR_DIR/PYTHONPATH so the CLI module itself still imports.
    from packages.frida.active import _safe_env
    env = _safe_env()
    cmd = [
        _frida_python(), "-m", "packages.frida.cli",
        "--target", str(binary.resolve()),
        "--script", str(script_path),
        "--out", str(side_dir),
        "--duration", str(duration),
        "--spawn",
    ]
    # frida spawn inherits the controller's stdio, so the PoC input
    # reaches the target by feeding it to the CLI process.
    stdin_ctx = open(poc, "rb") if poc is not None else None  # noqa: SIM115
    try:
        proc = subprocess.run(
            cmd,
            stdin=stdin_ctx if stdin_ctx is not None else subprocess.DEVNULL,
            capture_output=True, text=True,
            timeout=duration + _SIDE_TIMEOUT_SLACK,
            env=env,
        )
    except subprocess.TimeoutExpired as e:
        # An infrastructure hang must surface as an error, never leak
        # out as a verdict-bearing exit code.
        msg = f"frida session against {binary} hung: {e}"
        raise RuntimeError(msg) from e
    finally:
        if stdin_ctx is not None:
            stdin_ctx.close()
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip()[-400:]
        msg = f"frida session against {binary} failed: {tail}"
        raise RuntimeError(msg)


def _judge_side(side_dir: Path, binary: Path, sinks: Sequence[str],
                finding_location: tuple[str, int] | None) -> dict:
    """Summarise one run: which sinks fired, site match if resolvable."""
    from core.orchestration.frida_validation_bridge import (
        annotate_attack_paths,
        collect_runtime_evidence,
    )

    evidence = collect_runtime_evidence([side_dir],
                                        target_path=str(binary))
    events_total = 0
    events_path = side_dir / "events.jsonl"
    if events_path.is_file():
        try:
            with events_path.open(encoding="utf-8",
                                  errors="replace") as f:
                events_total = sum(1 for line in f if line.strip())
        except OSError:
            pass
    paths = [{
        "finding": _FINDING_ID,
        "steps": [{"function": s} for s in sinks],
    }]
    locations = ({_FINDING_ID: finding_location}
                 if finding_location is not None else None)
    annotated = annotate_attack_paths(paths, evidence, locations)

    fired: dict[str, dict] = {}
    site_match = False
    for step in annotated[0]["steps"]:
        ev = step.get("runtime_evidence")
        if not isinstance(ev, dict) or not ev.get("function_observed"):
            continue
        fired[step["function"]] = {
            "call_count": ev.get("call_count", 0),
            "callsite_match": ev.get("callsite_match"),
        }
        if ev.get("callsite_match") is True:
            site_match = True
    return {
        "run_dir": str(side_dir),
        "fired": fired,
        "any_fired": bool(fired),
        "site_match": site_match,
        "events_total": events_total,
    }


def verify_patch(
    before: Path,
    after: Path,
    sinks: Sequence[str],
    out_dir: Path,
    *,
    poc: Path | None = None,
    finding_location: tuple[str, int] | None = None,
    duration: float = 10.0,
) -> dict:
    """Compare sink reachability between an unpatched and patched build.

    ``before``/``after`` are the two binaries, ``sinks`` the watched
    function names (the finding's sink, e.g. ``system``), ``poc`` an
    optional input file fed to both runs on stdin, and
    ``finding_location`` the original finding's ``(file, line)`` used
    to qualify the pre-patch run at site level.

    Writes ``patch-verify.json`` into ``out_dir`` and returns the same
    report dict.  Raises ``ValueError`` on bad inputs and
    ``RuntimeError`` when a frida session fails.
    """
    from .sink_watch import SinkSpec, render_sink_watch

    for name, path in (("before", before), ("after", after)):
        if not path.is_file():
            msg = f"--{name} binary not found: {path}"
            raise ValueError(msg)
    if poc is not None and not poc.is_file():
        msg = f"--poc file not found: {poc}"
        raise ValueError(msg)
    if not sinks:
        msg = "at least one sink is required"
        raise ValueError(msg)

    out_dir.mkdir(parents=True, exist_ok=True)
    script_path = out_dir / "sink-watch.js"
    script_path.write_text(
        render_sink_watch([SinkSpec(fn=s) for s in sinks]),
        encoding="utf-8")

    sides: dict[str, dict] = {}
    for side, binary in (("before", before), ("after", after)):
        side_dir = out_dir / side
        # A reused out dir must never let a previous invocation's
        # events pass as this run's evidence (the runner APPENDS to
        # events.jsonl): stale pre-patch sink events would judge a
        # PoC that demonstrated nothing as a verified "closed".
        if side_dir.exists():
            shutil.rmtree(side_dir)
        side_dir.mkdir()
        log.info("patch-oracle: running %s side (%s)", side, binary)
        _run_side(binary, script_path, side_dir, poc, duration)
        sides[side] = _judge_side(side_dir, binary, sinks,
                                  finding_location)

    if not sides["before"]["any_fired"]:
        verdict, confidence = "inconclusive", None
        reason = ("sink did not fire pre-patch — the PoC does not "
                  "demonstrate the vulnerable path, so the patch "
                  "cannot be judged")
    elif sides["after"]["events_total"] == 0:
        # A healthy sink-watch session emits at least its attach
        # summary. Zero events means the session observed nothing;
        # silence from it is not evidence the sink stopped firing.
        verdict, confidence = "inconclusive", None
        reason = ("post-patch session produced no events at all — "
                  "the session is broken, not the sink silent; "
                  "nothing can be concluded")
    elif sides["after"]["any_fired"]:
        verdict, confidence = "still_fires", "function"
        reason = ("sink still fires post-patch with the same input "
                  "(function-level comparison; if the patch sanitises "
                  "arguments rather than removing the call, confirm "
                  "manually)")
    else:
        verdict = "closed"
        confidence = "site" if sides["before"]["site_match"] else "function"
        reason = ("sink fired pre-patch"
                  + (" at the finding's source location"
                     if confidence == "site" else "")
                  + " and did not fire post-patch with the same input")

    report = {
        "verdict": verdict,
        "confidence": confidence,
        "reason": reason,
        "sinks": list(sinks),
        "poc": str(poc) if poc is not None else None,
        "finding_location": (
            f"{finding_location[0]}:{finding_location[1]}"
            if finding_location is not None else None),
        "before": sides["before"],
        "after": sides["after"],
    }
    report_path = out_dir / "patch-verify.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n",
                           encoding="utf-8")
    return report


def _parse_location(value: str) -> tuple[str, int]:
    path, sep, line = value.rpartition(":")
    if not sep or not path or not line.isdigit():
        msg = f"expected file:line, got {value!r}"
        raise argparse.ArgumentTypeError(msg)
    return path, int(line)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="raptor frida-patch-verify",
        description=("Verify a candidate patch dynamically: run the "
                     "same PoC input against the unpatched and "
                     "patched builds under a frida sink watch and "
                     "compare sink reachability."),
    )
    parser.add_argument("--before", required=True, type=Path,
                        help="Unpatched binary.")
    parser.add_argument("--after", required=True, type=Path,
                        help="Binary built from the patched source.")
    parser.add_argument("--sink", action="append", required=True,
                        dest="sinks", metavar="FN",
                        help="Sink function to watch (repeatable), "
                             "e.g. --sink system.")
    parser.add_argument("--poc", type=Path,
                        help="Input file fed to both runs on stdin.")
    parser.add_argument("--location", type=_parse_location,
                        metavar="FILE:LINE",
                        help="Original finding location; qualifies the "
                             "pre-patch run at site level.")
    parser.add_argument("--duration", type=float, default=10.0,
                        help="Seconds per side. Default 10.")
    parser.add_argument("--out", required=True, type=Path,
                        help="Output directory (report + both run "
                             "dirs). The libexec wrapper injects one "
                             "via the run lifecycle when omitted.")
    args = parser.parse_args(argv)

    if "RAPTOR_DIR" not in os.environ:
        print("patch-verify: RAPTOR_DIR is not set (run via "
              "libexec/raptor-frida-patch-verify)", file=sys.stderr)
        return 2

    try:
        report = verify_patch(
            args.before, args.after, args.sinks, args.out,
            poc=args.poc, finding_location=args.location,
            duration=args.duration)
    except (ValueError, RuntimeError) as e:
        print(f"patch-verify: {e}", file=sys.stderr)
        return 2

    status = {"closed": "Closed", "still_fires": "Still Fires",
              "inconclusive": "Inconclusive"}[report["verdict"]]
    qualifier = (f" ({report['confidence']}-level)"
                 if report["confidence"] else "")
    print(f"patch-verify: {status}{qualifier} — {report['reason']}")
    print(f"patch-verify: report → {args.out / 'patch-verify.json'}")
    # Verdict-bearing exit codes; 2 stays reserved for errors so an
    # infrastructure failure can never read as a verdict.
    return {"closed": 0, "still_fires": 1, "inconclusive": 3}[
        report["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
