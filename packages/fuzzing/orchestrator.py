"""Fuzzing orchestrator -- the public entry point for /fuzz.

Detects the target type, checks the host's capabilities, picks the right
fuzzer, generates a harness if needed, and runs the campaign. Designed
to fail loudly and helpfully when the target cannot be fuzzed on the
current host rather than crashing six commands deep into AFL++.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.sandbox import run_trusted as _run_trusted
from core.logging import get_logger
from packages.fuzzing.capability import CapabilityReport, probe as probe_capabilities
from packages.fuzzing.target_detector import TargetInfo, detect as detect_target

logger = get_logger()

_EXECUTABLE_FUZZERS = {"afl", "libfuzzer"}


@dataclass
class CampaignPlan:
    """The orchestrator's decision about how to run."""

    target: TargetInfo
    capabilities: CapabilityReport
    fuzzer: Optional[str] = None
    needs_harness: bool = False
    can_run: bool = False
    blockers: List[str] = field(default_factory=list)
    hints: List[str] = field(default_factory=list)
    cmd_preview: List[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            "=" * 70,
            "RAPTOR FUZZING CAMPAIGN PLAN",
            "=" * 70,
            "",
            "Target:",
            f"  Path:    {self.target.path}",
            f"  Kind:    {self.target.kind}",
            f"  Arch:    {self.target.arch}",
            "",
            "Host capabilities:",
            f"  Platform: {self.capabilities.platform} {self.capabilities.arch}",
            f"  AFL++:    {'yes' if self.capabilities.has_afl() else 'no'}",
            f"  libFuzzer:{'yes' if self.capabilities.has_clang_fuzzer() else 'no'}",
            (
                "  radare2:  "
                f"{'yes' if self.capabilities.radare2 else 'no'}"
                + (
                    f" ({self.capabilities.radare2}, "
                    f"{'r2ghidra' if self.capabilities.has_r2ghidra else 'pdc'})"
                    if self.capabilities.radare2 and self.capabilities.has_r2pipe
                    else ""
                )
            ),
            f"  r2pipe:   {'yes' if self.capabilities.has_r2pipe else 'no'}",
            "",
        ]
        if self.fuzzer:
            lines.append(f"Selected fuzzer: {self.fuzzer}")
        if self.needs_harness:
            lines.append("Action required: generate libFuzzer harness")
        if self.blockers:
            lines.append("")
            lines.append("Blockers:")
            for b in self.blockers:
                lines.append(f"  - {b}")
        if self.hints:
            lines.append("")
            lines.append("Hints:")
            for h in self.hints:
                lines.append(f"  - {h}")
        lines.append("")
        lines.append(f"Can run: {'YES' if self.can_run else 'NO'}")
        lines.append("=" * 70)
        return "\n".join(lines)


class FuzzingOrchestrator:
    """Top-level entry point for any fuzzing target."""

    def __init__(self, llm=None) -> None:
        self.llm = llm
        self.capabilities = probe_capabilities()

    def plan(self, target_path: Path) -> CampaignPlan:
        """Inspect the target, pick a fuzzer, return a campaign plan.

        Does not run anything. The caller can present this to the user
        for confirmation, or call .execute(plan) to run it.
        """
        target = detect_target(Path(target_path))
        plan = CampaignPlan(target=target, capabilities=self.capabilities)

        # Carry blockers forward
        plan.blockers.extend(target.blockers)
        plan.hints.extend(target.hints)

        # Match target kind to fuzzer
        kind = target.kind
        caps = self.capabilities

        if kind == "elf-linux":
            plan.fuzzer = self._pick_for_unix_binary(caps, target.path)
        elif kind == "macho":
            plan.fuzzer = self._pick_for_unix_binary(caps, target.path)
        elif kind in ("pe-exe", "pe-dll"):
            plan.fuzzer = "winafl" if caps.platform == "Windows" else None
            if not plan.fuzzer:
                plan.blockers.append(
                    f"Windows PE binaries cannot be fuzzed on {caps.platform}. "
                    "Run RAPTOR on a Windows host with WinAFL installed."
                )
            else:
                plan.blockers.append(
                    "WinAFL target detection is available, but RAPTOR does "
                    "not orchestrate WinAFL campaigns yet."
                )
        elif kind == "pe-sys":
            plan.fuzzer = None
            plan.blockers.append(
                "Windows kernel drivers require snapshot fuzzing infrastructure "
                "(kAFL or Snapchange) which RAPTOR does not orchestrate yet. "
                "Use the static analysis pipeline (/codeql, /scan) on the source instead."
            )
        elif kind in ("source-c", "source-cpp"):
            plan.needs_harness = True
            plan.fuzzer = "libfuzzer" if caps.has_clang_fuzzer() else None
            if not plan.fuzzer:
                plan.blockers.append(
                    "Source-level fuzzing needs clang with libFuzzer support. "
                    "Install clang and verify with 'clang -fsanitize=fuzzer test.c'."
                )
            else:
                plan.blockers.append(
                    "Source targets need a compiled libFuzzer harness before "
                    "RAPTOR can run them. Generate/build a harness first, then "
                    "pass the resulting executable to /fuzz."
                )
        elif kind == "rust-crate":
            plan.fuzzer = "cargo-fuzz" if not target.blockers else None
            if plan.fuzzer:
                plan.blockers.append(
                    "cargo-fuzz target detection is available, but RAPTOR does "
                    "not orchestrate cargo-fuzz campaigns yet."
                )
        elif kind == "python-pkg":
            plan.fuzzer = "atheris" if not target.blockers else None
            if plan.fuzzer:
                plan.blockers.append(
                    "Atheris target detection is available, but RAPTOR does "
                    "not orchestrate Atheris campaigns yet."
                )
        else:
            plan.blockers.append(
                "Could not identify target type. Pass an executable binary, a "
                "C/C++ header, or a Cargo/Python project root."
            )

        if plan.fuzzer is None and not plan.blockers:
            if kind in ("elf-linux", "macho"):
                plan.blockers.append(
                    "No supported executable fuzzer is available for this binary. "
                    "Install/configure AFL++, or pass a binary compiled as a "
                    "libFuzzer harness with LLVMFuzzerTestOneInput."
                )
            else:
                plan.blockers.append(
                    "Target was detected, but no supported RAPTOR runner is "
                    "available for it on this host."
                )

        plan.can_run = (
            plan.fuzzer in _EXECUTABLE_FUZZERS
            and not plan.needs_harness
            and not plan.blockers
        )

        # Add capability-driven hints
        if caps.is_macos and caps.afl_shmem_ok is False:
            plan.hints.append(
                "AFL++ shared memory is misconfigured on this Mac. "
                "Run 'sudo afl-system-config' to fix, or RAPTOR will use libFuzzer "
                "where possible."
            )

        if plan.fuzzer == "afl" and not caps.afl_cov:
            plan.hints.append(
                "afl-cov is not installed. Coverage reports will be limited. "
                "Install: https://github.com/mrash/afl-cov"
            )

        return plan

    def _pick_for_unix_binary(self, caps: CapabilityReport, target_path: Optional[Path] = None) -> Optional[str]:
        """Pick AFL++ or libFuzzer for a Unix binary target.

        If the binary itself is libFuzzer-instrumented (has the
        LLVMFuzzerTestOneInput symbol), libFuzzer is the only correct
        choice -- AFL++ cannot drive a libFuzzer harness.
        """
        is_libfuzzer_binary = bool(target_path and self._is_libfuzzer_instrumented(target_path))
        if is_libfuzzer_binary:
            return "libfuzzer"
        if caps.has_afl() and caps.is_linux:
            return "afl"
        if caps.has_afl() and caps.is_macos and caps.afl_shmem_ok:
            return "afl"
        if caps.has_afl():
            return "afl"
        return None

    @staticmethod
    def _is_libfuzzer_instrumented(target_path: Path) -> bool:
        """Detect a libFuzzer harness by looking for LLVMFuzzerTestOneInput.

        Cheap and reliable: if the binary defines that symbol, only
        libFuzzer can drive it.

        We try `nm` first (always finds the symbol if present), then
        `strings -a` (all sections), then plain `strings` as a last
        resort. macOS's default `strings` only scans __TEXT and misses
        symbols in other Mach-O sections, so the order matters.
        """
        if not shutil.which("nm") and not shutil.which("strings"):
            return False

        for cmd in (
            ["nm", str(target_path)],
            ["strings", "-a", str(target_path)],
            ["strings", str(target_path)],
        ):
            if not shutil.which(cmd[0]):
                continue
            try:
                result = _run_trusted(
                    cmd, capture_output=True, text=True, timeout=15,
                )
                if (result.stdout or "") and "LLVMFuzzerTestOneInput" in result.stdout:
                    return True
            except Exception:
                continue
        return False

    def execute(
        self,
        plan: CampaignPlan,
        *,
        out_dir: Path,
        duration_seconds: int = 600,
        corpus_dir: Optional[Path] = None,
        dict_path: Optional[Path] = None,
        binary_understand: bool = True,
        source_context_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Execute a planned campaign. Raises if plan.can_run is False.

        binary_understand: when True (default) and the target is a binary
        and radare2 is available, run a pre-fuzz binary analysis pass and
        write binary-context-map.json into the output directory. The map
        is consumed by adaptive corpus generation and harness selection.
        """
        if not plan.can_run:
            raise RuntimeError(
                f"Cannot run plan: {'; '.join(plan.blockers) or 'no blockers reported'}"
            )

        out_dir = Path(out_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        # Persist plan and capability report for the run record
        (out_dir / "fuzzing_plan.json").write_text(
            json.dumps({
                "target": {
                    "path": str(plan.target.path),
                    "kind": plan.target.kind,
                    "arch": plan.target.arch,
                },
                "fuzzer": plan.fuzzer,
                "needs_harness": plan.needs_harness,
            }, indent=2)
        )
        (out_dir / "capability_report.json").write_text(
            json.dumps(plan.capabilities.to_dict(), indent=2, default=str)
        )

        logger.info(plan.summary())

        corpus_dir, generated_corpus_info = self._prepare_corpus(
            plan,
            out_dir=out_dir,
            corpus_dir=corpus_dir,
            source_context_dir=source_context_dir,
        )

        # Optional pre-fuzz: binary-level adversarial analysis via radare2.
        # Mirrors what /understand --map does for source-level targets.
        if binary_understand and plan.target.kind in ("elf-linux", "macho", "pe-exe", "pe-dll"):
            if not plan.capabilities.radare2:
                logger.info("Skipping radare2 binary analysis: radare2 not found")
            elif not plan.capabilities.has_r2pipe:
                logger.info("Skipping radare2 binary analysis: Python r2pipe module not installed")
            else:
                try:
                    from packages.binary_analysis import analyse_binary_context
                    decompiler = "r2ghidra" if plan.capabilities.has_r2ghidra else "pdc"
                    logger.info("=" * 70)
                    logger.info("BINARY CONTEXT ANALYSIS (radare2)")
                    logger.info("=" * 70)
                    logger.info(f"radare2: {plan.capabilities.radare2}")
                    logger.info(f"decompiler: {decompiler}")
                    logger.info(f"output: {out_dir / 'binary-context-map.json'}")
                    ctx_map = analyse_binary_context(
                        plan.target.path,
                        out_path=out_dir / "binary-context-map.json",
                        llm=self.llm,
                    )
                    logger.info(
                        "radare2 binary-context-map written: "
                        f"{len(ctx_map.entry_points)} entry points, "
                        f"{len(ctx_map.dangerous_sinks)} sinks, "
                        f"{len(ctx_map.fuzz_priorities)} prioritised functions"
                    )
                except Exception as e:
                    logger.warning(f"Binary understand failed (non-fatal): {e}")

        if plan.fuzzer == "afl":
            result = self._run_afl(plan, out_dir, duration_seconds, corpus_dir, dict_path)
        elif plan.fuzzer == "libfuzzer":
            result = self._run_libfuzzer(plan, out_dir, duration_seconds, corpus_dir, dict_path)
        else:
            raise RuntimeError(f"Fuzzer '{plan.fuzzer}' not yet wired into orchestrator.")
        if generated_corpus_info:
            result["generated_corpus"] = generated_corpus_info
        return result

    def _prepare_corpus(
        self,
        plan: CampaignPlan,
        *,
        out_dir: Path,
        corpus_dir: Optional[Path],
        source_context_dir: Optional[Path],
    ) -> tuple[Optional[Path], Optional[Dict[str, Any]]]:
        """Generate an agentic seed corpus when the caller did not provide one."""
        if corpus_dir is not None:
            return corpus_dir, None
        try:
            from packages.autonomous import CorpusGenerator

            generated_dir = out_dir / "generated-corpus"
            context_dir = source_context_dir or plan.target.path.parent
            generator = CorpusGenerator(
                plan.target.path,
                source_dir=context_dir,
            )
        except Exception as e:
            logger.warning(f"Autonomous corpus generator unavailable: {e}")
            return corpus_dir, None

        try:
            seeds = generator.generate_autonomous_corpus(generated_dir, max_seeds=64)
        except Exception as e:
            logger.warning(f"Autonomous corpus generation failed: {e}")
            return corpus_dir, None
        if seeds <= 0:
            return corpus_dir, None

        info = {
            "path": str(generated_dir),
            "seeds": seeds,
            "source_context_dir": str(context_dir),
            "commands_detected": sorted(generator.detected_commands.keys()),
            "formats_detected": sorted(generator.detected_formats),
        }
        (out_dir / "generated-corpus.json").write_text(json.dumps(info, indent=2))
        logger.info(f"Generated agentic fuzz corpus: {seeds} seeds at {generated_dir}")
        return generated_dir, info

    def _run_afl(
        self,
        plan: CampaignPlan,
        out_dir: Path,
        duration_seconds: int,
        corpus_dir: Optional[Path],
        dict_path: Optional[Path],
    ) -> Dict[str, Any]:
        from packages.fuzzing.afl_runner import AFLRunner
        from packages.fuzzing.telemetry import FuzzingTelemetry

        afl_out = out_dir / "afl"
        runner = AFLRunner(
            binary_path=plan.target.path,
            corpus_dir=corpus_dir,
            output_dir=afl_out,
            dict_path=dict_path,
            check_sanitizers=True,
            use_showmap=True,
        )
        runner.telemetry = FuzzingTelemetry(
            out_dir=out_dir,
            fuzzer="afl++",
            target=str(plan.target.path),
        )
        runner.telemetry.start()
        try:
            crashes, crashes_dir = runner.run_fuzzing(duration=duration_seconds)
        finally:
            runner.telemetry.stop()
        return {
            "fuzzer": "afl",
            "crashes": crashes,
            "crashes_dir": str(crashes_dir),
            "stats": runner.get_stats(),
            "telemetry": str(out_dir / "fuzz-summary.json"),
            "events": str(out_dir / "fuzz-events.jsonl"),
        }

    def _run_libfuzzer(
        self,
        plan: CampaignPlan,
        out_dir: Path,
        duration_seconds: int,
        corpus_dir: Optional[Path],
        dict_path: Optional[Path],
    ) -> Dict[str, Any]:
        from packages.fuzzing.libfuzzer_runner import LibFuzzerRunner
        from packages.fuzzing.telemetry import FuzzingTelemetry

        runner = LibFuzzerRunner(
            harness_path=plan.target.path,
            corpus_dir=corpus_dir,
            output_dir=out_dir / "libfuzzer",
            dict_path=dict_path,
            max_total_time=duration_seconds,
        )
        telemetry = FuzzingTelemetry(
            out_dir=out_dir,
            fuzzer="libfuzzer",
            target=str(plan.target.path),
        )
        telemetry.start()
        try:
            # Pass telemetry to the runner so it can stream live progress
            # rather than dumping everything at the end.
            result = runner.run(telemetry=telemetry)
            # Final consolidation in case the streamed parse missed anything
            telemetry.update_stats(
                total_executions=result.stats.total_executions,
                executions_per_second=result.stats.executions_per_second,
                coverage_features=result.stats.coverage_features,
                corpus_size=result.stats.corpus_size,
            )
            # Re-emit any crashes the streaming parser missed (e.g. via the
            # crash directory glob in _parse_result)
            for crash_path in result.crashes:
                if not any(
                    str(crash_path) in str(e)
                    for e in []   # streaming events not tracked here
                ):
                    pass
        finally:
            telemetry.stop()
        return {
            "fuzzer": "libfuzzer",
            "crashes": len(result.crashes),
            "timeouts": len(result.timeouts),
            "oom_events": len(result.oom_inputs),
            "crashes_dir": str(runner.crashes_dir),
            "stats": result.stats.__dict__,
            "telemetry": str(out_dir / "fuzz-summary.json"),
            "events": str(out_dir / "fuzz-events.jsonl"),
        }
