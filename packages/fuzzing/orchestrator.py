"""Fuzzing orchestrator -- the public entry point for /fuzz.

Detects the target type, checks the host's capabilities, picks the right
fuzzer, flags when a harness must be built first (source targets plan
with a blocker telling the operator to build one — nothing here
generates it), and runs the campaign. Designed
to fail loudly and helpfully when the target cannot be fuzzed on the
current host rather than crashing six commands deep into AFL++.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.logging import get_logger
from core.sandbox import run_trusted as _run_trusted
from packages.fuzzing.capability import CapabilityReport
from packages.fuzzing.capability import probe as probe_capabilities
from packages.fuzzing.target_detector import TargetInfo
from packages.fuzzing.target_detector import detect as detect_target

_BINARY_UNDERSTAND_KINDS = frozenset({"elf-linux", "elf-kmod", "macho", "pe-exe", "pe-dll", "pe-sys"})

logger = get_logger()

_EXECUTABLE_FUZZERS = {"afl", "libfuzzer"}


@dataclass
class CampaignPlan:
    """The orchestrator's decision about how to run."""

    target: TargetInfo
    capabilities: CapabilityReport
    fuzzer: str | None = None
    needs_harness: bool = False
    can_run: bool = False
    blockers: list[str] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)
    #: source tree to be built AFL-instrumented in the pinned AFL++
    #: image and fuzzed from its exported rootfs (trust-gated;
    #: candidacy verified at plan time, the build runs in execute()).
    env_build: bool = False
    #: the caller's explicit consent flag (None = project marker),
    #: re-used by execute() so plan and build see the same decision.
    env_build_consent: bool | None = None

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
        if self.env_build:
            lines.append(
                "Env build: AFL-instrumented build in the pinned AFL++ "
                "image; campaign runs from its rootfs under the sandbox")
        if self.needs_harness:
            lines.append("Action required: generate libFuzzer harness")
        if self.blockers:
            lines.append("")
            lines.append("Blockers:")
            lines.extend(f"  - {b}" for b in self.blockers)
        if self.hints:
            lines.append("")
            lines.append("Hints:")
            lines.extend(f"  - {h}" for h in self.hints)
        lines.append("")
        lines.append(f"Can run: {'Yes' if self.can_run else 'No'}")
        lines.append("=" * 70)
        return "\n".join(lines)


class FuzzingOrchestrator:
    """Top-level entry point for any fuzzing target."""

    def __init__(self, llm=None) -> None:
        self.llm = llm
        self.capabilities = probe_capabilities()

    def plan(
        self,
        target_path: Path,
        *,
        env_build: bool | None = None,
    ) -> CampaignPlan:
        """Inspect the target, pick a fuzzer, return a campaign plan.

        Does not run anything. The caller can present this to the user
        for confirmation, or call .execute(plan) to run it.

        ``env_build``: explicit consent for building a source tree in
        the AFL++ image (None = defer to the project ``build`` trust
        marker). The build itself runs in execute().
        """
        target = detect_target(Path(target_path))
        plan = CampaignPlan(target=target, capabilities=self.capabilities,
                            env_build_consent=env_build)
        if env_build and not target.path.is_dir():
            plan.hints.append(
                "--env-build applies to source-tree targets; ignored "
                f"for this {target.kind} file")

        # Carry blockers forward
        plan.blockers.extend(target.blockers)
        plan.hints.extend(target.hints)

        # Match target kind to fuzzer
        kind = target.kind
        caps = self.capabilities

        if kind in {"elf-linux", "macho"}:
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
        elif kind in ("pe-sys", "elf-kmod"):
            plan.fuzzer = None
            plan.blockers.append(
                "Kernel drivers require a harness or snapshot fuzzing infrastructure "
                "(kAFL or Snapchange) which RAPTOR does not orchestrate yet."
            )
        elif kind in ("source-c", "source-cpp"):
            # Env build-on-demand first: a source TREE whose build the
            # operator authorised (project 'build' marker or explicit
            # flag) gets an AFL-instrumented build in the pinned AFL++
            # image and fuzzes from its rootfs — no harness needed for
            # repo-native executables. Candidacy is cheap (consent +
            # command resolution, no docker run); the harness route
            # below is untouched when it declines.
            from packages.fuzzing.env_build import env_build_candidate
            candidate, why = (
                env_build_candidate(target.path, build=env_build)
                if target.path.is_dir() else (False, "")
            )
            if candidate:
                plan.fuzzer = "afl"
                plan.env_build = True
                # The detector's harness-generation hints describe the
                # route NOT taken — showing them beside "Env build:"
                # reads as a contradiction.
                plan.hints = [h for h in plan.hints
                              if "harness" not in h.lower()]
            else:
                if why:
                    plan.hints.append(why)
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

    def _pick_for_unix_binary(self, caps: CapabilityReport, target_path: Path | None = None) -> str | None:
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
            except Exception:  # noqa: BLE001, S112 — probe is best-effort
                continue
        return False

    def execute(
        self,
        plan: CampaignPlan,
        *,
        out_dir: Path,
        duration_seconds: int = 600,
        corpus_dir: Path | None = None,
        dict_path: Path | None = None,
        binary_understand: bool = True,
        source_context_dir: Path | None = None,
        seed_profile: str = "default",
        env_target: str | None = None,
        keep_env_rootfs: bool = False,
        env_sanitizer: str = "",
        env_cmplog: bool = False,
    ) -> dict[str, Any]:
        """Execute a planned campaign. Raises if plan.can_run is False.

        binary_understand: when True (default) and the target is a binary
        and radare2 is available, run a pre-fuzz binary analysis pass and
        write binary-context-map.json into the output directory. The map
        is consumed by adaptive corpus generation and harness selection.
        """
        if not plan.can_run:
            msg = f"Cannot run plan: {'; '.join(plan.blockers) or 'no blockers reported'}"
            raise RuntimeError(msg)

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
            }, indent=2),
            encoding="utf-8",
        )
        (out_dir / "capability_report.json").write_text(
            json.dumps(plan.capabilities.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )

        logger.info(plan.summary())

        env_build = None
        if plan.env_build:
            from packages.fuzzing.env_build import env_build_for_fuzzing
            env_build = env_build_for_fuzzing(
                plan.target.path, out_dir, build=plan.env_build_consent,
                sanitizer=env_sanitizer, cmplog=env_cmplog)
            if not env_build.ok:
                raise RuntimeError(
                    f"env build failed ({env_build.reason}): "
                    f"{env_build.detail or 'see build log'}"
                )
            logger.info(
                "Env-built %d AFL-instrumented binar%s in %s%s: %s",
                len(env_build.binaries),
                "y" if len(env_build.binaries) == 1 else "ies",
                env_build.base_image,
                " (GUESSED build command)" if env_build.guessed else "",
                ", ".join(env_build.binaries),
            )

        def _discard_env_rootfs() -> None:
            """Idempotent rootfs cleanup — every exit from the section
            between a successful env build and campaign end runs
            through here (corpus generation scans the hostile source
            tree, a real interrupt window on large repos; a leaked
            rootfs is several GB in the run dir)."""
            if (env_build is None or not env_build.rootfs
                    or keep_env_rootfs):
                return
            if not env_build.rootfs.exists():
                return
            import shutil as _shutil
            _shutil.rmtree(env_build.rootfs, ignore_errors=True)
            logger.info(
                "env rootfs removed (%s); the campaign outputs and the "
                "read-only extracted binaries remain — re-run the build "
                "to reproduce crashes in-image, or pass "
                "--keep-env-rootfs to retain it",
                env_build.rootfs,
            )

        try:
            corpus_dir, generated_corpus_info = self._prepare_corpus(
                plan,
                out_dir=out_dir,
                corpus_dir=corpus_dir,
                source_context_dir=source_context_dir,
                seed_profile=seed_profile,
            )
        except BaseException:
            _discard_env_rootfs()
            raise

        # Optional pre-fuzz: binary-level adversarial analysis via radare2.
        # Mirrors what /understand --map does for source-level targets.
        if binary_understand and plan.target.kind in _BINARY_UNDERSTAND_KINDS:
            if not plan.capabilities.radare2:
                logger.info("Skipping radare2 binary analysis: radare2 not found")
            elif not plan.capabilities.has_r2pipe:
                logger.info("Skipping radare2 binary analysis: Python r2pipe module not installed")
            else:
                try:
                    from packages.binary_analysis import analyse_blackbox_binary
                    decompiler = "r2ghidra" if plan.capabilities.has_r2ghidra else "pdc"
                    logger.info("=" * 70)
                    logger.info("BINARY CONTEXT ANALYSIS (radare2)")
                    logger.info("=" * 70)
                    logger.info("radare2: %s", plan.capabilities.radare2)
                    logger.info("decompiler: %s", decompiler)
                    logger.info("output: %s", out_dir / 'binary-context-map.json')
                    binary_result = analyse_blackbox_binary(
                        plan.target.path,
                        out_dir=out_dir,
                        llm=self.llm,
                    )
                    logger.info(
                        "binary evidence map written: %s entry point candidates, %s sinks, %s candidate flows", len(binary_result.context_map.get('entry_points', [])), len(binary_result.context_map.get('sink_details', [])), len(binary_result.context_map.get('candidate_flows', []))
                    )
                except Exception as e:  # noqa: BLE001 — non-fatal
                    logger.warning("Binary understand failed (non-fatal): %s", e)

        if plan.fuzzer == "afl":
            try:
                result = self._run_afl(
                    plan, out_dir, duration_seconds, corpus_dir, dict_path,
                    env_build=env_build, env_target=env_target)
            finally:
                _discard_env_rootfs()
            if env_build is not None:
                result["env_build"] = {
                    "base_image": env_build.base_image,
                    "build_command": env_build.command,
                    "build_command_source": env_build.command_source,
                    "guessed_build_command": env_build.guessed,
                    "binaries": env_build.binaries,
                    "sanitizer": getattr(env_build, "sanitizer", ""),
                    "cmplog": bool(getattr(env_build, "cmplog_binaries",
                                           {})),
                }
        elif plan.fuzzer == "libfuzzer":
            result = self._run_libfuzzer(plan, out_dir, duration_seconds, corpus_dir, dict_path)
        else:
            msg = f"Fuzzer '{plan.fuzzer}' not yet wired into orchestrator."
            raise RuntimeError(msg)
        if generated_corpus_info:
            result["generated_corpus"] = generated_corpus_info
        if binary_understand and plan.target.kind in _BINARY_UNDERSTAND_KINDS:
            try:
                from packages.binary_analysis import append_fuzz_evidence_to_run

                bundle = append_fuzz_evidence_to_run(
                    plan.target.path,
                    out_dir=out_dir,
                    fuzz_dir=out_dir,
                )
                if bundle is not None:
                    logger.info(
                        "binary graph updated with fuzz evidence: %s crash witnesses", len(bundle.crashes)
                    )
            except Exception as e:  # noqa: BLE001 — non-fatal
                logger.warning("Binary fuzz evidence append failed (non-fatal): %s", e)

        # Fuzz → audit coverage bridge: when the target carries gcov
        # instrumentation, replay the corpus and emit per-function
        # coverage-fuzz.json for /audit's priority scorer and review
        # context. Degrades silently on uninstrumented targets.
        try:
            from packages.fuzzing.coverage_bridge import emit_fuzz_coverage

            stats = result.get("stats") or {}
            iterations = 0
            for k in ("execs_done", "total_execs", "executions"):
                try:
                    iterations = int(stats.get(k) or 0)
                except (TypeError, ValueError):
                    iterations = 0
                if iterations:
                    break
            cov_path = emit_fuzz_coverage(
                out_dir,
                binary=plan.target.path,
                source_root=source_context_dir,
                input_mode=result.get("input_mode", "file"),
                iterations=iterations,
                crashes=int(result.get("crashes") or 0),
            )
            if cov_path is not None:
                result["fuzz_coverage"] = str(cov_path)
        except Exception as e:  # noqa: BLE001 — bridge is best-effort
            logger.warning("Fuzz coverage bridge failed (non-fatal): %s", e)
        return result

    def _prepare_corpus(
        self,
        plan: CampaignPlan,
        *,
        out_dir: Path,
        corpus_dir: Path | None,
        source_context_dir: Path | None,
        seed_profile: str = "default",
    ) -> tuple[Path | None, dict[str, Any] | None]:
        """Generate or materialise a seed corpus when the caller did not provide one."""
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
        except Exception as e:  # noqa: BLE001 — falls back to builtin
            logger.warning("Autonomous corpus generator unavailable: %s", e)
            return self._prepare_builtin_corpus(out_dir, seed_profile)

        try:
            seeds = generator.generate_autonomous_corpus(generated_dir, max_seeds=64)
        except Exception as e:  # noqa: BLE001 — falls back to builtin
            logger.warning("Autonomous corpus generation failed: %s", e)
            return self._prepare_builtin_corpus(out_dir, seed_profile)
        if seeds <= 0:
            return self._prepare_builtin_corpus(out_dir, seed_profile)

        info = {
            "source": "autonomous",
            "path": str(generated_dir),
            "seeds": seeds,
            "source_context_dir": str(context_dir),
            "commands_detected": sorted(generator.detected_commands.keys()),
            "formats_detected": sorted(generator.detected_formats),
        }
        (out_dir / "generated-corpus.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
        logger.info("Generated agentic fuzz corpus: %s seeds at %s", seeds, generated_dir)
        return generated_dir, info

    def _prepare_builtin_corpus(
        self,
        out_dir: Path,
        seed_profile: str = "default",
    ) -> tuple[Path, dict[str, Any]]:
        """Materialise RAPTOR's checked-in baseline corpus for this campaign."""
        from packages.fuzzing.seed_corpus import prepare_builtin_seed_corpus

        seed_dir = out_dir / "seed-corpus"
        manifest = prepare_builtin_seed_corpus(seed_dir, profile=seed_profile)
        info = {
            "source": "raptor_builtin_seed_corpus",
            "profile": seed_profile,
            "path": str(seed_dir),
            "seeds": manifest["seed_count"],
            "manifest": str(seed_dir / "manifest.json"),
        }
        (out_dir / "seed-corpus.json").write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
        logger.info(
            "Using RAPTOR built-in seed corpus: %s seeds at %s", manifest['seed_count'], seed_dir
        )
        return seed_dir, info

    def _run_afl(
        self,
        plan: CampaignPlan,
        out_dir: Path,
        duration_seconds: int,
        corpus_dir: Path | None,
        dict_path: Path | None,
        env_build=None,
        env_target: str | None = None,
    ) -> dict[str, Any]:
        from packages.fuzzing.afl_runner import AFLRunner
        from packages.fuzzing.telemetry import FuzzingTelemetry

        afl_out = out_dir / "afl"
        if env_build is not None:
            rel = self._pick_env_binary(env_build, env_target)
            extra_flags: list[str] = []
            if getattr(env_build, "sanitizer", "") == "asan":
                # ASAN shadow mappings blow AFL's default memory limit
                extra_flags += ["-m", "none"]
            runner = AFLRunner(
                binary_path=env_build.rootfs / "src" / rel,
                corpus_dir=corpus_dir,
                output_dir=afl_out,
                dict_path=dict_path,
                check_sanitizers=True,
                use_showmap=True,
                sandbox_rootfs=env_build.rootfs,
                binary_in_rootfs=env_build.binaries[rel],
                afl_fuzz_path=env_build.afl_fuzz,
                cmplog_in_rootfs=getattr(env_build, "cmplog_binaries",
                                         {}).get(rel),
                extra_afl_flags=extra_flags or None,
            )
            telemetry_target = f"{plan.target.path} :: {rel} (env-built)"
        else:
            runner = AFLRunner(
                binary_path=plan.target.path,
                corpus_dir=corpus_dir,
                output_dir=afl_out,
                dict_path=dict_path,
                check_sanitizers=True,
                use_showmap=True,
            )
            telemetry_target = str(plan.target.path)
        runner.telemetry = FuzzingTelemetry(
            out_dir=out_dir,
            fuzzer="afl++",
            target=telemetry_target,
        )
        runner.telemetry.start()
        try:
            crashes, crashes_dir = runner.run_fuzzing(duration=duration_seconds)
        finally:
            runner.telemetry.stop()
        return {
            "fuzzer": "afl",
            "campaign_failed": bool(getattr(runner, "campaign_failed",
                                            False)),
            "crashes": crashes,
            # None (not "None") when the campaign produced no crashes
            # and AFL never created a crashes directory — downstream
            # consumers (_resolve_crashes_dir, raptor_agentic) treat
            # falsy as "no crashes dir".
            "crashes_dir": str(crashes_dir) if crashes_dir else None,
            "stats": runner.get_stats(),
            "input_mode": getattr(runner, "input_mode", "file"),
            "telemetry": str(out_dir / "fuzz-summary.json"),
            "events": str(out_dir / "fuzz-events.jsonl"),
        }

    @staticmethod
    def _pick_env_binary(env_build, env_target: str | None) -> str:
        """Choose which env-built binary to fuzz.

        Explicit ``env_target`` (repo-relative) wins; otherwise the
        single artifact; otherwise the sorted-first with the full list
        logged so the operator can re-run with an explicit choice.
        """
        rels = sorted(env_build.binaries)
        if env_target:
            if env_target not in env_build.binaries:
                raise RuntimeError(
                    f"--env-target {env_target!r} is not among the "
                    f"built binaries: {', '.join(rels)}"
                )
            return env_target
        if len(rels) > 1:
            logger.warning(
                "build produced %d binaries; fuzzing %s — pass "
                "--env-target <name> to pick another (%s)",
                len(rels), rels[0], ", ".join(rels),
            )
        return rels[0]

    def _run_libfuzzer(
        self,
        plan: CampaignPlan,
        out_dir: Path,
        duration_seconds: int,
        corpus_dir: Path | None,
        dict_path: Path | None,
    ) -> dict[str, Any]:
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
