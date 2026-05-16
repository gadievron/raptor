#!/usr/bin/env python3
"""
RAPTOR AFL++ Runner

Orchestrates AFL++ fuzzing campaigns with parallel workers.
"""

import os
import shutil
import subprocess

from core.sandbox import run as _sandbox_run, run_trusted as _run_trusted
# _run_trusted: read-only tools (strings, --help checks) — no namespace overhead.
# Full sandbox for afl-fuzz / afl-showmap (execute untrusted binary): network
# block + Landlock (target=output=self.output_dir — AFL reads and writes the
# same corpus/queue/crash directories).
import time
from pathlib import Path
from typing import List, Optional, Tuple

from core.logging import get_logger

logger = get_logger()


class AFLRunner:
    """Manages AFL++ fuzzing campaigns."""

    def __init__(
        self,
        binary_path: Path,
        corpus_dir: Optional[Path] = None,
        output_dir: Optional[Path] = None,
        dict_path: Optional[Path] = None,
        input_mode: str = "stdin",
        check_sanitizers: bool = False,
        recompile_guide: bool = False,
        use_showmap: bool = False,
        extra_afl_flags: Optional[List[str]] = None,
    ):
        self.binary = Path(binary_path).resolve()
        if not self.binary.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")
        
        if not self.binary.is_file():
            raise ValueError(f"Path is not a file: {binary_path}")
        
        if not self.binary.stat().st_mode & 0o111:  # Check if executable
            raise PermissionError(f"Binary is not executable: {binary_path}")

        # Anchor default output to RaptorConfig.get_out_dir() so
        # fuzz output lands under the operator-configured run
        # base, NOT a literal `out/` relative to whatever
        # cwd the script happened to launch from. Pre-fix
        # `Path(f"out/fuzz_{name}")` was relative to the current
        # working directory at runner-construction time. Two
        # failure modes:
        #   * Operator running RAPTOR from `~/work/foo/` got
        #     fuzz output in `~/work/foo/out/fuzz_*` instead of
        #     the configured project run dir.
        #   * Script invoked via cron / systemd / CI from `/`
        #     wrote `/out/fuzz_*` (or failed with permission
        #     denied), polluting the root filesystem.
        # `RaptorConfig.get_out_dir()` resolves to the active
        # project's run dir (or DEFAULT_OUTPUT_BASE when no
        # project is active) per the standard run-lifecycle
        # rule.
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            from core.config import RaptorConfig
            self.output_dir = RaptorConfig.get_out_dir() / f"fuzz_{self.binary.stem}"
        # Resolve corpus AFTER output_dir so the default-corpus
        # path can anchor under output_dir (rather than CWD).
        self.corpus_dir = Path(corpus_dir) if corpus_dir else self._create_default_corpus()
        self.dict_path = Path(dict_path) if dict_path else None
        self.input_mode = input_mode
        self.check_sanitizers = check_sanitizers
        self.recompile_guide = recompile_guide
        self.use_showmap = use_showmap
        self.extra_afl_flags = list(extra_afl_flags or [])

        # Check AFL++ availability
        self.afl_fuzz = shutil.which("afl-fuzz")
        if not self.afl_fuzz:
            raise RuntimeError(
                "AFL++ not found. Install with: sudo apt install afl++ (Ubuntu) or brew install afl++ (macOS)"
            )

        # Validate AFL command
        self._validate_afl_command()

        logger.info(f"AFL++ found: {self.afl_fuzz}")
        logger.info(f"Binary: {self.binary}")
        logger.info(f"Corpus: {self.corpus_dir}")
        logger.info(f"Output: {self.output_dir}")

    def _validate_afl_command(self) -> None:
        """Validate that AFL command works with basic arguments."""
        try:
            # Test AFL with --help flag (should exit cleanly)
            result = _run_trusted(
                [self.afl_fuzz, "--help"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode not in [0, 1]:  # AFL --help typically returns 1
                logger.warning(f"AFL validation returned unexpected exit code: {result.returncode}")
                if result.stderr:
                    logger.warning(f"AFL stderr: {result.stderr.strip()}")
        except subprocess.TimeoutExpired:
            logger.warning("AFL validation timed out - AFL may be slow to start")
        except Exception as e:
            logger.warning(f"AFL validation failed: {e}")
            raise RuntimeError(f"AFL++ validation failed: {e}")

    def _create_default_corpus(self) -> Path:
        """Create minimal default corpus if none provided.

        Anchored to ``self.output_dir`` (not CWD) so running
        ``/fuzz`` from inside a target tree does NOT plant seed
        files in ``<target>/out/corpus_default/``.
        """
        corpus = self.output_dir / "corpus_default"
        corpus.mkdir(parents=True, exist_ok=True)

        # Create some basic seed inputs
        seeds = [
            b"A" * 10,
            b"test\n",
            b"\x00\x01\x02\x03",
            b"GET / HTTP/1.0\r\n\r\n",
        ]

        for idx, seed in enumerate(seeds):
            (corpus / f"seed{idx}").write_bytes(seed)

        logger.info(f"Created default corpus with {len(seeds)} seeds")
        return corpus

    def check_binary_instrumentation(self) -> bool:
        """Check if binary is instrumented for AFL."""
        # Try to detect AFL instrumentation. `strings` runs over
        # the operator-supplied (potentially attacker-controlled)
        # target binary. Pre-fix this had no `timeout=` — a
        # malformed binary with extreme string-table density
        # could pin `strings` for many minutes (well-known DoS:
        # a 1 GB ELF with .rodata of nothing but printable ASCII
        # produces gigabytes of stdout that strings tries to
        # buffer). Cap at 60 seconds — well above what a
        # legitimate scan needs (a normal multi-MB binary
        # finishes in << 1 second).
        try:
            result = _run_trusted(
                ["strings", str(self.binary)],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            logger.warning(
                "strings %s exceeded 60s — assuming not "
                "AFL-instrumented (treat as needs-QEMU)",
                self.binary,
            )
            return False

        is_instrumented = "__AFL" in result.stdout or "afl" in result.stdout.lower()

        if is_instrumented:
            logger.info("✓ Binary appears to be AFL-instrumented")
        else:
            logger.warning("⚠ Binary does not appear to be AFL-instrumented")
            logger.warning("  Consider recompiling with afl-gcc/afl-clang for better results")
            logger.warning("  Using QEMU mode for non-instrumented binary")

        return is_instrumented

    def _check_afl_compatibility(self) -> None:
        """Check if the system is compatible with AFL++."""
        import platform
        
        # Check if we're on macOS
        if platform.system() == "Darwin":
            logger.info("macOS detected - checking AFL compatibility...")
            
            # Try to run afl-fuzz with a simple help command to check shared memory
            try:
                result = _run_trusted(
                    ["afl-fuzz", "--help"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                # If afl-fuzz --help fails with shmget error, the system needs configuration
                if "shmget" in result.stderr or "No space left on device" in result.stderr:
                    logger.error("❌ AFL shared memory configuration issue detected!")
                    logger.error("   On macOS, AFL requires higher shared memory limits.")
                    logger.error("   Run the following commands:")
                    logger.error("   1. afl-system-config (as root/sudo)")
                    logger.error("   2. Reboot your system")
                    logger.error("   Alternative: Use pre-compiled binaries without AFL instrumentation")
                    raise RuntimeError("AFL shared memory not configured on macOS")
                    
            except subprocess.TimeoutExpired:
                logger.warning("AFL --help command timed out")
            except FileNotFoundError:
                logger.error("afl-fuzz not found in PATH")
                raise RuntimeError("AFL++ not installed")
            except Exception as e:
                logger.warning(f"AFL compatibility check failed: {e}")

    def check_binary_sanitizers(self) -> bool:
        """Check if binary is compiled with sanitizers like ASAN.

        See `check_binary_instrumentation` for the timeout
        rationale — same 60s cap, same DoS class.
        """
        try:
            result = _run_trusted(
                ["strings", str(self.binary)],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            logger.warning(
                "strings %s exceeded 60s — sanitizer check "
                "skipped, assuming none",
                self.binary,
            )
            return False

        has_asan = "asan" in result.stdout.lower() or "__asan" in result.stdout.lower()
        has_ubsan = "ubsan" in result.stdout.lower() or "__ubsan" in result.stdout.lower()

        if has_asan or has_ubsan:
            logger.info("✓ Binary appears to be compiled with sanitizers")
            if has_asan:
                logger.info("  - AddressSanitizer (ASAN) detected")
            if has_ubsan:
                logger.info("  - UndefinedBehaviorSanitizer (UBSAN) detected")
            return True
        else:
            logger.warning("⚠ Binary does not appear to be compiled with sanitizers")
            logger.warning("  Consider recompiling with -fsanitize=address for better bug detection")
            return False

    def show_recompile_guide(self) -> None:
        """Show guide for recompiling binary with AFL instrumentation and sanitizers."""
        print("\n" + "=" * 70)
        print("RECOMPILATION GUIDE FOR OPTIMAL AFL FUZZING")
        print("=" * 70)
        print("To get the best results from AFL, recompile your binary with:")
        print("1. AFL instrumentation (for coverage-guided fuzzing)")
        print("2. Sanitizers (for detecting more bugs)")
        print()
        print("Example commands:")
        print("  # For C/C++ with AFL-gcc:")
        print(f"  AFL_CC=afl-gcc AFL_CXX=afl-g++ CC=afl-gcc CXX=afl-g++ \\")
        print(f"  CFLAGS='-fsanitize=address -fsanitize=undefined' \\")
        print(f"  CXXFLAGS='-fsanitize=address -fsanitize=undefined' \\")
        print(f"  make clean && make")
        print()
        print("  # For C/C++ with AFL-clang:")
        print(f"  AFL_CC=afl-clang AFL_CXX=afl-clang++ CC=afl-clang CXX=afl-clang++ \\")
        print(f"  CFLAGS='-fsanitize=address -fsanitize=undefined' \\")
        print(f"  CXXFLAGS='-fsanitize=address -fsanitize=undefined' \\")
        print(f"  make clean && make")
        print()
        print("  # For Rust (if applicable):")
        print("  RUSTFLAGS='-fsanitize=address' cargo build --release")
        print("  # Then instrument with afl-rustc")
        print()
        print("After recompilation, run fuzzing again for better coverage and bug detection.")
        print("=" * 70)

    def run_fuzzing(
        self,
        duration: int = 3600,
        parallel_jobs: int = 1,
        timeout_ms: int = 1000,
        max_crashes: Optional[int] = None,
    ) -> Tuple[int, Path]:
        """
        Run AFL++ fuzzing campaign.

        Args:
            duration: Fuzzing duration in seconds
            parallel_jobs: Number of parallel AFL instances
            timeout_ms: Timeout per execution in milliseconds
            max_crashes: Stop after finding N unique crashes

        Returns:
            Tuple of (num_crashes, crashes_dir)
        """
        logger.info("=" * 70)
        logger.info("STARTING AFL++ FUZZING CAMPAIGN")
        logger.info("=" * 70)
        logger.info(f"Duration: {duration}s ({duration/60:.1f} minutes)")
        logger.info(f"Parallel jobs: {parallel_jobs}")
        logger.info(f"Timeout: {timeout_ms}ms")
        if max_crashes:
            logger.info(f"Stop after: {max_crashes} crashes")

        # Pre-flight check for AFL compatibility
        self._check_afl_compatibility()

        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Check instrumentation
        is_instrumented = self.check_binary_instrumentation()

        # Additional checks if requested
        if self.check_sanitizers:
            self.check_binary_sanitizers()

        if self.recompile_guide:
            self.show_recompile_guide()

        # Start AFL instances
        processes = []

        for job_id in range(parallel_jobs):
            is_main = job_id == 0
            instance_name = "main" if is_main else f"secondary{job_id}"

            cmd = self._build_afl_command(
                instance_name=instance_name,
                is_main=is_main,
                timeout_ms=timeout_ms,
                use_qemu=not is_instrumented,
            )

            logger.info(f"Starting AFL instance: {instance_name}")
            logger.debug(f"Command: {' '.join(cmd)}")

            # AFL refuses to run if the host's core_pattern pipes cores (apport,
            # systemd-coredump) or the CPU governor is not 'performance'. Both
            # are the default on modern Linux desktops, and both are outside
            # RAPTOR's control — asking the operator to tune them for every
            # fuzzing run is not realistic. Setting these env vars tells AFL
            # to tolerate both: we lose a small amount of speed and the
            # guarantee that external cores are captured (AFL still writes its
            # own crash artefacts under crashes/).
            # Use get_safe_env() as the base, NOT os.environ.copy().
            # Pre-fix the AFL subprocess inherited the operator's
            # FULL environment including any RAPTOR-internal vars
            # (RAPTOR_*, ANTHROPIC_API_KEY, OPENAI_API_KEY,
            # AWS_*, GH_TOKEN, etc.). AFL itself doesn't
            # interpret most of those, but:
            #   * The fuzzed binary inherits the same env. If the
            #     target reads `getenv("AWS_*")` (boto SDK,
            #     credentials chain) or shells out (passing env
            #     to libc functions), the operator's
            #     credentials reach attacker-controlled code in
            #     the fuzz target.
            #   * On crash, AFL writes the env to the crash
            #     metadata in `crashes/`; reports / triage flows
            #     that include those files leak credentials.
            # `get_safe_env()` strips dangerous / sensitive
            # variables (see core/config.py DANGEROUS_ENV_VARS,
            # LLM_API_KEY_VARS) by default. AFL_* vars get
            # added explicitly below.
            from core.config import RaptorConfig
            afl_env = RaptorConfig.get_safe_env()
            afl_env.setdefault("AFL_SKIP_CPUFREQ", "1")
            afl_env.setdefault("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")

            # Intentionally bare Popen — AFL fuzz daemon is long-running and
            # needs streaming output. Cannot use sandbox_run (blocks until exit).
            #
            # `stdout=DEVNULL` instead of `PIPE`. Pre-fix both
            # streams went to PIPE buffers without ANY drainer
            # thread consuming them while AFL ran. AFL's
            # status-screen writes to stdout periodically; after
            # roughly the OS-default 64KB pipe buffer filled, the
            # next write blocked AFL waiting for a reader — the
            # whole fuzzing daemon stalled silently with no
            # error visible to the operator (process showed as
            # alive but execs/sec dropped to 0). The stall could
            # last hours before the operator noticed in the
            # status dashboard.
            #
            # stdout=DEVNULL discards the (verbose, redundant
            # with our own status capture) AFL output without
            # buffer-fill risk. stderr stays PIPE because:
            #  (1) it's much lower volume — AFL only writes to
            #      stderr on startup errors and shutdown,
            #  (2) the post-exit `proc.communicate(timeout=1)`
            #      below collects it for diagnostic logging
            #      (the shmget / SHM-config error messages
            #      operators rely on for setup troubleshooting).
            # 64KB stderr pre-exit is plenty for either case.
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                env=afl_env,
            )
            processes.append((instance_name, proc))

        # Monitor fuzzing
        start_time = time.time()
        crashes_dir = self.output_dir / "main" / "crashes"
        last_logged_crashes = 0
        last_status_time = 0

        try:
            while time.time() - start_time < duration:
                time.sleep(10)  # Check every 10 seconds
                current_time = time.time()

                # Count unique crashes
                if crashes_dir.exists():
                    num_crashes = len([f for f in crashes_dir.iterdir() if f.name.startswith("id:")])

                    if num_crashes > last_logged_crashes:
                        logger.info(f"Progress: {num_crashes} unique crashes found")
                        last_logged_crashes = num_crashes

                    if max_crashes and num_crashes >= max_crashes:
                        logger.info(f"✓ Reached {max_crashes} crashes, stopping early")
                        break

                # Periodic status update (every 60 seconds)
                if current_time - last_status_time >= 60:
                    elapsed = current_time - start_time
                    stats = self.get_stats()
                    if stats:
                        execs_per_sec = stats.get('execs_per_sec', 'N/A')
                        total_execs = stats.get('execs_done', 'N/A')
                        paths_found = stats.get('paths_found', 'N/A')
                        stability = stats.get('stability', 'N/A')
                        bitmap_cvg = stats.get('bitmap_cvg', 'N/A')
                        
                        logger.info(f"Status: {elapsed:.0f}s elapsed | {execs_per_sec} exec/s | {total_execs} total execs | {paths_found} paths | {stability}% stable | {bitmap_cvg}% coverage")
                    else:
                        logger.info(f"Status: {elapsed:.0f}s elapsed (no stats available yet)")
                    
                    last_status_time = current_time

                # Check if all processes are still running
                running_processes = []
                for name, proc in processes:
                    if proc.poll() is not None:
                        # Process has exited - capture error output
                        exit_code = proc.returncode
                        try:
                            stdout, stderr = proc.communicate(timeout=1)
                            if stderr and stderr.strip():
                                # stderr is already a string due to text=True in Popen
                                stderr_str = stderr.strip()
                                logger.error(f"AFL instance {name} exited with code {exit_code}")
                                logger.error(f"AFL stderr: {stderr_str}")

                                # Check for common AFL startup errors
                                if "shmget() failed" in stderr_str or "No space left on device" in stderr_str or "Invalid argument" in stderr_str:
                                    logger.error("=" * 70)
                                    logger.error("AFL SHARED MEMORY CONFIGURATION ERROR")
                                    logger.error("=" * 70)
                                    logger.error("Your system's shared memory limits are too low for AFL++.")
                                    logger.error("")
                                    logger.error("To fix this, run:")
                                    logger.error("  sudo afl-system-config")
                                    logger.error("")
                                    logger.error("Or manually configure with:")
                                    logger.error("  sudo sysctl kern.sysv.shmmax=524288000")
                                    logger.error("  sudo sysctl kern.sysv.shmall=131072000")
                                    logger.error("  sudo sysctl kern.sysv.shmseg=48")
                                    logger.error("")
                                    logger.error("After running these commands, try fuzzing again.")
                                    logger.error("=" * 70)

                            else:
                                logger.warning(f"AFL instance {name} exited unexpectedly with code {exit_code}")
                        except subprocess.TimeoutExpired:
                            logger.error(f"AFL instance {name} exited with code {exit_code} (could not read output)")
                    else:
                        running_processes.append((name, proc))
                
                processes = running_processes
                
                # If no processes are running, stop fuzzing
                if not processes:
                    logger.error("All AFL instances have exited - stopping fuzzing campaign")
                    break

        finally:
            # Stop all AFL instances. Use communicate(timeout=5)
            # NOT wait(timeout=5) — pre-fix `proc.wait()` could
            # deadlock indefinitely if AFL had buffered output in
            # the stderr PIPE that no one had drained (stdout is
            # DEVNULL post-batch-450; stderr is still PIPE for
            # diagnostic capture). On SIGTERM AFL writes a
            # shutdown banner + final stats to stderr — for
            # campaigns that ran long enough to fill 64KB of
            # stderr, wait() blocked forever waiting for the
            # process to exit while the process blocked forever
            # waiting for stderr-pipe space. communicate() drains
            # the pipe and waits in a single thread-safe call.
            logger.info("Stopping AFL instances...")
            for name, proc in processes:
                proc.terminate()
                try:
                    proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    logger.warning(f"Force killing {name}")
                    proc.kill()
                    try:
                        proc.communicate(timeout=2)
                    except subprocess.TimeoutExpired:
                        # Kernel-level wedge — at this point we've
                        # done what we can; orphan the proc.
                        pass

        # Count final crashes
        total_crashes = 0
        if crashes_dir.exists():
            crash_files = [f for f in crashes_dir.iterdir() if f.name.startswith("id:")]
            total_crashes = len(crash_files)

        elapsed = time.time() - start_time
        
        # Final status report
        final_stats = self.get_stats()
        if final_stats:
            total_execs = final_stats.get('execs_done', 'N/A')
            execs_per_sec = final_stats.get('execs_per_sec', 'N/A')
            paths_found = final_stats.get('paths_found', 'N/A')
            stability = final_stats.get('stability', 'N/A')
            bitmap_cvg = final_stats.get('bitmap_cvg', 'N/A')
            
            logger.info("=" * 70)
            logger.info("FINAL FUZZING STATISTICS")
            logger.info("=" * 70)
            logger.info(f"Total executions: {total_execs}")
            logger.info(f"Executions per second: {execs_per_sec}")
            logger.info(f"Paths found: {paths_found}")
            logger.info(f"Stability: {stability}%")
            logger.info(f"Bitmap coverage: {bitmap_cvg}%")
            logger.info(f"Unique crashes: {total_crashes}")
            logger.info("=" * 70)
        logger.info("=" * 70)
        logger.info("FUZZING CAMPAIGN COMPLETE")
        logger.info("=" * 70)
        logger.info(f"Duration: {elapsed:.1f}s")
        logger.info(f"Unique crashes: {total_crashes}")
        logger.info(f"Crashes dir: {crashes_dir}")
        logger.info("=" * 70)

        # Run coverage analysis if requested
        coverage_stats = {}
        if self.use_showmap:
            logger.info("Running coverage analysis with afl-showmap...")
            coverage_stats = self.run_showmap()
            if coverage_stats:
                logger.info("Coverage stats:")
                for key, value in coverage_stats.items():
                    logger.info(f"  {key}: {value}")

        return total_crashes, crashes_dir

    def _build_afl_command(
        self,
        instance_name: str,
        is_main: bool,
        timeout_ms: int,
        use_qemu: bool = False,
    ) -> List[str]:
        """Build AFL command line."""
        cmd = [self.afl_fuzz]

        # Input/output directories
        if is_main:
            cmd.extend(["-i", str(self.corpus_dir)])
        else:
            cmd.extend(["-i", "-"])  # Secondary instances sync from main

        cmd.extend(["-o", str(self.output_dir)])

        # Instance name
        if is_main:
            cmd.extend(["-M", instance_name])
        else:
            cmd.extend(["-S", instance_name])

        # Timeout
        cmd.extend(["-t", str(timeout_ms)])

        # QEMU mode if not instrumented
        if use_qemu:
            cmd.append("-Q")

        # Disable CPU affinity for now
        cmd.append("-d")

        # Dictionary if provided
        if self.dict_path and self.dict_path.exists():
            cmd.extend(["-x", str(self.dict_path)])

        # Optional SAGE-derived or operator-supplied AFL++ flags (before ``--``).
        if self.extra_afl_flags:
            cmd.extend(self.extra_afl_flags)

        # Target binary
        cmd.append("--")
        cmd.append(str(self.binary))

        # Input mode
        if self.input_mode == "file":
            cmd.append("@@")
        # For stdin, AFL pipes input automatically

        return cmd

    def get_stats(self) -> dict:
        """Get fuzzing statistics from AFL."""
        stats_file = self.output_dir / "main" / "fuzzer_stats"

        if not stats_file.exists():
            return {}

        stats = {}
        # Explicit `encoding="utf-8"` + `errors="replace"`. Pre-fix
        # bare `open(stats_file)` used the host locale encoding —
        # AFL writes its `fuzzer_stats` file in UTF-8 (the C side
        # writes ASCII keys + UTF-8 stringified values), so a
        # latin-1 / cp1252 default could mojibake non-ASCII path
        # components in `target_mode`, `command_line`, etc., and
        # raise UnicodeDecodeError on operator paths with i18n
        # characters. `errors="replace"` keeps the parse going even
        # if a byte sequence somehow doesn't decode (preferred over
        # crashing the whole stats read for a single bad value).
        with open(stats_file, encoding="utf-8", errors="replace") as f:
            for line in f:
                if ":" in line:
                    key, value = line.strip().split(":", 1)
                    stats[key.strip()] = value.strip()

        return stats

    def run_showmap(self) -> dict:
        """Run afl-showmap to analyze coverage."""
        showmap_cmd = ["afl-showmap", "-o", "/dev/null", "--", str(self.binary)]

        stdin_input = None
        test_input = None

        if self.input_mode == "file":
            showmap_cmd.append("@@")
            # For file mode, use first corpus file as the input file
            test_input = self.corpus_dir / "seed0" if (self.corpus_dir / "seed0").exists() else None
            if test_input:
                # AFL will replace @@ with the input file path
                # We need to set AFL_INPUT_FILE environment variable
                pass
        else:
            # For stdin mode, need to provide input via stdin parameter
            test_input = self.corpus_dir / "seed0" if (self.corpus_dir / "seed0").exists() else None
            if test_input:
                try:
                    stdin_input = open(test_input, 'rb')
                except Exception as e:
                    logger.warning(f"Failed to open test input {test_input}: {e}")
                    return {}
            else:
                logger.warning("No test input for afl-showmap with stdin mode")
                return {}

        try:
            from core.config import RaptorConfig
            env = RaptorConfig.get_safe_env()
            if self.input_mode == "file" and test_input:
                env['AFL_INPUT_FILE'] = str(test_input)

            # Landlock readable_paths: afl-showmap needs to READ
            # the target binary (self.binary) and the input
            # corpus file (test_input). Both typically live
            # OUTSIDE self.output_dir — the binary in the
            # operator's build dir, the input under the project's
            # corpus tree. Pre-fix the only readable+writable
            # path was self.output_dir, so:
            #
            #   * afl-showmap couldn't open the binary →
            #     "afl-showmap: cannot open binary" error,
            #     coverage report empty, operators saw "0%
            #     coverage" with no signal that landlock was the
            #     blocker.
            #   * AFL_INPUT_FILE pointed outside the readable
            #     scope → afl-showmap couldn't read it either.
            #
            # Add binary parent + input parent to readable_paths
            # so afl-showmap can open both. Output stays
            # restricted to output_dir.
            readable_paths = [str(Path(self.binary).parent)]
            if test_input:
                readable_paths.append(str(Path(test_input).parent))

            # Bound afl-showmap wallclock. Pre-fix the call had no
            # `timeout=` — afl-showmap runs the (attacker-controlled)
            # target binary with a single corpus entry to extract
            # coverage; a target with an infinite loop, a sleep, or
            # any non-terminating control flow on the chosen input
            # would hang the analyser indefinitely. afl-showmap's
            # own `-t` flag bounds the per-execution timeout, but a
            # subprocess-level safety net catches the wedge case
            # where the target ignores SIGALRM (e.g. a binary that
            # blocks signals or installs a custom handler that
            # masks the timeout). 5 minutes is generous: typical
            # showmap runs are sub-second; even instrumentation-
            # heavy binaries finish in well under a minute.
            result = _sandbox_run(
                showmap_cmd,
                block_network=True,
                target=str(self.output_dir),
                output=str(self.output_dir),
                readable_paths=readable_paths,
                capture_output=True,
                text=True,
                stdin=stdin_input,
                cwd=str(self.output_dir),
                env=env,
                timeout=300,
            )

            # Parse output for coverage info
            if result.returncode == 0:
                coverage = {}
                for line in result.stdout.split('\n'):
                    if ':' in line and 'total' in line.lower():
                        parts = line.split(':')
                        if len(parts) == 2:
                            key = parts[0].strip()
                            value = parts[1].strip()
                            coverage[key] = value
                logger.info("Coverage analysis complete")
                return coverage
            else:
                logger.warning(f"afl-showmap failed: {result.stderr}")
                return {}

        except Exception as e:
            logger.warning(f"Error running afl-showmap: {e}")
            return {}
        finally:
            if stdin_input:
                stdin_input.close()
