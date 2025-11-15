#!/usr/bin/env python3
"""
RAPTOR AFL++ Runner

Orchestrates AFL++ fuzzing campaigns with parallel workers.
"""

import os
import shutil
import subprocess
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
    ):
        self.binary = Path(binary_path).resolve()
        if not self.binary.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")
        
        if not self.binary.is_file():
            raise ValueError(f"Path is not a file: {binary_path}")
        
        if not self.binary.stat().st_mode & 0o111:  # Check if executable
            raise PermissionError(f"Binary is not executable: {binary_path}")

        self.corpus_dir = Path(corpus_dir) if corpus_dir else self._create_default_corpus()
        self.output_dir = Path(output_dir) if output_dir else Path(f"out/fuzz_{self.binary.stem}")
        self.dict_path = Path(dict_path) if dict_path else None
        self.input_mode = input_mode
        self.check_sanitizers = check_sanitizers
        self.recompile_guide = recompile_guide
        self.use_showmap = use_showmap

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
            result = subprocess.run(
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
        """Create minimal default corpus if none provided."""
        corpus = Path("out/corpus_default")
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
        # Try to detect AFL instrumentation
        result = subprocess.run(
            ["strings", str(self.binary)],
            capture_output=True,
            text=True,
        )

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
                result = subprocess.run(
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
        """Check if binary is compiled with sanitizers like ASAN."""
        result = subprocess.run(
            ["strings", str(self.binary)],
            capture_output=True,
            text=True,
        )

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

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
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
                            if stderr.strip():
                                stderr_str = stderr.decode('utf-8', errors='replace').strip()
                                logger.error(f"AFL instance {name} exited with code {exit_code}")
                                logger.error(f"AFL stderr: {stderr_str}")
                                
                                # Check for common AFL startup errors
                                if "shmget() failed" in stderr_str or "No space left on device" in stderr_str:
                                    logger.error("AFL shared memory configuration error detected!")
                                    logger.error("On macOS, run: afl-system-config")
                                    logger.error("You may need to reboot after running afl-system-config")
                                    logger.error("Alternative: Use binaries compiled without AFL instrumentation")
                                
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
            # Stop all AFL instances
            logger.info("Stopping AFL instances...")
            for name, proc in processes:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logger.warning(f"Force killing {name}")
                    proc.kill()

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
        with open(stats_file) as f:
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
            env = os.environ.copy()
            if self.input_mode == "file" and test_input:
                env['AFL_INPUT_FILE'] = str(test_input)

            result = subprocess.run(
                showmap_cmd,
                capture_output=True,
                text=True,
                stdin=stdin_input,
                cwd=str(self.output_dir),
                env=env,
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
