#!/usr/bin/env python3
"""
RAPTOR AFL++ Runner

Orchestrates AFL++ fuzzing campaigns with parallel workers.
"""

import os
import re
import shutil
import signal
import subprocess
import threading

# _run_trusted: read-only tools (strings, --help checks) — no namespace overhead.
# Full sandbox for afl-showmap AND the afl-fuzz campaign itself (both
# execute the untrusted target binary): network block + Landlock
# (target=output=self.output_dir — AFL reads and writes the same
# corpus/queue/crash directories) + seccomp + rlimits.
# The sandbox has no background/Popen API, so each afl-fuzz instance
# runs as a BLOCKING `core.sandbox.run` call on a supervising thread
# (`_SandboxedAFLInstance`). That works because AFL's control surface
# is the filesystem, not the process: the monitor loop reads
# `fuzzer_stats` and `crashes/` from the output directory.
import time
from pathlib import Path
from typing import ClassVar

from core.logging import get_logger
from core.sandbox import SandboxSetupError
from core.sandbox import run as _sandbox_run
from core.sandbox import run_trusted as _run_trusted
from packages.fuzzing.seed_corpus import prepare_builtin_seed_corpus

logger = get_logger()

_AFL_INT_RE = re.compile(r"^-?\d+")

# Stats keys that can carry the path/corpus discovery count across AFL++
# versions. Single source of truth — raptor_agentic's fuzz phase summary
# consumes the same tuple so the two lists cannot drift.
AFL_PATHS_FOUND_KEYS = (
    "paths_found", "corpus_found", "queued_paths", "cur_path", "corpus_count",
)
_AFL_CRASH_EXECS_RE = re.compile(r"(?:^|,)execs:(\d+)(?:,|$)")


# Re-exported for callers/tests; implementation shared with the
# libFuzzer runner and the capability probes.
from packages.fuzzing.env_hygiene import scrub_identity_env  # noqa: E402


class _SandboxedAFLInstance:
    """One afl-fuzz instance: a blocking ``core.sandbox.run`` call on a
    supervising thread.

    Containment matches the afl-showmap / libFuzzer siblings: network
    namespace deny, Landlock writes confined to the AFL output
    directory, seccomp escape-vector blocklist, rlimits. Reads stay
    wide (plus explicit ``readable_paths``) so targets with shared
    libraries outside the binary's directory keep working — mirroring
    the afl-showmap call shape.

    Lifetime: afl-fuzz self-terminates via ``-V <duration>`` and the
    sandbox ``timeout=`` is a wedge net above that. Early stop
    (max_crashes reached, operator interrupt) SIGTERMs the afl-fuzz
    process located by scanning ``/proc`` for this instance's unique
    argv — the host sees the real PID even when the sandbox runs the
    campaign in a PID namespace, and afl-fuzz installs a SIGTERM
    handler that stops the campaign and reaps the target.
    """

    _JOIN_GRACE_S = 15

    def __init__(
        self,
        *,
        name: str,
        cmd: list[str],
        env: dict,
        stdout_path: Path,
        stderr_path: Path,
        output_dir: Path,
        readable_paths: list[str],
        timeout_s: int,
        rootfs: Path | None = None,
    ) -> None:
        self.name = name
        self.cmd = list(cmd)
        self.env = env
        self.stdout_path = stdout_path
        self.stderr_path = stderr_path
        self.output_dir = output_dir
        self.readable_paths = list(readable_paths)
        self.timeout_s = timeout_s
        # Env-built campaigns: run afl-fuzz from the exported AFL++
        # image rootfs (sandbox image-rootfs mode). The target/output
        # host dirs are bound at their original paths inside the new
        # root, so the -o wiring and the monitor loop's host-side
        # reads are unchanged; everything else the campaign needs must
        # live under those binds (the public sandbox API forwards
        # readable_paths only under restrict_reads).
        self.rootfs = rootfs
        self.result: subprocess.CompletedProcess | None = None
        self.error: BaseException | None = None
        self._thread = threading.Thread(
            target=self._run, name=f"afl-{name}", daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        try:
            with open(self.stdout_path, "wb") as stdout_fp, \
                    open(self.stderr_path, "wb") as stderr_fp:
                extra = {}
                if self.rootfs is not None:
                    extra["rootfs"] = str(self.rootfs)
                self.result = _sandbox_run(
                    self.cmd,
                    block_network=True,
                    target=str(self.output_dir),
                    output=str(self.output_dir),
                    readable_paths=self.readable_paths,
                    cwd=str(self.output_dir),
                    env=self.env,
                    stdout=stdout_fp,
                    stderr=stderr_fp,
                    timeout=self.timeout_s,
                    caller_label=f"afl-fuzz-{self.name}",
                    # The target can read /proc/cpuinfo, /etc/os-release
                    # etc. — overlay the generic persona so the real
                    # host fingerprint never reaches attacker code
                    # (matches the afl-showmap call; smoke-verified in
                    # image-rootfs mode).
                    sanitise_host_fingerprint=True,
                    **extra,
                )
        except BaseException as exc:  # noqa: BLE001 — surfaced by the monitor loop
            self.error = exc

    def is_running(self) -> bool:
        return self._thread.is_alive()

    def returncode(self) -> int | None:
        if self.result is not None:
            return self.result.returncode
        return None

    def _host_pid(self) -> int | None:
        """Find this instance's afl-fuzz host PID via its unique argv.

        The campaign's argv is unique per instance: ``afl-fuzz`` argv0,
        the campaign output directory after ``-o``, and this instance's
        name after ``-M``/``-S``. AFL writes only its namespace-local
        PID into ``fuzzer_stats``, which is useless for host-side
        signalling — the /proc scan recovers the host PID instead.
        """
        needle_out = str(self.output_dir)
        try:
            proc_entries = list(Path("/proc").iterdir())
        except OSError:
            return None
        for pid_dir in proc_entries:
            if not pid_dir.name.isdigit():
                continue
            try:
                raw = (pid_dir / "cmdline").read_bytes()
            except OSError:
                continue
            args = [
                a.decode("utf-8", errors="replace")
                for a in raw.split(b"\0") if a
            ]
            if not args or Path(args[0]).name != "afl-fuzz":
                continue
            if needle_out not in args:
                continue
            for flag in ("-M", "-S"):
                try:
                    idx = args.index(flag)
                except ValueError:
                    continue
                if idx + 1 < len(args) and args[idx + 1] == self.name:
                    return int(pid_dir.name)
        return None

    def request_stop(self) -> None:
        """Stop the campaign: SIGTERM afl-fuzz, escalate to SIGKILL."""
        if not self.is_running():
            return
        pid = self._host_pid()
        if pid is not None:
            try:
                os.kill(pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pid = None
        self._thread.join(self._JOIN_GRACE_S)
        if self._thread.is_alive() and pid is not None:
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            self._thread.join(5)
        if self._thread.is_alive():
            logger.warning(
                "AFL instance %s did not stop on request; the sandbox "
                "timeout (%ss) will reap it",
                self.name, self.timeout_s,
            )


class AFLRunner:
    """Manages AFL++ fuzzing campaigns."""

    # AFL++ power schedules: explore (default), exploit, coe, fast, lin, quad,
    # rare. See docs/AFLplusplus/docs/power_schedules.md.
    _VALID_POWER_SCHEDULES: ClassVar[set[str]] = {
        "explore", "exploit", "coe", "fast", "lin", "quad", "rare", "seek",
    }

    def __init__(
        self,
        binary_path: Path,
        corpus_dir: Path | None = None,
        output_dir: Path | None = None,
        dict_path: Path | None = None,
        input_mode: str = "stdin",
        check_sanitizers: bool = False,
        recompile_guide: bool = False,
        use_showmap: bool = False,
        cmplog_binary: Path | None = None,
        power_schedule: str = "fast",
        use_laf_intel: bool = True,
        deterministic: bool = False,
        custom_mutator: Path | None = None,
        seed_profile: str = "default",
        extra_afl_flags: list[str] | None = None,
        sandbox_rootfs: Path | str | None = None,
        binary_in_rootfs: str | None = None,
        afl_fuzz_path: str | None = None,
        cmplog_in_rootfs: str | None = None,
    ) -> None:
        self.binary = Path(binary_path).resolve()
        if not self.binary.exists():
            msg = f"Binary not found: {binary_path}"
            raise FileNotFoundError(msg)

        if not self.binary.is_file():
            msg = f"Path is not a file: {binary_path}"
            raise ValueError(msg)

        if not self.binary.stat().st_mode & 0o111:  # Check if executable
            msg = f"Binary is not executable: {binary_path}"
            raise PermissionError(msg)

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

        # AFL++ advanced features
        self.cmplog_binary = Path(cmplog_binary).resolve() if cmplog_binary else None
        if self.cmplog_binary and not self.cmplog_binary.exists():
            msg = f"CmpLog binary not found: {cmplog_binary}"
            raise FileNotFoundError(msg)
        if power_schedule not in self._VALID_POWER_SCHEDULES:
            msg = (
                f"Invalid power schedule '{power_schedule}'. "
                f"Choose from: {sorted(self._VALID_POWER_SCHEDULES)}"
            )
            raise ValueError(msg)
        self.power_schedule = power_schedule
        self.use_laf_intel = use_laf_intel
        self.deterministic = deterministic
        self.custom_mutator = Path(custom_mutator).resolve() if custom_mutator else None
        self.seed_profile = seed_profile
        if self.custom_mutator and not self.custom_mutator.exists():
            msg = f"Custom mutator not found: {custom_mutator}"
            raise FileNotFoundError(msg)

        # Telemetry: instantiated lazily by run() to avoid creating
        # the events file when callers only build commands for tests.
        self.telemetry = None
        # Set by run_fuzzing: True when every instance died without a
        # clean exit and nothing was found (see the verdict comment
        # there). Callers turn this into a non-zero exit.
        self.campaign_failed = False

        # Env-built campaigns (sandbox image-rootfs mode): afl-fuzz
        # and the target binary come from the exported AFL++ image
        # rootfs, not the host. ``binary_path`` stays the HOST view of
        # the binary (``<rootfs>/src/<rel>``) so the instrumentation /
        # sanitizer strings-checks keep working; the afl-fuzz command
        # line uses the in-rootfs path.
        self.sandbox_rootfs = Path(sandbox_rootfs) if sandbox_rootfs else None
        self.binary_in_rootfs = binary_in_rootfs
        # In-rootfs cmplog twin (env builds): post-pivot path handed to
        # afl-fuzz -c on the main instance. Distinct from the host-path
        # cmplog_binary, which stays refused in rootfs mode.
        self.cmplog_in_rootfs = (cmplog_in_rootfs
                                 if self.sandbox_rootfs is not None
                                 else None)
        if self.sandbox_rootfs is not None:
            if not self.sandbox_rootfs.is_dir():
                raise FileNotFoundError(
                    f"sandbox rootfs not found: {sandbox_rootfs}")
            self.afl_fuzz = afl_fuzz_path or "/usr/local/bin/afl-fuzz"
            # Inside the pivoted image only the target/output binds are
            # visible — the public sandbox API forwards readable_paths
            # solely under restrict_reads, so a corpus or dictionary at
            # an arbitrary host path does not exist post-pivot
            # (empirical: afl-fuzz dies with "Unable to open <corpus>"
            # while the host-mode run reads it fine). Stage both under
            # output_dir, which IS bound at its original path.
            self.corpus_dir = self._stage_into_output(
                self.corpus_dir, "corpus-staged")
            if self.dict_path is not None:
                self.dict_path = self._stage_into_output(
                    self.dict_path, "dict-staged")
            # cmplog binaries and custom mutators are host paths with
            # no post-pivot presence; silently losing them would run a
            # weaker campaign than the caller configured. Refuse until
            # in-image support exists.
            if self.cmplog_binary or self.custom_mutator:
                raise ValueError(
                    "cmplog_binary / custom_mutator are not supported "
                    "with sandbox_rootfs campaigns (host paths are not "
                    "visible inside the image rootfs)")
            # No host which()/--help validation: the binary lives
            # inside the image and only executes post-pivot. Setup
            # failures surface loudly through SandboxSetupError /
            # the instance stderr logs.
        else:
            # Check AFL++ availability
            self.afl_fuzz = shutil.which("afl-fuzz")
            if not self.afl_fuzz:
                msg = "AFL++ not found. Install with: sudo apt install afl++ (Ubuntu) or brew install afl++ (macOS)"
                raise RuntimeError(msg)

            # Validate AFL command
            self._validate_afl_command()

        logger.info("AFL++ found: %s", self.afl_fuzz)
        logger.info("Binary: %s", self.binary)
        logger.info("Corpus: %s", self.corpus_dir)
        logger.info("Output: %s", self.output_dir)

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
                logger.warning("AFL validation returned unexpected exit code: %s", result.returncode)
                if result.stderr:
                    logger.warning("AFL stderr: %s", result.stderr.strip())
        except subprocess.TimeoutExpired:
            logger.warning("AFL validation timed out - AFL may be slow to start")
        except Exception as e:
            logger.warning("AFL validation failed: %s", e)
            msg = f"AFL++ validation failed: {e}"
            raise RuntimeError(msg) from e

    def _create_default_corpus(self) -> Path:
        """Create minimal default corpus if none provided.

        Anchored to ``self.output_dir`` (not CWD) so running
        ``/fuzz`` from inside a target tree does NOT plant seed
        files in ``<target>/out/corpus_default/``.
        """
        corpus = self.output_dir / "corpus_default"
        corpus.mkdir(parents=True, exist_ok=True)
        seed_profile = getattr(self, "seed_profile", "default")

        try:
            manifest = prepare_builtin_seed_corpus(corpus, profile=seed_profile)
            logger.info(
                "Created built-in default corpus with %s seeds (profile=%s)", manifest['seed_count'], seed_profile
            )
        except Exception as exc:  # noqa: BLE001 — best-effort: emergency seeds below
            logger.warning(
                "Built-in default corpus failed (%s); falling back to emergency "
                "minimal seeds",
                exc,
            )
            seeds = [
                b"A" * 10,
                b"test\n",
                b"\x00\x01\x02\x03",
                b"GET / HTTP/1.0\r\n\r\n",
            ]
            for idx, seed in enumerate(seeds):
                (corpus / f"seed{idx}").write_bytes(seed)
            logger.info("Created emergency default corpus with %d seeds", len(seeds))
        return corpus

    def _stage_into_output(self, source: Path, dirname: str) -> Path:
        """Copy *source* under ``output_dir`` unless it already lives
        there. Rootfs-mode campaigns can only see the output bind.

        Deliberately NOT ``shutil.copytree``: a hostile in-repo corpus
        can plant symlinks (``seed -> ~/.ssh/id_rsa`` would copy host
        secrets into the run dir as fuzz seeds; ``seed -> /dev/zero``
        wedges the copy), and a source dir that is an ancestor of
        ``output_dir`` would recurse into its own destination. AFL
        reads only top-level regular files from an input directory, so
        a flat, symlink-rejecting copy loses nothing. The staging dir
        is derived data: cleared first so a reused --out dir cannot
        bleed a previous run's seeds into this campaign.
        """
        source = Path(source)
        try:
            source.relative_to(self.output_dir)
            return source
        except ValueError:
            pass
        staged = self.output_dir / dirname
        if staged.exists():
            shutil.rmtree(staged)
        staged.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            copied = skipped = 0
            for entry in sorted(source.iterdir()):
                if entry.is_symlink() or not entry.is_file():
                    skipped += 1
                    continue
                shutil.copy2(entry, staged / entry.name)
                copied += 1
            if skipped:
                logger.warning(
                    "staging %s: skipped %d non-regular-file entries "
                    "(symlinks / subdirectories)", source, skipped)
            logger.info("staged %d seeds from %s into %s",
                        copied, source, staged)
        else:
            if source.is_symlink():
                source = source.resolve(strict=True)
            shutil.copy2(source, staged / source.name)
            staged = staged / source.name
            logger.info("staged %s into the campaign output dir: %s",
                        source, staged)
        return staged

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
                    logger.error("✗ AFL shared memory configuration issue detected!")
                    logger.error("   On macOS, AFL requires higher shared memory limits.")
                    logger.error("   Run the following commands:")
                    logger.error("   1. afl-system-config (as root/sudo)")
                    logger.error("   2. Reboot your system")
                    logger.error("   Alternative: Use pre-compiled binaries without AFL instrumentation")
                    msg = "AFL shared memory not configured on macOS"
                    raise RuntimeError(msg)
                    
            except subprocess.TimeoutExpired:
                logger.warning("AFL --help command timed out")
            except FileNotFoundError:
                logger.error("afl-fuzz not found in PATH")
                msg = "AFL++ not installed"
                raise RuntimeError(msg) from None
            except Exception as e:  # noqa: BLE001 — advisory pre-flight check only
                logger.warning("AFL compatibility check failed: %s", e)

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

        strings_output = result.stdout.lower()
        has_asan = self._has_runtime_sanitizer(strings_output, "asan")
        has_ubsan = self._has_runtime_sanitizer(strings_output, "ubsan")

        if has_asan or has_ubsan:
            logger.info("✓ Binary appears to be compiled with sanitizers")
            if has_asan:
                logger.info("  - AddressSanitizer (ASAN) detected")
            if has_ubsan:
                logger.info("  - UndefinedBehaviorSanitizer (UBSAN) detected")
            return True
        logger.warning("⚠ Binary does not appear to be compiled with sanitizers")
        logger.warning("  Consider recompiling with -fsanitize=address for better bug detection")
        return False

    @staticmethod
    def _has_runtime_sanitizer(strings_output: str, sanitizer: str) -> bool:
        """Detect real sanitizer runtime linkage without AFL helper false positives."""
        if sanitizer == "asan":
            strong_markers = (
                "__asan_init",
                "__asan_report_",
                "addresssanitizer",
                "asan_options",
            )
            weak_only = ("__asan_region_is_poisoned",)
        elif sanitizer == "ubsan":
            strong_markers = (
                "__ubsan_handle_",
                "undefinedbehaviorsanitizer",
                "ubsan_options",
            )
            weak_only = ()
        else:
            return False

        if any(marker in strings_output for marker in strong_markers):
            return True
        if weak_only and any(marker in strings_output for marker in weak_only):
            return False
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
        print("  AFL_CC=afl-gcc AFL_CXX=afl-g++ CC=afl-gcc CXX=afl-g++ \\")
        print("  CFLAGS='-fsanitize=address -fsanitize=undefined' \\")
        print("  CXXFLAGS='-fsanitize=address -fsanitize=undefined' \\")
        print("  make clean && make")
        print()
        print("  # For C/C++ with AFL-clang:")
        print("  AFL_CC=afl-clang AFL_CXX=afl-clang++ CC=afl-clang CXX=afl-clang++ \\")
        print("  CFLAGS='-fsanitize=address -fsanitize=undefined' \\")
        print("  CXXFLAGS='-fsanitize=address -fsanitize=undefined' \\")
        print("  make clean && make")
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
        max_crashes: int | None = None,
    ) -> tuple[int, Path | None]:
        """
        Run AFL++ fuzzing campaign.

        Args:
            duration: Fuzzing duration in seconds
            parallel_jobs: Number of parallel AFL instances
            timeout_ms: Timeout per execution in milliseconds
            max_crashes: Stop after finding N unique crashes

        Returns:
            Tuple of (num_crashes, crashes_dir). crashes_dir is None
            when the campaign produced no crashes and AFL never created
            a crashes directory.
        """
        logger.info("=" * 70)
        logger.info("STARTING AFL++ FUZZING CAMPAIGN")
        logger.info("=" * 70)
        logger.info("Duration: %ss (%.1f minutes)", duration, duration/60)
        logger.info("Parallel jobs: %s", parallel_jobs)
        logger.info("Timeout: %sms", timeout_ms)
        if max_crashes is not None:
            logger.info("Stop after: %s crashes", max_crashes)

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

        # Start AFL instances — each one a blocking `core.sandbox.run`
        # on a supervising thread (see _SandboxedAFLInstance). Landlock
        # writes are confined to output_dir; explicit readable paths
        # cover the binary/corpus inputs that live outside it (same
        # shape as the afl-showmap call below).
        instances: list[_SandboxedAFLInstance] = []
        log_dir = self.output_dir / "raptor-logs"
        log_dir.mkdir(parents=True, exist_ok=True)

        # In rootfs mode everything the campaign reads lives inside
        # the image tree (binary at /src) or under the output bind
        # (staged corpus/dict) — readable_paths would be dropped by
        # the sandbox API anyway (restrict_reads=False).
        if self.sandbox_rootfs is not None:
            readable_paths = []
        else:
            readable_paths = [str(self.binary.parent), str(self.corpus_dir)]
            readable_paths.extend(str(Path(extra).parent) for extra in (self.dict_path, self.cmplog_binary, self.custom_mutator) if extra)

        try:
            for job_id in range(parallel_jobs):
                is_main = job_id == 0
                instance_name = "main" if is_main else f"secondary{job_id}"

                cmd = self._build_afl_command(
                    instance_name=instance_name,
                    is_main=is_main,
                    timeout_ms=timeout_ms,
                    use_qemu=not is_instrumented,
                    duration=duration,
                )

                logger.info("Starting AFL instance: %s", instance_name)
                logger.debug("Command: %s", ' '.join(cmd))

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
                # The fuzzed binary is untrusted (often attacker-built)
                # and can getenv() anything here — scrub identity on
                # top of get_safe_env's credential strip. (/home PATH
                # components were never usable post-pivot anyway: the
                # campaign mount-ns binds system dirs only.)
                afl_env = scrub_identity_env(RaptorConfig.get_safe_env())
                afl_env.setdefault("AFL_SKIP_CPUFREQ", "1")
                # Skip AFL's own core binding. Each instance runs in a
                # private PID namespace, so AFL's free-core scan sees
                # only itself and every parallel instance would bind
                # the same lowest CPU (serialising -M/-S campaigns);
                # the kernel scheduler spreads them across the
                # sandbox's affinity set instead. Also removes the
                # persona/cpuset corner (a fingerprint overlay that
                # claims CPUs outside the real cgroup mask can no
                # longer trip AFL's bind-or-die logic).
                afl_env.setdefault("AFL_NO_AFFINITY", "1")
                afl_env.setdefault("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
                afl_env.setdefault("AFL_FORKSRV_INIT_TMOUT", "10000")
                if self.sandbox_rootfs is not None:
                    # Host PATH/HOME point at directories that do not
                    # exist inside the image rootfs.
                    afl_env["PATH"] = "/usr/local/bin:/usr/bin:/bin"
                    afl_env["HOME"] = "/tmp"

                stdout_path = log_dir / f"{instance_name}.stdout.log"
                stderr_path = log_dir / f"{instance_name}.stderr.log"
                (log_dir / f"{instance_name}.cmdline").write_text(" ".join(cmd) + "\n", encoding="utf-8")

                instance = _SandboxedAFLInstance(
                    name=instance_name,
                    cmd=cmd,
                    env=afl_env,
                    stdout_path=stdout_path,
                    stderr_path=stderr_path,
                    output_dir=self.output_dir,
                    readable_paths=readable_paths,
                    # afl-fuzz self-terminates via -V; the sandbox
                    # timeout is a wedge net well above that.
                    timeout_s=duration + 300,
                    rootfs=self.sandbox_rootfs,
                )
                instance.start()
                instances.append(instance)
        except BaseException:
            for inst in instances:
                inst.request_stop()
            raise

        all_instances = list(instances)

        # Monitor fuzzing
        start_time = time.time()
        # Track crash paths already reported to telemetry. A count
        # slice over the re-sorted union of all instances' crash dirs
        # mis-attributes new files: a fresh crash that sorts BEFORE an
        # already-seen one (secondary instances interleave) fell inside
        # the "seen" prefix and was never recorded, while an old crash
        # got re-emitted in its place.
        seen_crash_paths: set[Path] = set()
        last_status_time = 0

        try:
            while time.time() - start_time < duration:
                time.sleep(10)  # Check every 10 seconds
                current_time = time.time()

                # Count unique crashes across all instances (main + secondaries)
                crash_files = self._collect_all_crash_files()
                num_crashes = len(crash_files)

                new_crashes = [p for p in crash_files if p not in seen_crash_paths]
                if new_crashes:
                    logger.info("Progress: %s unique crashes found", num_crashes)
                    # Telemetry: emit a per-crash event for new ones only
                    if self.telemetry:
                        for crash_path in new_crashes:
                            self.telemetry.record_crash(str(crash_path), signal="afl")
                    seen_crash_paths.update(new_crashes)

                if max_crashes is not None and num_crashes >= max_crashes:
                    logger.info("✓ Reached %s crashes, stopping early", max_crashes)
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

                        logger.info("Status: %.0fs elapsed | %s exec/s | %s total execs | %s paths | %s%% stable | %s%% coverage", elapsed, execs_per_sec, total_execs, paths_found, stability, bitmap_cvg)

                        # Mirror to telemetry for live status line and JSONL trail
                        if self.telemetry:
                            try:
                                self.telemetry.update_stats(
                                    total_executions=int(stats.get("execs_done", 0) or 0),
                                    executions_per_second=int(float(stats.get("execs_per_sec", 0) or 0)),
                                    paths_found=int(stats.get("paths_found", 0) or 0),
                                    corpus_size=int(stats.get("corpus_count", 0) or 0),
                                    coverage_percent=float(str(stats.get("bitmap_cvg", "0")).rstrip("%") or 0),
                                )
                            except (ValueError, TypeError):
                                pass
                    else:
                        logger.info("Status: %.0fs elapsed (no stats available yet)", elapsed)

                    last_status_time = current_time

                # Check if all instances are still running
                running_instances = []
                for inst in instances:
                    if inst.is_running():
                        running_instances.append(inst)
                        continue
                    if isinstance(inst.error, SandboxSetupError):
                        # Isolation could not engage — fail loud, never
                        # fall back to an unsandboxed campaign.
                        raise inst.error
                    exit_code = inst.returncode()
                    if isinstance(inst.error, subprocess.TimeoutExpired):
                        logger.warning(
                            "AFL instance %s hit the sandbox wedge timeout (%ss)",
                            inst.name, inst.timeout_s,
                        )
                    stderr_str = self._tail_file(inst.stderr_path)
                    if exit_code == 0:
                        logger.info("AFL instance %s completed (exit 0)", inst.name)
                    elif stderr_str:
                        logger.error("AFL instance %s exited with code %s", inst.name, exit_code)
                        logger.error("AFL stderr saved to: %s", inst.stderr_path)
                        logger.error("AFL stderr tail:\n%s", stderr_str)
                        self._log_common_afl_startup_error(stderr_str)
                        if self.telemetry:
                            self.telemetry.record_error(
                                f"AFL {inst.name} exited {exit_code}: {stderr_str[-500:]}"
                            )
                    else:
                        logger.warning(
                            "AFL instance %s exited unexpectedly with code %s; stdout=%s stderr=%s", inst.name, exit_code, inst.stdout_path, inst.stderr_path
                        )

                instances = running_instances

                # If no instances are running, stop fuzzing
                if not instances:
                    logger.error("All AFL instances have exited - stopping fuzzing campaign")
                    break

        finally:
            # Stop all still-running AFL instances (early stop via
            # max_crashes, operator interrupt, or duration elapsed
            # before -V fired). request_stop SIGTERMs afl-fuzz and
            # escalates to SIGKILL; log files are closed by each
            # instance's own thread.
            logger.info("Stopping AFL instances...")
            for inst in instances:
                inst.request_stop()

        # Surface sandbox-engagement failures even when the monitor
        # loop never observed the death (zero/short durations).
        for inst in all_instances:
            if isinstance(inst.error, SandboxSetupError):
                raise inst.error

        # Count final crashes across all instances
        crash_files = self._collect_all_crash_files()
        total_crashes = len(crash_files)

        # Campaign-failure verdict: every instance died without a clean
        # exit and nothing was found. Pre-fix a campaign whose afl-fuzz
        # aborted at startup (bad corpus, missing target, forkserver
        # failure) still flowed into "CAMPAIGN COMPLETE" with exit 0
        # and stats {} — a run that executed zero inputs read as a
        # clean no-findings result. The errors were logged, but logs
        # are not exit codes. A clean-exit instance (afl-fuzz returns
        # 0 on -V expiry and on graceful SIGTERM stop) or any crash
        # found keeps the campaign successful — and an instance still
        # alive at verdict time (SIGTERM unanswered, sandbox timeout
        # pending) blocks the all-dead conclusion rather than being
        # miscounted as a dirty exit.
        self.campaign_failed = total_crashes == 0 and not any(
            inst.is_running()
            or (inst.error is None and inst.returncode() == 0)
            for inst in all_instances
        )
        if self.campaign_failed:
            logger.error(
                "CAMPAIGN FAILED: all %d instance(s) exited without a "
                "clean completion and no crashes were recorded — see "
                "the per-instance stderr logs above",
                len(all_instances),
            )
        # Single directory containing every collected crash — with parallel
        # secondaries, returning only main/crashes would count secondary
        # crashes in the total above but silently exclude them from the
        # downstream CrashCollector analysis phase.
        crashes_dir = self._merge_crash_files(crash_files)

        elapsed = time.time() - start_time
        
        # Final status report
        final_stats = self.get_stats()
        if final_stats:
            total_execs = final_stats.get('execs_done', 'N/A')
            execs_per_sec = final_stats.get('execs_per_sec', 'N/A')
            paths_found = self._afl_paths_found(final_stats)
            stability = final_stats.get('stability', 'N/A')
            bitmap_cvg = final_stats.get('bitmap_cvg', 'N/A')
            
            logger.info("=" * 70)
            logger.info("FINAL FUZZING STATISTICS")
            logger.info("=" * 70)
            logger.info("Total executions: %s", total_execs)
            logger.info("Executions per second: %s", execs_per_sec)
            logger.info("Paths found: %s", paths_found)
            logger.info("Stability: %s%%", stability)
            logger.info("Bitmap coverage: %s%%", bitmap_cvg)
            logger.info("Unique crashes: %s", total_crashes)
            logger.info("=" * 70)

            if self.telemetry:
                max_crash_execs = self._max_crash_execs(
                    self.output_dir / "main" / "crashes"
                )
                self.telemetry.update_stats(
                    total_executions=max(
                        self._parse_afl_int(final_stats.get("execs_done")),
                        max_crash_execs,
                    ),
                    executions_per_second=self._parse_afl_int(final_stats.get("execs_per_sec")),
                    paths_found=self._afl_paths_found(final_stats),
                    corpus_size=self._parse_afl_int(final_stats.get("corpus_count")),
                    coverage_percent=self._parse_afl_percent(final_stats.get("bitmap_cvg")),
                )
                self.telemetry.stats.crashes = total_crashes
        logger.info("=" * 70)
        logger.info("FUZZING CAMPAIGN COMPLETE")
        logger.info("=" * 70)
        logger.info("Duration: %.1fs", elapsed)
        logger.info("Unique crashes: %s", total_crashes)
        logger.info("Crashes dir: %s", crashes_dir)
        logger.info("=" * 70)

        # Run coverage analysis if requested
        coverage_stats = {}
        if self.use_showmap:
            logger.info("Running coverage analysis with afl-showmap...")
            coverage_stats = self.run_showmap()
            if coverage_stats:
                logger.info("Coverage stats:")
                for key, value in coverage_stats.items():
                    logger.info("  %s: %s", key, value)

        return total_crashes, crashes_dir

    def _find_first_seed(self) -> Path | None:
        """Return the first seed file in the corpus directory, or *None*.

        The corpus generator writes ``seed-NNNN-<kind>`` files; the
        emergency fallback writes ``seed0``.  We accept whichever is
        present, preferring the sorted-first regular file.
        """
        try:
            for entry in sorted(self.corpus_dir.iterdir()):
                if entry.is_file():
                    return entry
        except OSError:
            pass
        return None

    def _collect_all_crash_files(self) -> list[Path]:
        """Collect crash files from main and all secondary instance directories."""
        crash_files: list[Path] = []
        for sub in sorted(self.output_dir.iterdir()):
            crashes_dir = sub / "crashes"
            if sub.is_dir() and crashes_dir.is_dir():
                crash_files.extend(
                    f for f in crashes_dir.iterdir() if f.name.startswith("id:")
                )
        return sorted(crash_files)

    def _merge_crash_files(self, crash_files: list[Path]) -> Path | None:
        """Return one directory containing every collected crash file.

        Single-instance campaigns (or ones where only the main instance
        crashed) keep the historical ``main/crashes`` directory. When a
        secondary instance found crashes, hardlink (or copy) every crash
        into ``<output_dir>/merged_crashes`` so the downstream
        CrashCollector sees them all. Names keep their ``id:`` prefix
        (the collector filters on it) and gain an ``,instance:<name>``
        suffix to disambiguate identical AFL ids across instances.

        With no crashes collected, return ``main/crashes`` only when it
        actually exists, else ``None``. Pre-fix ``all()`` over the empty
        list returned a possibly-nonexistent path that downstream
        consumers (CrashCollector) rejected with FileNotFoundError.
        """
        main_crashes = self.output_dir / "main" / "crashes"
        if not crash_files:
            return main_crashes if main_crashes.is_dir() else None
        if all(f.parent.parent.name == "main" for f in crash_files):
            return main_crashes

        merged = self.output_dir / "merged_crashes"
        merged.mkdir(parents=True, exist_ok=True)
        for f in crash_files:
            instance = f.parent.parent.name
            dest = merged / f"{f.name},instance:{instance}"
            if dest.exists():
                continue
            try:
                dest.hardlink_to(f)
            except OSError:
                shutil.copy2(f, dest)
        return merged

    @staticmethod
    def _tail_file(path: Path, max_bytes: int = 4096) -> str:
        try:
            data = path.read_bytes()
        except OSError:
            return ""
        return data[-max_bytes:].decode(errors="replace").strip()

    @staticmethod
    def _log_common_afl_startup_error(stderr_str: str) -> None:
        lowered = stderr_str.lower()
        if (
            "shmget() failed" in lowered
            or "shmat() failed" in lowered
            or "no space left on device" in lowered
            or "cannot allocate memory" in lowered
        ):
            logger.error("=" * 70)
            logger.error("AFL SHARED MEMORY CONFIGURATION ERROR")
            logger.error("=" * 70)
            logger.error("Your system's shared memory limits are too low for AFL++.")
            logger.error("To fix this, run: sudo afl-system-config")
            logger.error("=" * 70)
        elif "timeout while initializing fork server" in lowered:
            logger.error("=" * 70)
            logger.error("AFL FORKSERVER INITIALIZATION TIMEOUT")
            logger.error("=" * 70)
            logger.error(
                "The target did not enter AFL's forkserver quickly enough. "
                "Try a non-ASAN AFL build for discovery, increase "
                "AFL_FORKSRV_INIT_TMOUT, or replay crashes under ASAN later."
            )
            logger.error("=" * 70)

    @staticmethod
    def _parse_afl_int(value) -> int:
        """Parse AFL integer-ish fields, tolerating N/A, percents and decimals."""
        if value is None:
            return 0
        text = str(value).strip().replace(",", "")
        match = _AFL_INT_RE.match(text)
        if not match:
            return 0
        try:
            return int(match.group(0))
        except ValueError:
            return 0

    @staticmethod
    def _parse_afl_percent(value) -> float:
        if value is None:
            return 0.0
        try:
            return float(str(value).strip().rstrip("%") or 0)
        except ValueError:
            return 0.0

    @classmethod
    def _afl_paths_found(cls, stats: dict) -> int:
        """Map current AFL++ stats to a useful path/corpus discovery count."""
        for key in AFL_PATHS_FOUND_KEYS:
            if key in stats:
                return cls._parse_afl_int(stats[key])
        return 0

    @staticmethod
    def _max_crash_execs(crashes_dir: Path) -> int:
        """Use AFL crash filenames as lower-bound exec count when stats lag."""
        if not crashes_dir.exists():
            return 0
        max_execs = 0
        for path in crashes_dir.iterdir():
            if not path.is_file() or not path.name.startswith("id:"):
                continue
            match = _AFL_CRASH_EXECS_RE.search(path.name)
            if match:
                max_execs = max(max_execs, int(match.group(1)))
        return max_execs

    def _build_afl_command(
        self,
        instance_name: str,
        is_main: bool,
        timeout_ms: int,
        use_qemu: bool = False,
        duration: int | None = None,
    ) -> list[str]:
        """Build AFL command line.

        Wires up advanced AFL++ features when configured:
          -p <schedule>        power schedule (default: fast)
          -c <cmplog_binary>   CmpLog binary for input-to-state guidance
          -d                   deterministic mutations off (faster startup)
          -X <mutator.so>      custom mutator library
          -x <dict>            dictionary for structured input
          -V <seconds>         self-terminate after the campaign duration
                               (the campaign runs as a blocking sandboxed
                               call — -V is its primary clock; the sandbox
                               timeout is only the wedge net)

        LAF-intel is a compile-time feature (AFL_LLVM_LAF_*), so it is
        applied to the cmplog/main binary at compile time, not here.
        """
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

        # Campaign duration: afl-fuzz exits on its own after this many
        # seconds. The runner blocks inside the sandbox for the whole
        # campaign, so afl-fuzz must be self-terminating.
        if duration is not None:
            cmd.extend(["-V", str(duration)])

        # Power schedule -- default 'fast' is faster than the legacy 'explore'.
        # Different schedules suit different campaigns: 'explore' for breadth,
        # 'exploit' to dig into known interesting paths, 'rare' to chase
        # uncovered branches.
        cmd.extend(["-p", self.power_schedule])

        # QEMU mode if not instrumented
        if use_qemu:
            cmd.append("-Q")

        # Skip deterministic mutations unless explicitly requested.
        # Modern AFL++ guidance is to skip determinism on the main fuzzer
        # since havoc is generally more effective per CPU second.
        if not self.deterministic:
            cmd.append("-d")

        # CmpLog: input-to-state correspondence. The cmplog binary tracks
        # comparison operands and feeds them back to the mutator. Massive
        # win for parsers with magic numbers, version checks, checksums.
        # Only attached to the main instance to avoid duplicating work.
        if is_main and self.cmplog_binary:
            cmd.extend(["-c", str(self.cmplog_binary)])
        elif is_main and self.cmplog_in_rootfs:
            cmd.extend(["-c", self.cmplog_in_rootfs])

        # Custom mutator library (.so), for grammar-aware or structure-aware
        # mutators (libprotobuf-mutator, custom JSON mutators, LLM bridges).
        if self.custom_mutator:
            cmd.extend(["-X", str(self.custom_mutator)])

        # Dictionary if provided
        if self.dict_path and self.dict_path.exists():
            cmd.extend(["-x", str(self.dict_path)])

        # Optional SAGE-derived or operator-supplied AFL++ flags (before ``--``).
        if self.extra_afl_flags:
            cmd.extend(self.extra_afl_flags)

        # Target binary (in-rootfs path for env-built campaigns; the
        # binary only executes post-pivot where the image is "/")
        cmd.append("--")
        if self.sandbox_rootfs is not None and self.binary_in_rootfs:
            cmd.append(self.binary_in_rootfs)
        else:
            cmd.append(str(self.binary))

        # Input mode
        if self.input_mode == "file":
            cmd.append("@@")
        # For stdin, AFL pipes input automatically

        return cmd

    def get_stats(self) -> dict:
        """Get fuzzing statistics from AFL."""
        stats_file = self.output_dir / "main" / "fuzzer_stats"
        stats = {}
        try:
            with open(stats_file, encoding="utf-8", errors="replace") as f:
                for line in f:
                    if ":" in line:
                        key, value = line.strip().split(":", 1)
                        stats[key.strip()] = value.strip()
        except FileNotFoundError:
            pass
        return stats

    def run_showmap(self) -> dict:
        """Run afl-showmap to analyze coverage."""
        if self.sandbox_rootfs is not None:
            showmap = str(Path(self.afl_fuzz).parent / "afl-showmap")
            target_bin = self.binary_in_rootfs or str(self.binary)
        else:
            showmap = "afl-showmap"
            target_bin = str(self.binary)
        showmap_cmd = [showmap, "-o", "/dev/null", "--", target_bin]

        stdin_input = None
        test_input = None

        # Find the first seed file in the corpus directory.  The corpus
        # generator names seeds ``seed-NNNN-<kind>`` but the emergency
        # fallback still writes ``seed0``.  Accept whichever exists.
        test_input = self._find_first_seed()

        if self.input_mode == "file":
            showmap_cmd.append("@@")
            if test_input:
                # AFL will replace @@ with the input file path
                # We need to set AFL_INPUT_FILE environment variable
                pass
        # For stdin mode, need to provide input via stdin parameter
        elif test_input:
            try:
                stdin_input = open(test_input, 'rb')  # noqa: SIM115 — closed in the finally below
            except Exception as e:  # noqa: BLE001 — showmap is best-effort
                logger.warning("Failed to open test input %s: %s", test_input, e)
                return {}
        else:
            logger.warning("No test input for afl-showmap with stdin mode")
            return {}

        try:
            from core.config import RaptorConfig
            # showmap replays the SAME untrusted target — same
            # identity scrub as the campaign env.
            env = scrub_identity_env(RaptorConfig.get_safe_env())
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
            if self.sandbox_rootfs is not None:
                # binary in-image, test_input under the staged corpus
                # (inside the output bind) — nothing external to bind.
                readable_paths = []
                env["PATH"] = "/usr/local/bin:/usr/bin:/bin"
                env["HOME"] = "/tmp"
            else:
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
            extra = {}
            if self.sandbox_rootfs is not None:
                extra["rootfs"] = str(self.sandbox_rootfs)
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
                sanitise_host_fingerprint=True,
                **extra,
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
            logger.warning("afl-showmap failed: %s", result.stderr)
            return {}

        except SandboxSetupError:
            raise  # sandbox isolation could not engage — fail loud, never mask as a benign result
        except Exception as e:  # noqa: BLE001 — showmap is best-effort
            logger.warning("Error running afl-showmap: %s", e)
            return {}
        finally:
            if stdin_input:
                stdin_input.close()
