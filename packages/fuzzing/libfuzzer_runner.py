"""libFuzzer campaign runner.

Wraps a libFuzzer-instrumented binary (compiled with clang
-fsanitize=fuzzer,address) and orchestrates a fuzzing campaign:
  - Manage corpus directory
  - Run the harness with appropriate flags
  - Capture crashes, timeouts, and OOMs
  - Collect coverage and stats
  - Produce a stable summary the orchestrator can consume

libFuzzer is in-process and persistent by default, so it is generally
faster and more reliable than AFL++ on systems where AFL++ has shmem
issues (notably macOS). It is the right choice for libraries with
generated harnesses.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from core.config import RaptorConfig
from core.logging import get_logger
from core.sandbox import run as _sandbox_run
from packages.fuzzing.output_hygiene import strip_terminal_controls

logger = get_logger()


@dataclass
class LibFuzzerStats:
    """Stats parsed from libFuzzer stderr."""

    total_executions: int = 0
    executions_per_second: int = 0
    coverage_features: int = 0
    coverage_pcs: int = 0
    corpus_size: int = 0
    crashes: int = 0
    timeouts: int = 0
    oom_events: int = 0
    leaks: int = 0
    elapsed_seconds: float = 0.0


@dataclass
class LibFuzzerResult:
    """Final result of a libFuzzer campaign."""

    target: str
    crashes: list[Path] = field(default_factory=list)
    timeouts: list[Path] = field(default_factory=list)
    oom_inputs: list[Path] = field(default_factory=list)
    leak_inputs: list[Path] = field(default_factory=list)
    stats: LibFuzzerStats = field(default_factory=LibFuzzerStats)
    output_dir: Path | None = None
    corpus_dir: Path | None = None
    returncode: int | None = None
    # True when the harness died without producing any finding — a
    # startup failure (missing shared lib, wrong binary) must not
    # surface as a clean zero-findings campaign. Mirrors the AFL
    # runner's campaign_failed verdict.
    campaign_failed: bool = False

    def total_findings(self) -> int:
        return (len(self.crashes) + len(self.timeouts)
                + len(self.oom_inputs) + len(self.leak_inputs))


class LibFuzzerRunner:
    """Run a libFuzzer harness."""

    _STATS_RE = re.compile(
        r"#(\d+)\s+(?:DONE|REDUCE|RELOAD|NEW|pulse)\s+cov:\s*(\d+)\s+ft:\s*(\d+)\s+corp:\s*(\d+).*?exec/s:\s*(\d+)"
    )

    def __init__(
        self,
        harness_path: Path,
        corpus_dir: Path | None = None,
        output_dir: Path | None = None,
        dict_path: Path | None = None,
        max_total_time: int = 600,
        max_len: int = 4096,
        timeout_seconds: int = 25,
        rss_limit_mb: int = 2048,
        jobs: int = 1,
        workers: int = 0,
    ) -> None:
        self.harness = Path(harness_path).resolve()
        if not self.harness.exists():
            msg = f"Harness binary not found: {harness_path}"
            raise FileNotFoundError(msg)
        if not self.harness.stat().st_mode & 0o111:
            msg = f"Harness is not executable: {harness_path}"
            raise PermissionError(msg)

        # Anchor the default output dir to RaptorConfig.get_out_dir()
        # (active project run dir, or the configured output base) —
        # NOT a literal `out/` relative to whatever cwd the runner was
        # constructed from. Same rule as the AFL runner: a CWD-relative
        # default planted libfuzzer_* dirs inside the operator's
        # current directory (or `/out` under cron/CI started from /).
        if output_dir:
            self.output_dir = Path(output_dir).resolve()
        else:
            self.output_dir = (
                RaptorConfig.get_out_dir()
                / f"libfuzzer_{self.harness.stem}_{int(time.time())}"
            ).resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.source_corpus_dir = Path(corpus_dir).resolve() if corpus_dir else None
        self.corpus_dir = self.output_dir / "corpus"
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        if self.source_corpus_dir:
            if not self.source_corpus_dir.exists():
                msg = f"Corpus directory not found: {corpus_dir}"
                raise FileNotFoundError(msg)
            self._seed_working_corpus(self.source_corpus_dir, self.corpus_dir)

        self.dict_path = Path(dict_path).resolve() if dict_path else None
        if self.dict_path and not self.dict_path.exists():
            msg = f"Dictionary not found: {dict_path}"
            raise FileNotFoundError(msg)

        self.max_total_time = max_total_time
        self.max_len = max_len
        self.timeout_seconds = timeout_seconds
        self.rss_limit_mb = rss_limit_mb
        self.jobs = max(1, jobs)
        self.workers = max(0, workers)

        self.crashes_dir = self.output_dir / "crashes"
        self.crashes_dir.mkdir(parents=True, exist_ok=True)

        logger.info("libFuzzer runner: harness=%s", self.harness)
        logger.info("  corpus: %s", self.corpus_dir)
        logger.info("  output: %s", self.output_dir)

    @staticmethod
    def _seed_working_corpus(source: Path, destination: Path) -> None:
        """Copy caller-provided seeds into the sandbox-writable corpus dir.

        Symlinks are rejected at every level, same as the AFL corpus
        stager: a hostile in-repo corpus can plant file symlinks
        (``seed -> ~/.ssh/id_rsa`` would copy host secrets into the run
        dir as fuzz inputs handed to the untrusted harness — and into
        persisted run artifacts) or directory-symlink loops that wedge
        the traversal. Only regular files reached through regular
        directories are copied.
        """
        skipped = 0
        pending: list[Path] = [source]
        while pending:
            current = pending.pop()
            try:
                entries = sorted(current.iterdir())
            except OSError:
                skipped += 1
                continue
            for item in entries:
                if item.is_symlink():
                    skipped += 1
                    continue
                if item.is_dir():
                    pending.append(item)
                    continue
                if not item.is_file():
                    skipped += 1
                    continue
                relative = item.relative_to(source)
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(item, target)
        if skipped:
            logger.warning(
                "corpus seeding: skipped %d non-regular entries "
                "(symlinks / special files / unreadable dirs)", skipped)

    def run(self, telemetry=None) -> LibFuzzerResult:
        """Run the campaign and return the result.

        If telemetry is provided, libFuzzer's stderr is parsed into the same
        event stream after the sandboxed campaign exits.
        """
        cmd = self._build_command()
        logger.info("libFuzzer command: %s", ' '.join(cmd))

        # The harness is untrusted target code — same identity scrub
        # as the AFL campaign env.
        from packages.fuzzing.env_hygiene import scrub_identity_env
        env = scrub_identity_env(RaptorConfig.get_safe_env())
        env.setdefault(
            "ASAN_OPTIONS",
            "abort_on_error=1:symbolize=1:detect_leaks=1:detect_stack_use_after_return=1",
        )
        env.setdefault("UBSAN_OPTIONS", "abort_on_error=1:symbolize=1:print_stacktrace=1")

        start = time.time()
        # The harness's streams go straight to disk (same shape as the
        # AFL sibling's per-instance logs): capture_output would buffer
        # an untrusted, possibly hostile harness's output unbounded in
        # THIS process's memory. Parsing reads back a bounded tail —
        # final stats and artifact lines are emitted at the end of the
        # stream, so the tail is the informative part.
        stdout_path = self.output_dir / "stdout.log"
        stderr_path = self.output_dir / "stderr.log"
        wedge_timeout = False
        try:
            with open(stdout_path, "wb") as stdout_fp, \
                    open(stderr_path, "wb") as stderr_fp:
                completed = _sandbox_run(
                    cmd,
                    block_network=True,
                    target=str(self.harness.parent),
                    output=str(self.output_dir),
                    restrict_reads=True,
                    readable_paths=self._readable_paths(),
                    stdout=stdout_fp,
                    stderr=stderr_fp,
                    timeout=self.max_total_time + max(30, self.timeout_seconds + 5),
                    cwd=str(self.output_dir),
                    env=env,
                )
            returncode = completed.returncode
        except subprocess.TimeoutExpired:
            logger.warning("libFuzzer exceeded campaign timeout; parsing partial output")
            returncode = -1
            wedge_timeout = True
        except KeyboardInterrupt:
            logger.warning("Campaign interrupted by user")
            raise

        elapsed = time.time() - start
        stdout = self._read_log_tail(stdout_path)
        stderr = self._read_log_tail(stderr_path)

        if telemetry is not None:
            for line in stderr.splitlines():
                self._parse_progress_line(line, telemetry)

        result = self._parse_result(stderr, stdout, elapsed)
        result.returncode = returncode
        # Failure verdict: a dirty exit with zero findings means the
        # harness never really ran (startup death, missing lib). A
        # dirty exit WITH findings is normal — libFuzzer exits non-zero
        # on the crash it found. The sandbox wedge timeout is excluded:
        # the campaign ran its full duration, zero findings there is a
        # legitimate outcome.
        result.campaign_failed = (
            not wedge_timeout
            and returncode != 0
            and result.total_findings() == 0
        )
        if result.campaign_failed:
            logger.error(
                "libFuzzer campaign FAILED (rc=%s, no findings) — see %s",
                returncode, stderr_path,
            )
        logger.info(
            "libFuzzer done (rc=%s): %s execs, %s/s, cov=%s features, crashes=%s", returncode, result.stats.total_executions, result.stats.executions_per_second, result.stats.coverage_features, len(result.crashes)
        )
        return result

    # Bound on how much harness output is read back for parsing —
    # mirrors the coverage bridge's capture cap.
    _MAX_PARSE_BYTES = 4 * 1024 * 1024

    @classmethod
    def _read_log_tail(cls, path: Path) -> str:
        try:
            size = path.stat().st_size
            with open(path, "rb") as fh:
                if size > cls._MAX_PARSE_BYTES:
                    fh.seek(size - cls._MAX_PARSE_BYTES)
                return fh.read(cls._MAX_PARSE_BYTES).decode(errors="replace")
        except OSError:
            return ""

    def _readable_paths(self) -> list[str]:
        paths = [str(self.harness.parent), str(self.corpus_dir), str(self.output_dir)]
        if self.source_corpus_dir:
            paths.append(str(self.source_corpus_dir))
        if self.dict_path:
            paths.append(str(self.dict_path.parent))
        return paths

    def _parse_progress_line(self, line: str, telemetry) -> None:
        """Parse a single libFuzzer stderr line and forward to telemetry."""
        line = line.strip()
        if not line:
            return

        # libFuzzer status lines look like:
        #   #1234   NEW    cov: 12 ft: 24 corp: 5/16b lim: 4 exec/s: 100 rss: 32Mb
        match = self._STATS_RE.search(line)
        if match:
            execs, cov, ft, corp, eps = match.groups()
            try:
                telemetry.update_stats(
                    total_executions=int(execs),
                    coverage_pcs=int(cov),
                    coverage_features=int(ft),
                    corpus_size=int(corp),
                    executions_per_second=int(eps),
                    paths_found=int(corp),     # libFuzzer's corpus size is closest to "paths"
                )
            except (ValueError, TypeError):
                pass

        # Crash markers. Lines come from the untrusted harness's
        # stderr and get relayed to the operator's terminal — strip
        # escape-injection vectors first.
        if "ERROR:" in line and ("Sanitizer" in line or "ERROR: libFuzzer" in line):
            telemetry.record_error(strip_terminal_controls(line)[:200])
        if "Test unit written to" in line:
            # Format: "Test unit written to ./crash-deadbeef..."
            parts = line.split("Test unit written to", 1)
            if len(parts) == 2:
                path = strip_terminal_controls(parts[1].strip())
                basename = path.rsplit("/", 1)[-1].lower()
                if "timeout" in basename:
                    telemetry.record_timeout(path)
                elif "oom" in basename:
                    telemetry.record_oom(path)
                elif "leak" in basename:
                    # LSAN leak artifact (detect_leaks=1) — ends the
                    # campaign like a crash does.
                    telemetry.record_crash(path, signal="lsan-leak")
                elif "crash" in basename:
                    telemetry.record_crash(path, signal="libfuzzer")

    def _build_command(self) -> list[str]:
        cmd = [str(self.harness)]
        cmd.append(str(self.corpus_dir))
        cmd.extend([
            f"-max_total_time={self.max_total_time}",
            f"-max_len={self.max_len}",
            f"-timeout={self.timeout_seconds}",
            f"-rss_limit_mb={self.rss_limit_mb}",
            "-print_final_stats=1",
            f"-artifact_prefix={self.crashes_dir}/",
        ])
        if self.dict_path:
            cmd.append(f"-dict={self.dict_path}")
        if self.jobs > 1:
            cmd.append(f"-jobs={self.jobs}")
        if self.workers > 0:
            cmd.append(f"-workers={self.workers}")
        return cmd

    def _parse_result(
        self,
        stderr: str,
        _stdout: str,
        elapsed: float,
    ) -> LibFuzzerResult:
        result = LibFuzzerResult(
            target=str(self.harness),
            output_dir=self.output_dir,
            corpus_dir=self.corpus_dir,
        )
        result.stats.elapsed_seconds = elapsed

        # Parse stats from stderr
        for match in self._STATS_RE.finditer(stderr):
            execs, cov, ft, corp, eps = match.groups()
            result.stats.total_executions = max(result.stats.total_executions, int(execs))
            result.stats.coverage_pcs = max(result.stats.coverage_pcs, int(cov))
            result.stats.coverage_features = max(result.stats.coverage_features, int(ft))
            result.stats.corpus_size = max(result.stats.corpus_size, int(corp))
            result.stats.executions_per_second = int(eps)

        # Crash detection. leak- artifacts are produced by LSAN
        # (detect_leaks=1 is set on the campaign env) and end the
        # campaign — dropping them reported a leak-terminated run as
        # zero findings.
        for prefix, target_list in (
            ("crash-", result.crashes),
            ("timeout-", result.timeouts),
            ("oom-", result.oom_inputs),
            ("leak-", result.leak_inputs),
        ):
            for path in self.crashes_dir.glob(f"{prefix}*"):
                if path.is_file():
                    target_list.append(path)

        result.stats.crashes = len(result.crashes)
        result.stats.timeouts = len(result.timeouts)
        result.stats.oom_events = len(result.oom_inputs)
        result.stats.leaks = len(result.leak_inputs)

        return result
