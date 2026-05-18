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
from typing import List, Optional

from core.config import RaptorConfig
from core.logging import get_logger
from core.sandbox import run as _sandbox_run

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
    elapsed_seconds: float = 0.0


@dataclass
class LibFuzzerResult:
    """Final result of a libFuzzer campaign."""

    target: str
    crashes: List[Path] = field(default_factory=list)
    timeouts: List[Path] = field(default_factory=list)
    oom_inputs: List[Path] = field(default_factory=list)
    stats: LibFuzzerStats = field(default_factory=LibFuzzerStats)
    output_dir: Optional[Path] = None
    corpus_dir: Optional[Path] = None

    def total_findings(self) -> int:
        return len(self.crashes) + len(self.timeouts) + len(self.oom_inputs)


class LibFuzzerRunner:
    """Run a libFuzzer harness."""

    _STATS_RE = re.compile(
        r"#(\d+)\s+(?:DONE|REDUCE|RELOAD|NEW|pulse)\s+cov:\s*(\d+)\s+ft:\s*(\d+)\s+corp:\s*(\d+).*?exec/s:\s*(\d+)"
    )

    def __init__(
        self,
        harness_path: Path,
        corpus_dir: Optional[Path] = None,
        output_dir: Optional[Path] = None,
        dict_path: Optional[Path] = None,
        max_total_time: int = 600,
        max_len: int = 4096,
        timeout_seconds: int = 25,
        rss_limit_mb: int = 2048,
        jobs: int = 1,
        workers: int = 0,
    ) -> None:
        self.harness = Path(harness_path).resolve()
        if not self.harness.exists():
            raise FileNotFoundError(f"Harness binary not found: {harness_path}")
        if not self.harness.stat().st_mode & 0o111:
            raise PermissionError(f"Harness is not executable: {harness_path}")

        self.output_dir = (
            Path(output_dir).resolve()
            if output_dir
            else Path(f"out/libfuzzer_{self.harness.stem}_{int(time.time())}").resolve()
        )
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.source_corpus_dir = Path(corpus_dir).resolve() if corpus_dir else None
        self.corpus_dir = self.output_dir / "corpus"
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        if self.source_corpus_dir:
            if not self.source_corpus_dir.exists():
                raise FileNotFoundError(f"Corpus directory not found: {corpus_dir}")
            self._seed_working_corpus(self.source_corpus_dir, self.corpus_dir)

        self.dict_path = Path(dict_path).resolve() if dict_path else None
        if self.dict_path and not self.dict_path.exists():
            raise FileNotFoundError(f"Dictionary not found: {dict_path}")

        self.max_total_time = max_total_time
        self.max_len = max_len
        self.timeout_seconds = timeout_seconds
        self.rss_limit_mb = rss_limit_mb
        self.jobs = max(1, jobs)
        self.workers = max(0, workers)

        self.crashes_dir = self.output_dir / "crashes"
        self.crashes_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"libFuzzer runner: harness={self.harness}")
        logger.info(f"  corpus: {self.corpus_dir}")
        logger.info(f"  output: {self.output_dir}")

    @staticmethod
    def _seed_working_corpus(source: Path, destination: Path) -> None:
        """Copy caller-provided seeds into the sandbox-writable corpus dir."""
        for item in source.rglob("*"):
            if not item.is_file():
                continue
            relative = item.relative_to(source)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)

    def run(self, telemetry=None) -> LibFuzzerResult:
        """Run the campaign and return the result.

        If telemetry is provided, libFuzzer's stderr is parsed into the same
        event stream after the sandboxed campaign exits.
        """
        cmd = self._build_command()
        logger.info(f"libFuzzer command: {' '.join(cmd)}")

        env = RaptorConfig.get_safe_env()
        env.setdefault(
            "ASAN_OPTIONS",
            "abort_on_error=1:symbolize=1:detect_leaks=1:detect_stack_use_after_return=1",
        )
        env.setdefault("UBSAN_OPTIONS", "abort_on_error=1:symbolize=1:print_stacktrace=1")

        start = time.time()
        try:
            completed = _sandbox_run(
                cmd,
                block_network=True,
                target=str(self.harness.parent),
                output=str(self.output_dir),
                restrict_reads=True,
                readable_paths=self._readable_paths(),
                capture_output=True,
                text=True,
                timeout=self.max_total_time + max(30, self.timeout_seconds + 5),
                cwd=str(self.output_dir),
                env=env,
            )
            returncode = completed.returncode
            stdout = completed.stdout or ""
            stderr = completed.stderr or ""
        except subprocess.TimeoutExpired as e:
            logger.warning("libFuzzer exceeded campaign timeout; parsing partial output")
            returncode = -1
            stdout = self._coerce_output(e.stdout)
            stderr = self._coerce_output(e.stderr)
        except KeyboardInterrupt:
            logger.warning("Campaign interrupted by user")
            raise

        elapsed = time.time() - start

        if telemetry is not None:
            for line in stderr.splitlines():
                self._parse_progress_line(line, telemetry)

        # Persist raw output for debugging
        (self.output_dir / "stderr.log").write_text(stderr)
        (self.output_dir / "stdout.log").write_text(stdout)

        result = self._parse_result(stderr, stdout, elapsed)
        logger.info(
            f"libFuzzer done (rc={returncode}): "
            f"{result.stats.total_executions} execs, "
            f"{result.stats.executions_per_second}/s, "
            f"cov={result.stats.coverage_features} features, "
            f"crashes={len(result.crashes)}"
        )
        return result

    def _readable_paths(self) -> List[str]:
        paths = [str(self.harness.parent), str(self.corpus_dir), str(self.output_dir)]
        if self.source_corpus_dir:
            paths.append(str(self.source_corpus_dir))
        if self.dict_path:
            paths.append(str(self.dict_path.parent))
        return paths

    @staticmethod
    def _coerce_output(value) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode(errors="replace")
        return str(value)

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

        # Crash markers
        if "ERROR:" in line and ("Sanitizer" in line or "ERROR: libFuzzer" in line):
            telemetry.record_error(line[:200])
        if "Test unit written to" in line:
            # Format: "Test unit written to ./crash-deadbeef..."
            parts = line.split("Test unit written to", 1)
            if len(parts) == 2:
                path = parts[1].strip()
                if "crash" in path.lower():
                    telemetry.record_crash(path, signal="libfuzzer")
                elif "timeout" in path.lower():
                    telemetry.record_timeout(path)
                elif "oom" in path.lower():
                    telemetry.record_oom(path)

    def _build_command(self) -> List[str]:
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
        stdout: str,
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

        # Crash detection
        for prefix, target_list in (
            ("crash-", result.crashes),
            ("timeout-", result.timeouts),
            ("oom-", result.oom_inputs),
        ):
            for path in self.crashes_dir.glob(f"{prefix}*"):
                if path.is_file():
                    target_list.append(path)

        result.stats.crashes = len(result.crashes)
        result.stats.timeouts = len(result.timeouts)
        result.stats.oom_events = len(result.oom_inputs)

        return result
