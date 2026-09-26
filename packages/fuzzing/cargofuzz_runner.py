"""cargo-fuzz (Rust) campaign runner.

cargo-fuzz builds a Rust crate's ``fuzz_targets/*.rs`` harnesses as
native libFuzzer binaries. This runner extends
:class:`~packages.fuzzing.libfuzzer_runner.LibFuzzerRunner` — the
campaign process contract (sandboxed blocking run, file-backed stream
capture, bounded log-tail parsing, stats grammar, crash-artifact
layout with ``crash-``/``timeout-``/``oom-`` prefixes,
campaign-failure verdict) is libFuzzer's own — and adds what Rust
changes:

  - a BUILD phase first: ``cargo fuzz build <target>`` compiles the
    fuzz target inside the sandbox, then the campaign executes the
    built binary DIRECTLY through the parent's libFuzzer contract
    (cargo never runs inside the campaign);
  - the campaign environment carries ``RUST_BACKTRACE=1`` so a panic
    prints its frames;
  - crashes are usually Rust panics — the panic message, location,
    and backtrace parsed from the harness output become the triage
    signal on the normalized crash records.

Containment contract:

  - The BUILD executes target code (``build.rs``, proc macros), so it
    runs under ``core.sandbox.run`` with ``block_network=True`` AND
    ``CARGO_NET_OFFLINE=true`` (dependencies must already be in the
    local cargo cache — the failure message says how to fetch them in
    a trusted context). Reads are restricted to the crate, the Rust
    toolchain roots (cargo/rustup homes), and the run directory.
    Writes are scoped to the run directory (``CARGO_TARGET_DIR``
    points the build artifacts there) plus ONE directory cargo itself
    requires: the fuzz workspace (older cargo-fuzz versions pin their
    own ``fuzz/target`` dir; lockfile generation writes
    ``fuzz/Cargo.lock``). The build phase's write scope is wider than
    the campaign's, never wider than what building the operator's
    chosen crate requires. Lane note: the mount-ns sandbox lane masks
    writable entries under the read-only target bind — strictly more
    restrictive; build writes land in the run dir, and an in-target
    write need (lockfile generation) surfaces as an EROFS build
    failure with the trusted-context ``cargo fetch`` remedy hinted.
  - The cargo home the build sees is HERMETIC and per-run: a run-local
    ``cargo-home`` inside the run directory, seeded by full copy
    (``cp --reflink=auto`` — NEVER hardlinks, whose shared inodes let
    an in-place write reach the host cache) of the host cache's
    ``registry/index`` + ``registry/cache`` only. The host ``~/.cargo``
    is never in the build's write scope: an offline build extracts
    dependency sources into ``registry/src`` at build time and cargo
    never re-verifies an extracted tree (``.cargo-ok`` sentinel only),
    so a hostile ``build.rs`` given a shared writable cargo home could
    poison the extraction that this host's later builds — RAPTOR's and
    the operator's own — silently compile. Verified on cargo 1.93:
    with ``registry/src`` pre-extracted, an offline build succeeds on
    a fully READ-ONLY cargo home, so a later series can narrow further
    by pre-extracting at seed time and dropping the run-local write
    grant too.
  - The CAMPAIGN keeps the parent's strict scope: network deny, read
    allowlist (binary, corpus, output), writes to the run directory
    only, sandbox rlimits, ``-rss_limit_mb`` in-process.
  - Both phases run on ``RaptorConfig.get_safe_env()`` +
    ``scrub_identity_env`` — never ambient ``os.environ`` — with only
    the cargo/rust variables the build needs added on top.

Toolchain: cargo and the cargo-fuzz subcommand are hard requirements
(construction refuses with an install hint). A nightly toolchain is
preferred — it enables cargo-fuzz's default AddressSanitizer build;
without one the build degrades to ``--sanitizer none`` with a warning
(panics and crashes are still caught, ASan findings are not).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from itertools import islice
from pathlib import Path
from typing import Any

from core.atomic_fs import open_exclusive_artifact, write_new_text
from core.config import RaptorConfig
from core.logging import get_logger
from packages.fuzzing import libfuzzer_runner as _lf
from packages.fuzzing.env_hygiene import scrub_identity_env
from packages.fuzzing.libfuzzer_runner import (
    LibFuzzerResult,
    LibFuzzerRunner,
)
from packages.fuzzing.output_hygiene import strip_terminal_controls
from packages.fuzzing.target_detector import (
    _CARGO_FUZZ_TARGET_NAME_RE,
    find_cargo_fuzz_dir,
    list_cargo_fuzz_targets,
)

logger = get_logger()

CARGO_INSTALL_HINT = (
    "cargo (the Rust build tool) was not found on PATH. "
    "Install Rust: https://rustup.rs"
)
CARGO_FUZZ_INSTALL_HINT = (
    "cargo-fuzz is not installed (no cargo-fuzz on PATH). "
    "Install with: cargo install cargo-fuzz"
)
NIGHTLY_HINT = (
    "no nightly Rust toolchain detected: cargo-fuzz builds with "
    "--sanitizer none (panics and crashes are still caught; "
    "AddressSanitizer findings are not). Install one with: "
    "rustup toolchain install nightly"
)

# Bounds on panic excerpts persisted into crash records and relayed to
# the operator. The panic text comes from the untrusted harness
# process's output.
_MAX_FRAMES = 40
_MAX_LINE_CHARS = 300
# How far below the panic header the one-line message of the new
# (rustc >= 1.73) two-line format is searched.
_MAX_MESSAGE_LOOKAHEAD = 5

# Old single-line panic format (rustc < 1.73):
#   thread 'main' panicked at 'boom', fuzz_targets/ft.rs:6:9
# Every repeat is bounded and the line itself is pre-bounded to
# _MAX_LINE_CHARS before matching.
_PANIC_OLD_RE = re.compile(
    r"^thread '([^']{1,128})' panicked at '(.{0,300})', "
    r"([^\s:]{1,300}):(\d{1,9}):(\d{1,9})\s{0,8}$"
)
# New two-line panic format (rustc >= 1.73):
#   thread '<unnamed>' panicked at fuzz_targets/ft.rs:6:9:
#   boom
_PANIC_NEW_RE = re.compile(
    r"^thread '([^']{1,128})' panicked at ([^\s:]{1,300}):"
    r"(\d{1,9}):(\d{1,9}):\s{0,8}$"
)
# RUST_BACKTRACE=1 numbered frame:  "   3: mycrate::parse"
_BACKTRACE_FRAME_RE = re.compile(
    r"^\s{1,16}(\d{1,4}): (\S.{0,300})$"
)


def cargo_executable() -> str | None:
    """Absolute path to cargo, or None when not installed."""
    found = shutil.which("cargo")
    if not found:
        return None
    path = Path(found)
    # which() honours relative PATH entries; the result becomes the
    # sandboxed build's argv[0], so pin it absolute.
    return str(path if path.is_absolute() else path.resolve())


def cargo_fuzz_available() -> bool:
    """Whether the ``cargo fuzz`` subcommand can resolve (cargo finds
    subcommands as ``cargo-fuzz`` executables on PATH)."""
    return shutil.which("cargo-fuzz") is not None


def _probe_env() -> dict:
    """Scrubbed env for trusted toolchain probes, with the rustup home
    restored (the identity scrub resets HOME, under which rustup would
    find no toolchains at all)."""
    env = scrub_identity_env(RaptorConfig.get_safe_env())
    rustup_home = _resolve_rustup_home()
    if rustup_home is not None:
        env["RUSTUP_HOME"] = str(rustup_home)
    return env


def nightly_toolchain_arg(cargo: str | None = None) -> str | None:
    """How to reach a nightly toolchain through *cargo*.

    Returns ``""`` when the default cargo already IS nightly,
    ``"+nightly"`` when rustup can select an installed nightly, and
    ``None`` when no nightly toolchain is available. Best-effort: a
    failing probe reads as no-nightly (the build then degrades to
    ``--sanitizer none`` rather than dying on a bad ``+nightly``).
    """
    cargo = cargo or cargo_executable()
    if cargo is None:
        return None
    env = _probe_env()
    try:
        version = subprocess.run(
            [cargo, "--version"], capture_output=True, text=True,
            timeout=10, env=env,
        )
        if "nightly" in (version.stdout or ""):
            return ""
    except (OSError, subprocess.SubprocessError):
        return None
    rustup = shutil.which("rustup")
    if not rustup:
        return None
    try:
        listing = subprocess.run(
            [rustup, "toolchain", "list"], capture_output=True,
            text=True, timeout=10, env=env,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    for line in (listing.stdout or "").splitlines():
        if line.strip().startswith("nightly"):
            return "+nightly"
    return None


def _resolve_cargo_home() -> Path | None:
    """The host's real cargo home (registry cache, rustup shims) — the
    identity scrub resets HOME, so it must be pinned explicitly."""
    env_home = os.environ.get("CARGO_HOME")
    if env_home:
        return Path(env_home)
    default = Path.home() / ".cargo"
    return default if default.is_dir() else None


def _resolve_rustup_home() -> Path | None:
    env_home = os.environ.get("RUSTUP_HOME")
    if env_home:
        return Path(env_home)
    default = Path.home() / ".rustup"
    return default if default.is_dir() else None


def crate_corpus_dir(crate_dir: Path, fuzz_target: str) -> Path | None:
    """The crate's own cargo-fuzz corpus for *fuzz_target*
    (``fuzz/corpus/<target>/``), when it exists and holds at least one
    regular file. The caller stages it through the bounded,
    symlink-refusing corpus stager — this only decides whether the
    conventional location is worth staging."""
    if not _CARGO_FUZZ_TARGET_NAME_RE.fullmatch(str(fuzz_target)):
        return None
    fuzz_dir = find_cargo_fuzz_dir(Path(crate_dir))
    if fuzz_dir is None:
        return None
    candidate = fuzz_dir / "corpus" / fuzz_target
    try:
        if not candidate.is_dir():
            return None
        # Bounded peek — the directory is scanned-repo content.
        for entry in islice(candidate.iterdir(), 4096):
            if entry.is_file() and not entry.is_symlink():
                return candidate
    except OSError:
        return None
    return None


@dataclass
class RustPanicInfo:
    """The Rust panic the harness reported for a crash.

    ``stack_key`` is a short content hash over the panic location and
    the backtrace frames — the Rust analogue of the atheris path's
    exception stack key, used for crash dedup and witness detail.
    """

    message: str
    location: str = ""
    thread: str = ""
    frames: list[str] = field(default_factory=list)
    stack_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "panic_message": self.message,
            "panic_location": self.location,
            "thread": self.thread,
            "frames": list(self.frames),
            "stack_key": self.stack_key,
        }


@dataclass
class CargoFuzzResult(LibFuzzerResult):
    """libFuzzer result plus the Rust-side triage signal."""

    #: Panic parsed from the campaign output (libFuzzer exits on the
    #: first crash, so at most one is in play per run).
    rust_panic: RustPanicInfo | None = None
    #: Normalized per-artifact crash records (also persisted to
    #: ``cargofuzz-crashes.json`` in the output dir).
    crash_records: list[dict[str, Any]] = field(default_factory=list)
    #: The built fuzz-target binary the campaign executed.
    built_binary: str = ""


class CargoFuzzRunner(LibFuzzerRunner):
    """Build and run a cargo-fuzz target under the fuzzing sandbox."""

    _ENGINE_NAME = "cargo-fuzz"

    def __init__(
        self,
        crate_dir: Path,
        fuzz_target: str,
        *,
        corpus_dir: Path | None = None,
        output_dir: Path | None = None,
        dict_path: Path | None = None,
        max_total_time: int = 600,
        max_len: int = 4096,
        timeout_seconds: int = 25,
        rss_limit_mb: int = 2048,
        build_timeout: int = 900,
        sanitizer: str | None = None,
    ) -> None:
        # The target name becomes a cargo bin name, a glob component,
        # and a command argument — vet the charset before ANY use.
        if not _CARGO_FUZZ_TARGET_NAME_RE.fullmatch(str(fuzz_target)):
            msg = (
                "fuzz target name must match [A-Za-z0-9_-]{1,64} "
                f"(got {str(fuzz_target)[:80]!r})"
            )
            raise ValueError(msg)
        self.fuzz_target = str(fuzz_target)
        self.crate_dir = Path(crate_dir).resolve()
        fuzz_dir = find_cargo_fuzz_dir(self.crate_dir)
        if fuzz_dir is None:
            msg = (
                f"no cargo-fuzz layout under {self.crate_dir} "
                "(expected fuzz/Cargo.toml + fuzz/fuzz_targets/). "
                "Scaffold with 'cargo fuzz init'."
            )
            raise FileNotFoundError(msg)
        self.fuzz_dir = fuzz_dir
        available = list_cargo_fuzz_targets(fuzz_dir)
        if self.fuzz_target not in available:
            msg = (
                f"fuzz target '{self.fuzz_target}' not found under "
                f"{fuzz_dir / 'fuzz_targets'} "
                f"(available: {', '.join(available) or 'none'})"
            )
            raise ValueError(msg)

        cargo = cargo_executable()
        if cargo is None:
            raise RuntimeError(CARGO_INSTALL_HINT)
        self.cargo = cargo
        if not cargo_fuzz_available():
            raise RuntimeError(CARGO_FUZZ_INSTALL_HINT)
        self._toolchain_arg = nightly_toolchain_arg(cargo)
        if sanitizer is None:
            sanitizer = "address" if self._toolchain_arg is not None \
                else "none"
            if self._toolchain_arg is None:
                logger.warning(NIGHTLY_HINT)
        self.sanitizer = sanitizer
        self.build_timeout = build_timeout
        self._host_cargo_home = _resolve_cargo_home()
        self._rustup_home = _resolve_rustup_home()
        self._built_binary: Path | None = None

        if output_dir is None:
            output_dir = (
                RaptorConfig.get_out_dir()
                / f"cargofuzz_{self.fuzz_target}_{int(time.time())}"
            )
        super().__init__(
            self.crate_dir,
            corpus_dir=corpus_dir,
            output_dir=output_dir,
            dict_path=dict_path,
            max_total_time=max_total_time,
            max_len=max_len,
            timeout_seconds=timeout_seconds,
            rss_limit_mb=rss_limit_mb,
        )
        # Build artifacts land in the run dir, not the target tree.
        self._cargo_target_dir = self.output_dir / "cargo-target"
        # Hermetic per-run cargo home (see the module containment
        # contract): seeded from the host cache, inside the run dir's
        # existing write scope — the host cache itself is never
        # build-writable.
        self._run_cargo_home = self.output_dir / "cargo-home"

    # ------------------------------------------------------------------
    # Subclass seams (campaign phase)
    # ------------------------------------------------------------------

    def _validate_harness(self) -> None:
        """At construction ``self.harness`` is the crate directory —
        the executable harness only exists after the build phase
        rebinds it (see :meth:`run`)."""
        if not self.harness.is_dir():
            msg = f"Rust crate directory not found: {self.harness}"
            raise FileNotFoundError(msg)

    def _campaign_env(self) -> dict:
        env = super()._campaign_env()
        # Panic frames are the triage signal — without a backtrace the
        # stack key collapses to the panic location alone.
        env["RUST_BACKTRACE"] = "1"
        return env

    def _new_result(self) -> CargoFuzzResult:
        return CargoFuzzResult(
            target=str(self.harness),
            output_dir=self.output_dir,
            corpus_dir=self.corpus_dir,
            built_binary=str(self._built_binary or ""),
        )

    def _parse_result(
        self,
        stderr: str,
        _stdout: str,
        elapsed: float,
    ) -> CargoFuzzResult:
        result = super()._parse_result(stderr, _stdout, elapsed)
        assert isinstance(result, CargoFuzzResult)  # _new_result contract
        # Rust panics print on stderr alongside libFuzzer's own crash
        # handling; stdout is checked second, belt-and-braces.
        result.rust_panic = (
            parse_rust_panic(stderr) or parse_rust_panic(_stdout)
        )
        result.crash_records = self._normalize_crash_records(result)
        self._persist_crash_records(result.crash_records)
        return result

    # ------------------------------------------------------------------
    # Build phase
    # ------------------------------------------------------------------

    def run(self, telemetry=None) -> CargoFuzzResult:
        """Build the fuzz target, then run the campaign.

        The build rebinds ``self.harness`` to the built binary: the
        parent's whole process contract (command construction, sandbox
        scopes, result identity) keys off it, and from here on the
        campaign is exactly a native libFuzzer campaign.
        """
        binary = self._build_fuzz_target()
        self._built_binary = binary
        self.harness = binary
        result = super().run(telemetry)
        assert isinstance(result, CargoFuzzResult)  # _new_result contract
        return result

    def _build_command_for_build(self) -> list[str]:
        cmd = [self.cargo]
        if self._toolchain_arg:
            cmd.append(self._toolchain_arg)
        cmd.extend(["fuzz", "build", self.fuzz_target])
        cmd.extend(["--sanitizer", self.sanitizer])
        return cmd

    def _build_env(self) -> dict:
        env = scrub_identity_env(RaptorConfig.get_safe_env())
        # Network posture: the sandbox denies the network AND cargo is
        # told so — a clean "dependencies not cached" error instead of
        # a hung download.
        env["CARGO_NET_OFFLINE"] = "true"
        env["CARGO_TARGET_DIR"] = str(self._cargo_target_dir)
        # ALWAYS the hermetic run-local home — never the host cache
        # (the build.rs it will run is target code; see the module
        # containment contract). The identity scrub also resets HOME,
        # under which cargo would derive the wrong home anyway.
        env["CARGO_HOME"] = str(self._run_cargo_home)
        if self._rustup_home is not None:
            env["RUSTUP_HOME"] = str(self._rustup_home)
        # cargo execs rustc from PATH; the identity scrub drops
        # /home/* PATH components, which is where rustup installs
        # live — re-append cargo's own directory.
        cargo_dir = str(Path(self.cargo).parent)
        parts = [p for p in env.get("PATH", "").split(os.pathsep) if p]
        if cargo_dir not in parts:
            parts.append(cargo_dir)
        env["PATH"] = os.pathsep.join(parts)
        return env

    def _rust_tool_paths(self) -> list[str]:
        """Rust toolchain roots the build sandbox's read allowlist
        needs beyond the system baseline (/usr, /bin, ...)."""
        system_prefixes = ("/usr/", "/lib/", "/lib64/", "/etc/",
                           "/bin/", "/sbin/")
        paths: list[str] = []
        candidates = [
            Path(self.cargo).parent,
            Path(self.cargo).resolve().parent,
            # READ-only: rustup shims and toolchains live here; the
            # write scope never includes it (hermetic run-local home).
            self._host_cargo_home,
            self._rustup_home,
        ]
        for candidate in candidates:
            if candidate is None:
                continue
            text = str(candidate)
            if text.startswith(system_prefixes):
                continue
            if candidate.is_dir() and text not in paths:
                paths.append(text)
        return paths

    def _build_readable_paths(self) -> list[str]:
        return [str(self.crate_dir), str(self.output_dir)]

    def _build_writable_paths(self) -> list[str]:
        """Directories cargo must write beyond the run dir — see the
        module containment contract for why. NEVER the host cargo
        home: the run-local ``cargo-home`` (inside the run dir's write
        scope) is the only cargo home the build can write."""
        return [str(self.fuzz_dir)]

    # Subtrees seeded from the host cache into the run-local cargo
    # home. registry/index (dependency resolution) and registry/cache
    # (the verified .crate archives) are sufficient: extraction into
    # registry/src happens per-run from the cache. bin/, config, and
    # any pre-extracted src are deliberately NOT copied — they are
    # either unneeded or exactly the poisoning surface.
    _SEED_SUBTREES = ("registry/index", "registry/cache")

    def _seed_run_cargo_home(self) -> None:
        """Seed the hermetic run-local cargo home from the host cache.

        Full COPY via ``cp --reflink=auto`` (cheap CoW clone on
        supporting filesystems, plain copy elsewhere). NEVER a
        hardlink farm: hardlinks share inodes, so a hostile build.rs
        writing a seeded file IN PLACE would reach the host cache
        through the link. Idempotent per run dir — an already-seeded
        subtree is kept (same-run rebuilds), a missing host cache
        seeds nothing (dep-less crates still build; dep builds fail
        with the offline hint). A REUSED output_dir keeps its
        run-local home across campaigns, previous campaigns' build.rs
        writes included — the same trust domain as every other reused
        artifact in that run dir, and never the host cache.
        """
        self._run_cargo_home.mkdir(parents=True, exist_ok=True)
        if self._host_cargo_home is None:
            return
        for rel in self._SEED_SUBTREES:
            source = self._host_cargo_home / rel
            destination = self._run_cargo_home / rel
            if not source.is_dir() or destination.exists():
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            copy = subprocess.run(
                ["cp", "-R", "--reflink=auto", "--", str(source),
                 str(destination)],
                capture_output=True, text=True,
                env=scrub_identity_env(RaptorConfig.get_safe_env()),
            )
            if copy.returncode != 0:
                logger.warning(
                    "cargo-home seed of %s failed (rc=%s): %s",
                    rel, copy.returncode,
                    strip_terminal_controls(copy.stderr)[:300],
                )

    def _build_fuzz_target(self) -> Path:
        """Sandboxed ``cargo fuzz build``; returns the built binary."""
        self._cargo_target_dir.mkdir(parents=True, exist_ok=True)
        self._seed_run_cargo_home()
        cmd = self._build_command_for_build()
        logger.info("%s build: %s", self._ENGINE_NAME, " ".join(cmd))
        stdout_path = self.output_dir / "build-stdout.log"
        stderr_path = self.output_dir / "build-stderr.log"
        try:
            # Exclusive create — the output dir is reused across
            # campaigns; a planted symlink/FIFO at these predictable
            # names must fail the open, not be followed.
            with os.fdopen(
                open_exclusive_artifact(stdout_path, replace=True), "wb",
            ) as stdout_fp, os.fdopen(
                open_exclusive_artifact(stderr_path, replace=True), "wb",
            ) as stderr_fp:
                completed = _lf._sandbox_run(
                    cmd,
                    block_network=True,
                    target=str(self.crate_dir),
                    output=str(self.output_dir),
                    restrict_reads=True,
                    readable_paths=self._build_readable_paths(),
                    writable_paths=self._build_writable_paths(),
                    tool_paths=self._rust_tool_paths() or None,
                    stdout=stdout_fp,
                    stderr=stderr_fp,
                    timeout=self.build_timeout,
                    cwd=str(self.crate_dir),
                    env=self._build_env(),
                    # env is get_safe_env() + identity scrub —
                    # acknowledged as filtered.
                    env_caller_filtered=True,
                )
        except subprocess.TimeoutExpired:
            msg = (
                f"cargo fuzz build exceeded {self.build_timeout}s for "
                f"target '{self.fuzz_target}' — see {stderr_path}"
            )
            raise RuntimeError(msg) from None
        if completed.returncode != 0:
            raise RuntimeError(self._build_failure_message(
                completed.returncode, stderr_path))
        binary = self._locate_built_binary()
        if binary is None:
            msg = (
                f"cargo fuzz build reported success but no "
                f"'{self.fuzz_target}' binary was found under "
                f"{self._cargo_target_dir} or "
                f"{self.fuzz_dir / 'target'} — see {stdout_path}"
            )
            raise RuntimeError(msg)
        logger.info("%s built: %s", self._ENGINE_NAME, binary)
        return binary

    # Bound on the build-log excerpt embedded in the failure message.
    # Build output is target-influenced (build.rs prints), so it is
    # control-stripped and bounded before any operator-facing relay.
    _MAX_BUILD_EXCERPT_CHARS = 1500

    def _build_failure_message(self, returncode: int,
                               stderr_path: Path) -> str:
        tail = self._read_log_tail(stderr_path)
        excerpt = strip_terminal_controls(
            tail[-self._MAX_BUILD_EXCERPT_CHARS:])
        if len(tail) > self._MAX_BUILD_EXCERPT_CHARS:
            excerpt = "[... earlier output elided ...]\n" + excerpt
        lines = [
            f"cargo fuzz build failed (rc={returncode}) for target "
            f"'{self.fuzz_target}'.",
            excerpt.rstrip(),
        ]
        # Hints key on the whole (already read-bounded) tail, not the
        # display excerpt — build.rs output can pad past the failing
        # line without hiding the remedy.
        lines.extend(_build_failure_hints(strip_terminal_controls(tail)))
        lines.append(f"Full build log: {stderr_path}")
        return "\n".join(line for line in lines if line)

    def _locate_built_binary(self) -> Path | None:
        """Find the built fuzz-target executable.

        The run-dir target dir (where ``CARGO_TARGET_DIR`` pointed the
        build) wins WHENEVER it holds a candidate; the crate's own
        ``<fuzz_dir>/target`` is consulted only when the run dir has
        none (cargo-fuzz versions that pin their own target dir).
        Recency never overrides that ordering: a hostile ``build.rs``
        can plant or future-mtime a binary in ``fuzz/target`` DURING
        the build, so a newest-wins pool spanning both roots would let
        it displace the freshly built run-dir artifact. Within one
        root, per-triple subdirectories are searched and the newest
        artifact wins.
        """
        def _mtime(path: Path) -> float:
            try:
                return path.stat().st_mtime
            except OSError:
                return 0.0

        for root in (self._cargo_target_dir, self.fuzz_dir / "target"):
            if not root.is_dir():
                continue
            candidates: list[Path] = []
            for pattern in (f"release/{self.fuzz_target}",
                            f"*/release/{self.fuzz_target}"):
                for path in root.glob(pattern):
                    try:
                        if path.is_file() and os.access(path, os.X_OK):
                            candidates.append(path)
                    except OSError:
                        continue
            if candidates:
                return max(candidates, key=_mtime).resolve()
        return None

    # ------------------------------------------------------------------
    # Crash normalization
    # ------------------------------------------------------------------

    def _normalize_crash_records(
        self, result: CargoFuzzResult,
    ) -> list[dict[str, Any]]:
        """One record per crash artifact, in the existing crash-record
        shape (``crash_id`` / ``input_file`` / triage signal).
        libFuzzer exits on the first crash, so the parsed panic
        attaches to every crash artifact of this run (in practice: the
        one)."""
        panic = result.rust_panic
        records: list[dict[str, Any]] = []
        for artifact in sorted(result.crashes):
            record: dict[str, Any] = {
                "crash_id": artifact.name,
                "input_file": str(artifact),
                "engine": "cargo-fuzz",
                "fuzz_target": self.fuzz_target,
                "binary": str(self._built_binary or ""),
            }
            if panic is not None:
                record.update(panic.to_dict())
                record["stack_hash"] = panic.stack_key
            records.append(record)
        return records

    def _persist_crash_records(self, records: list[dict[str, Any]]) -> None:
        # ALWAYS write, even an empty list: the output dir is inside
        # the campaign's sandbox write scope, so a hostile harness can
        # plant its own cargofuzz-crashes.json mid-run — an early
        # return on zero records would leave that forged
        # operator-facing sidecar in place after a crash-less campaign.
        try:
            path = self.output_dir / "cargofuzz-crashes.json"
            # Exclusive create (replace=True unlinks a planted SYMLINK
            # of this name ITSELF; the O_EXCL open fails loud on
            # anything reappearing in the window).
            write_new_text(
                path, json.dumps(records, indent=2), replace=True,
            )
            if records:
                logger.info("cargo-fuzz crash records: %s", path)
        except OSError as e:
            logger.warning(
                "could not persist cargo-fuzz crash records: %s", e)


def _build_failure_hints(excerpt: str) -> list[str]:
    """Precise remedies for the known build-failure classes, keyed on
    the (bounded, control-stripped) log excerpt."""
    hints: list[str] = []
    lowered = excerpt.lower()
    if ("offline" in lowered or "no matching package" in lowered
            or "failed to download" in lowered
            or "network" in lowered):
        hints.append(
            "Hint: the build runs network-isolated (CARGO_NET_OFFLINE). "
            "Fetch dependencies once in a trusted context — run "
            "'cargo fetch' inside the crate's fuzz/ directory — then "
            "re-run the campaign."
        )
    if ("nightly" in lowered or "-zsanitizer" in lowered
            or "unstable" in lowered):
        hints.append(
            "Hint: cargo-fuzz's sanitizer builds need a nightly Rust "
            "toolchain: rustup toolchain install nightly"
        )
    if "no such command: `fuzz`" in lowered:
        hints.append(f"Hint: {CARGO_FUZZ_INSTALL_HINT}")
    if "read-only file system" in lowered or "erofs" in lowered:
        hints.append(
            "Hint: the sandbox's mount-ns lane masks writable entries "
            "under the read-only target bind, so an in-crate write "
            "(fuzz/Cargo.lock generation, a cargo-fuzz-pinned "
            "fuzz/target) fails there. Run 'cargo fetch' inside the "
            "crate's fuzz/ directory once in a trusted context — it "
            "writes the lockfile — then re-run the campaign."
        )
    return hints


def parse_rust_panic(output: str) -> RustPanicInfo | None:
    """Parse the LAST Rust panic block from harness output.

    Handles both panic formats — the old single-line
    ``panicked at 'msg', file:line:col`` and the new (rustc >= 1.73)
    two-line ``panicked at file:line:col:`` + message — plus the
    ``RUST_BACKTRACE=1`` numbered frames that follow. All of it is
    untrusted target output: every line is stripped of terminal
    control sequences and length-bounded before matching, and the
    frame count is capped. Bidi override characters survive into the
    records by design (same posture as the atheris parser): the
    ``core.security.log_sanitisation`` contract escapes them at every
    operator-display egress, so they are inert where they are seen.
    """
    lines = output.splitlines()
    header_idx = -1
    for i, raw in enumerate(lines):
        if "panicked at" in raw:
            header_idx = i
    if header_idx < 0:
        return None

    header = strip_terminal_controls(lines[header_idx])[:_MAX_LINE_CHARS]
    thread = ""
    message = ""
    location = ""
    match = _PANIC_OLD_RE.match(header)
    if match:
        thread, message, file, line_no, col = match.groups()
        location = f"{file}:{line_no}:{col}"
        body_start = header_idx + 1
    else:
        match = _PANIC_NEW_RE.match(header)
        if match is None:
            # A "panicked at" substring that is not a panic header —
            # bail rather than mis-attribute arbitrary output.
            return None
        thread, file, line_no, col = match.groups()
        location = f"{file}:{line_no}:{col}"
        body_start = header_idx + 1
        # New format: the message is the first non-empty line below
        # the header, before the note/backtrace block.
        for raw in lines[body_start:body_start + _MAX_MESSAGE_LOOKAHEAD]:
            candidate = strip_terminal_controls(raw)[:_MAX_LINE_CHARS]
            stripped = candidate.strip()
            if not stripped:
                continue
            if stripped.startswith(("note:", "stack backtrace:")):
                break
            message = stripped
            body_start += 1
            break

    frames: list[str] = []
    for raw in lines[body_start:]:
        line = strip_terminal_controls(raw)[:_MAX_LINE_CHARS]
        frame = _BACKTRACE_FRAME_RE.match(line)
        if frame:
            frames.append(frame.group(2).strip())
            if len(frames) >= _MAX_FRAMES:
                break
        elif frames and not line.strip().startswith("at "):
            # Past the backtrace block.
            break

    digest = hashlib.sha256(
        "\n".join([location, *frames]).encode("utf-8", errors="replace")
    ).hexdigest()[:16]
    return RustPanicInfo(
        message=message,
        location=location,
        thread=thread,
        frames=frames,
        stack_key=digest,
    )
