"""Jazzer (JVM) campaign runner.

Jazzer is the coverage-guided JVM fuzzer: a native libFuzzer driver
that loads the JVM and calls a Java/Kotlin harness's
``fuzzerTestOneInput``. This runner extends
:class:`~packages.fuzzing.libfuzzer_runner.LibFuzzerRunner` — the
campaign process contract (sandboxed blocking run, file-backed stream
capture, bounded log-tail parsing, stats grammar, crash-artifact
layout with ``crash-``/``timeout-``/``oom-`` prefixes,
campaign-failure verdict) is libFuzzer's own — and adds what the JVM
changes:

  - a BUILD phase first when the harness classes must be compiled:
    Maven (``pom.xml``), Gradle (``build.gradle[.kts]``), or a bare
    ``javac`` compile for build-system-less trees, all inside the
    sandbox; the campaign then executes the ``jazzer`` binary DIRECTLY
    through the parent's libFuzzer contract with ``--cp`` /
    ``--target_class`` (the build tool never runs inside the
    campaign);
  - the campaign environment carries ``JAVA_HOME`` (the identity scrub
    resets HOME, under which the jazzer launcher would find no JVM);
  - crashes are usually uncaught Java exceptions or Jazzer finding
    reports — the exception type, message, and stack frames parsed
    from the harness output become the triage signal on the
    normalized crash records.

Containment contract:

  - The BUILD executes target code (``pom.xml`` plugins ARE code,
    ``build.gradle`` IS code), so it runs under ``core.sandbox.run``
    with ``block_network=True`` AND the build tool pinned offline
    (``mvn -o`` / ``gradle --offline``) — a clean "not cached" error
    instead of a hung download; the remedy is one trusted-context
    build (``mvn -DskipTests test-compile`` / ``gradle testClasses``)
    to populate the local cache, the ``cargo fetch`` precedent. Reads
    are restricted to the project, the JVM/build-tool roots, and the
    run directory. Writes are scoped to the run directory plus the
    directories the build tool itself requires inside the project:
    each module's ``target/`` (Maven) or ``build/`` dir plus the root
    ``.gradle/`` project cache (Gradle) — every granted dir is
    resolve()-contained under the project first (a repo-planted
    ``target`` symlink must not steer the grant elsewhere on the
    host), pre-created, and named here; never wider. A bare ``javac``
    compile writes the run directory only. Lane note: the mount-ns
    sandbox lane masks writable entries under the read-only target
    bind — strictly more restrictive; an in-project write need
    surfaces as an EROFS build failure whose hints name the
    trusted-context pre-build remedy.
  - The dependency caches the build sees are HERMETIC and per-run:
    ``~/.m2/repository`` and ``~/.gradle/caches`` are the same class
    of shared mutable cache as the cargo registry — a hostile build
    given a writable shared cache can poison artifacts that the
    operator's own later, trusted builds silently consume. The build
    gets a run-local ``m2-repo`` (via ``-Dmaven.repo.local``) /
    ``gradle-home`` (via ``GRADLE_USER_HOME``) inside the run
    directory, seeded by full copy (``cp --reflink=auto`` — NEVER
    hardlinks, whose shared inodes let an in-place write reach the
    host cache) of the host repository / the host
    ``caches/modules-2`` dependency cache. The host caches are never
    in the build's write scope — NOR its read set: the seeding copy
    runs outside the sandbox before the build, so the sandboxed
    (hostile) build never sees the host cache roots at all. That
    matters beyond poisoning: ``~/.gradle/gradle.properties`` and
    ``~/.m2/settings.xml`` carry signing keys and repository
    credentials that a read grant would hand to target code. A
    reused output_dir keeps its run-local caches across campaigns —
    the same trust domain as every other reused run-dir artifact,
    and never the host cache.
  - The repo's own ``mvnw`` / ``gradlew`` wrapper scripts are NEVER
    executed — they are target code whose first act is downloading a
    build-tool distribution. Only the system ``mvn`` / ``gradle`` /
    ``javac`` run, absolute-pinned.
  - The classpath the campaign hands to jazzer comes from the
    sandboxed build's own output (``classpath.txt`` /
    build-classpath), i.e. target-influenced text: entries are vetted
    before use — kept only when they exist and resolve inside the
    project or the run directory (which the campaign may read
    anyway), bounded in count and length, everything else dropped
    with a warning. A hostile build cannot widen the campaign's read
    allowlist through a planted classpath entry.
  - The CAMPAIGN keeps the parent's strict scope: network deny, read
    allowlist (jazzer, JVM, project, corpus, output), writes to the
    run directory only, sandbox rlimits, ``-rss_limit_mb`` in-process.
  - Both phases run on ``RaptorConfig.get_safe_env()`` +
    ``scrub_identity_env`` — never ambient ``os.environ`` — with only
    the JVM/build-tool variables the phase needs added on top.

Toolchain: the ``jazzer`` binary and a JVM are hard requirements
(construction refuses with install hints), plus the layout's build
tool — ``mvn``, ``gradle``, or ``javac`` for bare trees.
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
    _JAVA_BUILD_MARKERS,
    _JAZZER_SKIP_DIRS,
    _JAZZER_TARGET_CLASS_RE,
    list_jazzer_targets,
)

logger = get_logger()

JAZZER_INSTALL_HINT = (
    "jazzer (the JVM fuzzer) was not found on PATH. Download the "
    "standalone release from "
    "https://github.com/CodeIntelligenceTesting/jazzer/releases and "
    "put the `jazzer` binary on PATH."
)
JAVA_INSTALL_HINT = (
    "no JVM found (neither `java` on PATH nor a valid JAVA_HOME). "
    "Install a JRE/JDK (e.g. OpenJDK)."
)
JAVAC_INSTALL_HINT = (
    "javac not found on PATH — a bare Java source tree (no Maven/"
    "Gradle build) is compiled with javac. Install a JDK."
)
MAVEN_INSTALL_HINT = (
    "mvn not found on PATH — this project carries a pom.xml, so the "
    "harness classes are built with Maven. Install Maven (the repo's "
    "own mvnw wrapper is never executed)."
)
GRADLE_INSTALL_HINT = (
    "gradle not found on PATH — this project carries a Gradle build, "
    "so the harness classes are built with Gradle. Install Gradle "
    "(the repo's own gradlew wrapper is never executed)."
)
TRUSTED_BUILD_REMEDY = (
    "Populate the local dependency cache once in a trusted context — "
    "run 'mvn -DskipTests test-compile' (Maven) or 'gradle "
    "testClasses' (Gradle) inside the project — then re-run the "
    "campaign."
)

# Bounds on exception excerpts persisted into crash records and
# relayed to the operator. The report text comes from the untrusted
# harness process's output.
_MAX_FRAMES = 40
_MAX_LINE_CHARS = 300

# Jazzer finding report header:
#   == Java Exception: java.lang.IllegalStateException: boom: 7
#   == Java Exception: java.lang.ArrayIndexOutOfBoundsException
# The exception type is a Java FQCN (colon is not in its charset, so
# the greedy type group stops at the ": " message separator). Every
# repeat is bounded and the line itself is pre-bounded to
# _MAX_LINE_CHARS before matching.
_JAVA_EXC_MARKER = "== Java Exception:"
_JAVA_EXC_RE = re.compile(
    r"^== Java Exception:\s{1,8}([A-Za-z_$][A-Za-z0-9_$.]{0,300})"
    r"(?::\s(.{0,300}))?\s{0,8}$"
)
# JVM stack frame:  "\tat com.example.Foo.bar(Foo.java:42)"
# (also "at java.base/jdk...(...)", "(Native Method)",
# "(Unknown Source)").
_JAVA_FRAME_RE = re.compile(
    r"^\s{1,16}at ([^\s(]{1,300})\((.{0,300})\)\s{0,8}$"
)

# Bounds on target-influenced build outputs consumed on the run side.
_MAX_CLASSPATH_ENTRIES = 512
_MAX_CLASSPATH_ENTRY_CHARS = 4096
_MAX_CLASSPATH_FILE_BYTES = 1024 * 1024
_MAX_BUILD_MODULES = 64
_MAX_BARE_SOURCES = 2000
_MAX_JAZZER_DIR_JARS = 16

_SYSTEM_PREFIXES = ("/usr/", "/lib/", "/lib64/", "/etc/", "/bin/",
                    "/sbin/", "/opt/")


def jazzer_executable() -> str | None:
    """Absolute path to the jazzer binary, or None when not installed."""
    found = shutil.which("jazzer")
    if not found:
        return None
    path = Path(found)
    # which() honours relative PATH entries; the result becomes the
    # sandboxed campaign's argv[0], so pin it absolute.
    return str(path if path.is_absolute() else path.resolve())


def _absolute_which(name: str) -> str | None:
    found = shutil.which(name)
    if not found:
        return None
    path = Path(found)
    return str(path if path.is_absolute() else path.resolve())


def javac_executable() -> str | None:
    return _absolute_which("javac")


def maven_executable() -> str | None:
    return _absolute_which("mvn")


def gradle_executable() -> str | None:
    return _absolute_which("gradle")


def _resolve_java_home() -> Path | None:
    """The JVM installation root — JAVA_HOME when it names a real
    install, else derived from the ``java`` binary on PATH (the
    identity scrub resets HOME/JAVA_HOME, so it must be pinned
    explicitly into both phase environments)."""
    env_home = os.environ.get("JAVA_HOME")
    if env_home:
        candidate = Path(env_home)
        if (candidate / "bin" / "java").is_file():
            return candidate
    java = shutil.which("java")
    if not java:
        return None
    try:
        resolved = Path(java).resolve()
    except OSError:
        return None
    # <java_home>/bin/java
    if resolved.parent.name == "bin" and len(resolved.parents) >= 2:
        return resolved.parents[1]
    return resolved.parent


def build_tool_for(project_dir: Path) -> str:
    """Which build lane a java-project takes: ``maven`` (pom.xml),
    ``gradle`` (any Gradle marker), or ``bare`` (javac compile)."""
    project = Path(project_dir)
    if (project / "pom.xml").is_file():
        return "maven"
    if any((project / marker).is_file()
           for marker in _JAVA_BUILD_MARKERS[1:]):
        return "gradle"
    return "bare"


def build_tool_executable(tool: str) -> str | None:
    """Absolute path of the build lane's tool, or None when absent."""
    if tool == "maven":
        return maven_executable()
    if tool == "gradle":
        return gradle_executable()
    return javac_executable()


def build_tool_install_hint(tool: str) -> str:
    return {"maven": MAVEN_INSTALL_HINT,
            "gradle": GRADLE_INSTALL_HINT}.get(tool, JAVAC_INSTALL_HINT)


def project_corpus_dir(
    project_dir: Path,
    target_class: str,
    target_source: Path | None = None,
) -> Path | None:
    """The project's own seed corpus for *target_class*, when one
    exists at the jazzer JUnit convention location
    (``src/test/resources/<package-path>/<SimpleName>Inputs`` under
    the module that declares the harness) and holds at least one
    regular file. The caller stages it through the bounded,
    symlink-refusing corpus stager — this only decides whether the
    conventional location is worth staging."""
    if not _JAZZER_TARGET_CLASS_RE.fullmatch(str(target_class)):
        return None
    try:
        project = Path(project_dir).resolve()
    except OSError:
        return None
    parts = str(target_class).split(".")
    package_path = Path(*parts[:-1]) if len(parts) > 1 else Path()
    inputs_name = f"{parts[-1]}Inputs"

    module = project
    if target_source is not None:
        # Walk up from the harness source to the module root (the
        # nearest dir carrying a build marker), never above the
        # project.
        try:
            current = Path(target_source).resolve().parent
        except OSError:
            current = project
        while current != project and project in current.parents:
            if any((current / marker).is_file()
                   for marker in _JAVA_BUILD_MARKERS):
                module = current
                break
            current = current.parent

    candidate = (module / "src" / "test" / "resources"
                 / package_path / inputs_name)
    try:
        resolved = candidate.resolve()
        # The resources chain is scanned-repo content — a symlinked
        # segment must not point the corpus read off the project.
        if resolved != project and project not in resolved.parents:
            return None
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
class JavaExceptionInfo:
    """The Java exception (or Jazzer finding report — Jazzer's
    security detectors raise ``FuzzerSecurityIssue*`` exception types
    through the same report) the harness died on.

    ``stack_key`` is a short content hash over the exception type and
    the stack frames — the JVM analogue of the atheris path's
    exception stack key, used for crash dedup and witness detail.
    """

    exception_type: str
    message: str = ""
    frames: list[str] = field(default_factory=list)
    stack_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "exception_type": self.exception_type,
            "message": self.message,
            "frames": list(self.frames),
            "stack_key": self.stack_key,
        }


@dataclass
class JazzerResult(LibFuzzerResult):
    """libFuzzer result plus the JVM-side triage signal."""

    #: Exception parsed from the campaign output (libFuzzer exits on
    #: the first crash, so at most one is in play per run).
    java_exception: JavaExceptionInfo | None = None
    #: Normalized per-artifact crash records (also persisted to
    #: ``jazzer-crashes.json`` in the output dir).
    crash_records: list[dict[str, Any]] = field(default_factory=list)
    #: Which build lane compiled the harness classes.
    build_tool: str = ""
    #: The vetted classpath the campaign ran with.
    classpath: list[str] = field(default_factory=list)


class JazzerRunner(LibFuzzerRunner):
    """Build a JVM project's harness classes and run jazzer under the
    fuzzing sandbox."""

    _ENGINE_NAME = "jazzer"

    def __init__(
        self,
        project_dir: Path,
        target_class: str,
        *,
        target_source: Path | None = None,
        corpus_dir: Path | None = None,
        output_dir: Path | None = None,
        dict_path: Path | None = None,
        max_total_time: int = 600,
        max_len: int = 4096,
        timeout_seconds: int = 25,
        rss_limit_mb: int = 2048,
        build_timeout: int = 900,
    ) -> None:
        # The class name becomes a jazzer command argument and a
        # resource-path component — vet the charset before ANY use.
        if not _JAZZER_TARGET_CLASS_RE.fullmatch(str(target_class)):
            msg = (
                "jazzer target class must be a dotted Java identifier "
                f"chain (got {str(target_class)[:80]!r})"
            )
            raise ValueError(msg)
        self.target_class = str(target_class)
        self.project_dir = Path(project_dir).resolve()
        targets = list_jazzer_targets(self.project_dir)
        if not targets:
            msg = (
                f"no Jazzer fuzz targets under {self.project_dir} "
                "(expected a class with a fuzzerTestOneInput method or "
                "a @FuzzTest annotation)."
            )
            raise FileNotFoundError(msg)
        by_name = {t.class_name: t for t in targets}
        if self.target_class not in by_name:
            available = ", ".join(sorted(by_name)[:8])
            msg = (
                f"fuzz target '{self.target_class}' not found under "
                f"{self.project_dir} (available: {available or 'none'})"
            )
            raise ValueError(msg)
        self.target_source: Path | None = (
            Path(target_source) if target_source is not None
            else by_name[self.target_class].source
        )

        jazzer = jazzer_executable()
        if jazzer is None:
            raise RuntimeError(JAZZER_INSTALL_HINT)
        self.jazzer = jazzer
        self._java_home = _resolve_java_home()
        if self._java_home is None:
            raise RuntimeError(JAVA_INSTALL_HINT)
        self.build_tool = build_tool_for(self.project_dir)
        self._build_tool_path = build_tool_executable(self.build_tool)
        if self._build_tool_path is None:
            raise RuntimeError(build_tool_install_hint(self.build_tool))
        if self.build_tool == "bare" and self.target_source is not None \
                and self.target_source.suffix == ".kt":
            msg = (
                f"'{self.target_class}' is a Kotlin harness in a "
                "build-system-less tree — bare-source compilation is "
                "javac-only. Add a Gradle/Maven build for Kotlin."
            )
            raise RuntimeError(msg)
        self.build_timeout = build_timeout
        self._host_m2_repo = _resolve_host_m2_repo()
        self._host_gradle_home = _resolve_host_gradle_home()
        self._classpath: list[str] = []

        if output_dir is None:
            safe_stem = re.sub(r"[^A-Za-z0-9_]", "_", self.target_class)
            output_dir = (
                RaptorConfig.get_out_dir()
                / f"jazzer_{safe_stem}_{int(time.time())}"
            )
        super().__init__(
            Path(self.jazzer),
            corpus_dir=corpus_dir,
            output_dir=output_dir,
            dict_path=dict_path,
            max_total_time=max_total_time,
            max_len=max_len,
            timeout_seconds=timeout_seconds,
            rss_limit_mb=rss_limit_mb,
        )
        # Build artifacts land in the run dir where possible; Maven and
        # Gradle additionally write their own module output dirs (see
        # the module containment contract).
        self._run_classes = self.output_dir / "classes"
        self._classpath_file = self.output_dir / "classpath.txt"
        # Hermetic per-run dependency caches (see the module
        # containment contract): inside the run dir's existing write
        # scope — the host caches themselves are never build-writable.
        self._run_m2_repo = self.output_dir / "m2-repo"
        self._run_gradle_home = self.output_dir / "gradle-home"

    # ------------------------------------------------------------------
    # Subclass seams (campaign phase)
    # ------------------------------------------------------------------

    def _build_command(self) -> list[str]:
        # Parent builds ``[jazzer, corpus, <libFuzzer flags>]``; jazzer
        # passes single-dash flags through to libFuzzer and takes its
        # own ``--flag=value`` arguments for the JVM side.
        base = super()._build_command()
        return [
            base[0],
            f"--cp={os.pathsep.join(self._classpath)}",
            f"--target_class={self.target_class}",
            *base[1:],
        ]

    def _campaign_env(self) -> dict:
        env = super()._campaign_env()
        # The jazzer launcher locates libjvm through JAVA_HOME; the
        # identity scrub resets HOME, under which it would find none.
        env["JAVA_HOME"] = str(self._java_home)
        return env

    def _sandbox_tool_paths(self) -> list[str]:
        """JVM and jazzer roots the campaign sandbox's read allowlist
        needs beyond the system baseline."""
        paths: list[str] = []
        candidates = [
            self._java_home,
            Path(self.jazzer).parent,
            Path(self.jazzer).resolve().parent,
        ]
        for candidate in candidates:
            if candidate is None:
                continue
            text = str(candidate)
            if text.startswith(_SYSTEM_PREFIXES):
                continue
            if candidate.is_dir() and text not in paths:
                paths.append(text)
        return paths

    def _readable_paths(self) -> list[str]:
        paths = super()._readable_paths()
        if str(self.project_dir) not in paths:
            paths.append(str(self.project_dir))
        return paths

    def _new_result(self) -> JazzerResult:
        return JazzerResult(
            target=str(self.harness),
            output_dir=self.output_dir,
            corpus_dir=self.corpus_dir,
            build_tool=self.build_tool,
            classpath=list(self._classpath),
        )

    def _parse_result(
        self,
        stderr: str,
        _stdout: str,
        elapsed: float,
    ) -> JazzerResult:
        result = super()._parse_result(stderr, _stdout, elapsed)
        assert isinstance(result, JazzerResult)  # _new_result contract
        # Jazzer prints the finding report on stderr alongside
        # libFuzzer's own crash handling; stdout is checked second,
        # belt-and-braces.
        result.java_exception = (
            parse_java_exception(stderr) or parse_java_exception(_stdout)
        )
        result.crash_records = self._normalize_crash_records(result)
        self._persist_crash_records(result.crash_records)
        return result

    # ------------------------------------------------------------------
    # Build phase
    # ------------------------------------------------------------------

    def run(self, telemetry=None) -> JazzerResult:
        """Build the harness classpath, then run the campaign.

        Unlike the cargo-fuzz sibling there is no per-target binary to
        rebind ``self.harness`` to: the jazzer driver stays argv[0]
        and the build's product is the ``--cp`` classpath.
        """
        self._classpath = self._build_classpath()
        result = super().run(telemetry)
        assert isinstance(result, JazzerResult)  # _new_result contract
        return result

    def _build_classpath(self) -> list[str]:
        if self.build_tool == "maven":
            return self._build_maven()
        if self.build_tool == "gradle":
            return self._build_gradle()
        return self._build_bare()

    def _build_env(self) -> dict:
        env = scrub_identity_env(RaptorConfig.get_safe_env())
        env["JAVA_HOME"] = str(self._java_home)
        # The build tool and the JVM it execs come from PATH; the
        # identity scrub drops /home/* PATH components, where local
        # tool installs may live — re-append their own directories.
        parts = [p for p in env.get("PATH", "").split(os.pathsep) if p]
        for extra in (
            str(Path(self._build_tool_path).parent),
            str(self._java_home / "bin"),
        ):
            if extra not in parts:
                parts.append(extra)
        env["PATH"] = os.pathsep.join(parts)
        return env

    def _build_readable_paths(self) -> list[str]:
        return [str(self.project_dir), str(self.output_dir)]

    def _jvm_tool_paths(self) -> list[str]:
        """JVM / build-tool roots the build sandbox's read allowlist
        needs beyond the system baseline.

        The host dependency caches are deliberately NOT here: the
        seeding copy runs OUTSIDE the sandbox before the build, and
        the build itself uses only the run-local caches — so the
        sandboxed (hostile) build has no reason to read the host
        roots. A read grant on ``~/.gradle`` in particular would
        expose ``gradle.properties`` (signing keys, repository
        credentials) to target code; ``~/.m2`` likewise carries
        ``settings.xml`` server credentials beside the repository.
        """
        paths: list[str] = []
        candidates = [
            self._java_home,
            Path(self._build_tool_path).parent,
            Path(self._build_tool_path).resolve().parent,
        ]
        for candidate in candidates:
            if candidate is None:
                continue
            text = str(candidate)
            if text.startswith(_SYSTEM_PREFIXES):
                continue
            if candidate.is_dir() and text not in paths:
                paths.append(text)
        return paths

    def _module_build_dirs(self, marker_names: tuple[str, ...],
                           out_name: str) -> list[Path]:
        """The build tool's own output dirs inside the project — the
        ONLY in-project write grants the build gets.

        Modules are located by their marker files through a bounded,
        symlink-free walk, and BOTH levels are contained: the module
        dir comes from the walk (never through a directory symlink)
        and its ``<out_name>`` child is refused when it resolves
        outside the project — a repo-planted ``target``/``build``
        symlink would otherwise steer the write grant at an arbitrary
        host tree. Grant dirs are pre-created so the sandbox rules
        bind to real directories.
        """
        grants: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(
                self.project_dir, followlinks=False):
            dirnames[:] = sorted(
                d for d in dirnames
                if d not in _JAZZER_SKIP_DIRS and not d.startswith(".")
            )
            if len(grants) >= _MAX_BUILD_MODULES:
                break
            if not any(marker in filenames for marker in marker_names):
                continue
            module = Path(dirpath)
            out_dir = module / out_name
            try:
                if out_dir.is_symlink():
                    raise OSError("symlinked build output dir")
                out_dir.mkdir(exist_ok=True)
                resolved = out_dir.resolve()
            except OSError as e:
                logger.warning(
                    "refusing build write grant on %s: %s", out_dir, e)
                continue
            if resolved != self.project_dir and \
                    self.project_dir not in resolved.parents:
                logger.warning(
                    "refusing build write grant on %s: resolves to %s, "
                    "outside the project %s",
                    out_dir, resolved, self.project_dir,
                )
                continue
            grants.append(resolved)
        return grants

    # Subtrees seeded from the host gradle home into the run-local
    # one. caches/modules-2 is the dependency artifact+metadata cache;
    # daemon state, JDK downloads, and init scripts are deliberately
    # NOT copied — unneeded, or executable content.
    _GRADLE_SEED_SUBTREES = ("caches/modules-2",)

    def _seed_run_m2_repo(self) -> None:
        """Seed the hermetic run-local Maven repository from the host
        ``~/.m2/repository``.

        Full COPY via ``cp --reflink=auto`` (cheap CoW clone on
        supporting filesystems, plain copy elsewhere). NEVER a
        hardlink farm: hardlinks share inodes, so a hostile build
        plugin writing a seeded artifact IN PLACE would reach the host
        cache through the link. Maven has no separable index/archive
        split (the repository IS the artifact store), so the whole
        repository seeds. Idempotent per run dir — an already-seeded
        repo is kept (same-run rebuilds); a missing host repo seeds
        nothing (dependency-less builds still work; dependency builds
        fail with the offline hint).
        """
        if self._run_m2_repo.exists():
            return
        if self._host_m2_repo is None or not self._host_m2_repo.is_dir():
            self._run_m2_repo.mkdir(parents=True, exist_ok=True)
            return
        self._copy_seed(self._host_m2_repo, self._run_m2_repo)

    def _seed_run_gradle_home(self) -> None:
        """Seed the hermetic run-local Gradle home from the host
        cache's dependency subtree only (same copy/never-hardlink
        contract as the Maven seed)."""
        self._run_gradle_home.mkdir(parents=True, exist_ok=True)
        if self._host_gradle_home is None:
            return
        for rel in self._GRADLE_SEED_SUBTREES:
            source = self._host_gradle_home / rel
            destination = self._run_gradle_home / rel
            if not source.is_dir() or destination.exists():
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            self._copy_seed(source, destination)

    @staticmethod
    def _copy_seed(source: Path, destination: Path) -> None:
        copy = subprocess.run(
            ["cp", "-R", "--reflink=auto", "--", str(source),
             str(destination)],
            capture_output=True, text=True,
            env=scrub_identity_env(RaptorConfig.get_safe_env()),
        )
        if copy.returncode != 0:
            logger.warning(
                "dependency-cache seed of %s failed (rc=%s): %s",
                source, copy.returncode,
                strip_terminal_controls(copy.stderr)[:300],
            )

    def _run_build(self, cmd: list[str], *, env: dict,
                   writable_paths: list[str]) -> None:
        """One sandboxed build-tool invocation with the shared failure
        contract (bounded excerpt, keyed hints, full log path)."""
        logger.info("%s build (%s): %s", self._ENGINE_NAME,
                    self.build_tool, " ".join(cmd))
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
                    target=str(self.project_dir),
                    output=str(self.output_dir),
                    restrict_reads=True,
                    readable_paths=self._build_readable_paths(),
                    writable_paths=writable_paths,
                    tool_paths=self._jvm_tool_paths() or None,
                    stdout=stdout_fp,
                    stderr=stderr_fp,
                    timeout=self.build_timeout,
                    cwd=str(self.project_dir),
                    env=env,
                    # env is get_safe_env() + identity scrub —
                    # acknowledged as filtered.
                    env_caller_filtered=True,
                )
        except subprocess.TimeoutExpired:
            msg = (
                f"{self.build_tool} build exceeded {self.build_timeout}s "
                f"for target '{self.target_class}' — see {stderr_path}"
            )
            raise RuntimeError(msg) from None
        if completed.returncode != 0:
            raise RuntimeError(self._build_failure_message(
                completed.returncode, stdout_path, stderr_path))

    # Bound on the build-log excerpt embedded in the failure message.
    # Build output is target-influenced (build scripts print), so it
    # is control-stripped and bounded before any operator-facing
    # relay.
    _MAX_BUILD_EXCERPT_CHARS = 1500

    def _build_failure_message(self, returncode: int,
                               stdout_path: Path,
                               stderr_path: Path) -> str:
        # BOTH streams: Maven reports its failures ([ERROR] lines,
        # the offline-mode diagnosis) on STDOUT, Gradle and javac on
        # stderr — excerpting and hint-keying stderr alone leaves the
        # remedy silent on the Maven lane. stdout rides last so the
        # tail excerpt biases toward it when both carry text.
        tail = (self._read_log_tail(stderr_path) + "\n"
                + self._read_log_tail(stdout_path))
        excerpt = strip_terminal_controls(
            tail[-self._MAX_BUILD_EXCERPT_CHARS:])
        if len(tail) > self._MAX_BUILD_EXCERPT_CHARS:
            excerpt = "[... earlier output elided ...]\n" + excerpt
        lines = [
            f"{self.build_tool} build failed (rc={returncode}) for "
            f"target '{self.target_class}'.",
            excerpt.rstrip(),
        ]
        # Hints key on the whole (already read-bounded) tails, not the
        # display excerpt — build output can pad past the failing line
        # without hiding the remedy.
        lines.extend(_build_failure_hints(strip_terminal_controls(tail)))
        lines.append(f"Full build logs: {stderr_path} {stdout_path}")
        return "\n".join(line for line in lines if line)

    def _bare_java_sources(self) -> list[Path]:
        """Every ``.java`` source in the tree, for the bare ``javac``
        compile — bounded, symlink-refusing (the tree is scanned-repo
        content), build-output dirs pruned."""
        sources: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(
                self.project_dir, followlinks=False):
            dirnames[:] = sorted(
                d for d in dirnames
                if d not in _JAZZER_SKIP_DIRS and not d.startswith(".")
            )
            for name in sorted(filenames):
                if not name.endswith(".java"):
                    continue
                entry = Path(dirpath) / name
                try:
                    if entry.is_symlink() or not entry.is_file():
                        continue
                except OSError:
                    continue
                sources.append(entry)
                if len(sources) > _MAX_BARE_SOURCES:
                    msg = (
                        f"more than {_MAX_BARE_SOURCES} .java sources "
                        "in a build-system-less tree — the bare javac "
                        "lane is for small trees. Add a Maven/Gradle "
                        "build."
                    )
                    raise RuntimeError(msg)
        return sources

    def _jazzer_dir_jars(self) -> list[str]:
        """Jars shipped beside the jazzer binary (the standalone
        release carries jazzer_standalone.jar with the API classes a
        FuzzedDataProvider harness compiles against). Operator-installed
        location — bounded, sorted."""
        jars: list[str] = []
        try:
            entries = sorted(Path(self.jazzer).resolve().parent.iterdir())
        except OSError:
            return []
        for entry in entries:
            if entry.suffix == ".jar" and entry.is_file():
                jars.append(str(entry))
                if len(jars) >= _MAX_JAZZER_DIR_JARS:
                    break
        return jars

    def _build_bare(self) -> list[str]:
        sources = self._bare_java_sources()
        if not sources:
            msg = f"no .java sources found under {self.project_dir}"
            raise RuntimeError(msg)
        self._run_classes.mkdir(parents=True, exist_ok=True)
        cmd = [self._build_tool_path, "-d", str(self._run_classes)]
        jars = self._jazzer_dir_jars()
        if jars:
            cmd.extend(["-cp", os.pathsep.join(jars)])
        cmd.extend(str(s) for s in sources)
        # Writes: the run dir only (-d routes the classes there) — no
        # in-project grant at all on the bare lane.
        self._run_build(cmd, env=self._build_env(), writable_paths=[])
        return [str(self._run_classes)]

    def _build_maven(self) -> list[str]:
        self._seed_run_m2_repo()
        modules = self._module_build_dirs(("pom.xml",), "target")
        cmd = [
            self._build_tool_path, "-B", "-o",
            "test-compile", "dependency:build-classpath",
            f"-Dmdep.outputFile={self._classpath_file}",
            f"-Dmaven.repo.local={self._run_m2_repo}",
        ]
        self._run_build(cmd, env=self._build_env(),
                        writable_paths=[str(m) for m in modules])
        entries = self._read_classpath_file()
        # The dependency classpath plus each module's own compiled
        # classes (test-compile writes target/classes +
        # target/test-classes).
        for module in modules:
            for child in ("classes", "test-classes"):
                candidate = module / child
                if candidate.is_dir():
                    entries.append(str(candidate))
        classpath = self._vet_classpath_entries(entries)
        if not classpath:
            msg = (
                "maven build reported success but produced no usable "
                f"classpath — see {self._classpath_file} and "
                f"{self.output_dir / 'build-stderr.log'}"
            )
            raise RuntimeError(msg)
        return classpath

    # Trusted constant written into the run dir and handed to gradle
    # with -I: registers a task appending each project's main/test
    # runtime classpath to the file named by raptor.classpath.out.
    _GRADLE_INIT_SCRIPT = """\
// RAPTOR: collect the test/main runtime classpaths into the run dir.
allprojects { project ->
    project.tasks.register("raptorFuzzClasspath") {
        doLast {
            def outPath = System.getProperty("raptor.classpath.out")
            if (outPath == null) { return }
            def sourceSets = project.extensions.findByName("sourceSets")
            if (sourceSets == null) { return }
            def entries = []
            ["test", "main"].each { name ->
                try {
                    entries.addAll(
                        sourceSets.getByName(name).runtimeClasspath.files)
                } catch (Exception ignored) { }
            }
            new File(outPath).append(
                entries.collect { it.absolutePath }
                       .join(File.pathSeparator) + File.pathSeparator)
        }
    }
}
"""

    def _build_gradle(self) -> list[str]:
        self._seed_run_gradle_home()
        modules = self._module_build_dirs(
            ("build.gradle", "build.gradle.kts"), "build")
        # Root project cache dir — gradle writes .gradle/ in the root
        # project; same containment check as the module grants.
        grants = [str(m) for m in modules]
        dot_gradle = self.project_dir / ".gradle"
        try:
            if dot_gradle.is_symlink():
                # Same logged-refusal shape as every other steerable
                # grant — never a silent skip.
                raise OSError("symlinked project .gradle dir")
            dot_gradle.mkdir(exist_ok=True)
            resolved = dot_gradle.resolve()
            if resolved == self.project_dir \
                    or self.project_dir in resolved.parents:
                grants.append(str(resolved))
            else:
                logger.warning(
                    "refusing build write grant on %s: resolves to "
                    "%s, outside the project %s",
                    dot_gradle, resolved, self.project_dir,
                )
        except OSError as e:
            logger.warning(
                "refusing build write grant on %s: %s", dot_gradle, e)
        init_script = self.output_dir / "raptor-classpath-init.gradle"
        write_new_text(init_script, self._GRADLE_INIT_SCRIPT,
                       replace=True)
        env = self._build_env()
        env["GRADLE_USER_HOME"] = str(self._run_gradle_home)
        cmd = [
            self._build_tool_path, "--offline", "--no-daemon",
            "-I", str(init_script),
            f"-Draptor.classpath.out={self._classpath_file}",
            "testClasses", "raptorFuzzClasspath",
        ]
        self._run_build(cmd, env=env, writable_paths=grants)
        classpath = self._vet_classpath_entries(
            self._read_classpath_file())
        if not classpath:
            msg = (
                "gradle build reported success but produced no usable "
                f"classpath — see {self._classpath_file} and "
                f"{self.output_dir / 'build-stderr.log'}"
            )
            raise RuntimeError(msg)
        return classpath

    def _read_classpath_file(self) -> list[str]:
        """Entries from the build's classpath file — bounded read; the
        content is target-influenced and vetted downstream."""
        try:
            with self._classpath_file.open("rb") as fh:
                text = fh.read(_MAX_CLASSPATH_FILE_BYTES).decode(
                    "utf-8", errors="replace")
        except OSError:
            return []
        return [entry.strip() for entry in text.split(os.pathsep)
                if entry.strip()]

    def _vet_classpath_entries(self, entries: list[str]) -> list[str]:
        """Vet target-influenced classpath entries before they become
        a jazzer argument and part of the campaign's readable world.

        Kept: existing paths that resolve inside the project or the
        run directory (both already in the campaign's read scope), up
        to the count/length bounds, and whose RESOLVED text is free of
        ``os.pathsep``. Everything else — including a hostile build's
        attempt to classpath an arbitrary host file — is dropped, with
        one bounded warning naming the drop count.

        The pathsep check closes a join-boundary injection: the vetted
        entries are joined with ``os.pathsep`` into one ``--cp``
        argument, so a repo shipping a real directory chain like
        ``<project>/a:/etc`` would pass the exists+containment checks
        as ONE path and then split into TWO classpath entries
        (``<project>/a`` and ``/etc``) when the JVM parses the joined
        string.
        """
        kept: list[str] = []
        seen: set[str] = set()
        dropped = 0
        for raw in entries:
            if len(kept) >= _MAX_CLASSPATH_ENTRIES:
                dropped += 1
                continue
            if not raw or len(raw) > _MAX_CLASSPATH_ENTRY_CHARS:
                dropped += 1
                continue
            try:
                resolved = Path(raw).resolve()
                if not resolved.exists():
                    dropped += 1
                    continue
            except OSError:
                dropped += 1
                continue
            contained = False
            for root in (self.project_dir, self.output_dir):
                if resolved == root or root in resolved.parents:
                    contained = True
                    break
            if not contained:
                dropped += 1
                continue
            text = str(resolved)
            if os.pathsep in text:
                # Join-boundary injection (see docstring).
                dropped += 1
                continue
            if text not in seen:
                seen.add(text)
                kept.append(text)
        if dropped:
            logger.warning(
                "jazzer classpath: dropped %d entr%s (missing, "
                "oversize, over the %d-entry bound, or resolving "
                "outside the project / run dir)",
                dropped, "y" if dropped == 1 else "ies",
                _MAX_CLASSPATH_ENTRIES)
        return kept

    # ------------------------------------------------------------------
    # Crash normalization
    # ------------------------------------------------------------------

    def _normalize_crash_records(
        self, result: JazzerResult,
    ) -> list[dict[str, Any]]:
        """One record per crash artifact, in the existing crash-record
        shape (``crash_id`` / ``input_file`` / triage signal).
        libFuzzer exits on the first crash, so the parsed exception
        attaches to every crash artifact of this run (in practice: the
        one)."""
        exc = result.java_exception
        records: list[dict[str, Any]] = []
        for artifact in sorted(result.crashes):
            record: dict[str, Any] = {
                "crash_id": artifact.name,
                "input_file": str(artifact),
                "engine": "jazzer",
                "target_class": self.target_class,
                "build_tool": self.build_tool,
            }
            if exc is not None:
                record.update(exc.to_dict())
                record["stack_hash"] = exc.stack_key
            records.append(record)
        return records

    def _persist_crash_records(self, records: list[dict[str, Any]]) -> None:
        # ALWAYS write, even an empty list: the output dir is inside
        # the campaign's sandbox write scope, so a hostile harness can
        # plant its own jazzer-crashes.json mid-run — an early return
        # on zero records would leave that forged operator-facing
        # sidecar in place after a crash-less campaign.
        try:
            path = self.output_dir / "jazzer-crashes.json"
            # Exclusive create (replace=True unlinks a planted SYMLINK
            # of this name ITSELF; the O_EXCL open fails loud on
            # anything reappearing in the window).
            write_new_text(
                path, json.dumps(records, indent=2), replace=True,
            )
            if records:
                logger.info("jazzer crash records: %s", path)
        except OSError as e:
            logger.warning(
                "could not persist jazzer crash records: %s", e)


def _resolve_host_m2_repo() -> Path | None:
    """The host's real Maven repository — the identity scrub resets
    HOME, so it must be pinned explicitly (read-only seed source,
    never build-writable)."""
    default = Path.home() / ".m2" / "repository"
    return default if default.is_dir() else None


def _resolve_host_gradle_home() -> Path | None:
    env_home = os.environ.get("GRADLE_USER_HOME")
    if env_home:
        candidate = Path(env_home)
        return candidate if candidate.is_dir() else None
    default = Path.home() / ".gradle"
    return default if default.is_dir() else None


def _build_failure_hints(excerpt: str) -> list[str]:
    """Precise remedies for the known build-failure classes, keyed on
    the (bounded, control-stripped) log excerpt."""
    hints: list[str] = []
    lowered = excerpt.lower()
    if ("offline" in lowered or "could not resolve" in lowered
            or "cannot access" in lowered
            or "failed to download" in lowered
            or "no cached version" in lowered
            or "non-resolvable" in lowered):
        hints.append(
            "Hint: the build runs network-isolated (offline mode). "
            + TRUSTED_BUILD_REMEDY
        )
    if "read-only file system" in lowered or "erofs" in lowered:
        hints.append(
            "Hint: the sandbox's mount-ns lane masks writable entries "
            "under the read-only target bind, so an in-project write "
            "(module target/ or build/ outputs, the root .gradle/ "
            "cache) fails there. " + TRUSTED_BUILD_REMEDY
        )
    if ("java_home" in lowered
            or "unable to locate a java runtime" in lowered
            or "no java" in lowered):
        hints.append(f"Hint: {JAVA_INSTALL_HINT}")
    if "com.code_intelligence.jazzer" in lowered:
        hints.append(
            "Hint: the harness imports the Jazzer API. The bare javac "
            "lane adds jars found beside the jazzer binary to the "
            "compile classpath — install the standalone release "
            "(which ships jazzer_standalone.jar), or declare the "
            "com.code-intelligence:jazzer-api dependency in a "
            "Maven/Gradle build."
        )
    return hints


def parse_java_exception(output: str) -> JavaExceptionInfo | None:
    """Parse the LAST Jazzer finding report from harness output.

    Jazzer prints ``== Java Exception: <type>: <message>`` (message
    optional; its security detectors raise ``FuzzerSecurityIssue*``
    types through the same report) followed by JVM ``at ...(...)``
    stack frames before libFuzzer's crash handler writes the
    artifact. All of it is untrusted target output: every line is
    stripped of terminal control sequences and length-bounded before
    matching, and the frame count is capped. Frame collection stops
    at the first non-frame line (``Caused by:`` chains and
    ``DEDUP_TOKEN`` stay out of the key — the top frames are the
    dedup signal, matching the atheris idiom). Bidi override
    characters survive into the records by design (same posture as
    the sibling parsers): the ``core.security.log_sanitisation``
    contract escapes them at every operator-display egress, so they
    are inert where they are seen.
    """
    lines = output.splitlines()
    header_idx = -1
    for i, raw in enumerate(lines):
        if _JAVA_EXC_MARKER in raw:
            header_idx = i
    if header_idx < 0:
        return None

    header = strip_terminal_controls(lines[header_idx])[:_MAX_LINE_CHARS]
    match = _JAVA_EXC_RE.match(header)
    if match is None:
        # A "== Java Exception:" substring that is not a report header
        # — bail rather than mis-attribute arbitrary output.
        return None
    exc_type = match.group(1)
    message = (match.group(2) or "").strip()

    frames: list[str] = []
    for raw in lines[header_idx + 1:]:
        line = strip_terminal_controls(raw)[:_MAX_LINE_CHARS]
        if line.strip().startswith(("Caused by:", "Suppressed:")):
            # A cause/suppressed block's frames belong to a DIFFERENT
            # throwable. The explicit terminator matters for the
            # zero-frame top exception (a stack-suppressed wrapper):
            # the frames-started gate below never trips there, and the
            # cause's frames would otherwise attribute to the wrapper
            # and contaminate the dedup key.
            break
        frame = _JAVA_FRAME_RE.match(line)
        if frame:
            method, location = frame.groups()
            frames.append(f"{method}({location.strip()})")
            if len(frames) >= _MAX_FRAMES:
                break
        elif frames:
            # Past the top exception's frame block (DEDUP_TOKEN /
            # libFuzzer output).
            break

    digest = hashlib.sha256(
        "\n".join([exc_type, *frames]).encode("utf-8", errors="replace")
    ).hexdigest()[:16]
    return JavaExceptionInfo(
        exception_type=exc_type,
        message=message,
        frames=frames,
        stack_key=digest,
    )
