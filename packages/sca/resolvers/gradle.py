"""Gradle resolver wrapper.

Runs ``gradle dependencies --no-daemon --quiet`` (or the project's
``gradlew`` wrapper if present) in the project directory and captures
the resolved dep tree as ``proposed_lockfile`` bytes.

Gradle does not have a standard lockfile concept — projects opt in
via ``dependencyLocking { lockAllConfigurations() }`` which writes a
``gradle.lockfile``. When that file exists we read it back; otherwise
the captured ``dependencies`` task output is the lockfile-equivalent
artefact. Either way, success/failure is the binary signal cascade
validation needs.

Sandbox is critical: ``build.gradle`` is Turing-complete Groovy /
``build.gradle.kts`` is Turing-complete Kotlin — the resolver
literally evaluates target-supplied code as part of dep resolution.
Without the sandbox a hostile build.gradle could read $HOME or
exfiltrate, even on a "dry-run" task. With it: outbound TCP locked
to the Maven repo + Gradle plugin portal, $HOME hidden, FS confined.

Performance: Gradle is heavy (JVM warmup, daemon-disabled cold path).
Default 120s timeout is short for non-trivial projects; callers
running cascade for Gradle should bump ``timeout`` to ~300s. We keep
the default for protocol consistency rather than per-resolver
specials — cascade orchestrators have full control.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import List, Optional

from . import ResolverResult, _check_tool, _run

logger = logging.getLogger(__name__)


class GradleResolver:
    """``gradle dependencies`` wrapper."""

    ecosystem = "Maven"
    MANIFEST_FILES = (
        "build.gradle", "settings.gradle",
        "build.gradle.kts", "settings.gradle.kts",
        "gradle.lockfile",
    )
    # The Maven Central mirror + Gradle's own plugin portal. Some
    # projects pin to JFrog or a corporate mirror — those will
    # surface as proxy refusals (the right failure mode) rather
    # than a silent registry switcheroo.
    @property
    def proxy_hosts(self) -> list:
        """Egress-proxy hostname allowlist for gradle.
        Override (`"gradle"` key) → calibrate (`gradle --version`,
        cache-keyed on `GRADLE_USER_HOME`) → static default (Maven
        Central + Gradle Plugin Portal hosts).

        Operators on a JFrog / corporate Maven mirror should
        populate the override; the static default's surface fails
        loud at the proxy rather than rerouting silently."""
        from ._proxy_hosts import proxy_hosts_for_gradle
        return proxy_hosts_for_gradle()

    def is_available(self) -> bool:
        # Either a system Gradle or the project's wrapper. We probe
        # the system Gradle here because ``gradlew`` only exists
        # inside specific project trees; ``matches()`` decides which
        # to invoke at run time.
        return _check_tool(["gradle", "--version"])

    def matches(self, project_dir: Path) -> bool:
        return (
            (project_dir / "build.gradle").exists()
            or (project_dir / "build.gradle.kts").exists()
            or (project_dir / "settings.gradle").exists()
            or (project_dir / "settings.gradle.kts").exists()
        )

    def dry_run(
        self, project_dir: Path, *, timeout: int = 120,
    ) -> ResolverResult:
        if not self.is_available() and not _has_wrapper(project_dir):
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=False,
                error="neither gradle nor ./gradlew available",
            )
        if not self.matches(project_dir):
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error="no build.gradle / build.gradle.kts in project",
            )

        cmd = _resolve_gradle_cmd(project_dir) + [
            "dependencies", "--no-daemon", "--quiet",
        ]

        try:
            proc = _run(
                cmd,
                cwd=project_dir,
                timeout=timeout,
                proxy_hosts=self.proxy_hosts,
            )
        except subprocess.TimeoutExpired:
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error=f"gradle dependencies timed out after {timeout}s",
            )

        raw = (proc.stdout + "\n" + proc.stderr).strip()
        if proc.returncode != 0:
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error=(proc.stderr.strip()
                       or "gradle dependencies exited non-zero"),
                raw_output=raw,
            )
        # Prefer an explicit gradle.lockfile when the project opted
        # into dependency locking; otherwise the dep-tree output is
        # the closest lockfile-equivalent artefact we have.
        lockfile = _read_if_exists(project_dir / "gradle.lockfile")
        if lockfile is None:
            lockfile = proc.stdout.encode("utf-8") if proc.stdout else None
        return ResolverResult(
            ecosystem=self.ecosystem,
            success=True, available=True,
            proposed_lockfile=lockfile,
            raw_output=raw,
        )


def _has_wrapper(project_dir: Path) -> bool:
    return (project_dir / "gradlew").exists()


def _resolve_gradle_cmd(project_dir: Path) -> List[str]:
    """Prefer ``./gradlew`` (project-pinned version) over a system gradle."""
    if _has_wrapper(project_dir):
        return ["./gradlew"]
    return ["gradle"]


def _read_if_exists(p: Path) -> Optional[bytes]:
    try:
        return p.read_bytes()
    except OSError:
        return None


__all__ = ["GradleResolver"]
