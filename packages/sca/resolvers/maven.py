"""Maven resolver wrapper.

Runs ``mvn dependency:resolve --batch-mode --quiet`` against the
project's ``pom.xml``. Resolves the full transitive dep set against
the configured repository (defaults to Maven Central) and returns
exit-code success/failure as the cascade signal. The ``dependency:tree``
output is captured as ``proposed_lockfile`` bytes — Maven has no
true lockfile concept, but the resolved tree is the closest
equivalent artefact.

Sandbox is critical: Maven plugins are arbitrary Java that runs as
part of the build lifecycle; even ``dependency:resolve`` may engage
``<build>``-section plugins declared in the POM. Without the sandbox
a hostile pom.xml could ``maven-antrun-plugin`` its way to RCE
during *resolution*. With it: outbound TCP locked to the central
repo + Maven plugin repo, $HOME hidden, FS confined.

Performance: Maven is heavy (JVM warmup, plugin downloads on first
run). Default 120s timeout is short for non-trivial projects;
callers should bump to ~300s for first-run cascade validation.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import List

from . import ResolverResult, _check_tool, _run

logger = logging.getLogger(__name__)


class MavenResolver:
    """``mvn dependency:resolve`` wrapper."""

    ecosystem = "Maven"
    MANIFEST_FILES = ("pom.xml",)
    # Maven Central (the canonical repo) plus its modern alias.
    # Projects using corporate mirrors will surface as proxy
    # refusals — the right signal that the operator's repo
    # config wants explicit allowlist review.
    @property
    def proxy_hosts(self) -> list:
        """Egress-proxy hostname allowlist for maven.
        Override (`"maven"` key) → calibrate (`mvn --version`,
        cache-keyed on `MAVEN_OPTS`/`M2_HOME`) → static default
        (Maven Central + modern alias)."""
        from ._proxy_hosts import proxy_hosts_for_maven
        return proxy_hosts_for_maven()

    def is_available(self) -> bool:
        # Either system Maven or the project's wrapper.
        return _check_tool(["mvn", "--version"])

    def matches(self, project_dir: Path) -> bool:
        # Maven is the fallback for the Maven ecosystem — Gradle is
        # registered first, so a project with both build.gradle and
        # pom.xml goes to Gradle. A pure-Maven project has only pom.xml.
        return (project_dir / "pom.xml").exists()

    def dry_run(
        self, project_dir: Path, *, timeout: int = 120,
    ) -> ResolverResult:
        if not self.is_available() and not _has_wrapper(project_dir):
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=False,
                error="neither mvn nor ./mvnw available",
            )
        if not (project_dir / "pom.xml").exists():
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error="no pom.xml in project",
            )

        cmd = _resolve_mvn_cmd(project_dir) + [
            "dependency:resolve", "--batch-mode", "--quiet",
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
                error=f"mvn dependency:resolve timed out after {timeout}s",
            )

        raw = (proc.stdout + "\n" + proc.stderr).strip()
        if proc.returncode != 0:
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error=(proc.stderr.strip()
                       or "mvn dependency:resolve exited non-zero"),
                raw_output=raw,
            )
        # Maven has no lockfile; capture the resolved-tree-style
        # output as the closest equivalent for diff purposes.
        lockfile = proc.stdout.encode("utf-8") if proc.stdout else None
        return ResolverResult(
            ecosystem=self.ecosystem,
            success=True, available=True,
            proposed_lockfile=lockfile,
            raw_output=raw,
        )


def _has_wrapper(project_dir: Path) -> bool:
    return (project_dir / "mvnw").exists()


def _resolve_mvn_cmd(project_dir: Path) -> List[str]:
    """Prefer ``./mvnw`` (project-pinned version) over a system mvn."""
    if _has_wrapper(project_dir):
        return ["./mvnw"]
    return ["mvn"]


__all__ = ["MavenResolver"]
