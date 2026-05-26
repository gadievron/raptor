"""pnpm resolver wrapper.

Runs ``pnpm install --lockfile-only --ignore-scripts --no-frozen-lockfile``
in the project directory. ``--lockfile-only`` synthesises
``pnpm-lock.yaml`` without populating ``node_modules``;
``--ignore-scripts`` is mandatory belt-and-braces (the sandbox blocks
script execution at the syscall layer too); ``--no-frozen-lockfile``
lets the resolver actually update the lockfile (which is the point of
cascade validation).

Selection: matches any project with ``pnpm-lock.yaml``.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Optional

from . import ResolverResult, _check_tool, _run

logger = logging.getLogger(__name__)


class PnpmResolver:
    """``pnpm install --lockfile-only`` wrapper."""

    ecosystem = "npm"
    MANIFEST_FILES = ("package.json", "pnpm-lock.yaml")
    @property
    def proxy_hosts(self) -> list:
        """Egress-proxy hostname allowlist for pnpm.
        Override (`"pnpm"` key) → calibrate (`pnpm --version`,
        cache-keyed on `NPM_CONFIG_REGISTRY`) → static default
        (`registry.npmjs.org`)."""
        from ._proxy_hosts import proxy_hosts_for_pnpm
        return proxy_hosts_for_pnpm()

    def is_available(self) -> bool:
        return _check_tool(["pnpm", "--version"])

    def matches(self, project_dir: Path) -> bool:
        return (project_dir / "pnpm-lock.yaml").exists()

    def dry_run(
        self, project_dir: Path, *, timeout: int = 120,
    ) -> ResolverResult:
        if not self.is_available():
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=False,
                error="pnpm not found in PATH",
            )
        if not (project_dir / "package.json").exists():
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error="no package.json in project",
            )

        try:
            proc = _run(
                ["pnpm", "install", "--lockfile-only",
                 "--ignore-scripts", "--no-frozen-lockfile"],
                cwd=project_dir,
                timeout=timeout,
                proxy_hosts=self.proxy_hosts,
            )
        except subprocess.TimeoutExpired:
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error=f"pnpm install timed out after {timeout}s",
            )

        raw = (proc.stdout + "\n" + proc.stderr).strip()
        if proc.returncode != 0:
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error=(proc.stderr.strip()
                       or "pnpm install exited non-zero"),
                raw_output=raw,
            )
        lockfile = _read_if_exists(project_dir / "pnpm-lock.yaml")
        return ResolverResult(
            ecosystem=self.ecosystem,
            success=True, available=True,
            proposed_lockfile=lockfile,
            raw_output=raw,
        )


def _read_if_exists(p: Path) -> Optional[bytes]:
    try:
        return p.read_bytes()
    except OSError:
        return None


__all__ = ["PnpmResolver"]
