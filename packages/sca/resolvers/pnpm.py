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
from core.run.scratch import scratch_dir
from pathlib import Path

from . import ResolverResult, _check_tool, _run
from ._proxy_hosts import _PNPM_ENV_KEYS
from ._safe_io import copy_regular_file, read_regular_bytes

logger = logging.getLogger(__name__)


class PnpmResolver:
    """``pnpm install --lockfile-only`` wrapper."""

    ecosystem = "npm"
    CACHE_ENV_KEYS = _PNPM_ENV_KEYS
    CACHE_TOOLS = ("pnpm",)
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

        # Copy manifest files into a writable tempdir — the sandbox
        # only allows writes to the output dir and /tmp, not cwd.
        with scratch_dir("raptor-sca-pnpm-") as tmp:
            tmp_path = Path(tmp)
            # lstat-gated, size-bounded copies — a symlinked or
            # special-file manifest in the scanned (hostile) tree is
            # refused instead of followed / opened.
            for fname in ("package.json", "pnpm-lock.yaml"):
                copy_regular_file(project_dir / fname, tmp_path / fname)

            try:
                proc = _run(
                    ["pnpm", "install", "--lockfile-only",
                     "--ignore-scripts", "--no-frozen-lockfile"],
                    cwd=tmp_path,
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
            lockfile = _read_if_exists(tmp_path / "pnpm-lock.yaml")
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=lockfile is not None, available=True,
                error=None if lockfile is not None else "resolver produced no readable regular lockfile within the byte budget",
                proposed_lockfile=lockfile,
                raw_output=raw,
            )


def _read_if_exists(p: Path) -> bytes | None:
    return read_regular_bytes(p)


__all__ = ["PnpmResolver"]
