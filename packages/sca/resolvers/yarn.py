"""Yarn resolver wrapper.

Yarn ships in two incompatible flavours:

  - **Classic (1.x)** — invoked as ``yarn install --frozen-lockfile=false
    --ignore-scripts --no-bin-links``. Reads ``package.json`` + writes
    ``yarn.lock``.
  - **Berry (2.x+)** — invoked as ``yarn install --mode=update-lockfile
    --immutable-cache``. Same artefacts but a different lockfile
    format (``YAML`` instead of the v1 custom dialect).

We detect the major version once via ``yarn --version`` and pick the
right flag set. Both paths run with scripts disabled (defence in depth
on top of the sandbox).

Selection: ``YarnResolver`` matches any project with ``yarn.lock`` —
even when ``package.json`` is also present, the lockfile is the
authoritative signal that yarn is the project's tool of choice.
"""

from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path
from typing import Optional

from . import ResolverResult, _check_tool, _run

logger = logging.getLogger(__name__)


class YarnResolver:
    """``yarn install`` wrapper (classic + Berry)."""

    ecosystem = "npm"
    MANIFEST_FILES = ("package.json", "yarn.lock")
    @property
    def proxy_hosts(self) -> list:
        """Egress-proxy hostname allowlist for yarn.
        Override (`"yarn"` key) → calibrate (`yarn --version`,
        cache-keyed on `YARN_REGISTRY` (yarn 1) +
        `YARN_NPM_REGISTRY_SERVER` (yarn 2+)) → static default
        (`registry.yarnpkg.com` + `registry.npmjs.org`).

        Berry projects switching the registry via `.yarnrc.yml`
        without an env override will hit a proxy refusal at
        cascade time — the right failure mode (reveals an
        unallowed source)."""
        from ._proxy_hosts import proxy_hosts_for_yarn
        return proxy_hosts_for_yarn()

    def is_available(self) -> bool:
        return _check_tool(["yarn", "--version"])

    def matches(self, project_dir: Path) -> bool:
        return (project_dir / "yarn.lock").exists()

    def dry_run(
        self, project_dir: Path, *, timeout: int = 120,
    ) -> ResolverResult:
        if not self.is_available():
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=False,
                error="yarn not found in PATH",
            )
        if not (project_dir / "package.json").exists():
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error="no package.json in project",
            )

        major = _detect_major_version()
        if major is None or major <= 1:
            cmd = ["yarn", "install", "--frozen-lockfile=false",
                   "--ignore-scripts", "--no-bin-links",
                   "--non-interactive"]
        else:
            cmd = ["yarn", "install", "--mode=update-lockfile",
                   "--immutable-cache"]

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
                error=f"yarn install timed out after {timeout}s",
            )

        raw = (proc.stdout + "\n" + proc.stderr).strip()
        if proc.returncode != 0:
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error=(proc.stderr.strip()
                       or "yarn install exited non-zero"),
                raw_output=raw,
            )
        lockfile = _read_if_exists(project_dir / "yarn.lock")
        return ResolverResult(
            ecosystem=self.ecosystem,
            success=True, available=True,
            proposed_lockfile=lockfile,
            raw_output=raw,
        )


def _detect_major_version() -> Optional[int]:
    """Return Yarn's major version, or None if it can't be parsed."""
    try:
        proc = subprocess.run(
            ["yarn", "--version"],
            capture_output=True, text=True, timeout=5,
        )
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return None
    m = re.match(r"\s*(\d+)\.", proc.stdout)
    if m is None:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


def _read_if_exists(p: Path) -> Optional[bytes]:
    try:
        return p.read_bytes()
    except OSError:
        return None


__all__ = ["YarnResolver"]
