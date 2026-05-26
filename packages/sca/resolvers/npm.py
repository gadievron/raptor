"""npm resolver wrapper.

Runs ``npm install --dry-run --package-lock-only --ignore-scripts``
in the project directory. ``--ignore-scripts`` is **always** set —
this is the sandbox-not-needed mode; npm's preinstall/postinstall hooks
never execute via this path.

The resolved lockfile is written to ``package-lock.json`` even with
``--dry-run`` when ``--package-lock-only`` is also given (which
synthesises the lockfile from the manifest without actually installing
node_modules). We read that file back as the result.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Optional

from . import ResolverResult, _check_tool, _run

logger = logging.getLogger(__name__)


class NpmResolver:
    """``npm install --dry-run`` wrapper."""

    ecosystem = "npm"
    # Files the resolver-cache wrapper hashes to key memoisation.
    # See ``_cache.py``. Order doesn't matter — hash sorts by path.
    MANIFEST_FILES = ("package.json", "package-lock.json")
    @property
    def proxy_hosts(self) -> list:
        """Egress-proxy hostname allowlist for the npm subprocess.

        Three-layer resolution: operator override
        (``~/.config/raptor/sca-proxy-hosts.json`` ``"npm"`` key) →
        calibrated profile (cache-keyed on ``NPM_CONFIG_REGISTRY``)
        → static default (``registry.npmjs.org``).

        Custom-registry projects should add their host via the
        override config; the cascade validation surfaces the gap as
        a proxy refusal otherwise."""
        from ._proxy_hosts import proxy_hosts_for_npm
        return proxy_hosts_for_npm()

    def is_available(self) -> bool:
        return _check_tool(["npm", "--version"])

    def matches(self, project_dir: Path) -> bool:
        # npm is the fallback resolver for the npm ecosystem — it
        # matches any project with a package.json. yarn/pnpm are
        # registered before npm in the resolver list, so when their
        # tool-specific lockfiles are present they win the selection.
        return (project_dir / "package.json").exists()

    def dry_run(
        self, project_dir: Path, *, timeout: int = 120,
    ) -> ResolverResult:
        if not self.is_available():
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=False,
                error="npm not found in PATH",
            )
        if not (project_dir / "package.json").exists():
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error="no package.json in project",
            )

        try:
            proc = _run(
                ["npm", "install", "--dry-run", "--package-lock-only",
                  "--ignore-scripts", "--no-audit", "--no-fund",
                  # Cap per-origin sockets well under the sandbox egress
                  # proxy's tunnel limit (core/sandbox/proxy.py). npm's
                  # default + keep-alive lingering + retries can otherwise
                  # blow past the cap, get connections refused, and stall
                  # the scan past timeout.
                  "--maxsockets=8"],
                cwd=project_dir,
                timeout=timeout,
                proxy_hosts=self.proxy_hosts,
            )
        except subprocess.TimeoutExpired:
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error=f"npm install timed out after {timeout}s",
            )

        raw = (proc.stdout + "\n" + proc.stderr).strip()
        if proc.returncode != 0:
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error=(proc.stderr.strip()
                        or "npm install --dry-run exited non-zero"),
                raw_output=raw,
            )
        lockfile = _read_if_exists(
            project_dir / "package-lock.json")
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


__all__ = ["NpmResolver"]
