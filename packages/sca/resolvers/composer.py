"""Composer resolver wrapper.

Runs ``composer update --lock --no-install --no-interaction`` against
the project's ``composer.json``. ``--lock`` re-resolves and writes
``composer.lock`` without populating ``vendor/``; ``--no-install``
makes the no-install intent explicit; ``--no-interaction`` keeps the
subprocess non-blocking.

Composer's resolution is mostly metadata-only — packages aren't
unpacked or executed during ``update --no-install``. The sandbox
remains defence-in-depth: outbound TCP locked to Packagist + the
public composer mirror.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from . import ResolverResult, _check_tool, _run

logger = logging.getLogger(__name__)


class ComposerResolver:
    """``composer update --lock --no-install`` wrapper."""

    ecosystem = "Packagist"
    MANIFEST_FILES = ("composer.json", "composer.lock")
    @property
    def proxy_hosts(self) -> list:
        """Egress-proxy hostname allowlist for composer.
        Override (`"composer"` key) → calibrate (`composer
        --version`, cache-keyed on `COMPOSER`/`COMPOSER_HOME`) →
        static default (`repo.packagist.org` + `packagist.org`)."""
        from ._proxy_hosts import proxy_hosts_for_composer
        return proxy_hosts_for_composer()

    def is_available(self) -> bool:
        return _check_tool(["composer", "--version"])

    def matches(self, project_dir: Path) -> bool:
        return (project_dir / "composer.json").exists()

    def dry_run(
        self, project_dir: Path, *, timeout: int = 120,
    ) -> ResolverResult:
        if not self.is_available():
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=False,
                error="composer not found in PATH",
            )
        if not (project_dir / "composer.json").exists():
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error="no composer.json in project",
            )

        # ``composer update --lock`` writes composer.lock in-place;
        # use a temp copy so the operator's checkout is untouched.
        with tempfile.TemporaryDirectory(prefix="raptor-sca-composer-") as tmp:
            tmp_path = Path(tmp)
            for fname in ("composer.json", "composer.lock"):
                src = project_dir / fname
                if src.exists():
                    shutil.copy2(src, tmp_path / fname)

            try:
                proc = _run(
                    ["composer", "update", "--lock",
                     "--no-install", "--no-interaction",
                     "--no-progress"],
                    cwd=tmp_path,
                    timeout=timeout,
                    proxy_hosts=self.proxy_hosts,
                )
            except subprocess.TimeoutExpired:
                return ResolverResult(
                    ecosystem=self.ecosystem,
                    success=False, available=True,
                    error=f"composer update timed out after {timeout}s",
                )

            raw = (proc.stdout + "\n" + proc.stderr).strip()
            if proc.returncode != 0:
                return ResolverResult(
                    ecosystem=self.ecosystem,
                    success=False, available=True,
                    error=(proc.stderr.strip()
                           or "composer update exited non-zero"),
                    raw_output=raw,
                )
            lockfile = _read_if_exists(tmp_path / "composer.lock")
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


__all__ = ["ComposerResolver"]
