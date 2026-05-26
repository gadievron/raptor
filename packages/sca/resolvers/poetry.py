"""Poetry resolver wrapper.

Runs ``poetry lock --no-update`` to re-resolve the existing
``pyproject.toml`` against the current set of compatible versions.
Without ``--no-update`` Poetry would also bump non-target deps to
their newest compatible release; we want a minimal validate that
the proposed plan is internally consistent.

Selection: matches any project whose ``pyproject.toml`` declares
``[tool.poetry]``. A pyproject.toml with only PEP 621 ``[project]``
metadata is left to ``PipResolver`` since it's not a Poetry project.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Optional

from . import ResolverResult, _check_tool, _run

logger = logging.getLogger(__name__)


class PoetryResolver:
    """``poetry lock`` wrapper."""

    ecosystem = "PyPI"
    MANIFEST_FILES = ("pyproject.toml", "poetry.lock")
    @property
    def proxy_hosts(self) -> list:
        """Egress-proxy hostname allowlist for poetry.
        Override (`"poetry"` key) → calibrate (`poetry --version`,
        cache-keyed on `POETRY_REPOSITORIES_PRIMARY_URL` /
        `PIP_INDEX_URL`) → static default (`pypi.org` +
        `files.pythonhosted.org`)."""
        from ._proxy_hosts import proxy_hosts_for_poetry
        return proxy_hosts_for_poetry()

    def is_available(self) -> bool:
        return _check_tool(["poetry", "--version"])

    def matches(self, project_dir: Path) -> bool:
        pyproject = project_dir / "pyproject.toml"
        if not pyproject.exists():
            return False
        try:
            text = pyproject.read_text(encoding="utf-8")
        except OSError:
            return False
        # Cheap text check — no need to TOML-parse just to detect a
        # Poetry project. ``[tool.poetry]`` is unambiguous and
        # case-sensitive in TOML.
        return "[tool.poetry]" in text

    def dry_run(
        self, project_dir: Path, *, timeout: int = 120,
    ) -> ResolverResult:
        if not self.is_available():
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=False,
                error="poetry not found in PATH",
            )
        if not (project_dir / "pyproject.toml").exists():
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error="no pyproject.toml in project",
            )

        try:
            proc = _run(
                ["poetry", "lock", "--no-update", "--no-interaction"],
                cwd=project_dir,
                timeout=timeout,
                proxy_hosts=self.proxy_hosts,
            )
        except subprocess.TimeoutExpired:
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error=f"poetry lock timed out after {timeout}s",
            )

        raw = (proc.stdout + "\n" + proc.stderr).strip()
        if proc.returncode != 0:
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error=(proc.stderr.strip()
                       or "poetry lock exited non-zero"),
                raw_output=raw,
            )
        lockfile = _read_if_exists(project_dir / "poetry.lock")
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


__all__ = ["PoetryResolver"]
