"""NuGet resolver wrapper.

Runs ``dotnet restore --use-lock-file --force-evaluate --no-cache``
against the project's ``.csproj`` / ``.fsproj`` / ``.sln`` to
re-resolve the dep graph. ``--use-lock-file`` writes
``packages.lock.json`` (NuGet's optional lockfile, opt-in via
``RestorePackagesWithLockFile`` in the project file or by running
restore with the flag); ``--force-evaluate`` ignores any cached
resolution and re-resolves from scratch — what we want for cascade
validation.

NuGet's lockfile concept is recent and opt-in; many .NET projects
don't have one. When ``packages.lock.json`` doesn't exist after the
restore, success/failure is the binary signal cascade needs and
``proposed_lockfile`` is None.

Sandbox: NuGet packages can ship targets / props / scripts that run
during build but not during pure restore. Restore is closer to
T1-safe but the sandbox is defence-in-depth: outbound TCP locked
to api.nuget.org + nuget.org, $HOME hidden, FS confined.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import ResolverResult, _check_tool, _run

logger = logging.getLogger(__name__)


class NugetResolver:
    """``dotnet restore`` wrapper."""

    ecosystem = "NuGet"
    # ``.csproj`` / ``.fsproj`` filenames vary per project and
    # aren't a fixed glob — operators with project-file changes
    # may need to wait out the 24h TTL or flush manually. The
    # ``packages.lock.json`` lock IS a fixed name and dominates the
    # resolution-input shape.
    MANIFEST_FILES = ("packages.lock.json",)
    @property
    def proxy_hosts(self) -> list:
        """Egress-proxy hostname allowlist for nuget.
        Override (`"nuget"` key) → calibrate (`dotnet --version`,
        cache-keyed on `NUGET_PACKAGES`) → static default
        (`api.nuget.org` + `nuget.org`)."""
        from ._proxy_hosts import proxy_hosts_for_nuget
        return proxy_hosts_for_nuget()

    def is_available(self) -> bool:
        return _check_tool(["dotnet", "--version"])

    def matches(self, project_dir: Path) -> bool:
        # Detect any of the .NET project-file shapes. ``rglob`` is
        # bounded by ``project_dir`` so this stays cheap on
        # monorepos; we only check the top of the tree to avoid
        # cross-project surprises.
        for pattern in ("*.csproj", "*.fsproj", "*.sln"):
            if any(project_dir.glob(pattern)):
                return True
        return False

    def dry_run(
        self, project_dir: Path, *, timeout: int = 120,
    ) -> ResolverResult:
        if not self.is_available():
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=False,
                error="dotnet not found in PATH",
            )
        if not self.matches(project_dir):
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error=("no .csproj / .fsproj / .sln in project"),
            )

        # Copy project files into a writable tempdir — the sandbox
        # only allows writes to the output dir and /tmp, not cwd.
        with tempfile.TemporaryDirectory(prefix="raptor-sca-nuget-") as tmp:
            tmp_path = Path(tmp)
            for pattern in ("*.csproj", "*.fsproj", "*.sln"):
                for src in project_dir.glob(pattern):
                    shutil.copy2(src, tmp_path / src.name)
            lock_src = project_dir / "packages.lock.json"
            if lock_src.exists():
                shutil.copy2(lock_src, tmp_path / lock_src.name)

            try:
                proc = _run(
                    ["dotnet", "restore",
                     "--use-lock-file", "--force-evaluate",
                     "--no-cache", "--nologo"],
                    cwd=tmp_path,
                    timeout=timeout,
                    proxy_hosts=self.proxy_hosts,
                )
            except subprocess.TimeoutExpired:
                return ResolverResult(
                    ecosystem=self.ecosystem,
                    success=False, available=True,
                    error=f"dotnet restore timed out after {timeout}s",
                )

            raw = (proc.stdout + "\n" + proc.stderr).strip()
            if proc.returncode != 0:
                return ResolverResult(
                    ecosystem=self.ecosystem,
                    success=False, available=True,
                    error=(proc.stderr.strip()
                           or "dotnet restore exited non-zero"),
                    raw_output=raw,
                )
            lockfile = _read_if_exists(tmp_path / "packages.lock.json")
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=True, available=True,
                proposed_lockfile=lockfile,
                raw_output=raw,
            )


def _read_if_exists(p: Path) -> bytes | None:
    try:
        return p.read_bytes()
    except OSError:
        return None


__all__ = ["NugetResolver"]
