"""Go module resolver wrapper.

Runs ``go mod tidy -v -e`` in dry-run-equivalent mode (``-e`` continues
past errors) against a temporary copy of go.mod / go.sum so the user's
files aren't modified, then reads back the resulting go.sum as the
lockfile.

Go's resolver fetches metadata via the module proxy
(``proxy.golang.org`` by default) — no install hooks, no script
execution. Sandbox-not-needed.

Note: ``go mod tidy`` MUTATES the directory it runs in. We use
``shutil.copytree`` to a temp dir and run there. We bound the temp
copy by skipping known-large vendored / build-output paths.
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


class GoResolver:
    """``go mod tidy`` (in a temp copy) wrapper."""

    ecosystem = "Go"
    MANIFEST_FILES = ("go.mod", "go.sum")
    @property
    def proxy_hosts(self) -> list:
        """Egress-proxy hostname allowlist for the go subprocess.

        Three-layer resolution: operator override
        (``~/.config/raptor/sca-proxy-hosts.json`` ``"gomod"`` key)
        → calibrated profile (cache-keyed on ``GOPROXY`` /
        ``GOSUMDB`` / ``GOPRIVATE``) → static default
        (``proxy.golang.org`` + ``sum.golang.org``).

        A target with ``GOPROXY=direct`` or a private proxy surfaces
        as a proxy refusal until the host is added to the override
        — preferred over silently widening the default."""
        from ._proxy_hosts import proxy_hosts_for_gomod
        return proxy_hosts_for_gomod()

    def is_available(self) -> bool:
        return _check_tool(["go", "version"])

    def matches(self, project_dir: Path) -> bool:
        return (project_dir / "go.mod").exists()

    def dry_run(
        self, project_dir: Path, *, timeout: int = 120,
    ) -> ResolverResult:
        if not self.is_available():
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=False,
                error="go not found in PATH",
            )
        if not (project_dir / "go.mod").exists():
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error="no go.mod in project",
            )

        # Copy minimum needed files (go.mod, go.sum, vendor/) to a temp
        # dir so the user's checkout is untouched.
        with tempfile.TemporaryDirectory(prefix="raptor-sca-go-") as tmp:
            tmp_path = Path(tmp)
            for fname in ("go.mod", "go.sum"):
                src = project_dir / fname
                if src.exists():
                    shutil.copy2(src, tmp_path / fname)
            # ``go mod tidy`` walks .go files for imports too — copy
            # them at the top level if present (rough but functional).
            for go_file in project_dir.glob("*.go"):
                shutil.copy2(go_file, tmp_path / go_file.name)

            try:
                proc = _run(
                    ["go", "mod", "tidy", "-v", "-e"],
                    cwd=tmp_path,
                    timeout=timeout,
                    proxy_hosts=self.proxy_hosts,
                )
            except subprocess.TimeoutExpired:
                return ResolverResult(
                    ecosystem=self.ecosystem,
                    success=False, available=True,
                    error=f"go mod tidy timed out after {timeout}s",
                )

            raw = (proc.stdout + "\n" + proc.stderr).strip()
            if proc.returncode != 0:
                return ResolverResult(
                    ecosystem=self.ecosystem,
                    success=False, available=True,
                    error=(proc.stderr.strip()
                            or "go mod tidy exited non-zero"),
                    raw_output=raw,
                )
            lockfile = _read_if_exists(tmp_path / "go.sum")
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


__all__ = ["GoResolver"]
