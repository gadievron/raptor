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
import os
import subprocess
from core.run.scratch import scratch_dir
from pathlib import Path

from . import ResolverResult, _check_tool, _run
from ._proxy_hosts import _GOMOD_ENV_KEYS
from ._safe_io import copy_regular_file, read_regular_bytes

logger = logging.getLogger(__name__)

_SKIP_DIRS = {"vendor", "node_modules", ".git", "testdata"}
_MAX_FILES = 10_000


def _copy_go_sources(project_dir: Path, tmp_path: Path | None) -> tuple[str, ...]:
    """Copy the target's ``.go`` files into the temp resolve dir.

    With tmp_path=None, enumerate the same bounded input set without copying.

    Walks with ``os.walk(..., followlinks=False)`` — NOT ``rglob``:
    before Python 3.13 ``Path.rglob`` recurses THROUGH directory
    symlinks, so a hostile ``dir -> /`` link walked the whole host
    filesystem (regular .go files reached via the link pass the
    per-file gate and get copied into the resolve input), and a
    symlink cycle recursed unboundedly. The in-place prune also makes
    ``_SKIP_DIRS`` apply to TRAVERSAL, not just to copied paths. Same
    shape as ``verify._copy_target``.
    """
    selected = []
    copied = 0
    walk_root = project_dir.resolve()
    for dirpath, dirnames, filenames in os.walk(
        walk_root, followlinks=False,
    ):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        cur = Path(dirpath)
        for fname in sorted(filenames):
            if not fname.endswith(".go"):
                continue
            go_file = cur / fname
            # Cheap pre-filter keeps hostile symlink farms from
            # producing one refusal warning per entry; the copy
            # itself re-checks under O_NOFOLLOW (no TOCTOU).
            if go_file.is_symlink():
                continue
            copied += 1
            if copied > _MAX_FILES:
                return tuple(selected)
            rel = go_file.relative_to(walk_root)
            selected.append(str(rel))
            if tmp_path is not None:
                dest = tmp_path / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                copy_regular_file(go_file, dest)
    return tuple(selected)


class GoResolver:
    """``go mod tidy`` (in a temp copy) wrapper."""

    ecosystem = "Go"
    CACHE_ENV_KEYS = _GOMOD_ENV_KEYS
    CACHE_TOOLS = ("go",)
    MANIFEST_FILES = ("go.mod", "go.sum")

    def input_files(self, project_dir: Path) -> tuple[str, ...]:
        return (*self.MANIFEST_FILES, *_copy_go_sources(project_dir, None))

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
        with scratch_dir("raptor-sca-go-") as tmp:
            tmp_path = Path(tmp)
            # lstat-gated, size-bounded copies — a symlinked or
            # special-file manifest in the scanned (hostile) tree is
            # refused instead of followed / opened.
            for fname in ("go.mod", "go.sum"):
                copy_regular_file(project_dir / fname, tmp_path / fname)
            _copy_go_sources(project_dir, tmp_path)

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
            if lockfile is None:
                try:
                    (tmp_path / "go.sum").lstat()
                except FileNotFoundError:
                    # A successful empty/local-only module graph needs no go.sum.
                    # Only absence is allowed; refused symlinks/devices stay failures.
                    lockfile = b""
                except OSError:
                    pass
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=lockfile is not None, available=True,
                error=None if lockfile is not None else "resolver produced no readable regular lockfile within the byte budget",
                proposed_lockfile=lockfile,
                raw_output=raw,
            )


def _read_if_exists(p: Path) -> bytes | None:
    return read_regular_bytes(p)


__all__ = ["GoResolver"]
