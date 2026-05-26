"""Cargo resolver wrapper.

Runs ``cargo update`` against a temp copy of ``Cargo.toml`` /
``Cargo.lock`` so the user's checkout is untouched, then reads back
the resulting ``Cargo.lock`` as the proposed lockfile.

We intentionally don't pass ``--dry-run`` to the inner ``cargo
update``: Cargo's dry-run mode (added in 1.83) prints the would-be
changes but doesn't write the lockfile, leaving us with no
``proposed_lockfile`` to return. The temp-copy + non-dry-run pattern
mirrors what we do for Go and Bundler — same shape, same threat
model: the resolver runs sandboxed, the operator's tree is
untouched.

Sandbox is critical for Cargo: an attacker-controlled crate could
have a ``build.rs`` that runs at build time. ``cargo update`` itself
doesn't compile crates — it only resolves the dep graph and fetches
metadata — but the registry-loading code path could in principle hit
a Cargo CVE. The sandbox contains both: outbound TCP locked to the
crates.io hosts, FS confined to the temp dir, $HOME hidden.
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


class CargoResolver:
    """``cargo update`` (in a temp copy) wrapper."""

    # Internal canonical name is ``"Cargo"`` (matches Cargo.toml /
    # Cargo.lock filenames + the rest of SCA's naming pattern). OSV
    # uses ``"crates.io"`` and that translation lives in osv.py at
    # the query boundary; the resolver layer should NOT pre-emptively
    # use the OSV name — doing so causes get_resolver("Cargo") to
    # return None and silently skip Cargo cascade.
    ecosystem = "Cargo"
    MANIFEST_FILES = ("Cargo.toml", "Cargo.lock")
    @property
    def proxy_hosts(self) -> list:
        """Egress-proxy hostname allowlist for the cargo subprocess.

        Three-layer resolution: operator override
        (``~/.config/raptor/sca-proxy-hosts.json`` ``"cargo"`` key)
        → calibrated profile → static default
        (``crates.io`` + ``index.crates.io`` + ``static.crates.io``).

        ``index.crates.io`` is the sparse-protocol endpoint used by
        Cargo 1.74+ (default since 1.74); operators on alternate
        registries via ``CARGO_REGISTRIES_*`` should populate the
        override."""
        from ._proxy_hosts import proxy_hosts_for_cargo
        return proxy_hosts_for_cargo()

    def is_available(self) -> bool:
        return _check_tool(["cargo", "--version"])

    def matches(self, project_dir: Path) -> bool:
        return (project_dir / "Cargo.toml").exists()

    def dry_run(
        self, project_dir: Path, *, timeout: int = 120,
    ) -> ResolverResult:
        if not self.is_available():
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=False,
                error="cargo not found in PATH",
            )
        if not (project_dir / "Cargo.toml").exists():
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error="no Cargo.toml in project",
            )

        # Copy the manifest + lockfile to a temp dir; never mutate
        # the operator's checkout. Workspace members aren't copied
        # — for cascade-validation purposes the top-level manifest
        # is what matters; member-only crates get partial coverage.
        with tempfile.TemporaryDirectory(prefix="raptor-sca-cargo-") as tmp:
            tmp_path = Path(tmp)
            for fname in ("Cargo.toml", "Cargo.lock"):
                src = project_dir / fname
                if src.exists():
                    shutil.copy2(src, tmp_path / fname)

            try:
                proc = _run(
                    ["cargo", "update", "--quiet"],
                    cwd=tmp_path,
                    timeout=timeout,
                    proxy_hosts=self.proxy_hosts,
                )
            except subprocess.TimeoutExpired:
                return ResolverResult(
                    ecosystem=self.ecosystem,
                    success=False, available=True,
                    error=f"cargo update timed out after {timeout}s",
                )

            raw = (proc.stdout + "\n" + proc.stderr).strip()
            if proc.returncode != 0:
                return ResolverResult(
                    ecosystem=self.ecosystem,
                    success=False, available=True,
                    error=(proc.stderr.strip()
                           or "cargo update exited non-zero"),
                    raw_output=raw,
                )
            lockfile = _read_if_exists(tmp_path / "Cargo.lock")
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


__all__ = ["CargoResolver"]
