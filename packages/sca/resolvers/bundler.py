"""Bundler resolver wrapper.

Runs ``bundle lock`` against a temp copy of ``Gemfile`` /
``Gemfile.lock`` so the user's checkout is untouched, then reads back
the resulting ``Gemfile.lock`` as the proposed lockfile. The
temp-copy pattern matches Cargo and Go: ``bundle lock`` writes the
lockfile in-place, so we run it against a sacrificial copy.

We deliberately use ``bundle lock`` (resolver-only) rather than
``bundle update`` (which would also fetch gems and *could* trigger
native gem builds for source-only deps even in dry-run modes). The
sandbox blocks the network on top of that — the resolver hits only
``rubygems.org`` via the proxy.

Sandbox is critical: native gem builds are RCE-by-design under any
of the install paths; ``bundle lock`` doesn't install but past
Bundler bugs have run gem-supplied code during resolution. With the
sandbox: outbound TCP locked to rubygems.org, $HOME hidden, FS
confined to the temp dir.
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


class BundlerResolver:
    """``bundle lock`` (in a temp copy) wrapper."""

    ecosystem = "RubyGems"
    # Note: ``.gemspec`` files also affect resolution but vary per
    # project (no fixed name). The cache wrapper's manifest-list is
    # literal filenames only, so .gemspec drift may not invalidate
    # the cache — operators with .gemspec changes can flush by
    # bumping the .gemspec content into Gemfile.lock or via the
    # 24h TTL.
    MANIFEST_FILES = ("Gemfile", "Gemfile.lock")
    @property
    def proxy_hosts(self) -> list:
        """Egress-proxy hostname allowlist for the bundler subprocess.
        Override (`~/.config/raptor/sca-proxy-hosts.json` `"bundler"`
        key) → calibrate (`bundle --version`, cache-keyed on
        `BUNDLE_MIRROR_OF`/`BUNDLE_GEMFILE`) → static default
        (`rubygems.org` + `index.rubygems.org`)."""
        from ._proxy_hosts import proxy_hosts_for_bundler
        return proxy_hosts_for_bundler()

    def is_available(self) -> bool:
        return _check_tool(["bundle", "--version"])

    def matches(self, project_dir: Path) -> bool:
        return (project_dir / "Gemfile").exists()

    def dry_run(
        self, project_dir: Path, *, timeout: int = 120,
    ) -> ResolverResult:
        if not self.is_available():
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=False,
                error="bundle not found in PATH",
            )
        if not (project_dir / "Gemfile").exists():
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error="no Gemfile in project",
            )

        # Copy Gemfile + Gemfile.lock to a temp dir so the operator's
        # checkout is untouched. ``bundle lock`` writes the lockfile
        # in-place which is why the temp-copy pattern is needed.
        with tempfile.TemporaryDirectory(prefix="raptor-sca-bundler-") as tmp:
            tmp_path = Path(tmp)
            for fname in ("Gemfile", "Gemfile.lock"):
                src = project_dir / fname
                if src.exists():
                    shutil.copy2(src, tmp_path / fname)
            # ``Gemfile`` may ``eval_gemfile`` siblings via relative
            # paths; copy any *.gemspec files too so these references
            # resolve. Top-level only — deep gemspec layouts are
            # uncommon and would need bespoke handling.
            for spec in project_dir.glob("*.gemspec"):
                shutil.copy2(spec, tmp_path / spec.name)

            try:
                proc = _run(
                    ["bundle", "lock"],
                    cwd=tmp_path,
                    timeout=timeout,
                    proxy_hosts=self.proxy_hosts,
                )
            except subprocess.TimeoutExpired:
                return ResolverResult(
                    ecosystem=self.ecosystem,
                    success=False, available=True,
                    error=f"bundle lock timed out after {timeout}s",
                )

            raw = (proc.stdout + "\n" + proc.stderr).strip()
            if proc.returncode != 0:
                return ResolverResult(
                    ecosystem=self.ecosystem,
                    success=False, available=True,
                    error=(proc.stderr.strip()
                           or "bundle lock exited non-zero"),
                    raw_output=raw,
                )
            lockfile = _read_if_exists(tmp_path / "Gemfile.lock")
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


__all__ = ["BundlerResolver"]
