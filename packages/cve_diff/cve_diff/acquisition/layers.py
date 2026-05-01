"""
Acquisition layers: turn a `RepoRef` into a local directory with both commits.

Two strategies, tried in order (plan's cascade):

1. TargetedFetchLayer — `git init` + `git remote add` + `git fetch --depth=5`
   for each commit. Works for old CVEs whose fix commits aren't in recent
   history. ~70% of wins on the reference project's measured runs.

2. ShallowCloneLayer — `git clone --depth=D` for D in (100, 500) per
   Bug #3 ("progressive deepening"). Recovers when the server refuses direct
   commit fetches (common for older GitLab instances / some mirrors).
   The 2000-depth tier was dropped on the 2026-04-20 bench: it was the
   median 64s worst-case and caused 3/40 timeouts. If the SHA isn't
   reachable at 500 it almost never is at 2000 either — those fixes are
   cherry-picks off branches we can't resolve.

Dropped from the reference port: the `TemporalAcquisitionLayer` (deleted
branches, 925 LOC of workarounds) — the plan calls it "marginal value" and
drops it from Phase 1.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from cve_diff.core.exceptions import AcquisitionError
from cve_diff.core.models import RepoRef

PROGRESSIVE_DEPTHS: tuple[int, ...] = (100, 500)
TARGETED_DEPTH = 5
GIT_TIMEOUT_S = 120


def _commit_exists(repo_path: Path, sha: str) -> bool:
    # Local-only `cat-file` — but a defensive timeout prevents pathological
    # filesystems (broken NFS, dying disk) from hanging the pipeline.
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_path), "cat-file", "-e", f"{sha}^{{commit}}"],
            capture_output=True,
            check=False,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return False
    return completed.returncode == 0


def _clean_dest(dest: Path) -> None:
    """Remove ``dest`` if it exists and has content. No-op otherwise.

    Defensive: 60s timeout protects against pathological filesystems;
    transient subprocess failures are silently ignored — the next acquire
    attempt will surface a real error if rm-rf actually didn't work.
    Used by every layer's pre-acquire cleanup and the cascade's
    between-layer cleanup.

    Safety: refuses filesystem root, short absolute paths (< 3 path
    components), and relative paths. Production callers always pass a
    tempdir like ``/tmp/cve-diff-XXXX/...``. Guard protects against future
    caller mistakes (``Path("/")`` would otherwise become ``rm -rf /``).
    Raises ``ValueError`` rather than silently no-op'ing — such a path is
    a programming error, not a transient failure.
    """
    if not dest.is_absolute() or len(dest.parts) < 3:
        raise ValueError(f"_clean_dest refusing dangerous path: {dest!r}")
    if dest.exists() and any(dest.iterdir()):
        subprocess.run(
            ["rm", "-rf", str(dest)],
            capture_output=True, check=False, timeout=60,
        )


@dataclass
class LayerReport:
    name: str
    ok: bool
    detail: str = ""


class AcquisitionLayer:
    name: str = "abstract"

    def acquire(self, ref: RepoRef, dest: Path) -> LayerReport:
        raise NotImplementedError


@dataclass
class TargetedFetchLayer(AcquisitionLayer):
    name: str = "targeted_fetch"
    depth: int = TARGETED_DEPTH
    timeout_s: int = GIT_TIMEOUT_S

    def acquire(self, ref: RepoRef, dest: Path) -> LayerReport:
        dest.mkdir(parents=True, exist_ok=True)
        if any(dest.iterdir()):
            return LayerReport(self.name, False, f"dest not empty: {dest}")

        steps: list[list[str]] = [
            ["git", "-C", str(dest), "init", "-q", "-b", "main"],
            ["git", "-C", str(dest), "remote", "add", "origin", ref.repository_url],
        ]
        wanted = [ref.fix_commit]
        if isinstance(ref.introduced, str) and ref.introduced:
            wanted.append(ref.introduced)

        for sha in wanted:
            steps.append(
                ["git", "-C", str(dest), "fetch", "--depth", str(self.depth), "origin", sha]
            )

        for cmd in steps:
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=self.timeout_s, check=False
                )
            except subprocess.TimeoutExpired:
                return LayerReport(self.name, False, f"timeout: {' '.join(cmd)}")
            if result.returncode != 0:
                return LayerReport(self.name, False, f"{' '.join(cmd)} → {result.stderr.strip()[:200]}")

        if not _commit_exists(dest, ref.fix_commit):
            return LayerReport(self.name, False, f"fix_commit missing after fetch: {ref.fix_commit}")

        return LayerReport(self.name, True, "")


@dataclass
class ShallowCloneLayer(AcquisitionLayer):
    name: str = "shallow_clone"
    depths: tuple[int, ...] = PROGRESSIVE_DEPTHS
    timeout_s: int = GIT_TIMEOUT_S

    def acquire(self, ref: RepoRef, dest: Path) -> LayerReport:
        last_err = "no depth tried"
        for depth in self.depths:
            _clean_dest(dest)
            cmd = [
                "git", "clone", "--quiet", "--depth", str(depth),
                ref.repository_url, str(dest),
            ]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=self.timeout_s, check=False
                )
            except subprocess.TimeoutExpired:
                last_err = f"timeout @ depth={depth}"
                continue
            if result.returncode != 0:
                last_err = result.stderr.strip()[:200]
                continue
            if _commit_exists(dest, ref.fix_commit):
                return LayerReport(self.name, True, f"depth={depth}")
            last_err = f"fix_commit missing @ depth={depth}"
        return LayerReport(self.name, False, last_err)


@dataclass
class FullCloneLayer(AcquisitionLayer):
    """Full-history clone fallback for the two failure shapes the
    shallow tiers can't handle:

    1. Older git servers that reject ``fetch <unadvertised-sha>`` (e.g.
       BootHole / GRUB2 on git.savannah-style hosts) but accept a
       full clone.
    2. Deep cherry-picks that aren't reachable at depth=500 (kernel
       stable-branch fixes from years ago).

    Disk guardrail: aborts before clone if GitHub reports the repo
    is larger than ``max_size_mb``. Linux kernel (~3 GB) hits the
    guardrail and falls through to ``AcquisitionError`` rather than
    spinning for 5+ min on a clone we'll discard anyway.
    """
    name: str = "full_clone"
    timeout_s: int = 300
    max_size_mb: int = 2048

    def acquire(self, ref: RepoRef, dest: Path) -> LayerReport:
        # Disk guardrail: ask GitHub the repo size before cloning.
        # Only applies to github.com URLs; non-GitHub hosts skip the
        # check (most aren't multi-GB anyway).
        from cve_diff.core.url_re import GITHUB_REPO_URL_RE
        m = GITHUB_REPO_URL_RE.match(ref.repository_url)
        if m:
            try:
                from cve_diff.infra import github_client
                payload = github_client.get_repo(m.group(1))
                size_kb = (payload or {}).get("size")
            except Exception:  # noqa: BLE001
                size_kb = None
            if isinstance(size_kb, int) and size_kb > self.max_size_mb * 1024:
                return LayerReport(
                    self.name, False,
                    f"repo too large ({size_kb // 1024} MB > {self.max_size_mb} MB cap)",
                )

        _clean_dest(dest)
        cmd = ["git", "clone", "--quiet", ref.repository_url, str(dest)]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout_s, check=False
            )
        except subprocess.TimeoutExpired:
            return LayerReport(self.name, False, f"timeout @ full clone ({self.timeout_s}s)")
        if result.returncode != 0:
            return LayerReport(self.name, False, result.stderr.strip()[:200])
        if _commit_exists(dest, ref.fix_commit):
            return LayerReport(self.name, True, "")
        return LayerReport(self.name, False, "fix_commit missing after full clone")


@dataclass
class CascadingRepoAcquirer:
    layers: tuple[AcquisitionLayer, ...] = field(
        default_factory=lambda: (TargetedFetchLayer(), ShallowCloneLayer(), FullCloneLayer())
    )
    reports: list[LayerReport] = field(default_factory=list)

    def acquire(self, ref: RepoRef, dest: Path) -> None:
        self.reports = []
        for layer in self.layers:
            layer_dest = dest
            report = layer.acquire(ref, layer_dest)
            self.reports.append(report)
            if report.ok:
                return
            _clean_dest(layer_dest)
        raise AcquisitionError(
            "All acquisition layers failed: "
            + "; ".join(f"{r.name}={r.detail or 'no detail'}" for r in self.reports)
        )
