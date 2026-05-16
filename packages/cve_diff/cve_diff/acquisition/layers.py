"""
Acquisition layers: turn a `RepoRef` into a local directory with both commits.

Two strategies, tried in order (plan's cascade):

1. TargetedFetchLayer — ``core.git.fetch_commit`` per wanted SHA. Works for
   old CVEs whose fix commits aren't reachable from a depth-1 clone of HEAD.
   ~70% of wins on the reference project's measured runs.

2. ShallowCloneLayer — ``core.git.clone_repository`` with progressive depth
   (100, 500). Recovers when the server refuses direct commit fetches
   (common for older GitLab instances / some mirrors). The 2000-depth tier
   was dropped on the 2026-04-20 bench: median 64s worst-case and 3/40
   timeouts. If the SHA isn't reachable at 500 it almost never is at 2000.

3. FullCloneLayer — ``core.git.clone_repository`` with ``depth=None``.
   Last-resort for old git servers that reject ``fetch <unadvertised-sha>``
   (e.g. BootHole / GRUB2 on git.savannah-style hosts) and for deep cherry-
   picks not reachable at depth=500.

Pre-rewire each layer shelled out to ``git clone`` / ``git fetch`` directly
via ``subprocess.run``. That bypassed the egress proxy + sandbox isolation:
a malicious server-side hook on a forked clone (or a compromised mirror)
ran with full host network and filesystem access. The layers now route
every git transport through ``core.git.{clone_repository, fetch_commit}``,
which engages the sandbox + hostname-allowlisted egress proxy used by the
rest of RAPTOR.

Dropped from the reference port: the ``TemporalAcquisitionLayer`` (deleted
branches, 925 LOC of workarounds) — the plan calls it "marginal value" and
drops it from Phase 1.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from core.git import clone_repository, fetch_commit, get_safe_git_env
from core.git.clone import safe_git_command

from cve_diff.core.exceptions import AcquisitionError
from cve_diff.core.models import RepoRef

PROGRESSIVE_DEPTHS: tuple[int, ...] = (100, 500)
TARGETED_DEPTH = 5
# Sanity bound only — actual per-call timeout is delegated to
# ``RaptorConfig.GIT_CLONE_TIMEOUT`` inside ``core.git``. Retained so
# ``test_git_timeout_bounded`` keeps its acquire-budget invariant
# (≤180s) explicit at this layer.
GIT_TIMEOUT_S = 120


def _commit_exists(repo_path: Path, sha: str) -> bool:
    # Local-only ``cat-file`` check — operates on already-fetched objects
    # in ``repo_path/.git/`` and never touches the network. Stays as a
    # raw subprocess (no sandbox needed for purely-local reads); the
    # 30s timeout protects against pathological filesystems (broken NFS,
    # dying disk) hanging the pipeline.
    try:
        completed = subprocess.run(
            safe_git_command(
                "-C", str(repo_path),
                "cat-file", "-e", f"{sha}^{{commit}}",
            ),
            capture_output=True,
            check=False,
            timeout=30,
            env=get_safe_git_env(),
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
    # Single lstat() instead of three separate stat-class calls.
    # Pre-fix `is_symlink()` + `exists()` + `is_dir()` was three
    # syscalls with TOCTOU windows between each: a writer could
    # swap the path between checks (file→symlink→dir) and slip
    # past the safety gates. Single lstat collapses the window
    # to one syscall (the residual race between lstat and `rm` is
    # narrower and within `rm`'s own resolution semantics).
    import stat as _stat
    try:
        st = dest.lstat()
    except FileNotFoundError:
        return  # No-op when dest doesn't exist
    if _stat.S_ISLNK(st.st_mode):
        raise ValueError(f"_clean_dest refusing symlink: {dest!r}")
    if not _stat.S_ISDIR(st.st_mode):
        # `iterdir()` raises NotADirectoryError on regular files.
        # Refuse explicitly so the error is structured.
        raise ValueError(f"_clean_dest refusing non-directory: {dest!r}")
    if any(dest.iterdir()):
        # Use absolute path + sanitised env. Pre-fix the bare `rm`
        # was resolved via PATH — a hostile PATH entry (a CI
        # environment with `.` early in PATH, an operator-poisoned
        # ~/.bashrc) could shadow `/usr/bin/rm` with an attacker
        # binary that the destructive operation then ran.
        # `shutil.which("rm")` resolves once at module use-time
        # (not import — keeps the cost off the import critical
        # path); fallback to `/usr/bin/rm` keeps the operation
        # working on hosts where shutil.which trips on a weird
        # PATH config. `env=` to a stripped environment so the
        # subprocess can't pick up LD_PRELOAD / LD_LIBRARY_PATH /
        # other code-injection vectors via the parent's env.
        import shutil
        rm_bin = shutil.which("rm") or "/usr/bin/rm"
        from core.config import RaptorConfig
        subprocess.run(
            [rm_bin, "-rf", str(dest)],
            capture_output=True, check=False, timeout=60,
            env=RaptorConfig.get_safe_env(),
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

    def acquire(self, ref: RepoRef, dest: Path) -> LayerReport:
        dest.mkdir(parents=True, exist_ok=True)
        if any(dest.iterdir()):
            return LayerReport(self.name, False, f"dest not empty: {dest}")

        wanted = [ref.fix_commit]
        if isinstance(ref.introduced, str) and ref.introduced:
            wanted.append(ref.introduced)

        # ``fetch_commit`` initialises ``dest`` on first call, then
        # ``git fetch --depth=N origin <sha>`` per requested SHA. The
        # first SHA's fetch creates the repo; subsequent SHAs reuse
        # ``origin`` (set-url is idempotent inside fetch_commit).
        for sha in wanted:
            try:
                fetch_commit(dest, ref.repository_url, sha, depth=self.depth)
            except ValueError as e:
                # URL fails the allowlist, SHA fails the shape check, or
                # ``dest`` fails the writable-path check. All caller-side
                # bugs / inputs — propagate as a layer failure.
                return LayerReport(self.name, False, f"validation: {e}")
            except RuntimeError as e:
                return LayerReport(
                    self.name, False,
                    f"fetch {sha[:12]}: {str(e)[:200]}",
                )

        if not _commit_exists(dest, ref.fix_commit):
            return LayerReport(
                self.name, False,
                f"fix_commit missing after fetch: {ref.fix_commit}",
            )

        return LayerReport(self.name, True, "")


@dataclass
class ShallowCloneLayer(AcquisitionLayer):
    name: str = "shallow_clone"
    depths: tuple[int, ...] = PROGRESSIVE_DEPTHS

    def acquire(self, ref: RepoRef, dest: Path) -> LayerReport:
        last_err = "no depth tried"
        for depth in self.depths:
            _clean_dest(dest)
            try:
                clone_repository(ref.repository_url, dest, depth=depth)
            except ValueError as e:
                # URL allowlist / writable-path validator — surfaces
                # caller-side input issues. Stop trying further depths
                # since the inputs themselves are invalid.
                return LayerReport(
                    self.name, False, f"validation: {e}",
                )
            except RuntimeError as e:
                last_err = str(e)[:200]
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
    max_size_mb: int = 2048

    def acquire(self, ref: RepoRef, dest: Path) -> LayerReport:
        # Disk guardrail: ask GitHub the repo size before cloning.
        # Only applies to github.com URLs; non-GitHub hosts skip the
        # check (most aren't multi-GB anyway).
        from core.url_patterns import GITHUB_REPO_URL_RE
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
        try:
            clone_repository(ref.repository_url, dest, depth=None)
        except ValueError as e:
            return LayerReport(self.name, False, f"validation: {e}")
        except RuntimeError as e:
            return LayerReport(self.name, False, str(e)[:200])
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
