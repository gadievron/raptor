"""Sandbox-routed git clone + targeted fetch.

Two entry points:

  - ``clone_repository(url, target, depth=1)`` — shallow or full clone.
  - ``fetch_commit(repo_dir, url, sha, depth=5)`` — targeted fetch of a
    specific commit into an existing or fresh git directory. Useful when
    a full clone would be wasteful: the caller already knows the SHA and
    wants only that commit's history. Older CVE fix commits are often
    not reachable from a depth-1 clone of HEAD, so progressive-fetch
    cascades use this.

Both wrap their ``git`` subprocess in ``core.sandbox.run_untrusted``:

  - the egress proxy pinned to the small set of hostnames the URL
    allowlist permits (github.com / gitlab.com plus the known
    object-storage CDNs they redirect to);
  - landlocked filesystem so the git process can only write into
    the target / repo directory;
  - sanitised env (``RaptorConfig.get_git_env()`` — clears
    HTTP_PROXY / NO_PROXY etc., sets GIT_TERMINAL_PROMPT=0 and
    GIT_ASKPASS=true so a malformed-credential prompt can't hang
    the run);
  - bounded timeout (``RaptorConfig.GIT_CLONE_TIMEOUT``).

Pre-#210, scanner.py and recon/agent.py both implemented variants of
clone. Post-centralisation everyone calls through here.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, Optional

from core.config import RaptorConfig
from core.git.validate import validate_repo_url

# Git allows SHA abbreviations of 4+ chars; full SHA-1 is 40 hex.
# We reject anything that doesn't match this shape so a tainted SHA
# cannot be parsed as a ``git fetch`` flag (e.g. ``--upload-pack=`` for
# RCE on SSH transport, CVE-2017-1000117 family). Argument-position
# defence-in-depth — the URL is already on a regex allowlist.
#
# Note: ``re.fullmatch`` (not ``re.match``+``$``) — ``$`` in Python's ``re``
# matches *just before* a trailing newline, so ``"deadbeef\n"`` would
# otherwise sneak past a ``^...$`` check.
_SHA_RE = re.compile(r"[0-9a-fA-F]{4,40}")

logger = logging.getLogger(__name__)


# Egress allowlist for the sandbox network namespace. github.com /
# gitlab.com plus the CDN hosts they redirect to on clone (LFS, object
# storage). Add a host here only when the URL allowlist in
# ``validate.py`` also allows it — the two lists must stay coupled.
_PROXY_HOSTS = (
    "github.com", "gitlab.com",
    "codeload.github.com", "objects.githubusercontent.com",
)


def get_safe_git_env() -> Dict[str, str]:
    """Sanitised env for git subprocess. Same shape as scanner.py used
    pre-centralisation; promoted here so all callers share it."""
    return RaptorConfig.get_git_env()


def _validate_writable_path(p: Path, *, role: str) -> None:
    """Refuse caller-supplied paths that would unsafely widen the
    sandbox's writable scope.

    Both ``clone_repository`` and ``fetch_commit`` configure the
    sandbox writable scope as ``p.parent`` so the auto-materialised
    ``.home/`` lands sibling to the repo (not inside). That choice
    means a pathological ``p`` — empty, the filesystem root, or a
    direct child of ``/`` — turns into "sandbox writable = entire
    filesystem", which would let a compromised git server clobber
    arbitrary host paths even with the rest of the isolation engaged.

    Rejected shapes:
      - relative paths (cwd-dependent writable scope is implicit
        state — refuse and require the caller to be explicit);
      - filesystem root (``/``);
      - direct children of root (``/foo``, ``/etc``, …) where parent
        is still ``/``.
    """
    if not p.is_absolute():
        raise ValueError(
            f"{role} must be an absolute path; got {str(p)!r}. Relative "
            f"paths are unsafe here — the sandbox writable scope "
            f"({role}.parent) would be cwd-dependent."
        )
    # ``.resolve()`` follows symlinks so a pre-staged
    # ``/tmp/work -> /`` symlink can't sneak past the root checks.
    resolved = p.resolve()
    if resolved.parent == resolved:
        raise ValueError(
            f"{role}={str(p)!r} resolves to filesystem root; refusing "
            f"to grant the sandbox write access to the entire "
            f"filesystem"
        )
    if resolved.parent == Path(resolved.anchor):
        raise ValueError(
            f"{role}={str(p)!r} has filesystem root as its parent. "
            f"Sandbox writable scope ({role}.parent) would be the "
            f"entire root filesystem."
        )


def clone_repository(
    url: str, target: Path, depth: Optional[int] = 1,
) -> bool:
    """Shallow-clone ``url`` into ``target`` via the sandboxed runner.

    Args:
        url: must pass ``validate_repo_url``; rejected otherwise.
        target: destination directory. The sandbox is configured with
            this as the only writable path.
        depth: shallow-clone depth (default 1). Pass ``None`` to clone
            full history.

    Raises:
        ValueError: URL fails the allowlist, or ``target`` fails the
            writable-path check (relative, filesystem root, or
            direct child of root — see ``_validate_writable_path``).
        RuntimeError: ``git clone`` exited non-zero.
    """
    if not validate_repo_url(url):
        raise ValueError(f"Invalid or untrusted repository URL: {url}")
    _validate_writable_path(target, role="target")

    cmd = ["git", "clone"]
    if depth is not None:
        cmd.extend(["--depth", str(depth), "--no-tags"])
    cmd.extend([url, str(target)])

    logger.info("git clone: %s -> %s", url, target)
    try:
        from core.sandbox import run_untrusted
    except ImportError:
        raise RuntimeError(
            "core.sandbox unavailable - git clone refuses to run "
            "without sandbox isolation"
        )

    target.parent.mkdir(parents=True, exist_ok=True)
    proc = run_untrusted(
        cmd,
        target=str(target.parent),
        output=str(target.parent),
        env=get_safe_git_env(),
        use_egress_proxy=True,
        proxy_hosts=list(_PROXY_HOSTS),
        timeout=RaptorConfig.GIT_CLONE_TIMEOUT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()
        raise RuntimeError(
            f"git clone failed: {stderr or stdout or 'unknown error'}"
        )
    return True


def fetch_commit(
    repo_dir: Path, url: str, sha: str, depth: int = 5,
) -> bool:
    """Fetch a specific ``sha`` from ``url`` into ``repo_dir``.

    Initialises ``repo_dir`` as a fresh git repo if it isn't one already,
    adds (or replaces) an ``origin`` remote pointing at ``url``, then
    runs ``git fetch --depth=<depth> origin <sha>``. Same sandbox /
    proxy / env / timeout posture as :func:`clone_repository`.

    Targeted fetch is the right primitive when:

      - the caller already knows the SHA they need;
      - a depth-1 clone of HEAD wouldn't reach it (older fix commits,
        commits on long-since-deleted branches, cherry-picks);
      - paying the cost of a full clone is wasteful.

    Args:
        repo_dir: target directory. Created if absent. Must be the
            only writable path the sandbox grants the git process.
        url: remote URL; must pass ``validate_repo_url``.
        sha: commit SHA to fetch. Must be 4–40 hex chars
            (``[0-9a-fA-F]``) — ``--upload-pack=`` and friends would
            otherwise be parsed as ``git fetch`` flags.
        depth: shallow-fetch depth (default 5). The caller should
            cascade — start small, retry deeper on miss.

    Returns ``True`` on success.

    Raises:
        ValueError: URL fails the allowlist, ``repo_dir`` fails the
            writable-path check (relative, filesystem root, or direct
            child of root — see ``_validate_writable_path``), or SHA
            fails the shape check.
        RuntimeError: any of ``git init``, ``git remote``, or
            ``git fetch`` exited non-zero.
    """
    if not validate_repo_url(url):
        raise ValueError(f"Invalid or untrusted repository URL: {url}")
    _validate_writable_path(repo_dir, role="repo_dir")
    if not _SHA_RE.fullmatch(sha):
        # Defend against ``sha = "--upload-pack=cmd"`` style flag
        # injection at the ``git fetch <repo> <refspec>`` position.
        raise ValueError(
            f"Invalid commit SHA shape (expected 4-40 hex chars): {sha!r}"
        )

    try:
        from core.sandbox import run_untrusted
    except ImportError:
        raise RuntimeError(
            "core.sandbox unavailable - git fetch refuses to run "
            "without sandbox isolation"
        )

    repo_dir.mkdir(parents=True, exist_ok=True)
    env = get_safe_git_env()
    proxy_hosts = list(_PROXY_HOSTS)
    timeout = RaptorConfig.GIT_CLONE_TIMEOUT

    # ``output`` is the sandbox's writable allowlist. Use ``repo_dir.parent``
    # to match ``clone_repository``: with ``fake_home=True`` (the
    # ``run_untrusted`` default), the sandbox materialises ``{output}/.home/``
    # for the child's HOME. Passing ``repo_dir`` directly would put that
    # ``.home/`` *inside* the repo, polluting the caller's working tree.
    # The parent directory is one level wider but matches clone semantics
    # exactly — ``.home/`` ends up sibling to ``repo_dir``.
    sandbox_target = str(repo_dir.parent)

    def _run(cmd: list, *, network: bool):
        # ``git init`` and ``git remote`` are local-only; the sandbox
        # still runs them through ``run_untrusted`` for env hygiene.
        # The egress proxy is only engaged for the fetch step — local
        # ops have no need for it. NB: ``use_egress_proxy=True`` MUST be
        # paired with ``proxy_hosts`` for the proxy to start; passing
        # ``proxy_hosts`` alone is a no-op (the sandbox keeps
        # ``block_network=True`` and the child has no network at all).
        kwargs = dict(
            target=sandbox_target,
            output=sandbox_target,
            env=env,
            timeout=timeout,
            capture_output=True,
            text=True,
        )
        if network:
            kwargs["use_egress_proxy"] = True
            kwargs["proxy_hosts"] = proxy_hosts
        return run_untrusted(cmd, **kwargs)

    is_repo = (repo_dir / ".git").exists()
    if not is_repo:
        logger.info("git init: %s", repo_dir)
        proc = _run(
            ["git", "-C", str(repo_dir), "init", "--quiet"],
            network=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"git init failed: "
                f"{(proc.stderr or proc.stdout or 'unknown error').strip()}"
            )

    # ``remote add`` is idempotent-ish — if origin already exists we
    # rewrite the URL via ``set-url`` so the caller can reuse a
    # repo_dir across distinct URLs without surprises. If both fail
    # we surface BOTH errors so the operator sees the real cause
    # (e.g. disk full) rather than only the set-url echo.
    add_proc = _run(
        ["git", "-C", str(repo_dir), "remote", "add", "origin", url],
        network=False,
    )
    if add_proc.returncode != 0:
        set_proc = _run(
            ["git", "-C", str(repo_dir), "remote", "set-url", "origin", url],
            network=False,
        )
        if set_proc.returncode != 0:
            add_msg = (add_proc.stderr or add_proc.stdout or "").strip()
            set_msg = (set_proc.stderr or set_proc.stdout or "").strip()
            raise RuntimeError(
                f"git remote add/set-url failed: "
                f"add={add_msg or 'unknown error'}; "
                f"set-url={set_msg or 'unknown error'}"
            )

    logger.info("git fetch (depth=%d): %s @ %s", depth, url, sha)
    proc = _run(
        [
            "git", "-C", str(repo_dir), "fetch",
            "--depth", str(depth), "--no-tags",
            "origin", sha,
        ],
        network=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"git fetch failed: "
            f"{(proc.stderr or proc.stdout or 'unknown error').strip()}"
        )
    return True


__all__ = ["clone_repository", "fetch_commit", "get_safe_git_env"]
