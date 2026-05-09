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
import tempfile
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

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

# Strict 40-char SHA for ``ls-remote`` output parsing. Git always
# emits full SHAs; a line with a shorter "SHA" is malformed and
# possibly hostile (a remote can return arbitrary bytes), so we
# don't accept abbreviated SHAs in this position. (Distinct from
# ``_SHA_RE`` above, which validates *caller-supplied* SHAs that
# may be abbreviated by intent.)
_LS_REMOTE_SHA_RE = re.compile(r"[0-9a-fA-F]{40}")

logger = logging.getLogger(__name__)


# Egress allowlist for the sandbox network namespace. github.com /
# gitlab.com plus the CDN hosts they redirect to on clone (LFS, object
# storage). Add a host here only when the URL allowlist in
# ``validate.py`` also allows it — the two lists must stay coupled.
#
# Pre-fix this list missed two CDN hosts that GitHub / GitLab
# redirect to during clone-time content fetches:
#
#   raw.githubusercontent.com:    raw blob downloads (LFS objects,
#                                  release tarballs, attachment
#                                  fetches the smudge filter
#                                  triggers).
#   media.githubusercontent.com:  binary release artefacts (some
#                                  release-download flows that LFS-
#                                  configured repos hit during
#                                  checkout).
#
# Without these, clones of LFS-using repos failed with `unable to
# access 'https://raw.githubusercontent.com/...'` errors mid-checkout
# — operator saw "git clone failed" with no signal that the proxy
# allowlist was the missing piece. Add them so the egress proxy
# accepts the redirected hosts.
from ._proxy_hosts import proxy_hosts_for_git as _proxy_hosts_for_git
# Backwards-compat re-export — historical callers + tests reference
# ``core.git.clone._PROXY_HOSTS`` directly. Kept as the static-default
# tuple (no operator override applied) so existing semantics hold;
# new call sites should use ``_proxy_hosts_for_git()`` to pick up the
# operator override config.
from ._proxy_hosts import _DEFAULT_GIT_HOSTS as _PROXY_HOSTS


def get_safe_git_env() -> Dict[str, str]:
    """Sanitised env for git subprocess. Same shape as scanner.py used
    pre-centralisation; promoted here so all callers share it."""
    return RaptorConfig.get_git_env()


# Per-invocation `-c key=value` overrides for git commands operating
# on TARGET REPOSITORIES (i.e. cloned-from-untrusted-source). These
# are layered ON TOP of the env-strip via get_safe_git_env() because
# env vars cannot suppress per-repo config inside `target/.git/config`
# — git reads that unconditionally, and a hostile target can ship a
# `.git/config` containing:
#
#   [core]
#       fsmonitor = /tmp/attacker-script.sh
#
# which then runs the attacker script every time git inspects the
# index (status, diff, log, rev-parse, etc.). CVE-2024-32002 family.
#
# `git -c core.fsmonitor=` (empty value) DISABLES the fsmonitor
# regardless of any per-repo config. Other entries close known RCE
# vectors:
#
#   - core.editor=true: prevents git from launching an attacker-
#     specified editor on `git commit --amend` or rebase.
#   - core.pager=cat: prevents pager-shell-out for paged output.
#   - core.askPass=true: belt-and-braces with GIT_ASKPASS env.
#   - core.sshCommand=ssh: prevents per-repo SSH command override.
#   - protocol.file.allow=user: refuses file:// URLs as remotes.
#   - protocol.ext.allow=never: refuses ext:: protocol shells.
#
# Use `safe_git_command(*args)` below instead of building bare
# `["git", ...]` lists when operating on a target repo.
_SAFE_GIT_OVERRIDES = (
    "-c", "core.fsmonitor=",
    "-c", "core.editor=true",
    "-c", "core.pager=cat",
    "-c", "core.askPass=true",
    "-c", "core.sshCommand=ssh",
    "-c", "protocol.file.allow=user",
    "-c", "protocol.ext.allow=never",
)


def safe_git_command(*args: str) -> list:
    """Return a git argv list with per-invocation safety overrides
    layered between ``git`` and the caller's args.

    Use for git commands that operate on a TARGET REPOSITORY
    (cloned from untrusted source). Internal-only repos
    (RAPTOR's own .git, test fixtures) don't need this — bare
    ``["git", ...]`` is fine for them.

    Example::

        # Pre-fix:
        subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"])

        # Post-fix:
        subprocess.run(safe_git_command("-C", str(repo), "rev-parse", "HEAD"))

    The result is a list (not a tuple) so callers can extend it
    in-place if needed.
    """
    return ["git", *_SAFE_GIT_OVERRIDES, *args]


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
    # Pre-fix the validator only refused root and direct-children-of-
    # root. It silently accepted paths under sensitive system mounts:
    #
    #   /dev/shm/foo       — tmpfs visible to all users on the host;
    #                        a hostile git server cloning into
    #                        /dev/shm/x can plant attacker-readable
    #                        files in another user's environment.
    #   /proc/<pid>/...    — kernel-managed pseudo-fs; writes here
    #                        either no-op or modify process state
    #                        (cgroup membership, oom_adj, etc.).
    #                        Sandbox carving a writable hole into
    #                        /proc is meaningless at best and
    #                        privilege-escalation at worst.
    #   /sys/...           — same as /proc; kernel-managed and
    #                        denylist on principle.
    #   /run/...           — runtime state (PID files, sockets);
    #                        sandbox writes here can collide with
    #                        systemd / docker / similar.
    #
    # Reject these prefixes outright. Operator-legitimate sandbox
    # work belongs under /tmp, /var/tmp, $HOME, or a dedicated
    # workspace — not in system pseudo-fs locations.
    _str = str(p)
    _DENY_PREFIXES = ("/dev/", "/proc/", "/sys/", "/run/")
    for prefix in _DENY_PREFIXES:
        if _str.startswith(prefix) or _str == prefix.rstrip("/"):
            raise ValueError(
                f"{role}={str(p)!r} is under a system pseudo-fs prefix "
                f"({prefix}); refusing to grant the sandbox write "
                f"access. Use /tmp, /var/tmp, $HOME, or a dedicated "
                f"workspace path instead."
            )
    # Two checks against root, both required:
    #
    # 1. The RESOLVED form catches `/tmp/work -> /` symlink attacks
    #    (caller passes /tmp/work, .resolve() reveals the parent IS
    #    actually root after symlink follow-through).
    #
    # 2. The UNRESOLVED form catches macOS's pervasive
    #    /etc → /private/etc, /var → /private/var, /tmp → /private/tmp
    #    symlinks. With ONLY the resolved check, `/etc` on macOS
    #    resolves to `/private/etc` whose parent is `/private` —
    #    NOT root — so the validation passes and the sandbox becomes
    #    writable in `/private`, which is host-wide system state on
    #    macOS. The unresolved check sees `/etc`.parent == `/` and
    #    refuses, matching the Linux-side semantic intent.
    #
    # Either form being root → reject. Caught by core/sandbox/tests/
    # — first surfaced when the sandbox suite ran on macOS.
    resolved = p.resolve()
    for label, candidate in (("resolved", resolved), ("literal", p)):
        if candidate.parent == candidate:
            raise ValueError(
                f"{role}={str(p)!r} {label}-form is the filesystem "
                f"root; refusing to grant the sandbox write access "
                f"to the entire filesystem"
            )
        if candidate.parent == Path(candidate.anchor):
            raise ValueError(
                f"{role}={str(p)!r} {label}-form has filesystem root "
                f"as its parent. Sandbox writable scope "
                f"({role}.parent) would be the entire root filesystem."
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
        proxy_hosts=_proxy_hosts_for_git(),
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
    proxy_hosts = _proxy_hosts_for_git()
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


def ls_remote(
    url: str,
    *,
    proxy_hosts: Iterable[str],
    timeout: int = 20,
) -> List[Tuple[str, str]]:
    """Run ``git ls-remote --heads --tags`` against ``url``.

    Read-only operation that returns the refs the remote advertises.
    Sandbox-routed via ``run_untrusted`` with the egress proxy pinned
    to ``proxy_hosts``. Caller supplies the allowlist because consumers
    of this helper cover wider forge sets than the github/gitlab pair
    ``clone_repository`` accepts (cve_diff's agent uses it to probe
    non-GitHub forges like git.kernel.org, git.savannah.gnu.org,
    git.tukaani.org, etc).

    The egress proxy enforces:

      - hostname allowlist: connections to anything outside
        ``proxy_hosts`` are refused at CONNECT;
      - private-IP / loopback / link-local block: hostnames that
        resolve to RFC 1918 / 127.0.0.0/8 / 169.254.0.0/16 / etc.
        are refused regardless of the allowlist (closes the SSRF
        and DNS-rebinding surface);
      - HTTPS-only transport: SSH / git:// schemes can't tunnel
        through HTTPS-CONNECT.

    Args:
        url: HTTPS git URL. Must have a hostname and no userinfo.
            ``http://`` is rejected because the in-process egress
            proxy is HTTPS-CONNECT exclusively.
        proxy_hosts: hostname allowlist passed to the proxy. Must be
            non-empty, and bare hostnames only (no ``host:port``
            entries — the URL's port is unrelated to the allowlist
            check). The URL's host must also appear here (defence
            in depth — the proxy would refuse anyway).
        timeout: per-call wall-clock cap (seconds; default 20).
            Tighter than ``RaptorConfig.GIT_CLONE_TIMEOUT`` because
            ls-remote returns a ref-list, not whole repos.

    Returns:
        ``[(sha, ref), ...]`` — e.g.
        ``[("abc...", "refs/heads/main"), ("def...", "refs/tags/v1")]``.
        Lines whose first column isn't a SHA shape are skipped
        defensively.

    Raises:
        ValueError: URL fails scheme/userinfo/hostname checks, or
            ``proxy_hosts`` is empty, or URL host isn't in
            ``proxy_hosts``.
        RuntimeError: sandbox unavailable, or ``git ls-remote``
            exited non-zero.
        subprocess.TimeoutExpired: ``timeout`` elapsed before git
            returned. Propagated unchanged so callers handling the
            ``(RuntimeError, TimeoutExpired)`` tuple cover both
            shapes — same contract as ``clone_repository`` /
            ``fetch_commit``.
        FileNotFoundError: ``git`` binary not on PATH inside the
            sandbox. Caller-trusted (CI environments always have
            it); propagated for diagnosability.
    """
    proxy_host_list = list(proxy_hosts)
    if not proxy_host_list:
        raise ValueError("ls_remote requires non-empty proxy_hosts")

    # ``urlparse`` is more honest than a regex for the "is this a
    # safe URL shape" check — handles userinfo, fragments, ports
    # cleanly. ValueError surfaces on URLs containing null bytes /
    # invalid IPv6 / etc.; rare but worth surfacing as a ValueError
    # so callers don't see a stdlib internal type.
    try:
        parsed = urlparse(url)
    except ValueError as e:
        raise ValueError(f"ls_remote: malformed URL: {e}") from None

    # ``https`` only — the in-process egress proxy is HTTPS-CONNECT
    # exclusively, so plain ``http://`` would pass this check but
    # fail at the proxy with a confusing transport error. Refuse
    # upfront for a clearer contract.
    if parsed.scheme != "https":
        raise ValueError(
            f"ls_remote requires https URL; got scheme={parsed.scheme!r}"
        )
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(
            "ls_remote refuses URLs with userinfo (credentials in URL)"
        )
    if not parsed.hostname:
        raise ValueError(f"ls_remote: URL has no hostname: {url!r}")

    # IDNA round-trip on the hostname for canonicalisation. Pre-fix
    # `parsed.hostname.lower()` worked for ASCII hosts but missed
    # internationalised domain names. URL `https://пример.рф/...`
    # has parsed.hostname == "xn--e1afmkfd.xn--p1ai" already (urllib
    # canonicalises to punycode) — but a URL `https://Пример.рф/`
    # (mixed-case Cyrillic) parses to "пример.рф" (lower-cased
    # Cyrillic), which doesn't match a punycode allowlist entry
    # `xn--e1afmkfd.xn--p1ai`. The IDNA encode normalises to the
    # canonical punycode form so the allowlist comparison is
    # reliable across both ASCII and IDN inputs.
    host_raw = parsed.hostname.lower()
    try:
        host = host_raw.encode("idna").decode("ascii").lower()
    except (UnicodeError, UnicodeDecodeError):
        # Hostname not encodable — operator may have provided a
        # malformed value; fall back to the lowered original so
        # the explicit allowlist mismatch error fires below
        # rather than crashing here.
        host = host_raw

    # Pre-check the hostname is in the supplied allowlist. The proxy
    # enforces too — this is defence-in-depth and a clearer error
    # before the subprocess fires.
    allowed_lower = {h.lower() for h in proxy_host_list}
    if host not in allowed_lower:
        raise ValueError(
            f"ls_remote: URL host {host!r} not in proxy_hosts allowlist"
        )

    try:
        from core.sandbox import run_untrusted
    except ImportError:
        raise RuntimeError(
            "core.sandbox unavailable - git ls-remote refuses to run "
            "without sandbox isolation"
        )

    # ``ls-remote`` doesn't write to the host filesystem, but
    # ``run_untrusted`` requires a non-empty ``output`` so Landlock
    # engages and ``fake_home`` has somewhere to materialise.
    # An ephemeral temp dir gives the sandbox a writable scratch
    # area that's discarded as soon as we leave the with-block.
    with tempfile.TemporaryDirectory(prefix="raptor-ls-remote-") as td:
        # Pre-fix the log line emitted the raw URL. Operators
        # passing tokens via URL userinfo (`https://oauth2:
        # token@github.com/owner/repo.git`) leaked the token to
        # any log destination — RAPTOR's own log files,
        # forwarded log aggregators, and any operator who
        # `tail`d a long-running scan. The userinfo check
        # earlier in this function rejects URL tokens at
        # validation time, so this log line never sees them in
        # the canonical happy path — but defence-in-depth: a
        # future caller could land here without the validator
        # check (test fixtures, refactor that loosens the
        # gate). Run through redact_secrets() so any
        # credentials in URL form are masked before the log
        # write.
        from core.security.redaction import redact_secrets
        logger.info("git ls-remote: %s (allowlist=%s)",
                     redact_secrets(url),
                     ",".join(sorted(allowed_lower)))
        proc = run_untrusted(
            ["git", "ls-remote", "--heads", "--tags", url],
            target=td,
            output=td,
            env=get_safe_git_env(),
            use_egress_proxy=True,
            proxy_hosts=proxy_host_list,
            timeout=timeout,
            capture_output=True,
            text=True,
            # ``errors="replace"`` so a hostile remote returning
            # non-UTF-8 bytes doesn't surface as
            # ``UnicodeDecodeError``. The output parser uses a
            # strict 40-hex-char SHA regex below, so any U+FFFD
            # replacement chars in the SHA position fail the regex
            # and the line is skipped defensively.
            encoding="utf-8",
            errors="replace",
        )

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()
        raise RuntimeError(
            f"git ls-remote failed: {stderr or stdout or 'unknown error'}"
        )

    refs: List[Tuple[str, str]] = []
    for line in (proc.stdout or "").splitlines():
        # Each line is: ``<40-hex sha>\t<ref>``.
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        sha, ref = parts
        # Strict 40-char SHA — git always emits full SHAs in
        # ls-remote output. A shorter "SHA" is malformed and possibly
        # hostile (a remote can return arbitrary bytes), so we don't
        # accept abbreviated SHAs here. Distinct from caller-supplied
        # SHA validation in ``fetch_commit`` which allows abbreviation.
        if not _LS_REMOTE_SHA_RE.fullmatch(sha):
            continue
        refs.append((sha, ref))

    return refs


__all__ = ["clone_repository", "fetch_commit", "get_safe_git_env", "ls_remote"]
