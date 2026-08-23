"""Sandbox-routed git clone + targeted fetch.

Two entry points:

  - ``clone_repository(url, target, depth=1)`` — shallow or full clone.
  - ``fetch_commit(repo_dir, url, sha, depth=5)`` — targeted fetch of a
    specific commit into an existing or fresh git directory. Useful when
    a full clone would be wasteful: the caller already knows the SHA and
    wants only that commit's history. Older CVE fix commits are often
    not reachable from a depth-1 clone of HEAD, so progressive-fetch
    cascades use this.

Both wrap their ``git`` subprocess in ``core.sandbox.run_untrusted_networked``
(network calls) and ``core.sandbox.run_untrusted`` (local-only calls):

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
import shutil
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from core.config import RaptorConfig
from core.git.validate import validate_repo_url
from core.logging import log_security_event as _log_security_event
from core.security.redaction import redact_url_secrets_only

# Backwards-compat re-export — historical callers + tests reference
# ``core.git.clone._PROXY_HOSTS`` directly. Kept as the static-default
# tuple (no operator override applied) so existing semantics hold;
# new call sites should use ``_proxy_hosts_for_git()`` to pick up the
# operator override config. (See the egress-allowlist commentary
# further down for why these hosts and no others.)
from ._proxy_hosts import _DEFAULT_GIT_HOSTS as _PROXY_HOSTS  # noqa: F401
from ._proxy_hosts import proxy_hosts_for_git as _proxy_hosts_for_git
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

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
# allowlist was the missing piece. The hosts live in ``._proxy_hosts``
# (re-exported at the top of this module as ``_PROXY_HOSTS``) so the
# egress proxy accepts the redirected hosts.


def get_safe_git_env(*, preserve_proxy: bool = False) -> dict[str, str]:
    """Sanitised env for git subprocess. Same shape as scanner.py used
    pre-centralisation; promoted here so all callers share it.

    ``preserve_proxy=True`` keeps the operator's proxy vars
    (HTTP_PROXY / HTTPS_PROXY / NO_PROXY) in the returned env — same
    opt-in contract as ``RaptorConfig.get_safe_env``. Use ONLY for git
    invocations that dial a remote OUTSIDE the sandbox egress proxy
    (the dataflow walkers' targeted fetches): git honours proxy env,
    and on mandatory-egress-proxy hosts a fetch has no route without
    it. Everything else about the sanitisation (allowlist +
    dangerous-var strip + the GIT_ENV_VARS prompt/askpass pins) is
    identical. The sandbox-routed entry points in this module don't
    need it — their egress goes through the in-process proxy.
    """
    if preserve_proxy:
        env = RaptorConfig.get_safe_env(preserve_proxy=True)
        env.update(RaptorConfig.GIT_ENV_VARS)
        return env
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
#   - core.hooksPath=/dev/null: per-repo hooks directory pointer
#     (git ≥2.9). Hostile .git/config setting
#     ``core.hooksPath=.attacker-hooks`` fires arbitrary scripts on
#     every git op against the clone; pointing it at /dev/null
#     bypasses hook execution entirely.
#   - credential.helper=: per-repo credential helper RCE
#     (CVE-2017-1000117 family).
#   - core.gitProxy=: per-repo proxy command RCE.
#   - gpg.program=true (+ x509/ssh variants): `git log --format=%G?`
#     and friends invoke the configured signature verifier once per
#     signed commit walked, and the per-repo config can point it at
#     any program. Pinned to `true` (no-op) so ordinary target-repo
#     git ops never execute a repo-chosen verifier; the few callers
#     that deliberately verify signatures re-enable it through the
#     system binaries via `signature_probe_overrides()` below.
#   - diff.external=: per-repo external diff command. git treats the
#     empty value as a command to exec, so a `git diff` through these
#     overrides FAILS LOUDLY unless the caller passes `--no-ext-diff`
#     — deliberate: a diff invocation that forgot to disable external
#     drivers fails closed instead of silently honouring a repo-named
#     program. Per-driver `diff.<name>.command` entries share the
#     arbitrary-name problem filters have (next paragraph); the
#     explicit `--no-ext-diff` covers both.
#
# KNOWN LIMIT — clean/smudge filter drivers (`filter.<name>.clean` et
# al.) cannot be blanket-neutralised here: the driver names are
# repo-chosen, so there is no finite `-c` list that covers them. Any
# git operation that (re)hashes worktree content — `git status`'s
# index refresh, `git add`, checkout — runs them. Callers probing a
# target repo must therefore stick to plumbing that never re-hashes
# worktree files: `rev-parse`, `diff-index` WITHOUT a preceding
# refresh (stat-cache comparison only), `ls-files`. See
# core.run.provenance.target_snapshot for the pattern.
#
# Use `safe_git_command(*args)` below instead of building bare
# `["git", ...]` lists when operating on a target repo.
_SAFE_GIT_OVERRIDES = (
    "-c", "core.fsmonitor=",
    "-c", "core.editor=true",
    "-c", "core.pager=cat",
    "-c", "core.askPass=true",
    "-c", "core.sshCommand=ssh",
    "-c", "core.hooksPath=/dev/null",
    "-c", "credential.helper=",
    "-c", "core.gitProxy=",
    "-c", "protocol.file.allow=user",
    "-c", "protocol.ext.allow=never",
    "-c", "gpg.program=true",
    "-c", "gpg.x509.program=true",
    "-c", "gpg.ssh.program=true",
    "-c", "diff.external=",
)


# STRICT variant for READ-ONLY operations on target repos (log,
# rev-parse, rev-list, diff-index, ls-files, ...). Read-only ops never
# need a remote, so every transport can be refused wholesale:
#
#   - protocol.allow=never: one config kills file://, ext::, ssh://,
#     git://, http(s):// in a single stroke. Stronger than the
#     per-protocol pair in _SAFE_GIT_OVERRIDES — but note the
#     precedence trap: git resolves `protocol.<name>.allow` BEFORE the
#     `protocol.allow` catch-all, so the base tuple's
#     `protocol.file.allow=user` would still permit the file protocol.
#     The strict tuple therefore re-pins protocol.file.allow=never
#     explicitly (protocol.ext.allow is already `never` in the base).
#   - core.sshCommand=false: belt-and-braces on top of
#     protocol.allow=never — even if a transport were somehow
#     engaged, the SSH command is the no-op `false`, never a
#     repo- or env-chosen binary. (The base tuple pins `ssh` because
#     clone/fetch legitimately use SSH-capable transports.)
#
# These land AFTER _SAFE_GIT_OVERRIDES in the argv; git honours the
# LAST `-c` occurrence for a key, so the strict pins win.
#
# Do NOT use the strict variant for the NETWORK argv in
# clone_repository / fetch_commit / ls_remote — those genuinely need
# the https transport; protocol.allow=never would break every one of
# them. Their network argv use safe_git_command (per-protocol pins)
# plus the sandbox egress proxy as the network control; fetch_commit's
# LOCAL steps (init, remote add/set-url) never touch a transport and
# do use the strict variant.
#
# The clean/smudge KNOWN LIMIT above applies unchanged to the strict
# variant: filter drivers have repo-chosen names, so no finite `-c`
# list neutralises them. protocol.allow=never does NOT protect
# worktree-rehashing operations — strict callers must still stick to
# plumbing that never re-hashes worktree files (`rev-parse`,
# `rev-list`, `log`, `diff-index` without a refresh, `ls-files`).
_STRICT_READONLY_EXTRA_OVERRIDES = (
    "-c", "protocol.allow=never",
    "-c", "protocol.file.allow=never",
    "-c", "core.sshCommand=false",
)

# Full strict tuple — single source of truth for consumers that build
# their own argv (core.audit.git_oracle) and for tests that pin the
# hardening posture without duplicating literals.
_SAFE_GIT_READONLY_OVERRIDES = (
    *_SAFE_GIT_OVERRIDES,
    *_STRICT_READONLY_EXTRA_OVERRIDES,
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


def safe_git_readonly_command(*args: str) -> list:
    """Return a git argv list with the STRICT read-only safety overrides.

    Use for git commands that READ a target repository (cloned from an
    untrusted source) and never need a remote: ``log``, ``rev-parse``,
    ``rev-list``, ``diff-index``, ``ls-files``, local ``checkout`` /
    ``init`` / ``remote add`` steps, etc. On top of the
    :func:`safe_git_command` posture this refuses every transport
    (``protocol.allow=never``, with the per-protocol ``file`` pin
    re-closed — see :data:`_STRICT_READONLY_EXTRA_OVERRIDES`) and pins
    ``core.sshCommand=false``.

    Do NOT use for network operations (the clone / fetch / ls-remote
    argv inside :func:`clone_repository` / :func:`fetch_commit` /
    :func:`ls_remote`) — those need the https transport and would fail
    outright under ``protocol.allow=never``. They use
    :func:`safe_git_command`; their network control is the sandbox
    egress proxy, not this tuple.

    ``--no-pager`` is included as belt-and-braces with the
    ``core.pager=cat`` pin (it disables paging even for subcommands
    that consult a different pager config key).

    KNOWN LIMIT (same as :data:`_SAFE_GIT_OVERRIDES`): clean/smudge
    filter drivers cannot be blanket-neutralised — stick to plumbing
    that never re-hashes worktree content.

    Example::

        subprocess.run(
            safe_git_readonly_command("-C", str(repo), "rev-parse", "HEAD"),
            env=get_safe_git_env(), ...
        )
    """
    return ["git", "--no-pager", *_SAFE_GIT_READONLY_OVERRIDES, *args]


def signature_probe_overrides() -> list:
    """Extra ``-c`` pairs for the few call sites that deliberately verify
    commit signatures (``git log`` with ``%G?`` formats).

    ``_SAFE_GIT_OVERRIDES`` pins every ``gpg.*.program`` to ``true`` so an
    ordinary target-repo git op never executes a repo-configured verifier.
    These pairs re-enable verification through the SYSTEM binaries
    (resolved on PATH at call time) — later ``-c`` occurrences win, so
    appending them after the safe overrides restores real verification
    without ever honouring a program named by the target's own config::

        cmd = safe_git_command(*signature_probe_overrides(), "log", ...)

    A verifier that isn't installed keeps its neutral pin; the caller then
    sees unverifiable signature statuses rather than an error, which is
    the honest degradation (signature status "unknown", never fabricated).
    """
    pairs: list = []
    for key, prog in (
        ("gpg.program", "gpg"),
        ("gpg.x509.program", "gpgsm"),
        ("gpg.ssh.program", "ssh-keygen"),
    ):
        path = shutil.which(prog)
        if path:
            pairs += ["-c", f"{key}={path}"]
    return pairs


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
        is still ``/``;
      - paths under system pseudo-fs prefixes (``/dev/``, ``/proc/``,
        ``/sys/``, ``/run/``) — see the denylist commentary below.
    """
    if not p.is_absolute():
        msg = (
            f"{role} must be an absolute path; got {str(p)!r}. Relative "
            f"paths are unsafe here — the sandbox writable scope "
            f"({role}.parent) would be cwd-dependent."
        )
        raise ValueError(msg)
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
            msg = (
                f"{role}={str(p)!r} is under a system pseudo-fs prefix "
                f"({prefix}); refusing to grant the sandbox write "
                f"access. Use /tmp, /var/tmp, $HOME, or a dedicated "
                f"workspace path instead."
            )
            raise ValueError(msg)
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
            msg = (
                f"{role}={str(p)!r} {label}-form is the filesystem "
                f"root; refusing to grant the sandbox write access "
                f"to the entire filesystem"
            )
            raise ValueError(msg)
        if candidate.parent == Path(candidate.anchor):
            msg = (
                f"{role}={str(p)!r} {label}-form has filesystem root "
                f"as its parent. Sandbox writable scope "
                f"({role}.parent) would be the entire root filesystem."
            )
            raise ValueError(msg)


def clone_repository(
    url: str, target: Path, depth: int | None = 1,
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
        # Security-event stream (restored from the pre-restructure
        # core/git.py emitter, commit c1af3314): record the rejection
        # in the audit trail. Observability only — the ValueError
        # below is the behaviour; the emitter never raises. URL is
        # redacted first: rejected URLs are exactly the ones that may
        # carry userinfo credentials.
        _log_security_event(
            "invalid_repo_url",
            "Rejected potentially unsafe repository URL: "
            f"{redact_url_secrets_only(url)}",
            operation="clone_repository",
        )
        msg = f"Invalid or untrusted repository URL: {url}"
        raise ValueError(msg)
    _validate_writable_path(target, role="target")

    # Per-invocation config pins (see _SAFE_GIT_OVERRIDES): the clone
    # transport is https, which every pin is compatible with, and the
    # pins also govern the post-transfer checkout of the untrusted tree.
    cmd = safe_git_command("clone")
    if depth is not None:
        cmd.extend(["--depth", str(depth), "--no-tags"])
    cmd.extend([url, str(target)])

    # Redact any embedded credentials in the URL before logging.
    # ``validate_repo_url`` rejects userinfo upstream, but a future
    # caller path (or an upstream validator bypass) shouldn't leak
    # ``https://user:token@host/...`` into operator logs. Belt-and-
    # braces — symmetric posture with the rest of the codebase.
    logger.info("git clone: %s -> %s", redact_url_secrets_only(url), target)
    try:
        from core.sandbox import run_untrusted_networked
    except ImportError:
        msg = (
            "core.sandbox unavailable - git clone refuses to run "
            "without sandbox isolation"
        )
        raise RuntimeError(msg) from None

    target.parent.mkdir(parents=True, exist_ok=True)
    proc = run_untrusted_networked(
        cmd,
        target=str(target.parent),
        output=str(target.parent),
        env=get_safe_git_env(),
        proxy_hosts=_proxy_hosts_for_git(),
        fake_home=True,
        timeout=RaptorConfig.GIT_CLONE_TIMEOUT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()
        msg = f"git clone failed: {stderr or stdout or 'unknown error'}"
        raise RuntimeError(msg)
    # Host-side materialisation check. git's exit status reports what
    # happened INSIDE the sandbox — under the mount-ns backend the
    # child gets a private tmpfs /tmp, so if the destination isn't
    # covered by the bind tree (e.g. ``target.parent`` is /tmp itself,
    # which the per-ns tmpfs shadows and the bind step skips), git
    # writes the clone into the tmpfs, exits 0, and the tree vanishes
    # with the sandbox. Returning True there hands callers a phantom
    # clone that only fails at their next (host-side) access, far from
    # the cause. Verify on the HOST that the tree actually landed.
    if not target.is_dir():
        msg = (
            f"git clone reported success but {target} does not exist "
            f"on the host filesystem — the clone likely landed in the "
            f"sandbox's private /tmp tmpfs because the destination's "
            f"parent directory is not part of the sandbox bind tree. "
            f"Use a destination at least one level below /tmp (so its "
            f"parent is bind-mountable) or another writable workspace."
        )
        raise RuntimeError(msg)
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

    Returns ``True`` on success — the fetch completed AND
    ``FETCH_HEAD^{commit}`` resolved to an OID matching the request
    (exact equality for a full 40-hex SHA, prefix match for an
    abbreviation). Returns ``False`` when the transport succeeded but
    the fetched object does not match — an abbreviated SHA is
    remote-resolved and could be ambiguous or attacker-chosen, so a
    zero exit alone is not proof the wanted commit arrived.

    Raises:
        ValueError: URL fails the allowlist, ``repo_dir`` fails the
            writable-path check (relative, filesystem root, or direct
            child of root — see ``_validate_writable_path``), or SHA
            fails the shape check.
        RuntimeError: any of ``git init``, ``git remote``, or
            ``git fetch`` exited non-zero.
    """
    if not validate_repo_url(url):
        # Same restored emitter as clone_repository — see the comment
        # there. Redact before logging; never raises.
        _log_security_event(
            "invalid_repo_url",
            "Rejected potentially unsafe repository URL: "
            f"{redact_url_secrets_only(url)}",
            operation="fetch_commit",
        )
        msg = f"Invalid or untrusted repository URL: {url}"
        raise ValueError(msg)
    _validate_writable_path(repo_dir, role="repo_dir")
    if not _SHA_RE.fullmatch(sha):
        # Defend against ``sha = "--upload-pack=cmd"`` style flag
        # injection at the ``git fetch <repo> <refspec>`` position.
        msg = f"Invalid commit SHA shape (expected 4-40 hex chars): {sha!r}"
        raise ValueError(msg)

    try:
        from core.sandbox import run_untrusted, run_untrusted_networked
    except ImportError:
        msg = (
            "core.sandbox unavailable - git fetch refuses to run "
            "without sandbox isolation"
        )
        raise RuntimeError(msg) from None

    repo_dir.mkdir(parents=True, exist_ok=True)
    env = get_safe_git_env()
    proxy_hosts = _proxy_hosts_for_git()
    timeout = RaptorConfig.GIT_CLONE_TIMEOUT

    # ``output`` is the sandbox's writable allowlist. Use ``repo_dir.parent``
    # to match ``clone_repository``: ``fake_home=True`` materialises
    # ``{output}/.home/`` for the child's HOME. Passing ``repo_dir``
    # directly would put ``.home/`` *inside* the repo, polluting the
    # caller's working tree.
    sandbox_target = str(repo_dir.parent)

    def _run(cmd: list, *, network: bool):
        kwargs = {
            "target": sandbox_target,
            "output": sandbox_target,
            "env": env,
            "timeout": timeout,
            "capture_output": True,
            "text": True,
        }
        if network:
            return run_untrusted_networked(
                cmd, proxy_hosts=proxy_hosts, fake_home=True, **kwargs)
        return run_untrusted(cmd, **kwargs)

    is_repo = (repo_dir / ".git").exists()
    if not is_repo:
        logger.info("git init: %s", repo_dir)
        proc = _run(
            # Local step, no transport — strict read-only pins apply
            # (repo_dir may be a pre-existing clone whose .git/config
            # is untrusted).
            safe_git_readonly_command("-C", str(repo_dir), "init", "--quiet"),
            network=False,
        )
        if proc.returncode != 0:
            msg = (
                f"git init failed: "
                f"{(proc.stderr or proc.stdout or 'unknown error').strip()}"
            )
            raise RuntimeError(msg)

    # ``remote add`` is idempotent-ish — if origin already exists we
    # rewrite the URL via ``set-url`` so the caller can reuse a
    # repo_dir across distinct URLs without surprises. If both fail
    # we surface BOTH errors so the operator sees the real cause
    # (e.g. disk full) rather than only the set-url echo.
    add_proc = _run(
        # Local step, no transport — strict read-only pins apply.
        safe_git_readonly_command(
            "-C", str(repo_dir), "remote", "add", "origin", url,
        ),
        network=False,
    )
    if add_proc.returncode != 0:
        set_proc = _run(
            safe_git_readonly_command(
                "-C", str(repo_dir), "remote", "set-url", "origin", url,
            ),
            network=False,
        )
        if set_proc.returncode != 0:
            add_msg = (add_proc.stderr or add_proc.stdout or "").strip()
            set_msg = (set_proc.stderr or set_proc.stdout or "").strip()
            msg = (
                f"git remote add/set-url failed: "
                f"add={add_msg or 'unknown error'}; "
                f"set-url={set_msg or 'unknown error'}"
            )
            raise RuntimeError(msg)

    logger.info(
        "git fetch (depth=%d): %s @ %s",
        depth, redact_url_secrets_only(url), sha,
    )
    proc = _run(
        # Network step — base pins only (the strict variant's
        # protocol.allow=never would refuse the https transport).
        safe_git_command(
            "-C", str(repo_dir), "fetch",
            "--depth", str(depth), "--no-tags",
            "origin", sha,
        ),
        network=True,
    )
    if proc.returncode != 0:
        msg = (
            f"git fetch failed: "
            f"{(proc.stderr or proc.stdout or 'unknown error').strip()}"
        )
        raise RuntimeError(msg)

    # Verify WHAT the remote actually sent. A zero exit only proves
    # the transport succeeded — the remote controls the object behind
    # any abbreviated name, and even for a full SHA a hostile or
    # confused remote could satisfy the want differently. Resolve
    # FETCH_HEAD to a commit OID (local plumbing — strict read-only
    # pins) and require it to match the request: exact equality for a
    # full 40-hex SHA, prefix match for an abbreviation. Anything
    # else is a failed fetch, not a success.
    verify = _run(
        safe_git_readonly_command(
            "-C", str(repo_dir), "rev-parse", "--verify",
            "FETCH_HEAD^{commit}",
        ),
        network=False,
    )
    if verify.returncode != 0:
        logger.warning(
            "git fetch reported success but FETCH_HEAD does not "
            "resolve to a commit: %s",
            (verify.stderr or verify.stdout or "unknown error").strip(),
        )
        return False
    resolved = (verify.stdout or "").strip().lower()
    if not _LS_REMOTE_SHA_RE.fullmatch(resolved):
        logger.warning(
            "git fetch verification: unexpected rev-parse output %r",
            resolved[:80],
        )
        return False
    requested = sha.lower()
    matches = (
        resolved == requested
        if len(requested) == 40
        else resolved.startswith(requested)
    )
    if not matches:
        logger.warning(
            "git fetch verification: requested %s but FETCH_HEAD "
            "resolved to %s — refusing the fetched object",
            sha, resolved,
        )
        return False
    return True


def ls_remote(
    url: str,
    *,
    proxy_hosts: Iterable[str],
    timeout: int = 20,
    patterns: Iterable[str] | None = None,
    bearer_token: str | None = None,
) -> list[tuple[str, str]]:
    """Run ``git ls-remote --heads --tags`` against ``url``.

    Read-only operation that returns the refs the remote advertises.
    Sandbox-routed via ``run_untrusted_networked`` with the egress proxy pinned
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
        patterns: optional ref patterns appended after an ``--``
            end-of-options separator, so the remote only advertises
            matching refs (``git ls-remote <url> <pattern>...``).
            Each pattern must be non-empty and must not start with
            ``-`` (would otherwise be parseable as a git option —
            same argument-position defence as ``fetch_commit``'s
            SHA shape check).
        bearer_token: optional bearer credential for the forge
            (private repos / rate-limit relief). Injected via the
            ``GIT_CONFIG_COUNT``/``GIT_CONFIG_KEY_0``/
            ``GIT_CONFIG_VALUE_0`` environment mechanism as an
            ``http.extraheader`` — NEVER placed on argv (argv is
            world-readable via /proc/<pid>/cmdline) and never
            logged.

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
        msg = "ls_remote requires non-empty proxy_hosts"
        raise ValueError(msg)

    pattern_list = list(patterns) if patterns is not None else []
    for pat in pattern_list:
        if not pat or pat.startswith("-"):
            msg = (
                f"ls_remote: invalid ref pattern {pat!r} (empty or "
                f"leading dash — could be parsed as a git option)"
            )
            raise ValueError(msg)

    # ``urlparse`` is more honest than a regex for the "is this a
    # safe URL shape" check — handles userinfo, fragments, ports
    # cleanly. ValueError surfaces on URLs containing null bytes /
    # invalid IPv6 / etc.; rare but worth surfacing as a ValueError
    # so callers don't see a stdlib internal type.
    try:
        parsed = urlparse(url)
    except ValueError as e:
        msg = f"ls_remote: malformed URL: {e}"
        raise ValueError(msg) from None

    # ``https`` only — the in-process egress proxy is HTTPS-CONNECT
    # exclusively, so plain ``http://`` would pass this check but
    # fail at the proxy with a confusing transport error. Refuse
    # upfront for a clearer contract.
    if parsed.scheme != "https":
        msg = f"ls_remote requires https URL; got scheme={parsed.scheme!r}"
        raise ValueError(msg)
    if parsed.username is not None or parsed.password is not None:
        msg = "ls_remote refuses URLs with userinfo (credentials in URL)"
        raise ValueError(msg)
    if not parsed.hostname:
        msg = f"ls_remote: URL has no hostname: {url!r}"
        raise ValueError(msg)

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
        msg = f"ls_remote: URL host {host!r} not in proxy_hosts allowlist"
        raise ValueError(msg)

    try:
        from core.sandbox import run_untrusted_networked
    except ImportError:
        msg = (
            "core.sandbox unavailable - git ls-remote refuses to run "
            "without sandbox isolation"
        )
        raise RuntimeError(msg) from None

    # ``ls-remote`` doesn't write to the host filesystem, but
    # ``run_untrusted_networked`` requires a non-empty ``output`` so
    # Landlock engages and ``fake_home`` has somewhere to materialise.
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
        # ``--`` ends option parsing so neither the URL nor any ref
        # pattern can ever be interpreted as a git option.
        cmd = safe_git_command(
            "ls-remote", "--heads", "--tags", "--", url, *pattern_list,
        )
        env = get_safe_git_env()
        if bearer_token:
            # Credential rides the GIT_CONFIG_* env mechanism (git
            # ≥2.31), NOT argv: /proc/<pid>/cmdline is readable by
            # every same-uid process, env is not. Equivalent to
            # ``-c http.extraheader=...`` in precedence terms except
            # explicit ``-c`` options would win — safe_git_command
            # sets no http.extraheader, so this value applies. The
            # env dict is never logged.
            env.update({
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "http.extraheader",
                "GIT_CONFIG_VALUE_0":
                    f"Authorization: bearer {bearer_token}",
            })
        proc = run_untrusted_networked(
            cmd,
            target=td,
            output=td,
            env=env,
            proxy_hosts=proxy_host_list,
            fake_home=True,
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
        msg = f"git ls-remote failed: {stderr or stdout or 'unknown error'}"
        raise RuntimeError(msg)

    refs: list[tuple[str, str]] = []
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


__all__ = [
    "clone_repository",
    "fetch_commit",
    "get_safe_git_env",
    "ls_remote",
    "safe_git_command",
    "safe_git_readonly_command",
    "signature_probe_overrides",
]
