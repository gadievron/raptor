"""
core/security/_trust_common.py

Shared helper layer for the target-repo trust gates:

    core/security/cc_trust.py      (Claude Code config check)
    core/security/codeql_trust.py  (CodeQL pack/config check)

Same consolidation as :mod:`core.security.capped_read`, which owns the
hardened open/read both gates delegate to: each gate previously carried
a private, hand-synced copy of this layer — output sanitisation
(``_safe`` / ``_truncate`` / ``_mask``), the ``Finding`` / ``FileScan``
result shapes, the scan-report renderer, and the fail-closed
resolve-and-stat gate on supplied targets. One home ends the hand-sync;
the gates keep their genuinely different domain walks (settings/MCP
JSON vs pack/config YAML) in their own modules.

Both gates are FAIL-CLOSED by design: a target the checker cannot
resolve, stat, read, or parse is refused, never waved through, and the
operator's ``--trust-repo`` override downgrades a refusal to
warn-and-proceed — it never silences it. Nothing in this module may
weaken that posture.

Everything rendered here can carry attacker-chosen bytes (paths, config
values, exception text from hostile filesystems), so every rendered
string rides through :func:`safe_text`, values that can embed
credentials ride through :func:`mask`, and lengths are bounded by
:func:`truncate`.
"""

from __future__ import annotations

import os
import stat
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from core.security.capped_read import read_capped, read_capped_with_stat

# RAPTOR repo root = core/security/_trust_common.py -> ../../
# Both gates skip scanning RAPTOR's own repo (operator running RAPTOR
# against itself is implicitly trusted).
RAPTOR_DIR = Path(__file__).resolve().parents[2]

# One cap for every trust-gate config read. Real config/pack files are
# tiny (<10 KiB); the cap bounds the JSON/YAML parsers' memory exposure
# and anything over it is refused as oversized/unreadable — a BLOCKING
# finding, so a smaller cap can only move a file toward refusal, never
# wave it through. Both directions matter when touching this value:
# raising it widens parser exposure on attacker-supplied bytes;
# lowering it starts refusing larger legitimate configs (operators
# override per run via --trust-repo, so refusal is recoverable).
MAX_TRUST_CONFIG_BYTES = 1_000_000


def read_trust_config(path: Path) -> bytes | None:
    """Read up to ``MAX_TRUST_CONFIG_BYTES``; delegates the hardened
    open/read (O_NOFOLLOW, non-regular refusal, cap) to
    :func:`core.security.capped_read.read_capped`. None = refuse
    (fail-closed: callers treat an unreadable candidate as a blocking
    finding, never as absent)."""
    return read_capped(path, MAX_TRUST_CONFIG_BYTES)


# ---------------------------------------------------------------------------
# Self-recognition: registered worktrees of RAPTOR's own repo
# ---------------------------------------------------------------------------

# A git link file (a registry ``gitdir`` file or a worktree's ``.git``
# file) is a single path line; PATH_MAX is 4096 on Linux, so 8 KiB
# comfortably bounds every legitimate shape. Anything over the cap is
# treated as malformed → not self → the caller's normal scan runs.
GIT_LINK_MAX_BYTES = 8192


def read_git_link(path: Path) -> str | None:
    """Read a single-line git link file, bounded and fail-closed.

    Returns the stripped one-line payload, or None on ANY problem:
    unreadable, non-regular, symlink (O_NOFOLLOW via the shared capped
    read), oversized, empty, or multi-line.
    """
    return read_git_link_with_stat(path)[0]


def read_git_link_with_stat(
    path: Path,
) -> tuple[str, os.stat_result] | tuple[None, None]:
    """:func:`read_git_link` plus the fstat of the fd the payload was
    read from.

    For link files whose trust decision keys on stat fields (type,
    ownership): the returned stat describes the very inode the bytes
    came from, so type, ownership, and content are one atomic
    observation — a separate path-level lstat would leave a swap
    window between the stat and the read. ``(None, None)`` on ANY
    problem, same refusal set as :func:`read_git_link`.
    """
    raw, st = read_capped_with_stat(path, MAX_TRUST_CONFIG_BYTES)
    if raw is None or st is None or len(raw) > GIT_LINK_MAX_BYTES:
        return None, None
    text = os.fsdecode(raw).strip()
    if not text or any(c in text for c in ("\n", "\r", "\x00")):
        return None, None
    return text, st


def is_registered_worktree_of_self(target: Path, raptor_dir: Path) -> bool:
    """True iff ``target`` (already resolved) is a git worktree of
    RAPTOR's own repo, proven by BOTH sides of the worktree link.

    ``raptor_dir`` is supplied by each gate (its module-level
    ``_RAPTOR_DIR``, normally this module's :data:`RAPTOR_DIR`) rather
    than read here, so each gate keeps its own monkeypatch seam and no
    hidden global couples the gates' tests.

    INVARIANT — candidates come ONLY from trusted-side data: worktree
    roots are enumerated from ``raptor_dir/.git/worktrees/<name>/
    gitdir`` registry files (RAPTOR's own git metadata, written by the
    operator's ``git worktree add``) via direct file reads — no
    subprocess, no ``git`` binary, so the gates stay dependency-free
    and fast. Target-side content NEVER nominates a candidate: a
    hostile repo shipping a forged ``.git`` file that points at
    RAPTOR's gitdir gains nothing unless RAPTOR's own registry
    independently lists that exact path. The target's ``.git`` is read
    only AFTER a registry match, purely as the back-link confirmation
    — both sides must agree on the exact registry entry that nominated
    the match.

    INVARIANT — registrant uid equality, three ways: the nominating
    registry entry directory (``worktrees/<name>`` itself, trusted-side
    — an attacker who can re-own it can write the registry and needs
    none of this) anchors the registrant's uid; the directory at the
    registered path AND the target's ``.git`` back-link file must both
    carry that exact uid. A stale registry entry whose worktree was
    deleted (``rm -rf`` without a prune — and ``git worktree prune``
    cannot help: it only stats the path named in ``gitdir``, so a
    re-plant satisfies it) would otherwise trust hostile content
    planted at the vacated path by ANY local uid — under a sticky
    world-writable parent (/tmp, /var/tmp) the vacated name is free
    for everyone. A non-root attacker cannot choose the ``st_uid`` of
    anything they create (chown needs CAP_CHOWN; FUSE uid forgery
    needs the non-default ``user_allow_other``, without which every
    non-mounter access fails EACCES → fail-closed), so foreign
    ownership on either object is proof the object is not the
    registered worktree, whatever its contents claim. The anchor is
    deliberately the entry DIRECTORY, not the ``worktrees/<name>/
    gitdir`` file: ``git worktree move``/``repair`` rewrite that file
    (in place on some git versions, via lockfile-rename — re-owning it
    — on others), while no rewrite path touches the entry directory,
    so the anchor survives cross-uid repairs under either semantics.
    The back-link's type and ownership bind to the fstat of the very
    fd the capped read returned bytes from — one atomic observation of
    one inode, no lstat-then-open swap window.

    Fail closed everywhere: any OSError, unreadable/oversized/
    malformed file, symlinked ``.git`` (lstat first, never followed),
    a symlink at the registered root itself, a symlink at the registry
    entry (not a nomination), a uid mismatch on any of the three
    objects, or missing piece → False → the caller's normal scan runs.
    No exception escapes.
    """
    try:
        worktrees_dir = raptor_dir / ".git" / "worktrees"
        # RAPTOR itself checked out as a linked worktree: its ``.git``
        # is a FILE, so there is no registry to enumerate here — no
        # candidates, fail closed.
        if not worktrees_dir.is_dir():
            return False
        for entry in sorted(worktrees_dir.iterdir()):
            payload = read_git_link(entry / "gitdir")
            if payload is None:
                continue
            # Registry payload = path of the worktree's ``.git`` entry
            # (one absolute path line); the worktree root is its
            # parent.
            wt_git = Path(payload)
            if not wt_git.is_absolute():
                continue
            # Registrant anchor: the nominating registry entry
            # directory's owner. lstat (never follow) — a symlinked
            # registry entry is not a nomination. Trusted-side data:
            # the assumed attacker cannot write inside raptor_dir/
            # .git, so there is no TOCTOU of interest between this
            # lstat and the capped read above. ``git worktree add``
            # creates this directory, the worktree root, and the
            # ``.git`` back-link in one operation under one uid, so
            # every single-principal add (including sudo adds and
            # second-operator adds) satisfies the equality below by
            # construction.
            try:
                st_entry = os.lstat(entry)
            except OSError:
                continue
            if not stat.S_ISDIR(st_entry.st_mode):
                continue
            anchor_uid = st_entry.st_uid
            # The registered root must be a real DIRECTORY before any
            # resolve: a symlink at a registered path re-aims trust at
            # a path the registry never named (resolve() would follow
            # it, equating the link's target with the registered root,
            # and a forged back-link in that target would complete the
            # bidirectional check). os.lstat never follows — a symlink
            # (or anything else non-directory) is not a candidate.
            # ``git worktree add`` always creates a real directory, so
            # no legitimate shape is refused.
            try:
                st_root = os.lstat(wt_git.parent)
            except OSError:
                continue
            if not stat.S_ISDIR(st_root.st_mode):
                continue
            # The root at the registered path must be owned by the
            # registrant. A re-plant in a sticky world-writable parent
            # is necessarily owned by its creator (chown needs
            # CAP_CHOWN), so a foreign-uid root is not the registered
            # worktree, whatever its contents claim.
            if st_root.st_uid != anchor_uid:
                continue
            try:
                root = wt_git.parent.resolve()
            except (OSError, RuntimeError):
                continue
            if root != target:
                continue
            # Bidirectional link check. The target's own ``.git`` must
            # be a regular FILE — os.lstat first (never followed): a
            # symlink, or a real ``.git`` DIRECTORY squatting the
            # registered path (an ordinary clone), is not self. This
            # lstat is a cheap early reject only — it carries no
            # trust; type and ownership are re-taken below from the
            # fstat of the read fd.
            dotgit = target / ".git"
            try:
                st = os.lstat(dotgit)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            # Type + ownership bound to the READ fd: S_ISREG and
            # st_uid come from the fstat of the very inode the bytes
            # came from (the capped read opens with O_NOFOLLOW and
            # fstats the open fd), so type, ownership, and content are
            # one atomic observation — an lstat-then-open pair would
            # leave a swap window between the stat and the read. The
            # ownership check closes the composite where a
            # registrant-owned directory is renamed into the vacated
            # path and the attacker authors the back-link inside it:
            # a forged back-link file is attacker-owned, and a real
            # worktree's back-link names its OWN registry entry, not
            # the nominating one.
            back, st_git = read_git_link_with_stat(dotgit)
            if back is None or st_git is None:
                continue
            if not stat.S_ISREG(st_git.st_mode):
                continue
            if st_git.st_uid != anchor_uid:
                continue
            if not back.startswith("gitdir:"):
                continue
            back_path = Path(back[len("gitdir:"):].strip())
            if not back_path.is_absolute():
                # git can write the back-link relative to the worktree
                # root (relative-path worktrees).
                back_path = target / back_path
            try:
                if back_path.resolve() == entry.resolve():
                    return True
            except (OSError, RuntimeError):
                continue
        return False
    except Exception:
        # Fail closed: recognition is best-effort — anything
        # surprising means "not self" and the caller's normal scan
        # runs.
        return False


# U+2028/U+2029 line-separators — Zl/Zp categories slip past the Cc/Cf
# strip below but terminals render them as newlines, which could split
# gate output. Escaped spellings deliberately: the literal characters
# are invisible in an editor, so a reviewer cannot tell the set from a
# pair of ordinary quoted blanks — and an accidental "cleanup" to real
# spaces would silently disable the defence while corrupting every
# space in sanitised output.
EXTRA_STRIP = frozenset({"\u2028", "\u2029"})


def safe_text(s: str) -> str:
    """Strip Unicode control/format chars and line/paragraph separators.
    Defends against ANSI escapes, Trojan Source bidi (CVE-2021-42574),
    zero-width chars, and line-separator-driven output splitting."""
    return "".join(
        c if c == "\t" or (
            c not in EXTRA_STRIP
            and unicodedata.category(c) not in ("Cc", "Cf")
        ) else "?"
        for c in s
    )


def truncate(s: str, limit: int = 80) -> str:
    """Sanitise via :func:`safe_text`, then bound to ``limit`` chars
    with an explicit ellipsis marker."""
    safe = safe_text(s)
    return safe[:limit] + "..." if len(safe) > limit else safe


def mask(s: str, keep: int = 8) -> str:
    """Render a secret-bearing config value without echoing it.

    Scan output lands on stdout and from there in retained CI logs, so
    credential-helper commands, env values, MCP/extractor/build-hook
    command lines must not be printed verbatim — a leaked config file
    would otherwise republish its secrets into every build log. Keep a
    short prefix (enough to identify the binary/helper for triage),
    redact the tail, and show the length so distinct values remain
    distinguishable. ``keep=0`` fully redacts — used for env values,
    where the value IS the secret and even a prefix is a partial leak.
    """
    safe = safe_text(s)
    if not safe:
        return "(empty)"
    # A prefix of a value no longer than ``keep`` IS the value —
    # fully redact rather than echo it whole.
    prefix = safe[:keep] if 0 < keep < len(safe) else ""
    return f"{prefix}*** ({len(safe)} chars)"


@dataclass
class Finding:
    """One labelled row in the per-file findings table."""
    label: str          # e.g. "apiKeyHelper", "extractor", "env LD_PRELOAD"
    value: str          # rendered (sanitised/masked) value for the row
    blocking: bool      # True = blocks dispatch; False = info only


@dataclass
class FileScan:
    """Findings for one inspected file."""
    path: Path
    findings: list[Finding] = field(default_factory=list)

    def has_blocking(self) -> bool:
        return any(f.blocking for f in self.findings)


def resolve_supplied_target(
    repo_path: str,
    trust_override: bool,
    subject: str,
) -> tuple[str | None, bool]:
    """Resolve and stat a supplied target path, failing closed.

    A SUPPLIED target the checker cannot resolve or stat is refused,
    not waved through: these lanes previously returned "clean", but
    that verdict had examined nothing — a vanished (TOCTOU), mistyped,
    or pathological path skipped the gate entirely while the caller
    went on to use the same spelling. The trust override downgrades to
    warn-and-proceed exactly like a real finding, so the launcher's
    "Override: --trust-repo" hint stays truthful.

    Returns ``(resolved, refuse)``. When ``resolved`` is a path string
    the caller proceeds to its scan (``refuse`` is False). When
    ``resolved`` is None the path could not be examined and ``refuse``
    is the gate verdict: True unless the trust override was active.

    ``subject`` names what the gate inspects for the operator-facing
    message (e.g. ``"Claude Code config"`` / ``"CodeQL pack config"``).
    """
    try:
        resolved = str(Path(repo_path).resolve())
        os.stat(resolved)
    except (ValueError, OSError) as e:
        reason = getattr(e, "strerror", None) or type(e).__name__
        shown = truncate(safe_text(repo_path), limit=200)
        if trust_override:
            print(f"raptor: cannot examine {shown} for {subject} "
                  f"({safe_text(str(reason))}) — proceeding "
                  f"(trust override active)")
            return None, False
        # Caller-neutral phrasing: some call sites use the return only
        # as an early warning and enforce at later re-check sites.
        print(f"raptor: cannot examine {shown} for {subject} "
              f"({safe_text(str(reason))}) — treating as dangerous")
        return None, True
    return resolved, False


def render_scan_report(
    target: Path,
    scans: Sequence[FileScan],
    any_blocking: bool,
    trust_override: bool,
    subject: str,
) -> None:
    """Pure rendering — separated from the gates' scan functions so a
    cache (or any scan-once path) doesn't suppress the operator-visible
    warning on re-invocation, and the scans stay side-effect free.

    ``subject`` names what was scanned (e.g. ``"Claude Code config"`` /
    ``"CodeQL pack config"``).
    """
    safe_target = safe_text(str(target))
    if any_blocking:
        if trust_override:
            print(f"raptor: {safe_target} has dangerous {subject} "
                  f"(trust override active):")
        else:
            print(f"raptor: {safe_target} has dangerous {subject}:")
    else:
        print(f"raptor: {safe_target} has {subject}:")

    for fs in scans:
        try:
            rel = fs.path.relative_to(target)
        except ValueError:
            rel = fs.path
        print(f"  {safe_text(str(rel))}")
        if not fs.findings:
            continue
        label_w = max(len(f.label) for f in fs.findings) + 2
        for f in fs.findings:
            print(f"    {f.label:<{label_w}}{f.value}")
