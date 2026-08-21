"""Pinned-source registry and clone bootstrap for the corpus.

``sources.json`` (next to this module) is the URL registry: repo_key
-> primary URL, mirror URLs, ref-kind hint, optional post-clone
symlinks, and human notes.  Labels never carry URLs — they pin a
``repo`` key and a ref; this registry says where that repo lives.

Clone discipline follows the repo conventions for untrusted-adjacent
subprocess work: ``safe_git_command`` argument lists (never shell
strings), ``RaptorConfig.get_safe_env()``, explicit returncode checks
on every step (no exit-code laundering through pipes), and mirror
fallback on failure with the real stderr surfaced.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

SOURCES_PATH = Path(__file__).parent / "sources.json"

# Where pinned source trees live, relative to the RAPTOR repo root
# (the corpus tools run from there).  Shared by the runner, the label
# linter, and the fetch machinery.
FIXTURES_DIR = Path("out/audit-corpus-fixtures")

# Shallow kernel clones over a proxy can be slow; generous but bounded.
CLONE_TIMEOUT_S = 1800

# stderr fragments that indicate the *network route* failed (DNS,
# proxy, TCP), as opposed to the remote answering "no such ref" —
# callers use the distinction to degrade (offline: warn) vs fail
# (upstream rewrote history / deleted the tag: lint failure).
_CONNECTIVITY_STDERR_FRAGMENTS = (
    "could not resolve host",
    "could not resolve proxy",
    "failed to connect to",
    "connection refused",
    "connection timed out",
    "network is unreachable",
    "timed out",
    "gnutls handshake",
    "proxy connect aborted",
)


def looks_like_connectivity_error(stderr: str) -> bool:
    """True when *stderr* points at a network-route failure."""
    low = stderr.lower()
    return any(f in low for f in _CONNECTIVITY_STDERR_FRAGMENTS)


class SourceFetchError(RuntimeError):
    """A pinned source could not be fetched from any registered URL.

    ``connectivity`` is True when the failure looks like a network-
    route problem (offline host, dead proxy) rather than the remote
    rejecting the ref — callers that lint pins degrade gracefully on
    the former and fail loudly on the latter.
    """

    def __init__(self, msg: str, *, connectivity: bool = False) -> None:
        super().__init__(msg)
        self.connectivity = connectivity


@dataclass(frozen=True)
class SourceEntry:
    """One registry entry from sources.json."""

    repo_key: str
    url: str
    mirror_urls: Tuple[str, ...] = ()
    ref_kind: str = "tag"
    symlinks: Dict[str, str] = field(default_factory=dict)
    notes: str = ""

    @property
    def urls(self) -> Tuple[str, ...]:
        return (self.url, *self.mirror_urls)


def load_sources(path: Optional[Path] = None) -> Dict[str, SourceEntry]:
    """Load the source registry.  Raises on a malformed registry."""
    path = path or SOURCES_PATH
    raw = json.loads(path.read_text())
    repos = raw.get("repos")
    if not isinstance(repos, dict):
        raise ValueError(f"{path}: expected a top-level 'repos' mapping")
    entries: Dict[str, SourceEntry] = {}
    for key, val in repos.items():
        if not isinstance(val, dict) or not val.get("url"):
            raise ValueError(f"{path}: repo {key!r} needs a 'url'")
        entries[key] = SourceEntry(
            repo_key=key,
            url=val["url"],
            mirror_urls=tuple(val.get("mirror_urls", [])),
            ref_kind=val.get("ref_kind", "tag"),
            symlinks=dict(val.get("symlinks", {})),
            notes=val.get("notes", ""),
        )
    return entries


def _is_hex_sha(ref: str) -> bool:
    return len(ref) >= 7 and all(c in "0123456789abcdef" for c in ref)


def _stderr_tail(result: subprocess.CompletedProcess, n: int = 3) -> str:
    err = (result.stderr or "").strip()
    return " | ".join(err.splitlines()[-n:]) if err else "(no stderr)"


def _run_git(args, *, timeout_s: int) -> subprocess.CompletedProcess:
    from core.git import get_safe_git_env, safe_git_command

    # preserve_proxy: these invocations dial the upstream remote
    # directly (clone/fetch of pinned sources) — git resolves its
    # route from HTTP(S)_PROXY, and on mandatory-egress-proxy hosts a
    # fetch has no route without it.  Same opt-in contract as the
    # dataflow walkers' targeted fetches (core.git.clone.
    # get_safe_git_env docstring).
    return subprocess.run(
        safe_git_command(*args),
        capture_output=True,
        text=True,
        timeout=timeout_s,
        env=get_safe_git_env(preserve_proxy=True),
        check=False,
    )


def _clone_at_ref(
    url: str, ref: str, dest: Path, *, timeout_s: int,
) -> Tuple[bool, str]:
    """Shallow-clone *url* at tag/branch *ref* into *dest*."""
    result = _run_git(
        [
            "clone", "--depth", "1", "--branch", ref,
            "--config", "advice.detachedHead=false",
            url, str(dest),
        ],
        timeout_s=timeout_s,
    )
    if result.returncode != 0:
        return False, _stderr_tail(result)
    return True, ""


def _clone_at_sha(
    url: str, sha: str, dest: Path, *, timeout_s: int,
) -> Tuple[bool, str]:
    """Fetch a bare hex SHA shallowly (init + fetch + checkout)."""
    steps = [
        ["init", str(dest)],
        ["-C", str(dest), "remote", "add", "origin", url],
        ["-C", str(dest), "fetch", "--depth", "1", "origin", sha],
        ["-C", str(dest), "checkout", "--detach", "FETCH_HEAD"],
    ]
    for step in steps:
        result = _run_git(step, timeout_s=timeout_s)
        if result.returncode != 0:
            return False, f"git {step[0]}: {_stderr_tail(result)}"
    return True, ""


def _apply_symlinks(entry: SourceEntry, dest: Path) -> None:
    """Create the registry's post-clone symlinks (idempotent)."""
    for link, target in entry.symlinks.items():
        link_path = dest / link
        if link_path.exists() or link_path.is_symlink():
            continue
        if ".." in Path(target).parts or Path(target).is_absolute():
            raise ValueError(
                f"sources.json symlink target {target!r} for "
                f"{entry.repo_key!r} must be repo-relative"
            )
        link_path.symlink_to(target)
        logger.info(
            "source %s: linked %s -> %s", entry.repo_key, link, target,
        )


def clone_source(
    repo_key: str,
    ref: str,
    dest: Path,
    *,
    entry: Optional[SourceEntry] = None,
    timeout_s: int = CLONE_TIMEOUT_S,
) -> Path:
    """Create a pinned shallow clone of *repo_key* at *ref* in *dest*.

    Tries the primary URL, then each mirror; a partial clone from a
    failed attempt is removed before the next.  Raises
    :class:`SourceFetchError` with the last git stderr when every URL
    fails — the caller decides whether that aborts the run.
    """
    entry = _resolve_entry(repo_key, entry)

    dest.parent.mkdir(parents=True, exist_ok=True)
    last_err = ""
    for url in entry.urls:
        print(f"  Cloning {repo_key} at {ref} from {url}...", flush=True)
        if _is_hex_sha(ref):
            ok, last_err = _clone_at_sha(url, ref, dest, timeout_s=timeout_s)
        else:
            ok, last_err = _clone_at_ref(url, ref, dest, timeout_s=timeout_s)
        if ok:
            _apply_symlinks(entry, dest)
            return dest
        shutil.rmtree(dest, ignore_errors=True)
        logger.warning(
            "clone of %s from %s failed: %s", repo_key, url, last_err,
        )

    raise SourceFetchError(
        f"could not fetch {repo_key!r} at {ref!r} from any of "
        f"{list(entry.urls)}: {last_err}",
        connectivity=looks_like_connectivity_error(last_err),
    )


def _resolve_entry(repo_key: str, entry: Optional[SourceEntry]) -> SourceEntry:
    if entry is None:
        try:
            entry = load_sources().get(repo_key)
        except FileNotFoundError:
            # No registry at all — same failure mode as an unknown key.
            entry = None
    if entry is None:
        raise SourceFetchError(
            f"no sources.json entry for repo {repo_key!r} — "
            f"add one to {SOURCES_PATH}"
        )
    return entry


def _fetch_files_from(
    url: str, ref: str, files: Sequence[str], dest: Path, *, timeout_s: int,
) -> Tuple[bool, str]:
    """Sparse, blob-filtered fetch of *files* at *ref* into *dest*."""
    # ``--filter=blob:none`` keeps the transfer to commit + tree
    # objects plus only the blobs the sparse checkout touches; servers
    # without filter support ignore it with a warning (full blobs, same
    # result). Patterns are root-anchored so ``fs/dev.c`` never matches
    # ``other/fs/dev.c``.
    if _is_hex_sha(ref):
        fetch_step = ["-C", str(dest), "fetch", "--depth", "1",
                      "--filter=blob:none", "origin", ref]
    else:
        fetch_step = ["-C", str(dest), "fetch", "--depth", "1",
                      "--filter=blob:none", "origin", "tag", ref]
    steps = [
        ["init", str(dest)],
        ["-C", str(dest), "remote", "add", "origin", url],
        ["-C", str(dest), "sparse-checkout", "set", "--no-cone", "--",
         *[f"/{f.lstrip('/')}" for f in files]],
        fetch_step,
        ["-C", str(dest), "checkout", "--detach", "FETCH_HEAD"],
    ]
    for step in steps:
        result = _run_git(step, timeout_s=timeout_s)
        if result.returncode != 0:
            return False, f"git {step[0]}: {_stderr_tail(result)}"
    return True, ""


def fetch_files(
    repo_key: str,
    ref: str,
    files: Sequence[str],
    dest: Path,
    *,
    entry: Optional[SourceEntry] = None,
    timeout_s: int = CLONE_TIMEOUT_S,
) -> Path:
    """Fetch ONLY *files* of *repo_key* at *ref* into *dest*.

    The cheap path for pin verification (CI label lint): a sparse,
    blob-filtered, depth-1 checkout containing just the labelled
    files — no full source tree.  *dest* should be keyed by repo AND
    ref (e.g. ``cache/<repo_key>@<ref>``) so different pins never
    fight over one checkout.  An existing *dest* is reused when its
    HEAD already matches *ref*; the sparse pattern set is replaced
    with *files* on reuse, so callers must pass every file they need
    in one call.  Mirror fallback and error semantics match
    :func:`clone_source`.
    """
    entry = _resolve_entry(repo_key, entry)

    if (dest / ".git").exists():
        head = _run_git(
            ["-C", str(dest), "rev-parse", "HEAD"], timeout_s=60,
        )
        current = head.stdout.strip()
        if head.returncode == 0 and current:
            matches = (
                current.startswith(ref)
                if _is_hex_sha(ref)
                else _ref_resolves_to(dest, ref, current)
            )
            if matches:
                widen = _run_git(
                    ["-C", str(dest), "sparse-checkout", "set",
                     "--no-cone", "--",
                     *[f"/{f.lstrip('/')}" for f in files]],
                    timeout_s=timeout_s,
                )
                if widen.returncode == 0:
                    _apply_symlinks(entry, dest)
                    return dest
        # Wrong ref or broken checkout — refetch from scratch.
        shutil.rmtree(dest, ignore_errors=True)

    dest.parent.mkdir(parents=True, exist_ok=True)
    last_err = ""
    for url in entry.urls:
        print(
            f"  Fetching {len(files)} file(s) of {repo_key} at {ref} "
            f"from {url}...",
            flush=True,
        )
        ok, last_err = _fetch_files_from(
            url, ref, files, dest, timeout_s=timeout_s,
        )
        if ok:
            _apply_symlinks(entry, dest)
            return dest
        shutil.rmtree(dest, ignore_errors=True)
        logger.warning(
            "file fetch of %s from %s failed: %s", repo_key, url, last_err,
        )

    raise SourceFetchError(
        f"could not fetch files of {repo_key!r} at {ref!r} from any of "
        f"{list(entry.urls)}: {last_err}",
        connectivity=looks_like_connectivity_error(last_err),
    )


def _ref_resolves_to(dest: Path, ref: str, commit: str) -> bool:
    """True when tag/branch *ref* in *dest* peels to *commit*."""
    result = _run_git(
        ["-C", str(dest), "rev-parse", f"{ref}^{{commit}}"], timeout_s=60,
    )
    return result.returncode == 0 and result.stdout.strip() == commit
