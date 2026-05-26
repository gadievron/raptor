"""Hash-pin support — convert mutable git refs to commit SHAs.

Implements the design's ``raptor-sca fix --hash-pin`` feature for the
GitHub Actions workflow case (the primary Trivy-attack-class target).
Operators with non-GHA git refs (npm ``git+https://``, Cargo git,
Composer git) currently get a warning; those handlers can drop in here.

Auth strategy: use ``git ls-remote <repo> <ref>`` rather than the
GitHub REST API. ``ls-remote`` works against public repos without any
token, side-stepping the design's noted 60 req/hour unauthenticated
rate limit. When a token IS available (``GITHUB_TOKEN`` env), we do
inject it into the URL — useful for private repos and gives a
modest speedup on large monorepos.

The rewriter is line-based, idempotent (already-SHA refs are skipped),
and preserves the original ref as a trailing comment so operators can
audit + roll back.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ``uses: org/action@<ref>`` — captures the ref so we can decide whether
# to resolve it. Sub-action paths (``org/action/sub@<ref>``) are
# supported.
#
# ``prefix`` captures the FULL line lead so the rewrite preserves
# YAML indentation:
#   * ``[ \t]*`` — every leading space / tab on the line
#   * ``(?:-[ \t]+)?`` — optional ``- `` for list-item-on-its-own-line
#     form (``- uses: ...`` vs ``        uses: ...``)
#   * ``uses:[ \t]*`` — the key + trailing whitespace
#
# Pre-fix the prefix only captured ``(?:^|\s)uses:\s*`` which loses
# all but one char of leading indent; the rewrite replaced the
# whole line with just that one char + the new content, breaking
# YAML by collapsing 8-space indentation to 1.
_USES_RE = re.compile(
    r"""^(?P<prefix>[ \t]*(?:-[ \t]+)?uses:[ \t]*)
        (?P<owner>[A-Za-z0-9_.\-]+)/
        (?P<repo>[A-Za-z0-9_.\-]+)
        (?P<sub>(?:/[A-Za-z0-9_./\-]+)?)
        @(?P<ref>[A-Za-z0-9_./\-]+)
        (?P<trailing>[ \t]*(?:\#.*)?)?$
    """,
    re.MULTILINE | re.VERBOSE,
)

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


@dataclass
class HashPinChange:
    file: Path
    line: int
    action: str                         # ``org/action`` (with subpath if any)
    old_ref: str
    new_sha: str


@dataclass
class HashPinResult:
    changed_files: List[Path]
    changes: List[HashPinChange]
    skipped: List[Tuple[Path, int, str, str]]   # (file, line, action, reason)


def hash_pin_workflows(
    target: Path,
    *,
    workflows_dir: Optional[Path] = None,
    github_token: Optional[str] = None,
    write: bool = False,
) -> HashPinResult:
    """Walk ``.github/workflows/*.yml`` and rewrite mutable refs to
    commit SHAs.

    When ``write=False`` (default) the function only computes the
    rewrite plan; the original files are not modified. When ``True``,
    rewritten files are written in-place. Callers wanting a patch
    instead can run with ``write=False`` and diff the originals.
    """
    workflows = workflows_dir or (target / ".github" / "workflows")
    if not workflows.exists():
        return HashPinResult([], [], [])

    token = github_token or os.environ.get("GITHUB_TOKEN")
    cache: Dict[Tuple[str, str], Optional[str]] = {}

    changes: List[HashPinChange] = []
    skipped: List[Tuple[Path, int, str, str]] = []
    changed_files: List[Path] = []

    for wf_path in sorted(workflows.glob("*.y*ml")):
        try:
            text = wf_path.read_text(encoding="utf-8")
        except OSError as e:
            logger.warning("sca.hash_pin: cannot read %s: %s", wf_path, e)
            continue
        new_text, file_changes, file_skipped = _rewrite_file(
            text, wf_path, cache, token,
        )
        changes.extend(file_changes)
        skipped.extend(file_skipped)
        if file_changes:
            changed_files.append(wf_path)
            if write:
                from ._atomic import atomic_write_text
                try:
                    atomic_write_text(wf_path, new_text)
                except OSError as e:
                    logger.warning("sca.hash_pin: cannot write %s: %s",
                                    wf_path, e)
    return HashPinResult(changed_files, changes, skipped)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _rewrite_file(
    text: str, path: Path, cache: dict, token: Optional[str],
) -> Tuple[str, List[HashPinChange], List[Tuple[Path, int, str, str]]]:
    changes: List[HashPinChange] = []
    skipped: List[Tuple[Path, int, str, str]] = []
    lines = text.splitlines(keepends=True)
    out_lines: List[str] = []
    for idx, raw in enumerate(lines):
        m = _USES_RE.search(raw)
        if not m:
            out_lines.append(raw)
            continue
        owner = m.group("owner")
        repo = m.group("repo")
        sub = m.group("sub") or ""
        ref = m.group("ref")
        action = f"{owner}/{repo}{sub}"
        # Local actions (./ ) skip; SHA refs already pinned.
        if owner.startswith("."):
            out_lines.append(raw)
            continue
        if _SHA_RE.match(ref):
            out_lines.append(raw)
            continue
        sha = _resolve_sha(owner, repo, ref, cache, token)
        if sha is None:
            skipped.append((path, idx + 1, action,
                             "could not resolve ref via git ls-remote"))
            out_lines.append(raw)
            continue
        # Replace ``@<ref>`` with ``@<sha>``; keep the original ref as a
        # trailing comment so operators can audit + roll back.
        replacement = (
            f"{m.group('prefix')}{owner}/{repo}{sub}@{sha}  "
            f"# was {ref}"
        )
        # Preserve any original trailing newline.
        suffix = "\n" if raw.endswith("\n") else ""
        new_line = replacement + suffix
        out_lines.append(new_line)
        changes.append(HashPinChange(
            file=path, line=idx + 1,
            action=action, old_ref=ref, new_sha=sha,
        ))
    return "".join(out_lines), changes, skipped


def _resolve_sha(
    owner: str, repo: str, ref: str, cache: dict,
    token: Optional[str],
) -> Optional[str]:
    """Use ``git ls-remote`` to resolve a tag/branch/ref to a SHA."""
    key = (f"{owner}/{repo}", ref)
    if key in cache:
        return cache[key]
    url = f"https://github.com/{owner}/{repo}.git"
    # Pass token via -c http.extraheader rather than embedding in the
    # URL. The token still appears in our own /proc/<pid>/cmdline (so
    # same-uid processes can read it), but it no longer appears inside
    # the URL — keeping it out of git's URL-rewriting code paths and
    # its on-disk credential cache. For full token isolation, callers
    # should set the GIT_HTTP_EXTRAHEADER env var or use GIT_ASKPASS.
    cmd = ["git"]
    if token:
        cmd += ["-c", f"http.extraheader=Authorization: bearer {token}"]
    cmd += ["ls-remote", url, ref,
            f"refs/tags/{ref}", f"refs/heads/{ref}"]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=20,
        )
    except (subprocess.SubprocessError, OSError) as e:
        logger.warning("sca.hash_pin: git ls-remote failed for %s/%s@%s: %s",
                        owner, repo, ref, e)
        cache[key] = None
        return None
    if proc.returncode != 0:
        cache[key] = None
        return None
    # Output: ``<sha>\t<refname>\n``. Prefer the annotated-tag commit
    # (``^{}`` suffix) when present — that's the actual commit, not the
    # tag-object SHA.
    sha = _pick_sha(proc.stdout)
    cache[key] = sha
    return sha


def _pick_sha(stdout: str) -> Optional[str]:
    """Pick the right SHA from git ls-remote output.

    Prefers the dereferenced-tag entry (``<sha>\\trefs/tags/<tag>^{}``)
    over the annotated-tag entry (``<sha>\\trefs/tags/<tag>``) so we
    record the commit SHA, not the tag-object SHA.
    """
    annotated_lines = []
    plain_lines = []
    for line in stdout.splitlines():
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        sha, refname = parts[0].strip(), parts[1].strip()
        if not _SHA_RE.match(sha):
            continue
        if refname.endswith("^{}"):
            annotated_lines.append(sha)
        else:
            plain_lines.append(sha)
    if annotated_lines:
        return annotated_lines[0]
    if plain_lines:
        return plain_lines[0]
    return None


__all__ = ["HashPinChange", "HashPinResult", "hash_pin_workflows"]
