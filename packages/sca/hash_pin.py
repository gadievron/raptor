"""Hash-pin support — convert mutable git refs to commit SHAs.

Implements the design's ``raptor-sca fix --hash-pin`` feature for the
GitHub Actions workflow case (the primary Trivy-attack-class target).
Operators with non-GHA git refs (npm ``git+https://``, Cargo git,
Composer git) currently get a warning; those handlers can drop in here.

Auth strategy: use ``git ls-remote <repo> <ref>`` rather than the
GitHub REST API. ``ls-remote`` works against public repos without any
token, side-stepping the design's noted 60 req/hour unauthenticated
rate limit. When a token IS available (``GITHUB_TOKEN`` env), it is
passed via the ``GIT_CONFIG_*`` environment mechanism as an
``http.extraheader`` — useful for private repos and gives a modest
speedup on large monorepos. The token never appears on argv (argv is
readable by every same-uid process via /proc/<pid>/cmdline) and is
never logged.

Execution posture: every resolve goes through
:func:`core.git.ls_remote` — sandbox-routed (namespace + Landlock),
egress-proxied with the allowlist pinned to ``github.com``, safe-git
config pins applied. Pre-fix this module ran a raw ``subprocess.run``
with ambient proxy env (bypassing the egress allowlist) and carried
the bearer token on argv.

The rewriter is line-based, idempotent (already-SHA refs are skipped),
and preserves the original ref as a trailing comment so operators can
audit + roll back.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# Egress allowlist for the resolver's sandboxed ls-remote. GitHub
# Actions ``uses:`` refs always live on github.com — the URL below is
# constructed from that literal, so the allowlist is exactly one host.
_LS_REMOTE_PROXY_HOSTS = ("github.com",)


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
    changed_files: list[Path]
    changes: list[HashPinChange]
    skipped: list[tuple[Path, int, str, str]]   # (file, line, action, reason)


def hash_pin_workflows(
    target: Path,
    *,
    workflows_dir: Path | None = None,
    github_token: str | None = None,
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
    cache: dict[tuple[str, str], str | None] = {}

    changes: list[HashPinChange] = []
    skipped: list[tuple[Path, int, str, str]] = []
    changed_files: list[Path] = []

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
            if write:
                from ._atomic import atomic_write_text
                try:
                    atomic_write_text(wf_path, new_text)
                except OSError as e:
                    logger.warning("sca.hash_pin: cannot write %s: %s",
                                    wf_path, e)
                else:
                    changed_files.append(wf_path)
            else:
                changed_files.append(wf_path)
    return HashPinResult(changed_files, changes, skipped)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _rewrite_file(
    text: str, path: Path, cache: dict, token: str | None,
) -> tuple[str, list[HashPinChange], list[tuple[Path, int, str, str]]]:
    changes: list[HashPinChange] = []
    skipped: list[tuple[Path, int, str, str]] = []
    lines = text.splitlines(keepends=True)
    out_lines: list[str] = []
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
        trailing = (m.group('trailing') or '').strip()
        replacement = (
            f"{m.group('prefix')}{owner}/{repo}{sub}@{sha}  "
            f"# was {ref}"
        )
        if trailing:
            replacement += f"  {trailing}"
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
    token: str | None,
) -> str | None:
    """Use ``git ls-remote`` to resolve a tag/branch/ref to a SHA."""
    # A leading dash in any component could be parsed by git as an
    # option rather than a URL / ref pattern. The ``_USES_RE`` grammar
    # doesn't currently admit a leading ``-``, but validate here too so
    # this function stays safe for any future caller.
    if any(s.startswith("-") for s in (owner, repo, ref)):
        logger.warning(
            "sca.hash_pin: refusing to resolve %s/%s@%s "
            "(leading dash in component)", owner, repo, ref,
        )
        return None
    key = (f"{owner}/{repo}", ref)
    if key in cache:
        return cache[key]
    url = f"https://github.com/{owner}/{repo}.git"
    # Sandbox-routed, egress-allowlisted ls-remote via the safe-git
    # substrate (same convergence as cve_diff's agent tools). The
    # token rides the GIT_CONFIG_* env mechanism inside ls_remote —
    # never argv, never logged.
    try:
        from core.git import ls_remote
        refs = ls_remote(
            url,
            proxy_hosts=_LS_REMOTE_PROXY_HOSTS,
            timeout=20,
            patterns=(ref, f"refs/tags/{ref}", f"refs/heads/{ref}"),
            bearer_token=token,
        )
    except (RuntimeError, ValueError, OSError,
            subprocess.SubprocessError) as e:
        logger.warning("sca.hash_pin: git ls-remote failed for %s/%s@%s: %s",
                        owner, repo, ref, e)
        cache[key] = None
        return None
    # Refs: ``[(sha, refname), ...]``. Prefer the annotated-tag commit
    # (``^{}`` suffix) when present — that's the actual commit, not the
    # tag-object SHA.
    sha = _pick_sha(refs)
    cache[key] = sha
    return sha


def _pick_sha(refs: Iterable[tuple[str, str]]) -> str | None:
    """Pick the right SHA from git ls-remote ref pairs.

    Prefers the dereferenced-tag entry (``(<sha>, refs/tags/<tag>^{})``)
    over the annotated-tag entry (``(<sha>, refs/tags/<tag>)``) so we
    record the commit SHA, not the tag-object SHA.
    """
    annotated_lines = []
    tag_lines = []
    head_lines = []
    bare_lines = []
    for sha, refname in refs:
        sha, refname = sha.strip(), refname.strip()
        if not _SHA_RE.match(sha):
            continue
        if refname.endswith("^{}"):
            annotated_lines.append(sha)
        elif refname.startswith("refs/tags/"):
            tag_lines.append(sha)
        elif refname.startswith("refs/heads/"):
            head_lines.append(sha)
        else:
            bare_lines.append(sha)
    if annotated_lines:
        return annotated_lines[0]
    if tag_lines:
        return tag_lines[0]
    if bare_lines:
        return bare_lines[0]
    if head_lines:
        return head_lines[0]
    return None


__all__ = ["HashPinChange", "HashPinResult", "hash_pin_workflows"]
