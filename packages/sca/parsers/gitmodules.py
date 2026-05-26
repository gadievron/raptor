""".gitmodules parser — git submodule dependencies.

A ``.gitmodules`` file declares git submodules: external repos
pinned at specific commits and laid out under the parent repo's
working tree. The file itself is INI-format with sections like:

    [submodule "vendor/zlib"]
        path = vendor/zlib
        url = https://github.com/madler/zlib.git

The actual commit pin lives in the parent repo's git tree (as a
"gitlink" tree entry), not in ``.gitmodules``. We resolve the SHA
best-effort by reading ``.git/modules/<name>/HEAD``; if that
isn't readable (no ``.git`` directory, fresh clone, file missing)
the submodule is recorded with ``version=None``.

## OSV matching scope

Submodules don't have a clean OSV ecosystem. GHSA-style advisories
key on registry-published packages (npm, PyPI, etc.); a github.com
URL pin to a specific repo commit isn't directly queryable.

What this parser DOES today:

  * Parse ``.gitmodules`` and emit a ``Dependency`` row per
    submodule with ``ecosystem="GitHub"`` (for github.com URLs)
    or ``"GitGeneric"`` (others).
  * Record ``source_kind="git_submodule"`` and stash the URL +
    SHA in ``source_extra`` so reports can show what the operator
    has vendored.
  * Emit a purl: ``pkg:github/<owner>/<repo>@<sha>`` for github
    URLs (the closest thing to a canonical ID for git-pinned
    code), or ``pkg:generic/<host>/<path>@<sha>`` otherwise.

What this parser does NOT do:

  * Query OSV. The ``GitHub`` / ``GitGeneric`` ecosystem strings
    are SCA-internal identifiers; OSV won't return matches for
    them. Submodule findings appear in the SBOM (visibility is
    half the value) but not in the CVE-matching report. A future
    iteration could plug into OSV's ``GIT`` range type for direct
    commit-range matching against advisories that carry git
    ranges (uncommon, but real for some upstream-tracked CVEs).
  * Resolve transitive submodules (a submodule with its own
    ``.gitmodules``). The discovery walker hits each ``.gitmodules``
    independently anyway, so this falls out for free as long as
    the operator has run ``git submodule update --recursive``.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)


# Map submodule URL host → SBOM ecosystem string. SCA-internal —
# OSV does not recognise these names.
_GITHUB_ECOSYSTEM = "GitHub"
_GENERIC_ECOSYSTEM = "GitGeneric"

_SECTION_RE = re.compile(r'^\[submodule\s+"(.+?)"\s*\]\s*$')
_KEYVAL_RE = re.compile(r"^\s*([A-Za-z0-9_\-]+)\s*=\s*(.+?)\s*$")


@register(filenames=[".gitmodules"])
def parse(path: Path) -> List[Dependency]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning(
            "sca.parsers.gitmodules: read failed for %s: %s", path, e,
        )
        return []

    sections = _parse_sections(text)
    if not sections:
        return []

    repo_root = _find_repo_root(path)

    out: List[Dependency] = []
    for section_name, fields in sections:
        url = fields.get("url", "").strip()
        sm_path = fields.get("path", "").strip()
        if not url or not sm_path:
            # A malformed section without both url and path can't be
            # turned into a meaningful Dependency row.
            continue
        sha = _resolve_submodule_sha(repo_root, section_name) if repo_root else None
        dep = _build_dep(
            section_name=section_name,
            url=url,
            sm_path=sm_path,
            sha=sha,
            declared_in=path,
        )
        if dep is not None:
            out.append(dep)
    return out


def _parse_sections(text: str) -> List[Tuple[str, Dict[str, str]]]:
    """Walk the INI file, return ``[(section_name, {field: value}), ...]``.

    The grammar is git-config syntax: ``[submodule "name"]`` headers
    followed by indented or unindented ``key = value`` pairs. We
    skip comments (``#`` / ``;``) and tolerate stray blank lines.
    """
    out: List[Tuple[str, Dict[str, str]]] = []
    current_name: Optional[str] = None
    current_fields: Dict[str, str] = {}
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        section_match = _SECTION_RE.match(stripped)
        if section_match:
            if current_name is not None:
                out.append((current_name, current_fields))
            current_name = section_match.group(1)
            current_fields = {}
            continue
        if current_name is None:
            continue
        kv = _KEYVAL_RE.match(raw_line)
        if kv:
            current_fields[kv.group(1).lower()] = kv.group(2)
    if current_name is not None:
        out.append((current_name, current_fields))
    return out


def _find_repo_root(gitmodules_path: Path) -> Optional[Path]:
    """Walk up from the .gitmodules path looking for a ``.git``
    directory or file. Submodules can have ``.git`` as a file
    (containing ``gitdir: ../<path>``) — handled separately."""
    cur = gitmodules_path.resolve().parent
    while True:
        if (cur / ".git").exists():
            return cur
        if cur.parent == cur:
            return None
        cur = cur.parent


def _resolve_submodule_sha(
    repo_root: Path, submodule_name: str,
) -> Optional[str]:
    """Best-effort resolution of the submodule's committed SHA.

    For modern git layouts the submodule's own internal repo lives
    at ``<repo_root>/.git/modules/<submodule_name>/`` and its
    ``HEAD`` file (or ``ORIG_HEAD``) records the current commit.

    Submodule names sometimes contain characters git escapes; we
    don't try to recover those exotic cases — read fails, return
    None, the dep is recorded with version=None.

    Returns the 40-char hex SHA on success, None otherwise.
    """
    candidate = repo_root / ".git" / "modules" / submodule_name / "HEAD"
    if not candidate.is_file():
        return None
    try:
        contents = candidate.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    # HEAD may carry a direct SHA or a ``ref: refs/heads/<branch>``.
    if contents.startswith("ref:"):
        ref = contents[4:].strip()
        ref_path = repo_root / ".git" / "modules" / submodule_name / ref
        if not ref_path.is_file():
            return None
        try:
            ref_contents = ref_path.read_text(
                encoding="utf-8", errors="replace",
            ).strip()
        except OSError:
            return None
        return _validate_sha(ref_contents)
    return _validate_sha(contents)


def _validate_sha(text: str) -> Optional[str]:
    """Return the SHA if it looks like a 40-char hex git SHA. Tolerates
    a short SHA prefix (>=7 chars) but doesn't expand — treats only
    full-length SHAs as canonical."""
    text = text.strip()
    if re.fullmatch(r"[0-9a-fA-F]{40}", text):
        return text.lower()
    return None


def _build_dep(
    *, section_name: str, url: str, sm_path: str,
    sha: Optional[str], declared_in: Path,
) -> Optional[Dependency]:
    ecosystem, name, purl = _classify_url(url, sha)
    if name is None:
        return None
    pin_style = PinStyle.GIT if sha else PinStyle.WILDCARD
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=sha,
        declared_in=declared_in,
        scope="main",
        is_lockfile=bool(sha),         # the SHA is a real pin
        pin_style=pin_style,
        direct=True,
        purl=purl,
        parser_confidence=Confidence(
            "high" if sha else "medium",
            reason=(
                f"git submodule pinned at {sha[:12]}" if sha
                else "git submodule URL declared but commit unresolved"
            ),
        ),
        source_kind="git_submodule",
        source_extra={
            "url": url,
            "path": sm_path,
            "submodule_name": section_name,
        },
    )


def _classify_url(
    url: str, sha: Optional[str],
) -> Tuple[str, Optional[str], str]:
    """Classify a submodule URL into (ecosystem, name, purl).

    GitHub URLs get a ``pkg:github/<owner>/<repo>`` purl; others
    fall back to ``pkg:generic/<host>/<path>``. The ``name`` field
    (used by SBOM tooling for human display) is ``<owner>/<repo>``
    for GitHub or the full URL path for generic.
    """
    parsed = urlparse(_normalise_git_url(url))
    host = (parsed.hostname or "").lower()
    repo_path = parsed.path.lstrip("/")
    # Strip a trailing ``.git`` for a cleaner name + purl.
    if repo_path.endswith(".git"):
        repo_path = repo_path[: -len(".git")]
    if not repo_path:
        return _GENERIC_ECOSYSTEM, None, ""

    if host == "github.com" or host.endswith(".github.com"):
        parts = repo_path.split("/", 1)
        if len(parts) != 2:
            return _GENERIC_ECOSYSTEM, repo_path, _generic_purl(host, repo_path, sha)
        owner, repo = parts
        purl = f"pkg:github/{owner}/{repo}"
        if sha:
            purl += f"@{sha}"
        return _GITHUB_ECOSYSTEM, repo_path, purl

    return _GENERIC_ECOSYSTEM, f"{host}/{repo_path}", _generic_purl(host, repo_path, sha)


def _generic_purl(host: str, repo_path: str, sha: Optional[str]) -> str:
    purl = f"pkg:generic/{host}/{repo_path}"
    if sha:
        purl += f"@{sha}"
    return purl


def _normalise_git_url(url: str) -> str:
    """Convert ``git@github.com:owner/repo.git`` SSH-style refs to a
    parseable ``https://github.com/owner/repo.git`` form. Leaves
    ``https://...`` and ``git://...`` URLs alone."""
    if url.startswith("git@") and ":" in url:
        host_part, _, path_part = url[len("git@"):].partition(":")
        return f"https://{host_part}/{path_part}"
    return url
