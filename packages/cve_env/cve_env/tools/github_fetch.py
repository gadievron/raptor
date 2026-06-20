"""GitHub Contents API wrapper -- fetch file or directory listings.

Used by the agent to retrieve vulhub composes, advisory repos, upstream
source, etc., live. Unauthenticated rate limit is 60 req/h per IP; fine
for a smoke. If a GITHUB_TOKEN env var is present we'll include it.
"""

from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

from cve_env.config import GITHUB_API_BASE
from cve_env.tools.web_fetch import web_fetch
from cve_env.utils.exploit_text_sanitizer import sanitize_exploit_text

# File extensions / basenames whose raw content is build-relevant and
# should NOT be sanitized — Dockerfiles, package metadata, manifests,
# configs. Any file matching this allowlist gets the full 128 KiB cap;
# everything else (likely source code) is truncated and sanitized.
# PROSE docs (.md/.txt/.rst/.asciidoc + README/CHANGELOG) live in
# _PROSE_DOC_* below, NOT this raw-exempt set — they carry
# exploit-disclosure narrative (e.g. a README returning a raw
# deserialization PoC gadget chain that trips the AUP filter). Structured
# build files (Dockerfile/compose/manifests/lockfiles) stay raw here: they
# need verbatim fidelity and the sanitizer's whitespace-collapse would
# corrupt them.
_BUILD_ARTIFACT_EXTENSIONS: frozenset[str] = frozenset(
    {
        # Container builds
        ".dockerfile",
        # Package metadata / lockfiles
        ".lock",
        ".toml",
        ".cfg",
        ".ini",
        ".yaml",
        ".yml",
        ".json",
        # Build configs
        ".cmake",
        ".bzl",
        ".bazel",
        ".gradle",
    }
)
_BUILD_ARTIFACT_BASENAMES: frozenset[str] = frozenset(
    {
        "dockerfile",
        "containerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "composer.json",
        "composer.lock",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "go.mod",
        "go.sum",
        "cargo.toml",
        "cargo.lock",
        "requirements.txt",
        "requirements-dev.txt",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "gemfile",
        "gemfile.lock",
        "makefile",
        "cmakelists.txt",
        "license",
    }
)

# Prose/doc artifacts — build-RELEVANT but PROSE. Sanitized for
# exploit-disclosure language (kept at the full build cap so long install
# guides aren't truncated) while build literals survive.
_PROSE_DOC_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".md",
        ".txt",
        ".rst",
        ".asciidoc",
    }
)
_PROSE_DOC_BASENAMES: frozenset[str] = frozenset(
    {
        "readme",
        "readme.md",
        "readme.rst",
        "readme.txt",
        "changelog",
        "changelog.md",
        "changelog.rst",
        "changelog.txt",
    }
)

_SOURCE_FILE_CAP_BYTES = 2 * 1024  # 2 KiB for source files
_BUILD_FILE_CAP_BYTES = 128 * 1024  # 128 KiB for build/config files


def _is_build_artifact(path: str) -> bool:
    """True iff `path` is a STRUCTURED build file (Dockerfile, package
    metadata, config, manifest, lockfile) whose raw content must pass
    through verbatim. Prose docs are handled by `_is_prose_doc`;
    everything else is treated as potentially-vulnerable source code."""
    if not isinstance(path, str):
        return False
    basename = path.rsplit("/", 1)[-1].lower()
    if basename in _BUILD_ARTIFACT_BASENAMES:
        return True
    # Extension check
    if "." in basename:
        ext = "." + basename.rsplit(".", 1)[-1]
        if ext in _BUILD_ARTIFACT_EXTENSIONS:
            return True
    # Heuristic: basenames starting with "Dockerfile." (Dockerfile.dev etc.)
    return bool(basename.startswith("dockerfile"))


def _is_prose_doc(path: str) -> bool:
    """True iff `path` is a prose/doc artifact (README, CHANGELOG, .md,
    .txt, .rst, .asciidoc). Prose docs are build-RELEVANT but carry
    exploit-disclosure narrative, so they are sanitized (not returned raw)
    while build literals survive."""
    if not isinstance(path, str):
        return False
    basename = path.rsplit("/", 1)[-1].lower()
    # Structured build basenames (e.g. requirements.txt, cmakelists.txt) are
    # NOT prose even though they carry a .txt extension — they need verbatim
    # fidelity (whitespace-collapse would corrupt pinned versions / line lists).
    if basename in _BUILD_ARTIFACT_BASENAMES:
        return False
    if basename in _PROSE_DOC_BASENAMES:
        return True
    if "." in basename:
        ext = "." + basename.rsplit(".", 1)[-1]
        if ext in _PROSE_DOC_EXTENSIONS:
            return True
    return False


def _sanitize_fetched_content(path: str, content: str) -> str:
    """Truncate + sanitize file content based on path heuristics.

    Prose docs (README/CHANGELOG/.md/.txt/.rst) → sanitize for exploit-
    disclosure language at the full 128 KiB build cap — build literals
    survive, no truncation of long install guides.

    Structured build artifacts (Dockerfile, package.json, *.yml, etc.) →
    return raw content capped at 128 KiB (verbatim fidelity needed).

    Everything else (likely source code: .py, .php, .go, .java, etc.) →
    truncate to 2 KiB and run through exploit_text_sanitizer to strip
    exploit-disclosure language and rewrite class-verb terms. Agents
    that need version metadata should use package-manifest files
    (package.json / pom.xml / go.mod) — not raw source.
    """
    if not isinstance(content, str):
        return ""
    if _is_prose_doc(path):
        return sanitize_exploit_text(content, max_chars=_BUILD_FILE_CAP_BYTES)
    if _is_build_artifact(path):
        return content[:_BUILD_FILE_CAP_BYTES]
    truncated = content[:_SOURCE_FILE_CAP_BYTES]
    # sanitize_exploit_text default cap is 280 — pass our larger cap
    # explicitly so the truncation happens at the source-file level,
    # not the sanitizer level.
    return sanitize_exploit_text(truncated, max_chars=_SOURCE_FILE_CAP_BYTES)


@dataclass
class GhFetchResult:
    ok: bool
    url: str = ""
    kind: str = ""  # 'file' | 'dir' | 'symlink' | 'submodule'
    path: str = ""
    size: int = 0
    content: str = ""  # decoded for files; "" for directories
    entries: list[dict[str, Any]] = field(
        default_factory=list
    )  # [{name,type,path,size}]
    status: int = 0
    reason: str = ""
    reason_class: str = "ok"  # ok / rate_limited / transport / auth / not_found


# Per-process cache so ``resolve_github_token`` doesn't fork ``gh`` repeatedly.
_TOKEN_CACHE: dict[str, str | bool] = {"resolved": False, "value": ""}


def resolve_github_token() -> str:
    """Pick the GitHub token from env or `gh` CLI.

    Order of precedence:
      1. ``GITHUB_TOKEN`` env var (explicit, highest priority)
      2. ``gh auth token`` (the `gh` CLI's stored token; macOS keychain on
         this host). If the user already authenticated via `gh auth login`,
         this gives 5000 req/h for free without asking them to set an
         env var.
      3. Empty string (anonymous tier — 60 req/h).

    Anonymous = ``x-ratelimit-limit: 60``; with ``gh auth`` token =
    ``x-ratelimit-limit: 5000``. Cached per-process so we don't fork ``gh``
    on every API call.
    """
    if _TOKEN_CACHE["resolved"]:
        return str(_TOKEN_CACHE["value"])
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        # Strip dangerous env vars before gh auth so HTTPS_PROXY can't
        # redirect the auth-token resolution lookup. run_with_timeout folds
        # (FileNotFoundError, TimeoutExpired, OSError) into
        # outcome.returncode=None, so reading outcome.returncode == 0
        # implicitly handles all three: missing binary, timeout, or
        # transport error → token stays "".
        from cve_env.utils.run import run_with_timeout
        from cve_env.utils.safe_env import safe_subprocess_env

        outcome = run_with_timeout(
            ["gh", "auth", "token"],  # noqa: S603,S607 -- 'gh' is on PATH in dev env
            timeout=5,
            env=safe_subprocess_env(),
        )
        if outcome.returncode == 0:
            token = outcome.stdout.strip()
    _TOKEN_CACHE["resolved"] = True
    _TOKEN_CACHE["value"] = token
    return token


def _auth_header() -> dict[str, str]:
    token = resolve_github_token()
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}


def reset_token_cache() -> None:
    """Test helper: forget the cached token so re-resolution can be exercised.

    NOT registered in the per-CVE _RESET_GLOBALS pattern (cf.
    `image_resolve._RESET_GLOBALS`, `docker_run._RESET_GLOBALS`, etc.) because
    the GitHub token is a SHARED secret across all CVEs in a bench run —
    caching is intentional. Calling this from the per-CVE loop would force
    `resolve_github_token()` re-resolution on every CVE (extra `gh auth token`
    subprocess + cost). Use only from tests.
    """
    _TOKEN_CACHE["resolved"] = False
    _TOKEN_CACHE["value"] = ""


_CVE_REPO_RE = re.compile(r"^cve-\d{4}-\d+", re.IGNORECASE)
_POC_BOUNDED_RE = re.compile(r"(?:^|[^a-z0-9])poc(?:[^a-z0-9]|$)", re.IGNORECASE)


def _is_exploit_poc_repo(owner: str, repo: str) -> bool:
    """True iff ``owner/repo`` looks like a DEDICATED exploit-PoC repo
    rather than an environment/source repo.

    cve-env builds vulnerable ENVIRONMENTS, not exploits, so it must not pull
    PoC/exploit code into context: it both trips Anthropic's cyber safeguards
    (live refusals on repos literally named after a CVE) and is never needed
    for the build (the vulhub repo + upstream product source carry the build
    files). Precise (precision over recall) so it never blocks an
    environment/source fetch; ``vulhub`` is allowlisted because its paths
    legitimately contain ``CVE-…`` segments.
    """
    o = (owner or "").lower().strip()
    rp = (repo or "").lower().strip()
    if not o or not rp:
        return False
    if o == "vulhub":  # canonical environment source — always allowed
        return False
    if _CVE_REPO_RE.match(rp):  # repo literally named after a CVE = dedicated PoC
        return True
    blob = f"{o}/{rp}"
    if "exploit" in blob or "0day" in blob or "0-day" in blob:
        return True
    return bool(_POC_BOUNDED_RE.search(blob))


def github_fetch(
    *,
    owner: str,
    repo: str,
    path: str,
    ref: str = "",
) -> GhFetchResult:
    """GET https://api.github.com/repos/<owner>/<repo>/contents/<path>[?ref=X]."""
    if not owner or not repo:
        return GhFetchResult(
            ok=False, reason="owner and repo are required", reason_class="not_found"
        )
    # Refuse dedicated exploit-PoC repos BEFORE any network call — keeps
    # exploit code out of context (refusal trigger) and out of the deliverable.
    if _is_exploit_poc_repo(owner, repo):
        return GhFetchResult(
            ok=False,
            reason=(
                f"'{owner}/{repo}' looks like a dedicated exploit-PoC repo. "
                "cve-env builds vulnerable environments, not exploits: do NOT "
                "fetch PoC/exploit code (not needed for the build and it trips "
                "safety policy). Use the vulhub repo (owner='vulhub') or the "
                "upstream product source for build files instead."
            ),
            reason_class="poc_repo_blocked",
        )
    clean_path = path.strip("/")
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/contents/{clean_path}"
    if ref:
        url += f"?ref={ref}"
    headers = {"Accept": "application/vnd.github+json", **_auth_header()}
    r = web_fetch(url=url, headers=headers, max_bytes=1024 * 1024)
    if not r.ok:
        return GhFetchResult(
            ok=False,
            url=url,
            status=r.status,
            reason=f"github fetch failed: {r.reason}",
            reason_class=r.reason_class,
        )

    try:
        payload = json.loads(r.body)
    except json.JSONDecodeError as exc:
        return GhFetchResult(
            ok=False,
            url=url,
            status=r.status,
            reason=f"github json decode error: {exc}",
            reason_class="transport",
        )

    # Directory listing: list of dicts.
    if isinstance(payload, list):
        entries = [
            {
                "name": entry.get("name", ""),
                "type": entry.get("type", ""),
                "path": entry.get("path", ""),
                "size": entry.get("size", 0),
            }
            for entry in payload
            if isinstance(entry, dict)
        ]
        return GhFetchResult(
            ok=True,
            url=url,
            kind="dir",
            path=clean_path,
            entries=entries[:200],
            status=r.status,
        )

    # Single file / symlink / submodule: dict.
    if isinstance(payload, dict):
        kind = str(payload.get("type", ""))
        size = int(payload.get("size", 0) or 0)
        content = ""
        if kind == "file":
            encoding = payload.get("encoding")
            raw = payload.get("content", "")
            if encoding == "base64" and isinstance(raw, str):
                try:
                    decoded = base64.b64decode(raw)
                    content = decoded.decode("utf-8", errors="replace")
                except (ValueError, TypeError):
                    content = ""
            elif isinstance(raw, str):
                content = raw
            content = _sanitize_fetched_content(clean_path, content)
        return GhFetchResult(
            ok=True,
            url=url,
            kind=kind,
            path=clean_path,
            size=size,
            content=content,
            status=r.status,
        )

    return GhFetchResult(
        ok=False,
        url=url,
        status=r.status,
        reason="unexpected response shape",
        reason_class="transport",
    )


def github_fetch_payload(
    *,
    owner: str,
    repo: str,
    path: str,
    ref: str = "",
) -> dict[str, Any]:
    r = github_fetch(owner=owner, repo=repo, path=path, ref=ref)
    return {
        "ok": r.ok,
        "url": r.url,
        "kind": r.kind,
        "path": r.path,
        "size": r.size,
        "content": r.content,
        "entries": r.entries,
        "status": r.status,
        "reason": r.reason,
        "reason_class": r.reason_class,
    }
