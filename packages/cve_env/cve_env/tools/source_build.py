"""Source-repo clone + version-tag checkout + Dockerfile discovery.

Used by the ``source_build`` MCP tool when ``image_resolve`` returns
``not_found`` but the upstream has a public GitHub repo the agent can
build from. Uses urllib only for HTTP.

Returns a :class:`SourceBuildResult`: ``repo_dir`` + optional
``dockerfile_text`` + optional ``build_config`` hint. The agent either
builds directly (``docker_build(context_dir=repo_dir,
dockerfile_text=<text>)``) or scaffolds a new Dockerfile via
``dockerfile_gen`` using the ``build_config`` hint when the repo has no
Dockerfile.

Design choices:

* GitHub-only. `normalize_github_url` accepts the common URL forms
  (`git://`, `git+https://`, `git+ssh://`, `git@github.com:`, trailing
  `.git`) and coerces them to `https://github.com/<owner>/<repo>`. Any
  other host returns ``None`` so the caller fails cleanly.
* Progressive clone cascade: depth=1 → adaptive-sized steps → full.
  Per-call timeout kills the ``git`` subprocess.
* 4-tier version-tag match (exact, prefix-with-separator, prefix-prefix,
  fuzzy contains).
* Archive fallback via ``codeload.github.com`` tarball when clone hits
  rate limit / network failure.
* Dockerfile discovery in common locations + recursive search excluding
  test/example paths.
* Build-config detection (``pom.xml`` / ``package.json`` / …) for the
  scaffold-via-``dockerfile_gen`` path.
"""

from __future__ import annotations

import atexit
import io
import json
import logging
import os
import re
import shutil
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

if TYPE_CHECKING:
    from types import TracebackType

    from cve_env.utils.run import RunOutcome

logger = logging.getLogger(__name__)

_CLONE_TIMEOUT_SECONDS = 60
_DEEPEN_STEPS: tuple[int, ...] = (100, 500, 2000, 0)  # 0 == --unshallow
_GITHUB_HTTPS_PREFIX = "https://github.com/"
_GITHUB_OWNER_REPO_RE = re.compile(r"github\.com[:/]([^/]+)/([^/\s]+)")
# Charset matching GitHub's actual identifier rules (defense-in-depth so
# an attacker-controlled URL cannot smuggle shell metachars into owner/repo
# even if a future refactor logs or interpolates these into a string command).
_GITHUB_IDENT_RE = re.compile(r"[A-Za-z0-9._-]+")
_HTTP_TIMEOUT_SECONDS = 20


def _env_int(name: str, default: int) -> int:
    """Parse an int from env ``name``; fall back to ``default`` on absence or a
    malformed value (never raises at import/call time)."""
    try:
        return int(os.environ.get(name) or default)
    except ValueError:
        return default


# Security: bound external tarball/JSON reads + extraction so a malicious or
# accidentally-huge source cannot exhaust host memory or disk (decompression
# bomb). Defaults sit FAR above any real source repo (a single-tag source
# tarball is well under 1 GB), so legitimate builds never trip them; an
# over-cap fetch returns None and the cascade falls back to git clone — work is
# never blocked. All env-configurable for the rare giant-monorepo CVE.
_MAX_TARBALL_BYTES = _env_int("CVE_ENV_MAX_TARBALL_BYTES", 512 * 1024**2)  # 512 MiB
_MAX_JSON_BYTES = _env_int("CVE_ENV_MAX_JSON_BYTES", 64 * 1024 * 1024)  # 64 MiB
_MAX_EXTRACT_BYTES = _env_int("CVE_ENV_MAX_EXTRACT_BYTES", 2 * 1024**3)  # 2 GiB
_MAX_EXTRACT_MEMBERS = _env_int("CVE_ENV_MAX_EXTRACT_MEMBERS", 500_000)

_DOCKERFILE_LOCATIONS: tuple[str, ...] = (
    "Dockerfile",
    "Containerfile",
    "docker/Dockerfile",
    "docker/Containerfile",
    "build/Dockerfile",
    ".docker/Dockerfile",
    "deploy/Dockerfile",
)
_DOCKERFILE_GLOB_NAMES: tuple[str, ...] = ("Dockerfile", "Containerfile")
_SKIP_DOCKERFILE_SUBSTRINGS: tuple[str, ...] = ("test", "example", "sample", "demo")
_DEVCONTAINER_JSON = ".devcontainer/devcontainer.json"
_DEVCONTAINER_ROOT_JSON = ".devcontainer.json"
_JSONC_LINE_COMMENT = re.compile(r"^\s*//[^\n]*", re.MULTILINE)
_JSONC_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_JSONC_TRAILING_COMMA = re.compile(r",(\s*[}\]])")

_BUILD_CONFIG_TO_TYPE: dict[str, str] = {
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "package.json": "npm",
    "setup.py": "python",
    "pyproject.toml": "python",
    "requirements.txt": "python",
    "Cargo.toml": "rust",
    "go.mod": "go",
    "Gemfile": "ruby",
    "composer.json": "php",
}


# -- pure helpers ----------------------------------------------------------


# SCP-style git URL: ``[user@]host:path``. Matched explicitly because urlparse
# treats them as relative paths.
_SCP_GIT_RE = re.compile(r"^(?:[A-Za-z0-9._-]+@)?([A-Za-z0-9.-]+):(.+)$")
_GITHUB_GIT_SCHEMES = frozenset(
    {"http", "https", "git", "ssh", "git+http", "git+https", "git+ssh"}
)


def normalize_github_url(url: str | None) -> str | None:
    """Coerce any GitHub URL form into ``https://github.com/<owner>/<repo>``.

    Returns ``None`` for non-GitHub URLs or malformed inputs.

    Host validation uses ``urlparse(url).hostname`` (port/userinfo stripped)
    to prevent bypass via URLs like ``https://attacker.com/github.com/evil/repo``
    or ``https://github.com@attacker.com/x/y``.
    """
    if not url:
        return None
    url = url.strip()
    if url.endswith(".git"):
        url = url.removesuffix(".git")
    # SCP-style (``git@github.com:owner/repo``) first — urlparse misreads it.
    scp_match = _SCP_GIT_RE.match(url)
    if scp_match and "://" not in url:
        host, path = scp_match.group(1), scp_match.group(2)
        if host.lower() != "github.com":
            return None
        parts = [p for p in path.strip("/").split("/") if p]
    else:
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme.startswith("git+"):
            scheme = scheme.removeprefix("git+")
        if scheme not in {"http", "https", "git", "ssh"}:
            return None
        if (parsed.hostname or "").lower() != "github.com":
            return None
        parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    if not _GITHUB_IDENT_RE.fullmatch(owner) or not _GITHUB_IDENT_RE.fullmatch(repo):
        return None
    return f"{_GITHUB_HTTPS_PREFIX}{owner}/{repo}"


_COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _is_commit_sha(version: str) -> bool:
    """Detect a 40-char hex git SHA.

    Plugin/extension CVEs often have NO release tags but a well-known patch
    commit. The agent can pass that SHA (or `<sha>~1` is handled separately
    via `Bash`) directly as ``version`` and source_build will checkout it.
    """
    return bool(_COMMIT_SHA_RE.match(version.lower()))


def find_version_tag(tags: list[str], version: str) -> str | None:
    """Return the best-matching tag for ``version`` via 4-tier priority.

    1. Exact (``v1.2.3`` matches ``1.2.3``).
    2. Tag starts with ``<version>.`` or ``<version>-``.
    3. Version starts with ``<tag>.``.
    4. Fuzzy: tag contains normalized version.
    """
    norm = version.lstrip("v")
    pairs = [(t, t.lstrip("v")) for t in tags]
    for t, n in pairs:
        if n == norm:
            return t
    for t, n in pairs:
        if n.startswith(f"{norm}.") or n.startswith(f"{norm}-"):
            return t
    # Tier 3: tag is a prefix of version. May match too broadly for single-digit tags like '1'.
    for t, n in pairs:
        if norm.startswith(f"{n}."):
            return t
    for t, _ in pairs:
        if re.search(r"(?:^|[.\-_])" + re.escape(norm) + r"(?:$|[.\-_])", t):
            return t
    return None


def _pick_deepen_steps(size_kb: int | None) -> tuple[int, ...]:
    """Size-based clone-deepen cascade (GitHub API reports size in KB)."""
    if size_kb is None:
        return _DEEPEN_STEPS
    if size_kb < 5_000:
        return (0,)
    if size_kb < 50_000:
        return (100, 0)
    return (500, 5000, 0)


# -- dataclasses -----------------------------------------------------------


@dataclass
class SourceBuildConfig:
    clone_timeout_seconds: int = _CLONE_TIMEOUT_SECONDS
    work_dir: Path | None = None  # None → tempfile.mkdtemp per build()
    cleanup: bool = True
    adaptive_depth: bool = True
    archive_fallback: bool = True
    http_timeout_seconds: int = _HTTP_TIMEOUT_SECONDS


@dataclass
class _CloneOutcome:
    """Internal: needs_checkout=False when tarball fallback populated the tree."""

    tag: str | None
    warnings: list[str]
    needs_checkout: bool


@dataclass
class SourceBuildResult:
    """Public result. ``ok`` is True iff caller can proceed to docker_build."""

    repo_dir: Path | None
    checked_out_tag: str | None
    dockerfile_path: Path | None
    dockerfile_text: str | None
    build_config: str | None
    warnings: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def ok(self) -> bool:
        """True iff we have a checkout + either a Dockerfile or a build-config hint."""
        if self.checked_out_tag is None or self.repo_dir is None:
            return False
        return self.dockerfile_path is not None or self.build_config is not None


# -- main builder ----------------------------------------------------------


class SourceBuilder:
    """Clone + checkout + discovery. Use as context manager for auto-cleanup."""

    def __init__(self, config: SourceBuildConfig | None = None) -> None:
        self.config = config or SourceBuildConfig()
        self._temp_dirs: list[Path] = []
        self._retained = False

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if not self._retained:
            self.cleanup()

    def retain(self) -> None:
        """Caller owns the tree; no cleanup on ``__exit__``."""
        self._retained = True

    def build(
        self,
        *,
        source_url: str,
        product: str,
        version: str,
    ) -> SourceBuildResult:
        normalized = normalize_github_url(source_url)
        if normalized is None:
            return SourceBuildResult(
                repo_dir=None,
                checked_out_tag=None,
                dockerfile_path=None,
                dockerfile_text=None,
                build_config=None,
                error=f"not a GitHub URL: {source_url!r}",
            )

        work = self.config.work_dir or Path(tempfile.mkdtemp(prefix="cve-env-source-"))
        if self.config.work_dir is None:
            self._temp_dirs.append(work)
        # Security: ``product`` is LLM tool-call input. Reduce it to a single
        # path component and assert containment so an absolute or ``..``-laden
        # value cannot redirect the rmtree / clone / tar-extract below to an
        # arbitrary host path. Legitimate products are bare names (e.g.
        # "struts"), so ``Path(product).name`` is a no-op for real builds.
        safe_product = Path(product).name
        target = work / safe_product
        if (
            not safe_product
            or safe_product in (".", "..")
            or not target.resolve().is_relative_to(work.resolve())
        ):
            return SourceBuildResult(
                repo_dir=None,
                checked_out_tag=None,
                dockerfile_path=None,
                dockerfile_text=None,
                build_config=None,
                error=f"unsafe product name: {product!r}",
            )
        if target.exists():
            shutil.rmtree(target)

        if _is_commit_sha(version):
            outcome = self._clone_at_sha(normalized, target, version.lower())
        else:
            outcome = self._progressive_clone(normalized, target, version)
        if outcome.tag is None:
            return SourceBuildResult(
                repo_dir=target if target.exists() else None,
                checked_out_tag=None,
                dockerfile_path=None,
                dockerfile_text=None,
                build_config=None,
                warnings=outcome.warnings,
                error=f"no tag matched {version!r}",
            )
        if outcome.needs_checkout and not self._checkout(target, outcome.tag):
            return SourceBuildResult(
                repo_dir=target,
                checked_out_tag=None,
                dockerfile_path=None,
                dockerfile_text=None,
                build_config=None,
                warnings=outcome.warnings,
                error=f"checkout {outcome.tag!r} failed",
            )

        dockerfile_path = self._find_dockerfile(target)
        dockerfile_text = self._read_dockerfile(dockerfile_path)
        warnings = outcome.warnings
        devcontainer_image = self._find_devcontainer_image(target)
        if devcontainer_image is not None:
            warnings.append(f"devcontainer base image: {devcontainer_image}")
        return SourceBuildResult(
            repo_dir=target,
            checked_out_tag=outcome.tag,
            dockerfile_path=dockerfile_path,
            dockerfile_text=dockerfile_text,
            build_config=self._find_build_config(target),
            warnings=warnings,
        )

    def cleanup(self) -> None:
        if not self.config.cleanup:
            return
        for d in self._temp_dirs:
            if d.exists():
                shutil.rmtree(d, ignore_errors=True)
        self._temp_dirs.clear()

    # -- internals ---------------------------------------------------------

    def _run_git(
        self,
        args: list[str],
        *,
        cwd: Path | None = None,
        timeout: int | None = None,
    ) -> RunOutcome:
        # Strip dangerous env vars before git so a hostile GIT_SSH_COMMAND /
        # HTTPS_PROXY in the operator's shell can't redirect the clone.
        # Returns RunOutcome; callers check ``outcome.timed_out`` and run
        # site-specific cleanup (logger.warning, warnings.append, shutil.rmtree).
        from cve_env.utils.run import run_with_timeout
        from cve_env.utils.safe_env import safe_subprocess_env

        return run_with_timeout(
            args,
            cwd=cwd,
            timeout=timeout or self.config.clone_timeout_seconds,
            env=safe_subprocess_env(),
        )

    def _progressive_clone(self, url: str, target: Path, version: str) -> _CloneOutcome:
        warnings: list[str] = []
        if not self._clone_shallow(url, target):
            warnings.append(f"initial shallow clone failed: {url}")
            if self.config.archive_fallback:
                tag = self._archive_fallback(url, version, target, warnings)
                if tag is not None:
                    return _CloneOutcome(
                        tag=tag, warnings=warnings, needs_checkout=False
                    )
            return _CloneOutcome(tag=None, warnings=warnings, needs_checkout=True)

        self._fetch_tags(target)
        tag = find_version_tag(self._list_tags(target), version)
        if tag is not None:
            return _CloneOutcome(tag=tag, warnings=warnings, needs_checkout=True)

        steps = self._deepen_steps(url) if self.config.adaptive_depth else _DEEPEN_STEPS
        for depth in steps:
            warnings.append(
                f"no tag matched at current depth; deepening to "
                f"{'full' if depth == 0 else depth}"
            )
            if not self._deepen(target, depth):
                warnings.append(f"deepen to {'full' if depth == 0 else depth} failed")
                break
            tag = find_version_tag(self._list_tags(target), version)
            if tag is not None:
                return _CloneOutcome(tag=tag, warnings=warnings, needs_checkout=True)

        if self.config.archive_fallback:
            tag = self._archive_fallback(url, version, target, warnings)
            if tag is not None:
                return _CloneOutcome(tag=tag, warnings=warnings, needs_checkout=False)
        return _CloneOutcome(tag=None, warnings=warnings, needs_checkout=True)

    def _deepen_steps(self, url: str) -> tuple[int, ...]:
        size_kb = self._fetch_repo_size_kb(url)
        return _pick_deepen_steps(size_kb)

    def _fetch_repo_size_kb(self, github_url: str) -> int | None:
        match = _GITHUB_OWNER_REPO_RE.search(github_url)
        if not match:
            return None
        owner, repo = match.groups()
        api_url = f"https://api.github.com/repos/{owner}/{repo}"
        try:
            data = _http_get_json(api_url, timeout=self.config.http_timeout_seconds)
        except OSError:
            return None
        if not isinstance(data, dict):
            return None
        size = data.get("size")
        if isinstance(size, bool):
            return None
        if isinstance(size, (int, float)):
            return int(size)
        return None

    def _archive_fallback(
        self,
        url: str,
        version: str,
        target: Path,
        warnings: list[str],
    ) -> str | None:
        match = _GITHUB_OWNER_REPO_RE.search(url)
        if not match:
            return None
        owner, repo = match.groups()
        tags = self._list_tags_via_api(owner, repo)
        if not tags:
            warnings.append("archive fallback: no tags available via api.github.com")
            return None
        tag = find_version_tag(tags, version)
        if tag is None:
            warnings.append(f"archive fallback: no tag matched {version!r}")
            return None
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        if not self._download_tarball(owner, repo, tag, target):
            warnings.append(
                f"archive fallback: download or extract failed for tag {tag!r}"
            )
            return None
        warnings.append(f"archive fallback via codeload for tag {tag!r}")
        return tag

    def _list_tags_via_api(self, owner: str, repo: str) -> list[str]:
        out: list[str] = []
        api_url: str | None = (
            f"https://api.github.com/repos/{owner}/{repo}/tags?per_page=100"
        )
        max_pages = 10
        for _ in range(max_pages):
            if api_url is None:
                break
            try:
                data, next_url = _http_get_json_paginated(
                    api_url, timeout=self.config.http_timeout_seconds
                )
            except OSError:
                break
            if not isinstance(data, list) or not data:
                break
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name")
                if isinstance(name, str) and name:
                    out.append(name)
            api_url = next_url
        return out

    def _download_tarball(self, owner: str, repo: str, tag: str, target: Path) -> bool:
        codeload_url = (
            f"https://codeload.github.com/{owner}/{repo}/tar.gz/refs/tags/{tag}"
        )
        try:
            payload = _http_get_bytes(
                codeload_url, timeout=self.config.http_timeout_seconds
            )
        except OSError:
            return False
        if payload is None:
            return False
        try:
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tf:
                members = tf.getmembers()
                if not members:
                    return False
                # Security: bound extraction to defeat a decompression bomb
                # (tiny gzip -> enormous expansion). Over-cap -> refuse (cascade
                # falls back to clone). Caps sit far above any real source repo.
                if len(members) > _MAX_EXTRACT_MEMBERS:
                    logger.warning(
                        "source_build: tarball member count %d over cap %d — refusing extract",
                        len(members),
                        _MAX_EXTRACT_MEMBERS,
                    )
                    return False
                total_size = sum(max(0, m.size) for m in members)
                if total_size > _MAX_EXTRACT_BYTES:
                    logger.warning(
                        "source_build: tarball expands to %d B (cap %d) — refusing extract",
                        total_size,
                        _MAX_EXTRACT_BYTES,
                    )
                    return False
                top_segment = members[0].name.split("/", 1)[0]
                if not top_segment:
                    return False
                prefix = f"{top_segment}/"
                target.mkdir(parents=True, exist_ok=True)
                for m in members:
                    if m.name == top_segment:
                        continue
                    if not m.name.startswith(prefix):
                        continue
                    rel = m.name[len(prefix) :]
                    if not rel or ".." in Path(rel).parts:
                        continue
                    m.name = rel
                    # filter="data" rejects symlinks pointing outside the
                    # destination, absolute paths, setuid/sgid bits, and special
                    # device files. Required by Python 3.12; 3.14 makes it the
                    # default but the supported floor is 3.12.
                    try:
                        tf.extract(m, target, set_attrs=False, filter="data")
                    except TypeError:
                        # Python <3.12 does not support the filter parameter.
                        tf.extract(m, target, set_attrs=False)
        except (tarfile.TarError, OSError):
            return False
        return True

    def _clone_shallow(self, url: str, target: Path) -> bool:
        if not url.startswith(_GITHUB_HTTPS_PREFIX):
            logger.warning("refusing to clone non-GitHub URL: %s", url)
            return False
        outcome = self._run_git(["git", "clone", "--depth", "1", url, str(target)])
        if outcome.timed_out:
            logger.warning(
                "git clone timed out after %ss: %s",
                self.config.clone_timeout_seconds,
                url,
            )
            if target.exists():
                shutil.rmtree(target, ignore_errors=True)
            return False
        return outcome.returncode == 0

    def _deepen(self, repo_dir: Path, new_depth: int) -> bool:
        cmd = (
            ["git", "fetch", "--unshallow", "--tags"]
            if new_depth == 0
            else ["git", "fetch", f"--depth={new_depth}", "--tags"]
        )
        outcome = self._run_git(cmd, cwd=repo_dir)
        if outcome.timed_out:
            return False
        return outcome.returncode == 0

    def _fetch_tags(self, repo_dir: Path) -> bool:
        outcome = self._run_git(["git", "fetch", "--tags", "--depth=1"], cwd=repo_dir)
        if outcome.timed_out:
            return False
        return outcome.returncode == 0

    def _list_tags(self, repo_dir: Path) -> list[str]:
        outcome = self._run_git(["git", "tag", "--list"], cwd=repo_dir, timeout=15)
        if outcome.timed_out or outcome.returncode != 0:
            return []
        return [line.strip() for line in outcome.stdout.splitlines() if line.strip()]

    def _clone_at_sha(self, url: str, target: Path, sha: str) -> _CloneOutcome:
        """Clone a repo and check out a specific commit SHA.

        Strategy: full clone (most plugin/extension repos are small), then
        ``git checkout <sha>``. Skips tag matching entirely. The returned
        ``tag`` is the SHA itself so downstream treats it as the resolved
        ref. ``needs_checkout=False`` because checkout already happened.
        """
        warnings: list[str] = []
        if not url.startswith(_GITHUB_HTTPS_PREFIX):
            warnings.append(f"refusing to clone non-GitHub URL: {url}")
            return _CloneOutcome(tag=None, warnings=warnings, needs_checkout=False)
        outcome = self._run_git(["git", "clone", url, str(target)])
        if outcome.timed_out:
            warnings.append(
                f"git clone (full) timed out after "
                f"{self.config.clone_timeout_seconds}s for SHA checkout"
            )
            if target.exists():
                shutil.rmtree(target, ignore_errors=True)
            return _CloneOutcome(tag=None, warnings=warnings, needs_checkout=False)
        if outcome.returncode != 0:
            warnings.append(
                f"git clone failed for SHA checkout: {outcome.stderr.strip()[:200]}"
            )
            if target.exists():
                shutil.rmtree(target, ignore_errors=True)
            return _CloneOutcome(tag=None, warnings=warnings, needs_checkout=False)
        if not self._checkout(target, sha):
            warnings.append(f"git checkout {sha[:10]}... failed")
            return _CloneOutcome(tag=None, warnings=warnings, needs_checkout=False)
        return _CloneOutcome(tag=sha, warnings=warnings, needs_checkout=False)

    def _checkout(self, repo_dir: Path, tag: str) -> bool:
        outcome = self._run_git(["git", "checkout", tag], cwd=repo_dir, timeout=30)
        if outcome.timed_out:
            return False
        return outcome.returncode == 0

    def _find_dockerfile(self, repo_dir: Path) -> Path | None:
        for loc in _DOCKERFILE_LOCATIONS:
            path = repo_dir / loc
            if path.is_file():
                return path
        for name in _DOCKERFILE_GLOB_NAMES:
            for candidate in repo_dir.rglob(name):
                rel = candidate.relative_to(repo_dir)
                if not any(p in str(rel).lower() for p in _SKIP_DOCKERFILE_SUBSTRINGS):
                    return candidate
        return None

    def _read_dockerfile(self, path: Path | None) -> str | None:
        if path is None:
            return None
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return None
        # Cap at 64 KiB: real Dockerfiles are much smaller; anything bigger is
        # pathological and would bloat the tool_result payload.
        max_bytes = 64 * 1024
        if len(text) > max_bytes:
            return text[:max_bytes]
        return text

    def _find_build_config(self, repo_dir: Path) -> str | None:
        for filename, build_type in _BUILD_CONFIG_TO_TYPE.items():
            if (repo_dir / filename).is_file():
                return build_type
        return None

    def _find_devcontainer_image(self, repo_dir: Path) -> str | None:
        for rel in (_DEVCONTAINER_JSON, _DEVCONTAINER_ROOT_JSON):
            path = repo_dir / rel
            if not path.is_file():
                continue
            try:
                raw = path.read_text(encoding="utf-8")
            except OSError:
                continue
            stripped = _JSONC_BLOCK_COMMENT.sub("", raw)
            stripped = _JSONC_LINE_COMMENT.sub("", stripped)
            stripped = _JSONC_TRAILING_COMMA.sub(r"\1", stripped)
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            image = data.get("image") if isinstance(data, dict) else None
            if isinstance(image, str) and image.strip():
                return image.strip()
            continue
        return None


# -- HTTP helpers ----------------------------------------------------------


def _github_auth_headers() -> dict[str, str]:
    """Propagate GitHub auth to source_build's HTTP calls.

    Uses the shared ``resolve_github_token`` helper, which first reads
    ``GITHUB_TOKEN`` env var then falls back to ``gh auth token``. Without
    this, ``source_build``'s repo-size + tags + tarball calls hit the
    unauthenticated 60/h GitHub limit even when the user had a token set.
    """
    from cve_env.tools.github_fetch import resolve_github_token  # avoid cycle

    headers: dict[str, str] = {}
    token = resolve_github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _urlopen(req: urllib.request.Request, *, timeout: int) -> Any:
    """Perform ``urlopen`` via an opener with ``ProxyHandler({})`` so
    env-based proxy injection (``HTTP_PROXY`` / ``HTTPS_PROXY``) is defeated.

    urllib's default behaviour reads proxy env vars at ``urlopen()`` time
    via the global default opener. An attacker who controls the subprocess
    environment can route GitHub API calls through a malicious proxy.

    Note vs ``requests``: ``requests``'s ``proxies={}`` is a NO-OP (env
    vars still merge); the explicit-empty-string sentinel is required there.
    For ``urllib``, ``ProxyHandler({})`` IS sufficient to disable proxy
    lookup — different libraries, different semantics.
    """
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    return opener.open(req, timeout=timeout)


def _http_get_json(url: str, *, timeout: int) -> Any:
    if not url.startswith("https://"):
        raise ValueError(f"_http_get_json requires https:// URL, got: {url!r}")
    headers = {"Accept": "application/vnd.github+json"}
    headers.update(_github_auth_headers())
    req = urllib.request.Request(url, headers=headers)  # noqa: S310 — scheme validated above
    try:
        with _urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", 200)
            if status != 200:
                return None
            payload = resp.read(_MAX_JSON_BYTES + 1)
            if len(payload) > _MAX_JSON_BYTES:
                logger.warning(
                    "source_build: JSON response over cap %d B from %s — ignoring",
                    _MAX_JSON_BYTES,
                    url,
                )
                return None
    except urllib.error.HTTPError:
        return None
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, OSError):
            raise exc.reason from exc
        return None
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


_LINK_NEXT_RE = re.compile(r'<([^>]+)>;\s*rel="next"')


def _http_get_json_paginated(url: str, *, timeout: int) -> tuple[Any, str | None]:
    """Like :func:`_http_get_json` but also returns the ``next`` page URL
    from the ``Link`` response header (or ``None`` when there is no next page).
    """
    if not url.startswith("https://"):
        raise ValueError(
            f"_http_get_json_paginated requires https:// URL, got: {url!r}"
        )
    headers = {"Accept": "application/vnd.github+json"}
    headers.update(_github_auth_headers())
    req = urllib.request.Request(url, headers=headers)  # noqa: S310 — scheme validated above
    next_url: str | None = None
    try:
        with _urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", 200)
            if status != 200:
                return None, None
            # Parse Link header for pagination.
            link_header = resp.headers.get("Link", "")
            m = _LINK_NEXT_RE.search(link_header)
            if m:
                candidate = m.group(1)
                if candidate.startswith("https://"):
                    next_url = candidate
            payload = resp.read(_MAX_JSON_BYTES + 1)
            if len(payload) > _MAX_JSON_BYTES:
                logger.warning(
                    "source_build: JSON response over cap %d B from %s — ignoring",
                    _MAX_JSON_BYTES,
                    url,
                )
                return None, None
    except urllib.error.HTTPError:
        return None, None
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, OSError):
            raise exc.reason from exc
        return None, None
    try:
        return json.loads(payload.decode("utf-8")), next_url
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, None


def _http_get_bytes(url: str, *, timeout: int) -> bytes | None:
    if not url.startswith("https://"):
        raise ValueError(f"_http_get_bytes requires https:// URL, got: {url!r}")
    req = urllib.request.Request(url, headers=_github_auth_headers())  # noqa: S310 — scheme validated above
    try:
        with _urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", 200)
            if status != 200:
                return None
            body = resp.read(_MAX_TARBALL_BYTES + 1)
            if len(body) > _MAX_TARBALL_BYTES:
                logger.warning(
                    "source_build: tarball over cap %d B from %s — falling back to clone",
                    _MAX_TARBALL_BYTES,
                    url,
                )
                return None
    except urllib.error.HTTPError:
        return None
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, OSError):
            raise exc.reason from exc
        return None
    return body


# -- tool payload builder --------------------------------------------------

# Retained-clones registry. Each ``source_build_payload`` success retains
# its cloned tree so the agent's subsequent ``docker_build`` can read it.
# Without cleanup the trees accumulate (each ~50MB-1GB) and exhaust the
# host disk. An ``atexit`` hook removes every retained clone when the Python
# process exits.
#
# Bench-mode safety: the bench runner spawns one ``uv run cve-env build
# CVE-X`` Python process per CVE. Each process exits after its CVE
# completes -> ``atexit`` fires -> all clones from THAT CVE are removed.
# At most one CVE's worth of clones is on disk at any moment.
_RETAINED_DIRS: list[Path] = []


def _cleanup_retained_dirs() -> None:
    """Remove every directory the per-CVE process retained for source_build.

    atexit cleanup is best-effort; not called on SIGKILL. In long bench
    runs, monitor /tmp for orphaned cve-env- dirs.
    """
    while _RETAINED_DIRS:
        d = _RETAINED_DIRS.pop()
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)


atexit.register(_cleanup_retained_dirs)


def source_build_payload(
    *,
    source_url: str,
    product: str,
    version: str,
) -> dict[str, Any]:
    """One-shot entry point used by the MCP tool handler.

    Returns a JSON-serializable dict shaped for the tool_result envelope
    (the ``source_build`` handler in ``agent/tools.py`` wraps this in
    ``{"content": [{"type": "text", "text": json.dumps(...)}]}``).

    The builder RETAINS the cloned tree on success (the agent needs it
    for the subsequent ``docker_build(context_dir=...)`` call). The tree
    is registered in :data:`_RETAINED_DIRS`; an ``atexit`` hook removes
    all such trees when the Python process exits. Per-CVE bench mode
    guarantees at most one CVE's clones are on disk at a time.
    """
    builder = SourceBuilder()
    try:
        result = builder.build(
            source_url=source_url,
            product=product,
            version=version,
        )
    except Exception as exc:  # noqa: BLE001 -- surface any failure as tool payload
        builder.cleanup()
        # Symmetry with the not-result.ok failure branch below. cleanup()
        # rmtree'd anything that may have been clone'd before the exception;
        # no live path exists. Explicit repo_dir=None lets consumers use
        # tr['repo_dir'] safely instead of relying on dict.get default-None.
        return {
            "ok": False,
            "reason": "unexpected_error",
            "error": f"{type(exc).__name__}: {exc}",
            "repo_dir": None,
        }

    if not result.ok:
        # "A tag matched + tree cloned but no Dockerfile/build-config" is
        # RECOVERABLE — RETAIN the clone (it stays live) so the agent can
        # dockerfile_gen against it. Safe to echo repo_dir here precisely
        # BECAUSE we retain (not cleanup) — avoiding the stale-path crash where
        # the agent reads a repo_dir that has already been rmtree'd.
        if (
            result.checked_out_tag is not None
            and result.repo_dir is not None
            and result.repo_dir.exists()
        ):
            builder.retain()
            _RETAINED_DIRS.extend(builder._temp_dirs)
            return {
                "ok": False,
                "reason": _classify_failure(result),
                "error": result.error or "",
                "warnings": result.warnings,
                "repo_dir": str(result.repo_dir),
                "checked_out_tag": result.checked_out_tag,
                "build_config": result.build_config,
                "next_step_hint": _next_step_hint(result),
            }
        builder.cleanup()
        # cleanup() just rmtree'd the temp tree; do NOT echo repo_dir back —
        # the path is gone. Echoing a stale repo_dir crashes the agent when it
        # reads it and Bash'd `cd` into ENOENT.
        return {
            "ok": False,
            "reason": _classify_failure(result),
            "error": result.error or "",
            "warnings": result.warnings,
            "repo_dir": None,
            "checked_out_tag": result.checked_out_tag,
            "build_config": result.build_config,
            "next_step_hint": _next_step_hint(result),
        }

    builder.retain()
    _RETAINED_DIRS.extend(builder._temp_dirs)
    return {
        "ok": True,
        "repo_dir": str(result.repo_dir) if result.repo_dir else None,
        "checked_out_tag": result.checked_out_tag,
        "dockerfile_path": (
            str(result.dockerfile_path) if result.dockerfile_path else None
        ),
        "dockerfile_text": result.dockerfile_text,
        "build_config": result.build_config,
        "warnings": result.warnings,
        "next_step_hint": _next_step_hint(result),
    }


def _classify_failure(result: SourceBuildResult) -> str:
    if result.error is None:
        return "unknown"
    err = result.error.lower()
    if "not a github url" in err:
        return "not_github_url"
    if "no tag matched" in err:
        return "no_tag_matched"
    if "checkout" in err:
        return "checkout_failed"
    if result.repo_dir is None:
        return "clone_failed"
    return "no_dockerfile_or_build_config"


def _next_step_hint(result: SourceBuildResult) -> str:
    # When source_build rejected the URL because it isn't a GitHub URL
    # (OSDN.jp, GitLab.com, Bitbucket, SourceForge, Codeberg, custom git hosts,
    # …), tell the agent how to fall back via Bash without giving up. Otherwise
    # the agent burns turns searching GitHub mirrors and gives up because
    # source_build is GitHub-only; the Bash + curl + tar fallback lets it
    # attempt the source-overlay path.
    if result.error and "not a github url" in result.error.lower():
        # Recipes live in the system prompt's cascade (canonical location);
        # this hint just points there so the agent uses the cascade rather than
        # giving up.
        return (
            "non-GitHub URL — source_build is GitHub-only. PIVOT via the "
            "Phase 40 cascade in the system prompt: GitLab/Bitbucket/Codeberg "
            "via Bash + `git clone --depth=1 --branch=<tag> <https-url>`; "
            "OSDN/SourceForge via Bash + `curl -sSL ... | tar -xz` (use "
            "/download suffix on SourceForge URLs). Then dockerfile_gen with "
            "copy_ops to overlay onto a host image. Do NOT give_up(no_image)."
        )
    if result.dockerfile_text is not None:
        return (
            "call docker_build(context_dir=repo_dir, "
            "dockerfile_text=<dockerfile_text above>, image_tag=...)"
        )
    if result.build_config is not None:
        return (
            f"no Dockerfile in repo; call dockerfile_gen with build_config="
            f"{result.build_config!r}, then docker_build"
        )
    # A tag DID match + the tree is cloned, but the repo has no
    # Dockerfile/build-config. This is recoverable — the clone is on disk;
    # point the agent at dockerfile_gen against it (otherwise the fall-through
    # hint below misleadingly says "no tag matched" and the agent quits).
    if result.checked_out_tag is not None and result.repo_dir is not None:
        return (
            f"tag {result.checked_out_tag!r} checked out — the clone is on disk at "
            "repo_dir but the repo has no Dockerfile/build-config. Call dockerfile_gen "
            "with context_dir=repo_dir (so its auto-build (b1) targets the clone, NOT "
            "an empty context) — it builds against the clone in the SAME call; then "
            "docker_run. Do NOT give_up — the source is already cloned."
        )
    # no_tag_matched must suggest dockerfile_gen, not give_up: the agent may
    # otherwise follow "no next step; give_up" literally and skip
    # dockerfile_gen even though the source is already cloned. The CVE can
    # still succeed via dockerfile_gen with RUN git clone.
    return (
        "no tag matched; call dockerfile_gen with install_steps containing "
        "'RUN git clone --depth=1 <source_url>' to build from source, "
        "or stage source via Bash then COPY into the image. "
        "Alternatively re-try source_build with an explicit version tag."
    )


__all__ = [
    "SourceBuildConfig",
    "SourceBuildResult",
    "SourceBuilder",
    "find_version_tag",
    "normalize_github_url",
    "source_build_payload",
]
