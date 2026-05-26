"""Manifest + lockfile discovery.

Walks a target repo finding files the parsers know about. Skips vendored
trees, doesn't follow symlinks, soft-caps depth.

Output: List[Manifest], one per discovered file. The parsers are keyed by
filename in parsers/__init__.py; discovery is parser-agnostic — it just
identifies candidates.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Iterator, List, Optional, Set

from .models import Manifest

logger = logging.getLogger(__name__)

# Directory names skipped at any depth in the tree.
# These are package install dirs, build outputs, VCS metadata, editor
# state. Skipping them is a 10-100x speedup on real repos and avoids
# treating vendored copies as direct deps.
EXCLUDED_DIR_NAMES: Set[str] = {
    # Per-ecosystem package install dirs
    "node_modules",
    "vendor",
    "bower_components",
    # NB: ``packages`` is NOT excluded — it's a legitimate top-level
    # directory in many monorepos (raptor, rush, lerna, etc.). Skipping
    # it silently dropped real manifests in the wild.

    # VCS
    ".git",
    ".svn",
    ".hg",

    # Build outputs
    "target",
    "build",
    "dist",
    "out",
    "_build",

    # Python virtualenvs / caches
    "__pycache__",
    ".tox",
    ".venv",
    "venv",
    ".env",        # virtualenvs sometimes named '.env'
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",

    # Tooling state
    ".gradle",
    ".idea",
    ".vscode",
    ".angular",
    ".next",
    ".nuxt",
    ".cache",
    ".turbo",
    ".claude",         # Claude Code agent worktrees + ephemeral state
    "codeql_dbs",      # CodeQL DB cache — 10K+ index files per database
    "codeql_db",       # singular variant used by some configurations
}

# Filenames that hint a directory is dependency-related junk we should
# skip even when the dir name itself is innocuous.
# (Reserved for future use; currently empty.)
_TRIPWIRE_FILES: Set[str] = set()

# Map of filename -> ecosystem identifier.
# Lockfile detection is a separate flag — see _is_lockfile.
# Multi-ecosystem files (some package.json variants) are disambiguated
# at parse time, not here.
MANIFEST_FILENAMES = {
    # Java / Maven / Gradle
    "pom.xml": "Maven",
    "build.gradle": "Maven",       # Gradle uses Maven artifact coordinates
    "build.gradle.kts": "Maven",
    "settings.gradle": "Maven",
    "settings.gradle.kts": "Maven",
    "gradle.lockfile": "Maven",

    # Python
    "requirements.txt": "PyPI",
    "pyproject.toml": "PyPI",
    "Pipfile": "PyPI",
    "Pipfile.lock": "PyPI",
    "poetry.lock": "PyPI",
    "uv.lock": "PyPI",
    "setup.py": "PyPI",            # legacy; lower-priority parser
    "setup.cfg": "PyPI",            # legacy

    # Node.js
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "shrinkwrap.json": "npm",

    # Rust (cargo.py)
    "Cargo.toml": "Cargo",
    "Cargo.lock": "Cargo",

    # Go
    "go.mod": "Go",
    "go.sum": "Go",

    # Ruby — bare ``Gemfile`` here; ``Gemfile.lock*`` variants
    # (incl. ManageIQ's ``Gemfile.lock.release``, migration-time
    # ``Gemfile.lock.next``) are routed via ``_is_gemfile_lock_variant``.
    "Gemfile": "RubyGems",

    # .NET
    # *.csproj/*.fsproj/*.vbproj are pattern-matched; see _walk()
    "packages.config": "NuGet",
    "packages.lock.json": "NuGet",

    # PHP
    "composer.json": "Packagist",
    "composer.lock": "Packagist",

    # C / C++ — vcpkg manifest mode + Conan + git submodules.
    # Conan and vcpkg are queried via OSV's ``ConanCenter`` /
    # ``vcpkg`` ecosystems. ``.gitmodules`` rows aren't OSV-
    # queryable today (no ``Git`` ecosystem); they appear in the
    # SBOM for visibility but the report's CVE matcher skips
    # them. The discovery layer needs them registered so the
    # parser dispatcher routes correctly.
    "vcpkg.json": "vcpkg",
    "conanfile.txt": "ConanCenter",
    "conanfile.py": "ConanCenter",
    "conan.lock": "ConanCenter",
    ".gitmodules": "GitHub",       # SCA-internal — see gitmodules.py
    # CMake FetchContent_Declare blocks. Ecosystem is "GitHub" or
    # "CMake-FetchContent" per-dep; the discovery classification
    # here is just for "this file may yield dep rows" — the parser
    # decides per-row.
    "CMakeLists.txt": "CMake-FetchContent",

    # CI / dev-tooling — pre-commit hook configs. The parser
    # resolves each ``repo:`` URL to its underlying registry
    # package via ``data/precommit_repo_map.json``; emitted deps
    # carry ``ecosystem="PyPI"`` / ``"npm"`` / ``"RubyGems"`` /
    # ``"GitHub"`` (fallback) per row. The classification here is
    # a placeholder ecosystem — the per-Dependency ``ecosystem``
    # field is what matters for OSV.
    ".pre-commit-config.yaml": "PreCommit",
    ".pre-commit-config.yml": "PreCommit",

    # Cloud-native deployment artefacts. Same SCA-internal-
    # placeholder convention — parsers emit per-Dependency
    # ``ecosystem`` (``"Helm"`` / ``"OCI"``) which is what feeds
    # downstream. ``OCI`` rows currently appear in the SBOM for
    # visibility but the report's CVE matcher skips them; the
    # B9-fetcher unification follow-up will hook them into the
    # OS-package SBOM pipeline.
    "Chart.yaml": "Helm",
    "Chart.lock": "Helm",
    ".gitlab-ci.yml": "GitLabCI",
    ".gitlab-ci.yaml": "GitLabCI",
}

# Filenames that match additional patterns (extension-based).
PATTERN_FILENAMES = {
    ".csproj": "NuGet",
    ".fsproj": "NuGet",
    ".vbproj": "NuGet",
}

# Lockfile flag — these are resolved-version sources of truth.
LOCKFILE_NAMES: Set[str] = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "shrinkwrap.json",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "Cargo.lock",
    "go.sum",
    "Gemfile.lock",
    "packages.lock.json",
    "composer.lock",
    "gradle.lockfile",
    "conan.lock",
}

# Requirements*.txt convention — anything matching `requirements*.txt`
# is treated as a PEP 508 requirements file.
def _is_requirements_variant(name: str) -> bool:
    return name.startswith("requirements") and name.endswith(".txt")


# Gemfile.lock variants — ManageIQ ships ``Gemfile.lock.release``
# (gitignored dev lock, release-time copy committed to the tag);
# some Rails monoliths use ``Gemfile.lock.next`` during gem upgrades.
# Identical byte-for-byte format. ``Gemfile.modules`` (a DSL fragment,
# NOT a lockfile — used by OpenProject) is excluded by the ``.lock``
# substring check.
def _is_gemfile_lock_variant(name: str) -> bool:
    return name.startswith("Gemfile.lock")


# Inline-install source shapes — Dockerfile, devcontainer.json, shell
# scripts, GHA workflows. These aren't manifests in the traditional sense;
# they're files that *contain* install commands. The parser dispatcher
# (``inline_installs``) extracts pip / apt / yum / dnf / apk lines.
#
# Ecosystem is reported as "Inline" because a single Dockerfile can contain
# both PyPI and Debian installs — the per-Dependency ``ecosystem`` field
# is what matters for OSV lookups.
def _is_inline_install_source(path: Path) -> bool:
    name = path.name
    if name in ("Dockerfile", "Containerfile",
                "devcontainer.json", ".devcontainer.json"):
        return True
    if name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
        return True
    if path.suffix in (".dockerfile", ".sh", ".bash"):
        return True
    if path.suffix in (".yml", ".yaml"):
        parts = path.parts
        # ``.github/workflows/*.yml`` — workflows at any depth.
        for j in range(len(parts) - 2):
            if parts[j] == ".github" and parts[j + 1] == "workflows":
                return True
        # Composite actions: ``action.yml`` / ``action.yaml`` at the
        # repo root (when the repo IS an action) or under any
        # ``.github/actions/<name>/`` directory. They carry the same
        # ``uses:`` and ``run:`` shapes the workflow parser already
        # handles.
        if name in ("action.yml", "action.yaml"):
            return True
    return False


# Default soft cap on tree depth. Most real repos have <6 levels.
DEFAULT_MAX_DEPTH = 10


def find_manifests(
    repo: Path,
    max_depth: int = DEFAULT_MAX_DEPTH,
    extra_excludes: Optional[Set[str]] = None,
    include_test_paths: bool = False,
) -> List[Manifest]:
    """Walk repo finding manifests + lockfiles.

    Args:
        repo: project root (absolute or relative; resolved before walking).
        max_depth: soft cap on directory depth from repo root.
        extra_excludes: directory names to skip in addition to the default.
        include_test_paths: if True, include manifests under ``tests/`` /
            ``__tests__/`` / etc. Default False because real-world test
            fixtures regularly contain synthetic stress-test manifests
            (e.g. Semgrep ships ``cli/tests/performance/targets_perf_sca/
            100k/Gemfile.lock`` with 100,000 fake gem names) which SCA
            would otherwise treat as real dependencies and query the
            upstream registry for. The May 2026 200-project sweep
            against Semgrep surfaced 23,000+ bogus rubygems.org queries
            for ``package0`` through ``package99999``.

    Returns:
        List of Manifest, one per discovered file. Order is deterministic
        (sorted by path) so test outputs are stable.

    Raises:
        FileNotFoundError if `repo` doesn't exist.
    """
    repo = repo.resolve(strict=False)
    if not repo.exists():
        raise FileNotFoundError(f"target does not exist: {repo}")
    if not repo.is_dir():
        raise NotADirectoryError(f"target is not a directory: {repo}")

    # Scan-boundary cache reset: parsers with per-process caches
    # (CPM, Gradle catalog) clear here so a stale parse from a
    # previous scan on a different target can't leak across runs.
    # Within this scan the caches are retained — csproj parsers
    # walking up to the same Directory.Packages.props don't re-
    # parse the file once per csproj.
    from .parsers import directory_packages_props as _cpm
    from .parsers import gradle_version_catalog as _gvc
    _cpm.reset_cache()
    _gvc.reset_cache()

    excludes = EXCLUDED_DIR_NAMES | (extra_excludes or set())
    found: List[Manifest] = []

    # Test-path filtering is deferred until after classification so a
    # rejected path doesn't pay the parse-classification cost twice.
    # Imported lazily to avoid a circular dep at module-import time.
    if not include_test_paths:
        from ._test_paths import is_test_path
    else:
        is_test_path = None

    sln_paths: List[Path] = []
    for path in _walk(repo, max_depth=max_depth, excludes=excludes):
        eco = _classify(path)
        if eco is None:
            # Track .sln separately — it's a discovery aid, not
            # a manifest. Out-of-tree csproj referenced from a
            # .sln get pulled in below for solution graph
            # completeness (monorepos where ``src/A/A.sln``
            # references ``src/Shared/Shared.csproj`` etc.).
            if path.suffix.lower() == ".sln":
                sln_paths.append(path)
            continue
        if is_test_path is not None and is_test_path(path, repo):
            continue
        is_lock = (path.name in LOCKFILE_NAMES
                   or _is_gemfile_lock_variant(path.name))
        found.append(Manifest(
            path=path,
            ecosystem=eco,
            is_lockfile=is_lock,
            workspace_root=None,  # populated by parser pass that knows
                                  # the workspace conventions
        ))

    # Visual Studio solution (.sln) graph enrichment. csproj files
    # referenced from a .sln but living outside the rglob tree
    # (typical in monorepos with sibling-shared projects) are
    # otherwise invisible to SCA. Dedupe against the rglob-found
    # set; apply the same test-path filter as the primary walk.
    if sln_paths:
        from .parsers.sln import find_sln_referenced_csprojs
        already_seen = {m.path for m in found}
        for sln in sln_paths:
            for csproj in find_sln_referenced_csprojs(
                sln, repo_root=repo,
            ):
                if csproj in already_seen:
                    continue
                if is_test_path is not None and is_test_path(csproj, repo):
                    continue
                csproj_eco = _classify(csproj)
                if csproj_eco is None:
                    continue
                found.append(Manifest(
                    path=csproj, ecosystem=csproj_eco,
                    is_lockfile=False, workspace_root=None,
                ))
                already_seen.add(csproj)

    # Deterministic ordering for stable test output.
    found.sort(key=lambda m: (str(m.path),))
    logger.info("sca.discovery: found %d manifest candidates under %s",
                len(found), repo)
    return found


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _walk(root: Path, max_depth: int, excludes: Set[str]) -> Iterator[Path]:
    """Walk root yielding paths, honouring exclusions, no symlink follow."""
    root_str = str(root)
    root_depth = len(root.parts)

    # os.walk(followlinks=False) is the canonical no-follow walk —
    # but it still LISTS symlinks in ``filenames``, just doesn't
    # descend through them. A ``requirements.txt`` that's a symlink
    # to ``/etc/passwd`` would still be yielded and parsed without
    # the per-file reject below. Two failure modes worth blocking:
    #
    #   1. Operator-visible noise: a shared workspace
    #      ``requirements.txt`` symlinked into a project tree
    #      gets flagged against the wrong project.
    #   2. Confused-deputy disclosure: parser output flows into
    #      LLM prompts; symlinks pointing at host filesystem
    #      (``/etc/*``, ``~/.aws/credentials``) leak via prompt.
    #
    # Reject symlinks at file level AND at any parent directory —
    # the file itself may not be a symlink even when reached via
    # a symlinked parent.
    for dirpath, dirnames, filenames in os.walk(root_str, followlinks=False):
        cur = Path(dirpath)
        depth = len(cur.parts) - root_depth
        if depth >= max_depth:
            # Don't recurse further; still yield files at this depth.
            dirnames[:] = []
        elif _is_composite_actions_parent(cur):
            # Inside ``.github/actions/`` — don't apply the
            # generic exclude list. Composite-action directories
            # commonly use names like ``build`` / ``setup`` /
            # ``dist`` / ``out`` that collide with EXCLUDED_DIR_NAMES;
            # pruning them silently drops the embedded
            # ``action.yml``.
            pass
        else:
            # In-place prune.
            dirnames[:] = [d for d in dirnames if not _should_skip_dir(d, excludes)]

        # Per-iteration: refuse if any parent on the path between
        # ``root`` and ``cur`` is a symlink. Walked once per dir
        # rather than per-file so a deep symlink-rooted subtree
        # doesn't pay the stat cost on every yielded file.
        parent_symlinked = False
        check = cur
        while check != root and check.parent != check:
            try:
                if check.is_symlink():
                    parent_symlinked = True
                    break
            except OSError:
                parent_symlinked = True
                break
            check = check.parent
        if parent_symlinked:
            continue

        for fn in filenames:
            p = cur / fn
            try:
                if p.is_symlink():
                    continue
            except OSError:
                continue
            yield p


def _is_composite_actions_parent(cur: Path) -> bool:
    """True when ``cur`` is the ``.github/actions`` directory whose
    immediate children are individual composite-action folders."""
    parts = cur.parts
    return (
        len(parts) >= 2
        and parts[-1] == "actions"
        and parts[-2] == ".github"
    )


def _should_skip_dir(name: str, excludes: Set[str]) -> bool:
    """Return True if a directory name matches an exclusion.

    Also matches the ephemeral PEP 668 venv directory left behind if a
    crashed prior run didn't clean up — the resolver creates these as
    ``.raptor-sca-venv-<pid>`` so the suffix varies per run.
    """
    if name.startswith(".raptor-sca-venv-"):
        return True
    if name.startswith(".") and name in excludes:
        return True
    return name in excludes


def _classify(path: Path) -> Optional[str]:
    """Return the ecosystem string for a path, or None if not a manifest."""
    name = path.name
    if name in MANIFEST_FILENAMES:
        return MANIFEST_FILENAMES[name]
    # Extension-based patterns (csproj/fsproj/vbproj)
    suffix = path.suffix
    if suffix in PATTERN_FILENAMES:
        return PATTERN_FILENAMES[suffix]
    # requirements*.txt convention
    if _is_requirements_variant(name):
        return "PyPI"
    # Gemfile.lock + release-time variants (Gemfile.lock.release / .next)
    if _is_gemfile_lock_variant(name):
        return "RubyGems"
    # Inline-install sources (Dockerfile / devcontainer / shell / GHA).
    # The actual ecosystem of each emitted dep is set by the parser,
    # since one file can mix pip and apt installs.
    if _is_inline_install_source(path):
        return "Inline"
    # Docker Compose / overlay variants. ``docker-compose.dev.yml``
    # etc. — too many shapes for static MANIFEST_FILENAMES; matched
    # by predicate.
    if _is_compose_file(name):
        return "OCI"
    # Kubernetes manifests — content-sniffed by the parser
    # (top-level ``kind:`` must match a workload). Discovery
    # speculatively routes any otherwise-unclassified YAML through
    # the parser; the parser returns [] for non-workload YAMLs.
    if path.suffix.lower() in (".yml", ".yaml"):
        return "Kubernetes"
    return None


def _is_compose_file(name: str) -> bool:
    """Match ``compose.yml`` / ``compose.yaml`` /
    ``docker-compose*.yml`` / ``compose.<overlay>.yml``."""
    lower = name.lower()
    if not (lower.endswith(".yml") or lower.endswith(".yaml")):
        return False
    if lower.startswith("docker-compose"):
        return True
    if lower == "compose.yml" or lower == "compose.yaml":
        return True
    if lower.startswith("compose."):
        return True
    return False
