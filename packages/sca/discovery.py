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

    # Ruby
    "Gemfile": "RubyGems",
    "Gemfile.lock": "RubyGems",

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
) -> List[Manifest]:
    """Walk repo finding manifests + lockfiles.

    Args:
        repo: project root (absolute or relative; resolved before walking).
        max_depth: soft cap on directory depth from repo root.
        extra_excludes: directory names to skip in addition to the default.

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

    excludes = EXCLUDED_DIR_NAMES | (extra_excludes or set())
    found: List[Manifest] = []

    for path in _walk(repo, max_depth=max_depth, excludes=excludes):
        eco = _classify(path)
        if eco is None:
            continue
        is_lock = path.name in LOCKFILE_NAMES
        found.append(Manifest(
            path=path,
            ecosystem=eco,
            is_lockfile=is_lock,
            workspace_root=None,  # populated by parser pass that knows
                                  # the workspace conventions
        ))

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

    # os.walk(followlinks=False) is the canonical no-follow walk.
    # We mutate dirnames in-place to prune the descent.
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

        for fn in filenames:
            yield cur / fn


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
    # Inline-install sources (Dockerfile / devcontainer / shell / GHA).
    # The actual ecosystem of each emitted dep is set by the parser,
    # since one file can mix pip and apt installs.
    if _is_inline_install_source(path):
        return "Inline"
    return None
