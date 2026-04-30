"""
Classify a diff by the shape of its changed files.

Motivation: Phase 2 gate (data/baselines/phase2_gate.md) surfaced that several
Phase-1-passing CVEs landed on distro packaging mirrors or projects that only
bumped a submodule / version string when a vendor released a patched upstream.
The diff is technically "real" but it doesn't contain the upstream fix. This
module lets the pipeline flag those cases as low-confidence.

Three shapes:
  - "source"          : at least one changed file is source code
  - "packaging_only"  : only packaging / version-manifest / submodule files changed
  - "notes_only"      : only release-notes / changelog files changed (a strict
                        subset of packaging_only — kept separate because it's
                        the most extreme form: no code change at all)
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

_NOTES_NAMES = frozenset({
    "CHANGELOG", "CHANGELOG.md", "CHANGELOG.rst", "CHANGELOG.txt",
    "CHANGES", "CHANGES.md", "CHANGES.rst", "CHANGES.txt",
    "NEWS", "NEWS.md", "NEWS.rst",
    "HISTORY", "HISTORY.md", "HISTORY.rst",
    "RELEASE_NOTES.md", "RELEASE-NOTES.md", "ReleaseNotes.md",
})

_NOTES_DIR_RE = re.compile(
    r"(?i)(^|/)(relnotes|releasenotes|release_notes|changelog|changelogs|"
    r"release-notes|notes)/"
)

_PACKAGING_NAMES = frozenset({
    "VERSION", "version", "VERSION.txt", ".version",
    "configure.ac", "configure", "Makefile.am",
    "Dockerfile", ".dockerignore",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "go.mod", "go.sum",
    "Cargo.toml", "Cargo.lock",
    "Gemfile", "Gemfile.lock",
    "requirements.txt", "setup.py", "setup.cfg", "pyproject.toml", "Pipfile",
    "Pipfile.lock", "poetry.lock",
    # Maven / Gradle: release-bump commits land here on jvm CVEs.
    "pom.xml",
    "build.gradle", "build.gradle.kts",
    "settings.gradle", "settings.gradle.kts",
    "gradle.properties",
    # PHP Composer and CMake — same intrinsic bridge as the above.
    "composer.json", "composer.lock", "CMakeLists.txt",
    ".gitmodules",
})

_PACKAGING_SUFFIXES = (
    ".spec",       # RPM
    ".nuspec",     # NuGet
)

_PACKAGING_DIR_RE = re.compile(
    r"(?i)(^|/)(debian|rpm|SPECS|SOURCES|packaging|"
    r"rpm-build|alpine|nix|nixpkgs)/"
)


def _classify_one(path: str) -> str:
    """Return 'notes' | 'packaging' | 'source' for a single file path."""
    p = PurePosixPath(path)
    name = p.name

    if name in _NOTES_NAMES:
        return "notes"
    if _NOTES_DIR_RE.search(path):
        return "notes"
    if name in _PACKAGING_NAMES:
        return "packaging"
    if any(path.endswith(sfx) for sfx in _PACKAGING_SUFFIXES):
        return "packaging"
    if _PACKAGING_DIR_RE.search(path):
        return "packaging"
    return "source"


def classify(files: list[str]) -> str:
    """Classify a diff by its set of changed file paths."""
    if not files:
        return "source"
    categories = {_classify_one(f) for f in files}
    if categories == {"notes"}:
        return "notes_only"
    if categories <= {"notes", "packaging"}:
        return "packaging_only"
    return "source"
