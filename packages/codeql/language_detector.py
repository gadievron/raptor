#!/usr/bin/env python3
"""
Language Detection for CodeQL

Automatically detects programming languages in a repository
to determine which CodeQL databases need to be created.
"""

import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

# Add parent directory to path for imports
# packages/codeql/language_detector.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[2]))

from core.logging import get_logger

logger = get_logger()


@dataclass
class LanguageInfo:
    """Information about detected language."""
    language: str
    confidence: float  # 0.0 - 1.0
    file_count: int
    extensions_found: set[str]
    build_files_found: list[str]
    indicators_found: list[str]
    total_lines: int = 0


class LanguageDetector:
    """
    Autonomous language detection for CodeQL database creation.

    Scans repository and identifies languages with confidence scores
    based on file extensions, build files, and structural indicators.
    """

    # Language patterns with extensions, build files (exact-name and
    # ``build_file_suffixes`` suffix-matched, e.g. ``*.csproj``), and
    # structural indicators.
    #
    # ``min_confidence`` is the gate that keeps stray build manifests
    # (e.g. a ``pom.xml`` in a docs example dir, a meta-repo
    # ``package.json`` with no JS/TS source) from forcing a detection.
    # With ``file_count=0`` the confidence math caps at ~0.2 (build-file
    # boost only, no base or ratio). Every value here is >=0.5 by
    # design — DO NOT lower any of these below 0.3 without re-deriving
    # the manifest-only ceiling in ``_analyze_language``. The
    # build-manifest-promotion path (gh #548) relies on this gap.
    LANGUAGE_PATTERNS: ClassVar[dict[str, dict]] = {
        "java": {
            "extensions": {".java"},
            "build_files": {"pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "gradlew"},
            "build_file_suffixes": (),
            "indicators": {"src/main/java/", "src/test/java/"},
            "min_confidence": 0.5,
        },
        "python": {
            "extensions": {".py"},
            "build_files": {"setup.py", "pyproject.toml", "requirements.txt", "Pipfile", "poetry.lock", "setup.cfg"},
            "build_file_suffixes": (),
            "indicators": {"__init__.py", "__main__.py"},
            "min_confidence": 0.5,
        },
        "javascript": {
            "extensions": {".js", ".jsx", ".mjs", ".cjs"},
            "build_files": {"package.json", "package-lock.json", "yarn.lock", "webpack.config.js", ".npmrc"},
            "build_file_suffixes": (),
            "indicators": {"node_modules/", "src/", "dist/"},
            "min_confidence": 0.5,
        },
        "typescript": {
            "extensions": {".ts", ".tsx"},
            "build_files": {"tsconfig.json", "package.json"},
            "build_file_suffixes": (),
            "indicators": {"src/", "dist/"},
            "min_confidence": 0.5,
        },
        "go": {
            "extensions": {".go"},
            "build_files": {"go.mod", "go.sum", "go.work"},
            "build_file_suffixes": (),
            "indicators": {"main.go", "cmd/", "pkg/"},
            "min_confidence": 0.6,
        },
        "cpp": {
            "extensions": {".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".hxx"},
            "build_files": {"CMakeLists.txt", "Makefile", "configure", "meson.build", "makefile"},
            "build_file_suffixes": (),
            "indicators": {"src/", "include/"},
            "min_confidence": 0.5,
        },
        "csharp": {
            "extensions": {".cs"},
            "build_files": {"packages.config", "nuget.config"},
            "build_file_suffixes": (".csproj", ".sln"),
            "indicators": {"Properties/", "bin/", "obj/"},
            "min_confidence": 0.6,
        },
        "ruby": {
            "extensions": {".rb"},
            "build_files": {"Gemfile", "Gemfile.lock", "Rakefile"},
            "build_file_suffixes": (".gemspec",),
            "indicators": {"lib/", "spec/", "test/"},
            "min_confidence": 0.6,
        },
        "swift": {
            "extensions": {".swift"},
            "build_files": {"Package.swift", "Podfile"},
            "build_file_suffixes": (),
            "indicators": {"Sources/", "Tests/"},
            "min_confidence": 0.7,
        },
        "kotlin": {
            "extensions": {".kt", ".kts"},
            "build_files": {"build.gradle.kts", "settings.gradle.kts"},
            "build_file_suffixes": (),
            "indicators": {"src/main/kotlin/", "src/test/kotlin/"},
            "min_confidence": 0.6,
        },
    }

    # CodeQL supported languages (as of 2024)
    CODEQL_SUPPORTED: ClassVar[set[str]] = {
        "java", "python", "javascript", "typescript", "go",
        "cpp", "csharp", "ruby", "swift", "kotlin"
    }

    # Directories to ignore during scanning
    IGNORE_DIRS: ClassVar[set[str]] = {
        ".git", ".svn", ".hg", ".bzr",
        "node_modules", "venv", "env", ".venv", ".env",
        "__pycache__", ".pytest_cache", ".mypy_cache",
        "target", "build", "dist", "out", "bin", "obj",
        ".gradle", ".mvn", ".idea", ".vscode", ".vs",
        "vendor", "bower_components",
        # NOTE: `packages` was previously listed here but removed
        # — many real user repos have a top-level `packages/`
        # directory containing actual source (npm workspaces,
        # Lerna monorepos, pnpm workspaces, custom Python
        # multi-package layouts including RAPTOR itself). Pre-fix
        # the language detector skipped them entirely, producing
        # zero-language detection for monorepos and forcing
        # operators to manually --language override. Remove
        # from ignore set; rely on the more specific
        # `node_modules` / `__pycache__` / `vendor` entries to
        # exclude vendored content.
    }

    # Files to ignore (exact name match)
    IGNORE_FILES: ClassVar[set[str]] = {
        ".DS_Store", "Thumbs.db", ".gitignore", ".dockerignore",
    }
    # File suffixes to ignore (endswith match)
    IGNORE_SUFFIXES = (".lock", ".min.js", ".bundle.js")

    def __init__(self, repo_path: Path, max_files: int = 10000):
        """
        Initialize language detector.

        Args:
            repo_path: Path to repository
            max_files: Maximum files to scan (performance limit)
        """
        self.repo_path = Path(repo_path)
        self.max_files = max_files

        if not self.repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")
        if not self.repo_path.is_dir():
            raise ValueError(f"Repository path is not a directory: {repo_path}")

    def detect_languages(self, min_files: int = 3) -> dict[str, LanguageInfo]:
        """
        Detect all languages in repository with confidence scores.

        Args:
            min_files: Minimum source files required when no build
                manifest is present. Languages with a matching build
                manifest (``go.mod``, ``pom.xml``, ``package.json``,
                etc.) are detected regardless of source-file count,
                provided the per-language confidence threshold is met
                (gh #548).

        Returns:
            Dict mapping language name -> LanguageInfo
        """
        logger.info("Detecting languages in: %s", self.repo_path)

        # Scan repository and collect statistics
        stats = self._scan_repository()

        # Calculate confidence scores for each language
        detected = {}
        for lang, patterns in self.LANGUAGE_PATTERNS.items():
            info = self._analyze_language(lang, patterns, stats)

            # `min_files` exists to filter out false positives from stray
            # source files. A matching build manifest defeats that risk
            # on its own — see gh #548, where a real Go API with 2 .go
            # files + go.mod was silently dropped under the old `>=3`
            # gate. `min_confidence` still protects against stray
            # manifests alone (e.g. a `pom.xml` in a docs example dir):
            # a manifest without matching source extensions yields
            # confidence ~0.2, below every language's per-pattern
            # threshold.
            has_build_signal = bool(info.build_files_found)
            meets_threshold = info.file_count >= min_files or has_build_signal
            meets_confidence = info.confidence >= patterns["min_confidence"]

            if meets_threshold and meets_confidence:
                detected[lang] = info
                logger.info(
                    "✓ Detected %s: %s files, confidence=%.2f",
                    lang,
                    info.file_count,
                    info.confidence
                )
            elif info.file_count > 0 or has_build_signal:
                # Language had *some* signal but didn't pass — flag
                # loudly so operators don't silently skip languages
                # they expect to be covered. Quiet path is reserved
                # for languages with zero presence in the repo.
                # (gh #548)
                logger.warning(
                    "⚠ Skipping %s: file_count=%s (min=%s), confidence=%.2f (min=%s), build_files=%s",
                    lang,
                    info.file_count,
                    min_files,
                    info.confidence,
                    patterns['min_confidence'],
                    sorted(info.build_files_found) or 'none'
                )

        if not detected:
            logger.warning("No languages detected that meet minimum criteria")
        else:
            logger.info("Total languages detected: %d", len(detected))

        return detected

    def detect_languages_floor(self, floor: int = 2) -> dict[str, LanguageInfo]:
        """
        Last-resort detection tier — include any language with at least
        ``floor`` source files, **ignoring the per-language confidence
        threshold**. Logs a loud WARNING per language so the operator
        knows the scan is running on low-confidence detection.

        Use only when ``detect_languages`` has already returned empty
        with min_files=1 — i.e. the target has source code present but
        no build manifests or structural indicators that would let
        confidence clear the gate. Fixture / vendored trees (multi-
        language, no build files by design) and minimal repros land
        here. Caller is responsible for ordering: floor detection is
        a fallback, not a default.

        Args:
            floor: Minimum source files required per language. Default 2
                — high enough to filter out a single stray file from
                another language, low enough to admit minimal repros.

        Returns:
            Dict mapping language name -> LanguageInfo for languages
            meeting only the file-count floor.
        """
        logger.info(
            "Detecting languages in: %s (floor tier, floor=%s, ignoring confidence gate)",
            self.repo_path,
            floor
        )
        stats = self._scan_repository()

        detected = {}
        for lang, patterns in self.LANGUAGE_PATTERNS.items():
            info = self._analyze_language(lang, patterns, stats)
            if info.file_count >= floor:
                detected[lang] = info
                logger.warning(
                    "⚠ Floor-tier include %s: file_count=%s (floor=%s), confidence=%.2f (would-be-min=%s), build_files=%s — low-confidence detection, verify scan results",
                    lang,
                    info.file_count,
                    floor,
                    info.confidence,
                    patterns['min_confidence'],
                    sorted(info.build_files_found) or 'none'
                )

        if not detected:
            logger.warning(
                "No languages detected even at floor=%s; target has no scannable source code",
                floor
            )
        else:
            logger.info("Floor-tier detected: %d language(s)", len(detected))

        return detected

    def _scan_repository(self) -> dict:
        """
        Scan repository and collect file statistics.

        Returns:
            Dictionary with extension counts, build files, and indicators
        """
        stats = {
            "extensions": defaultdict(int),
            "build_files": set(),
            "indicators": set(),
            "total_files": 0,
            "scanned_files": 0,
        }

        # Hoist the pattern aggregates out of the per-file loop — they
        # are class-constant derived and were previously rebuilt for
        # every scanned file.
        build_files = self._get_all_build_files()
        build_suffixes = self._get_all_build_suffixes()
        indicators = self._get_all_indicators()

        pruned_dirs: list[str] = []
        try:
            for file_path in self._walk_repository(pruned_dirs):
                stats["scanned_files"] += 1

                # Check for build files (exact name or suffix)
                fname = file_path.name
                if fname in build_files or fname.endswith(build_suffixes):
                    stats["build_files"].add(fname)

                # Check for structural indicators
                relative = file_path.relative_to(self.repo_path).as_posix()
                for indicator in indicators:
                    if self._indicator_matches(indicator, relative):
                        stats["indicators"].add(indicator)

                # Count extensions
                if file_path.suffix:
                    stats["extensions"][file_path.suffix] += 1

                stats["total_files"] += 1

                # Performance limit
                if stats["scanned_files"] >= self.max_files:
                    logger.warning(
                        "Reached max file scan limit (%s), detection may be incomplete",
                        self.max_files
                    )
                    break

        except Exception as e:  # noqa: BLE001 — detection is best-effort; a scan error degrades to partial stats, never a crash
            logger.error("Error scanning repository: %s", e)

        # Ignored directories are pruned from the descent, so files
        # under a real node_modules/, dist/, bin/ or obj/ never reach
        # the loop above — but the directory's *presence* is exactly
        # the structural evidence those indicators encode. Match
        # indicators against the pruned directory paths directly.
        for rel_dir in pruned_dirs:
            for indicator in indicators:
                if self._indicator_matches(indicator, rel_dir):
                    stats["indicators"].add(indicator)

        logger.debug("Scanned %s files", stats['scanned_files'])
        return stats

    @staticmethod
    def _indicator_matches(indicator: str, relative_path: str) -> bool:
        """Match a structural indicator on path-segment boundaries.

        A plain substring test lets lookalike names inflate confidence:
        ``redist/`` would match ``dist/``, ``sbin/`` would match
        ``bin/``, ``domain.go`` would match ``main.go``. Anchor the
        indicator so it only matches whole path segments.
        """
        if indicator.endswith("/"):
            # Directory indicator: must start a segment run at the
            # path root or immediately after a separator.
            return relative_path.startswith(indicator) or "/" + indicator in relative_path
        # File-name indicator: must be a complete final segment.
        return relative_path == indicator or relative_path.endswith("/" + indicator)

    def _walk_repository(self, pruned_dirs: list[str] | None = None):
        """Walk repository while respecting ignore patterns.

        Uses `os.walk` with in-place `dirnames` pruning so we
        DON'T descend into ignored directories. Pre-fix `rglob`
        walked the entire tree first then post-filtered via `if
        any(ignored in path.parts)` — for repos with
        `node_modules` (millions of files), `__pycache__`, or
        large `target/` builds, that meant enumerating those
        files just to discard them, taking minutes on monorepos.
        os.walk + dirnames-prune skips the descent entirely.

        Args:
            pruned_dirs: Optional accumulator. Receives the repo-
                relative path (with trailing ``/``) of every ignored
                directory pruned from the descent, so the caller can
                still treat the directory's presence as structural
                evidence (e.g. ``node_modules/``) without scanning
                its contents.
        """
        import os
        # Declared build files (poetry.lock, yarn.lock, Gemfile.lock)
        # would otherwise be swallowed by the ".lock" ignore suffix —
        # detection evidence must win over noise filtering.
        build_files = self._get_all_build_files()
        try:
            for dirpath, dirnames, filenames in os.walk(
                self.repo_path, followlinks=False,
            ):
                # In-place prune ignored dirs from descent.
                kept = []
                for d in dirnames:
                    if d in self.IGNORE_DIRS:
                        if pruned_dirs is not None:
                            rel = (Path(dirpath) / d).relative_to(self.repo_path).as_posix()
                            pruned_dirs.append(rel + "/")
                    else:
                        kept.append(d)
                dirnames[:] = kept
                for name in filenames:
                    if (
                        name not in build_files
                        and (name in self.IGNORE_FILES or name.endswith(self.IGNORE_SUFFIXES))
                    ):
                        continue
                    p = Path(dirpath) / name
                    if p.is_file():
                        yield p
        except PermissionError as e:
            logger.warning("Permission denied accessing: %s", e)

    def _analyze_language(self, lang: str, patterns: dict, stats: dict) -> LanguageInfo:
        """
        Analyze confidence score for a language based on patterns.

        Confidence calculation:
        - Base: 0.3 if any files with language extension found
        - +0.2 per build file found (max +0.4)
        - +0.1 per indicator found (max +0.3)
        - +0.0 to +0.3 based on file count ratio
        - Manifest-only ceiling: with zero source files, only the
          build-file boost applies, capped at 0.2 — below every
          language's ``min_confidence`` (see LANGUAGE_PATTERNS)

        Args:
            lang: Language name
            patterns: Language patterns dict
            stats: Repository scan statistics

        Returns:
            LanguageInfo object
        """
        # Count files with language extensions
        file_count = sum(
            count for ext, count in stats["extensions"].items()
            if ext in patterns["extensions"]
        )

        # Find matching build files (exact name or suffix)
        suffixes = patterns.get("build_file_suffixes", ())
        build_files_found = [
            bf for bf in stats["build_files"]
            if bf in patterns["build_files"] or (suffixes and bf.endswith(suffixes))
        ]

        # Find matching indicators
        indicators_found = [
            ind for ind in stats["indicators"]
            if ind in patterns["indicators"]
        ]

        # Find extensions found
        extensions_found = {
            ext for ext in stats["extensions"]
            if ext in patterns["extensions"]
        }

        # Calculate confidence score
        if file_count == 0:
            # Manifest-only ceiling: with zero source files the
            # build-file boost is the ONLY signal admitted, capped at
            # 0.2 — below every language's ``min_confidence``. Boosts
            # from indicators must not stack here: a hostile repo can
            # plant manifests + indicator directories with no source
            # at all, and ungated boosts would clear the detection
            # gate (0.4 build + 0.3 indicators = 0.7).
            confidence = min(0.2 * len(build_files_found), 0.2)
        else:
            confidence = 0.3

            # Build files boost (max +0.4)
            confidence += min(0.2 * len(build_files_found), 0.4)

            # Indicators boost (max +0.3)
            confidence += min(0.1 * len(indicators_found), 0.3)

            # File count ratio boost (max +0.3)
            if stats["total_files"] > 0:
                ratio = file_count / stats["total_files"]
                confidence += min(ratio, 0.3)

            # Cap at 1.0
            confidence = min(confidence, 1.0)

        return LanguageInfo(
            language=lang,
            confidence=confidence,
            file_count=file_count,
            extensions_found=extensions_found,
            build_files_found=build_files_found,
            indicators_found=indicators_found,
        )

    def _get_all_build_files(self) -> set[str]:
        """Get set of all exact-match build files across all languages."""
        build_files = set()
        for patterns in self.LANGUAGE_PATTERNS.values():
            build_files.update(patterns["build_files"])
        return build_files

    def _get_all_build_suffixes(self) -> tuple[str, ...]:
        """Get tuple of all suffix-match build file patterns."""
        suffixes: list[str] = []
        for patterns in self.LANGUAGE_PATTERNS.values():
            suffixes.extend(patterns.get("build_file_suffixes", ()))
        return tuple(suffixes)

    def _get_all_indicators(self) -> set[str]:
        """Get set of all structural indicators across all languages."""
        indicators = set()
        for patterns in self.LANGUAGE_PATTERNS.values():
            indicators.update(patterns["indicators"])
        return indicators

    def filter_codeql_supported(self, detected: dict[str, LanguageInfo]) -> dict[str, LanguageInfo]:
        """
        Filter detected languages to only CodeQL-supported ones.

        Args:
            detected: Dictionary of detected languages

        Returns:
            Filtered dictionary with only CodeQL-supported languages
        """
        supported = {
            lang: info for lang, info in detected.items()
            if lang in self.CODEQL_SUPPORTED
        }

        # Log unsupported languages
        unsupported = set(detected.keys()) - set(supported.keys())
        if unsupported:
            logger.warning(
                "Languages detected but not supported by CodeQL: %s", ', '.join(unsupported)
            )

        return supported


def main():
    """CLI entry point for testing."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Detect languages in repository")
    parser.add_argument("--repo", required=True, help="Repository path")
    parser.add_argument("--min-files", type=int, default=3, help="Minimum files to detect language")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    detector = LanguageDetector(Path(args.repo))
    detected = detector.detect_languages(min_files=args.min_files)
    supported = detector.filter_codeql_supported(detected)

    if args.json:
        output = {
            lang: {
                "confidence": info.confidence,
                "file_count": info.file_count,
                "extensions": list(info.extensions_found),
                "build_files": info.build_files_found,
            }
            for lang, info in supported.items()
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"\n{'=' * 70}")
        print("DETECTED LANGUAGES (CodeQL-supported only)")
        print(f"{'=' * 70}")
        for lang, info in supported.items():
            print(f"\n{lang.upper()}:")
            print(f"  Confidence: {info.confidence:.2f}")
            print(f"  Files: {info.file_count}")
            print(f"  Extensions: {', '.join(info.extensions_found)}")
            if info.build_files_found:
                print(f"  Build files: {', '.join(info.build_files_found)}")


if __name__ == "__main__":
    main()
