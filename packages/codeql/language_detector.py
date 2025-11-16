#!/usr/bin/env python3
"""
Language Detection for CodeQL

Automatically detects programming languages in a repository
to determine which CodeQL databases need to be created.
"""

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.logging import get_logger

logger = get_logger()


@dataclass
class LanguageInfo:
    """Information about detected language."""
    language: str
    confidence: float  # 0.0 - 1.0
    file_count: int
    extensions_found: Set[str]
    build_files_found: List[str]
    indicators_found: List[str]
    total_lines: int = 0


class LanguageDetector:
    """
    Autonomous language detection for CodeQL database creation.

    Scans repository and identifies languages with confidence scores
    based on file extensions, build files, and structural indicators.
    """

    # Language patterns with extensions, build files, and structural indicators
    LANGUAGE_PATTERNS = {
        "java": {
            "extensions": {".java"},
            "build_files": {"pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "gradlew"},
            "indicators": {"src/main/java/", "src/test/java/"},
            "min_confidence": 0.5,
        },
        "python": {
            "extensions": {".py"},
            "build_files": {"setup.py", "pyproject.toml", "requirements.txt", "Pipfile", "poetry.lock", "setup.cfg"},
            "indicators": {"__init__.py", "__main__.py"},
            "min_confidence": 0.5,
        },
        "javascript": {
            "extensions": {".js", ".jsx", ".mjs", ".cjs"},
            "build_files": {"package.json", "package-lock.json", "yarn.lock", "webpack.config.js", ".npmrc"},
            "indicators": {"node_modules/", "src/", "dist/"},
            "min_confidence": 0.5,
        },
        "typescript": {
            "extensions": {".ts", ".tsx"},
            "build_files": {"tsconfig.json", "package.json"},
            "indicators": {"src/", "dist/"},
            "min_confidence": 0.5,
        },
        "go": {
            "extensions": {".go"},
            "build_files": {"go.mod", "go.sum", "go.work"},
            "indicators": {"main.go", "cmd/", "pkg/"},
            "min_confidence": 0.6,
        },
        "cpp": {
            "extensions": {".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".hxx"},
            "build_files": {"CMakeLists.txt", "Makefile", "configure", "meson.build", "makefile"},
            "indicators": {"src/", "include/"},
            "min_confidence": 0.5,
        },
        "csharp": {
            "extensions": {".cs"},
            "build_files": {".csproj", ".sln", "packages.config", "nuget.config"},
            "indicators": {"Properties/", "bin/", "obj/"},
            "min_confidence": 0.6,
        },
        "ruby": {
            "extensions": {".rb"},
            "build_files": {"Gemfile", "Gemfile.lock", "Rakefile", ".gemspec"},
            "indicators": {"lib/", "spec/", "test/"},
            "min_confidence": 0.6,
        },
        "swift": {
            "extensions": {".swift"},
            "build_files": {"Package.swift", "Podfile"},
            "indicators": {"Sources/", "Tests/"},
            "min_confidence": 0.7,
        },
        "kotlin": {
            "extensions": {".kt", ".kts"},
            "build_files": {"build.gradle.kts", "settings.gradle.kts"},
            "indicators": {"src/main/kotlin/", "src/test/kotlin/"},
            "min_confidence": 0.6,
        },
    }

    # CodeQL supported languages (as of 2024)
    CODEQL_SUPPORTED = {
        "java", "python", "javascript", "typescript", "go",
        "cpp", "csharp", "ruby", "swift", "kotlin"
    }

    # Directories to ignore during scanning
    IGNORE_DIRS = {
        ".git", ".svn", ".hg", ".bzr",
        "node_modules", "venv", "env", ".venv", ".env",
        "__pycache__", ".pytest_cache", ".mypy_cache",
        "target", "build", "dist", "out", "bin", "obj",
        ".gradle", ".mvn", ".idea", ".vscode", ".vs",
        "vendor", "packages", "bower_components",
    }

    # Files to ignore
    IGNORE_FILES = {
        ".DS_Store", "Thumbs.db", ".gitignore", ".dockerignore",
        ".lock", ".min.js", ".bundle.js",
    }

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

    def detect_languages(self, min_files: int = 3) -> Dict[str, LanguageInfo]:
        """
        Detect all languages in repository with confidence scores.

        Args:
            min_files: Minimum files required to consider a language present

        Returns:
            Dict mapping language name -> LanguageInfo
        """
        logger.info(f"Detecting languages in: {self.repo_path}")

        # Scan repository and collect statistics
        stats = self._scan_repository()

        # Calculate confidence scores for each language
        detected = {}
        for lang, patterns in self.LANGUAGE_PATTERNS.items():
            info = self._analyze_language(lang, patterns, stats)

            # Only include if meets minimum criteria
            if info.file_count >= min_files and info.confidence >= patterns["min_confidence"]:
                detected[lang] = info
                logger.info(
                    f"✓ Detected {lang}: {info.file_count} files, "
                    f"confidence={info.confidence:.2f}"
                )

        if not detected:
            logger.warning("No languages detected that meet minimum criteria")
        else:
            logger.info(f"Total languages detected: {len(detected)}")

        return detected

    def _scan_repository(self) -> Dict:
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

        try:
            for file_path in self._walk_repository():
                stats["scanned_files"] += 1

                # Check for build files
                if file_path.name in self._get_all_build_files():
                    stats["build_files"].add(file_path.name)

                # Check for structural indicators
                relative = str(file_path.relative_to(self.repo_path))
                for indicator in self._get_all_indicators():
                    if indicator in relative:
                        stats["indicators"].add(indicator)

                # Count extensions
                if file_path.suffix:
                    stats["extensions"][file_path.suffix] += 1

                stats["total_files"] += 1

                # Performance limit
                if stats["scanned_files"] >= self.max_files:
                    logger.warning(
                        f"Reached max file scan limit ({self.max_files}), "
                        f"detection may be incomplete"
                    )
                    break

        except Exception as e:
            logger.error(f"Error scanning repository: {e}")

        logger.debug(f"Scanned {stats['scanned_files']} files")
        return stats

    def _walk_repository(self):
        """Walk repository while respecting ignore patterns."""
        try:
            for path in self.repo_path.rglob("*"):
                # Skip ignored directories
                if any(ignored in path.parts for ignored in self.IGNORE_DIRS):
                    continue

                # Skip ignored files
                if path.name in self.IGNORE_FILES:
                    continue

                # Only process files
                if path.is_file():
                    yield path
        except PermissionError as e:
            logger.warning(f"Permission denied accessing: {e}")

    def _analyze_language(self, lang: str, patterns: Dict, stats: Dict) -> LanguageInfo:
        """
        Analyze confidence score for a language based on patterns.

        Confidence calculation:
        - Base: 0.3 if any files with language extension found
        - +0.2 per build file found (max +0.4)
        - +0.1 per indicator found (max +0.3)
        - +0.0 to +0.3 based on file count ratio

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

        # Find matching build files
        build_files_found = [
            bf for bf in stats["build_files"]
            if bf in patterns["build_files"]
        ]

        # Find matching indicators
        indicators_found = [
            ind for ind in stats["indicators"]
            if ind in patterns["indicators"]
        ]

        # Find extensions found
        extensions_found = {
            ext for ext in stats["extensions"].keys()
            if ext in patterns["extensions"]
        }

        # Calculate confidence score
        confidence = 0.0

        # Base confidence if any files found
        if file_count > 0:
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

    def _get_all_build_files(self) -> Set[str]:
        """Get set of all build files across all languages."""
        build_files = set()
        for patterns in self.LANGUAGE_PATTERNS.values():
            build_files.update(patterns["build_files"])
        return build_files

    def _get_all_indicators(self) -> Set[str]:
        """Get set of all structural indicators across all languages."""
        indicators = set()
        for patterns in self.LANGUAGE_PATTERNS.values():
            indicators.update(patterns["indicators"])
        return indicators

    def get_primary_language(self, detected: Dict[str, LanguageInfo]) -> str:
        """
        Get primary language (highest confidence + file count).

        Args:
            detected: Dictionary of detected languages

        Returns:
            Primary language name
        """
        if not detected:
            raise ValueError("No languages detected")

        # Sort by confidence, then by file count
        sorted_langs = sorted(
            detected.items(),
            key=lambda x: (x[1].confidence, x[1].file_count),
            reverse=True
        )

        primary = sorted_langs[0][0]
        logger.info(f"Primary language: {primary}")
        return primary

    def filter_codeql_supported(self, detected: Dict[str, LanguageInfo]) -> Dict[str, LanguageInfo]:
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
                f"Languages detected but not supported by CodeQL: {', '.join(unsupported)}"
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
