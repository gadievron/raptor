#!/usr/bin/env python3
"""
Build System Detection for CodeQL

Automatically detects build systems and generates appropriate
build commands for CodeQL database creation.
"""

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from shlex import quote
from typing import Dict, List, Optional
import xml.etree.ElementTree as ET

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.logging import get_logger

logger = get_logger()


@dataclass
class BuildSystem:
    """Information about detected build system."""
    type: str  # maven, gradle, npm, etc.
    command: str  # Build command to use
    working_dir: Path  # Directory to run command in
    env_vars: Dict[str, str]  # Environment variables needed
    confidence: float  # 0.0 - 1.0
    detected_files: List[str]  # Files that indicated this build system


class BuildDetector:
    """
    Autonomous build system detection and command generation.

    Detects build systems by analyzing build files and generates
    appropriate commands for CodeQL database creation.
    """

    # Build system patterns per language
    BUILD_SYSTEMS = {
        "java": {
            "maven": {
                "files": ["pom.xml"],
                "command": "mvn clean compile -DskipTests -Dmaven.test.skip=true",
                "env_vars": {"MAVEN_OPTS": "-Xmx2048m"},
                "priority": 1,
            },
            "gradle": {
                "files": ["build.gradle", "build.gradle.kts", "settings.gradle", "gradlew"],
                "command": "./gradlew build -x test --no-daemon",
                "command_fallback": "gradle build -x test --no-daemon",
                "env_vars": {"GRADLE_OPTS": "-Xmx2048m"},
                "priority": 2,
            },
            "ant": {
                "files": ["build.xml"],
                "command": "ant compile",
                "env_vars": {},
                "priority": 3,
            },
        },
        "python": {
            "poetry": {
                "files": ["pyproject.toml", "poetry.lock"],
                "command": "poetry install --no-root",
                "env_vars": {},
                "priority": 1,
            },
            "pip": {
                "files": ["requirements.txt", "setup.py", "pyproject.toml"],
                "command": "pip install -e . || pip install -r requirements.txt",
                "env_vars": {},
                "priority": 2,
            },
            "setuptools": {
                "files": ["setup.py"],
                "command": "python setup.py build",
                "env_vars": {},
                "priority": 3,
            },
        },
        "javascript": {
            "npm": {
                "files": ["package.json", "package-lock.json"],
                "command": "npm install && npm run build",
                "command_fallback": "npm install",
                "env_vars": {"NODE_ENV": "development"},
                "priority": 1,
            },
            "yarn": {
                "files": ["package.json", "yarn.lock"],
                "command": "yarn install && yarn build",
                "command_fallback": "yarn install",
                "env_vars": {"NODE_ENV": "development"},
                "priority": 2,
            },
            "pnpm": {
                "files": ["package.json", "pnpm-lock.yaml"],
                "command": "pnpm install && pnpm run build",
                "command_fallback": "pnpm install",
                "env_vars": {"NODE_ENV": "development"},
                "priority": 3,
            },
        },
        "typescript": {
            "npm": {
                "files": ["package.json", "tsconfig.json"],
                "command": "npm install && npm run build",
                "command_fallback": "npm install && tsc",
                "env_vars": {"NODE_ENV": "development"},
                "priority": 1,
            },
            "yarn": {
                "files": ["package.json", "yarn.lock", "tsconfig.json"],
                "command": "yarn install && yarn build",
                "command_fallback": "yarn install && tsc",
                "env_vars": {"NODE_ENV": "development"},
                "priority": 2,
            },
        },
        "go": {
            "gomod": {
                "files": ["go.mod"],
                "command": "go build ./...",
                "env_vars": {"CGO_ENABLED": "0"},
                "priority": 1,
            },
        },
        "cpp": {
            "cmake": {
                "files": ["CMakeLists.txt"],
                "command": "cmake . && make",
                "env_vars": {},
                "priority": 1,
            },
            "make": {
                "files": ["Makefile", "makefile"],
                "command": "make",
                "env_vars": {},
                "priority": 2,
            },
            "autotools": {
                "files": ["configure", "configure.ac"],
                "command": "./configure && make",
                "env_vars": {},
                "priority": 3,
            },
            "meson": {
                "files": ["meson.build"],
                "command": "meson setup builddir && meson compile -C builddir",
                "env_vars": {},
                "priority": 4,
            },
        },
        "csharp": {
            "dotnet": {
                "files": [".csproj", ".sln"],
                "command": "dotnet build",
                "env_vars": {},
                "priority": 1,
            },
            "msbuild": {
                "files": [".csproj", ".sln"],
                "command": "msbuild /t:Build",
                "env_vars": {},
                "priority": 2,
            },
        },
        "ruby": {
            "bundler": {
                "files": ["Gemfile", "Gemfile.lock"],
                "command": "bundle install",
                "env_vars": {},
                "priority": 1,
            },
            "rake": {
                "files": ["Rakefile"],
                "command": "rake build",
                "env_vars": {},
                "priority": 2,
            },
        },
    }

    def __init__(self, repo_path: Path):
        """
        Initialize build detector.

        Args:
            repo_path: Path to repository
        """
        self.repo_path = Path(repo_path)

        if not self.repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")

    def detect_build_system(self, language: str) -> Optional[BuildSystem]:
        """
        Detect build system for given language.

        Args:
            language: Programming language

        Returns:
            BuildSystem object or None if no build system detected
        """
        logger.info(f"Detecting build system for {language} in: {self.repo_path}")

        if language not in self.BUILD_SYSTEMS:
            logger.warning(f"No build system detection for language: {language}")
            return None

        # Get build systems for this language
        build_systems = self.BUILD_SYSTEMS[language]

        # Try each build system in priority order
        detected = []
        for build_type, config in build_systems.items():
            result = self._check_build_system(language, build_type, config)
            if result:
                detected.append(result)

        if not detected:
            logger.warning(f"No build system detected for {language}")
            return None

        # Return highest priority (lowest priority number)
        best = min(detected, key=lambda x: self.BUILD_SYSTEMS[language][x.type]["priority"])
        logger.info(f"✓ Detected {best.type} build system for {language}")
        logger.info(f"  Command: {best.command}")
        return best

    def _check_build_system(self, language: str, build_type: str, config: Dict) -> Optional[BuildSystem]:
        """
        Check if a specific build system is present.

        Args:
            language: Programming language
            build_type: Build system type
            config: Build system configuration

        Returns:
            BuildSystem object or None
        """
        detected_files = []
        working_dir = self.repo_path

        # Check for build files
        for build_file in config["files"]:
            # Check for exact match
            if (self.repo_path / build_file).exists():
                detected_files.append(build_file)

            # Check for extension match (e.g., *.csproj)
            if build_file.startswith("."):
                matches = list(self.repo_path.rglob(f"*{build_file}"))
                if matches:
                    detected_files.append(build_file)
                    # Use the directory of the first match
                    working_dir = matches[0].parent

        if not detected_files:
            return None

        # Calculate confidence based on number of indicators
        confidence = min(0.5 + (len(detected_files) * 0.2), 1.0)

        # Choose command (with fallback support)
        command = config["command"]

        # Special handling for gradle wrapper
        if build_type == "gradle" and "./gradlew" in command:
            gradlew = self.repo_path / "gradlew"
            if not gradlew.exists() or not os.access(gradlew, os.X_OK):
                # Fall back to system gradle
                command = config.get("command_fallback", command)
                logger.debug("Gradle wrapper not found, using system gradle")

        # Special handling for npm/yarn/pnpm build scripts
        if build_type in ["npm", "yarn", "pnpm"]:
            # Check if build script exists in package.json
            package_json = self.repo_path / "package.json"
            if package_json.exists():
                if not self._has_build_script(package_json):
                    # Use fallback command (just install)
                    command = config.get("command_fallback", command)
                    logger.debug("No build script in package.json, using install only")

        return BuildSystem(
            type=build_type,
            command=command,
            working_dir=working_dir,
            env_vars=config.get("env_vars", {}),
            confidence=confidence,
            detected_files=detected_files,
        )

    def _has_build_script(self, package_json: Path) -> bool:
        """Check if package.json has a build script."""
        try:
            import json
            with open(package_json) as f:
                data = json.load(f)
                scripts = data.get("scripts", {})
                return "build" in scripts
        except Exception as e:
            logger.debug(f"Error parsing package.json: {e}")
            return False

    def detect_all_build_systems(self, languages: List[str]) -> Dict[str, Optional[BuildSystem]]:
        """
        Detect build systems for multiple languages.

        Args:
            languages: List of programming languages

        Returns:
            Dict mapping language -> BuildSystem (or None)
        """
        result = {}
        for language in languages:
            result[language] = self.detect_build_system(language)
        return result

    def validate_build_command(self, build_system: BuildSystem, timeout: int = 30) -> bool:
        """
        Validate that build command can be executed.

        Does a quick check (e.g., mvn --version, gradle --version) to ensure
        the build tool is available.

        Args:
            build_system: BuildSystem to validate
            timeout: Timeout in seconds

        Returns:
            True if build command is likely to work
        """
        # Map build types to validation commands
        validation_commands = {
            "maven": ["mvn", "--version"],
            "gradle": ["gradle", "--version"],
            "ant": ["ant", "-version"],
            "npm": ["npm", "--version"],
            "yarn": ["yarn", "--version"],
            "pnpm": ["pnpm", "--version"],
            "pip": ["pip", "--version"],
            "poetry": ["poetry", "--version"],
            "gomod": ["go", "version"],
            "cmake": ["cmake", "--version"],
            "make": ["make", "--version"],
            "dotnet": ["dotnet", "--version"],
            "bundler": ["bundle", "--version"],
        }

        validation_cmd = validation_commands.get(build_system.type)
        if not validation_cmd:
            logger.debug(f"No validation command for {build_system.type}")
            return True  # Assume it's OK if we can't validate

        try:
            result = subprocess.run(
                validation_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                cwd=build_system.working_dir,
            )
            success = result.returncode == 0
            if success:
                logger.debug(f"✓ Validated {build_system.type} is available")
            else:
                logger.warning(f"✗ {build_system.type} validation failed")
            return success
        except FileNotFoundError:
            logger.warning(f"✗ {build_system.type} not found in PATH")
            return False
        except subprocess.TimeoutExpired:
            logger.warning(f"✗ {build_system.type} validation timed out")
            return False
        except Exception as e:
            logger.warning(f"✗ Error validating {build_system.type}: {e}")
            return False

    def generate_no_build_config(self, language: str) -> BuildSystem:
        """
        Generate a no-build configuration for languages that don't require compilation.

        Args:
            language: Programming language

        Returns:
            BuildSystem configured for no-build mode
        """
        logger.info(f"Using no-build mode for {language}")

        return BuildSystem(
            type="no-build",
            command="",  # Empty command for no-build
            working_dir=self.repo_path,
            env_vars={},
            confidence=1.0,
            detected_files=[],
        )


def main():
    """CLI entry point for testing."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Detect build systems")
    parser.add_argument("--repo", required=True, help="Repository path")
    parser.add_argument("--language", required=True, help="Programming language")
    parser.add_argument("--validate", action="store_true", help="Validate build command")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    detector = BuildDetector(Path(args.repo))
    build_system = detector.detect_build_system(args.language)

    if not build_system:
        print(f"No build system detected for {args.language}")
        return

    if args.validate:
        valid = detector.validate_build_command(build_system)
        if not valid:
            print(f"WARNING: Build command validation failed")

    if args.json:
        output = {
            "type": build_system.type,
            "command": build_system.command,
            "working_dir": str(build_system.working_dir),
            "env_vars": build_system.env_vars,
            "confidence": build_system.confidence,
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"\n{'=' * 70}")
        print(f"BUILD SYSTEM DETECTED: {build_system.type.upper()}")
        print(f"{'=' * 70}")
        print(f"Command: {build_system.command}")
        print(f"Working directory: {build_system.working_dir}")
        print(f"Confidence: {build_system.confidence:.2f}")
        if build_system.env_vars:
            print(f"Environment variables: {build_system.env_vars}")


if __name__ == "__main__":
    main()
