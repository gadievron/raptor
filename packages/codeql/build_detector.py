#!/usr/bin/env python3
"""
Build System Detection for CodeQL

Automatically detects build systems and generates appropriate
build commands for CodeQL database creation.
"""

import os
import re
import subprocess
from core.sandbox import run as _sandbox_run, run_trusted as _run_trusted
# _run_trusted: read-only tools (--version checks) — no namespace overhead.
# Build-detection work compiles/executes untrusted content: each call site
# passes target=output=<repo_path> so Landlock engages alongside seccomp +
# namespace net block (full sandbox).
import sys
from dataclasses import dataclass, field
from pathlib import Path
from shlex import quote
from typing import Dict, List, Optional

# Add parent directory to path for imports
# packages/codeql/build_detector.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[2]))

from core.logging import get_logger

logger = get_logger()


@dataclass
class BuildSystem:
    """Information about detected build system."""
    type: str  # maven, gradle, npm, etc.
    command: str  # Build command to use
    working_dir: Path  # Directory to run command in
    env_vars: Dict[str, str]  # Env vars we inject as-is (RAPTOR-chosen constants)
    confidence: float  # 0.0 - 1.0
    detected_files: List[str]  # Files that indicated this build system
    cleanup_paths: List[Path] = field(default_factory=list)  # Temp files/dirs to remove after CodeQL
    # Env var NAMES to auto-detect at build time. Each name must have
    # a corresponding detector in core.build.toolchain.DETECTORS. The
    # detected value (if non-None) is merged into the build
    # subprocess's env alongside env_vars. See ~/design/env-handling.md.
    env_detect: List[str] = field(default_factory=list)


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
                "env_detect": ["JAVA_HOME"],
                "priority": 1,
            },
            "gradle": {
                "files": ["build.gradle", "build.gradle.kts", "settings.gradle", "gradlew"],
                "command": "./gradlew build -x test --no-daemon",
                "command_fallback": "gradle build -x test --no-daemon",
                "env_vars": {"GRADLE_OPTS": "-Xmx2048m"},
                "env_detect": ["JAVA_HOME"],
                "priority": 2,
            },
            "ant": {
                "files": ["build.xml"],
                "command": "ant compile",
                "env_vars": {"ANT_OPTS": "-Xmx2048m"},
                "env_detect": ["JAVA_HOME"],
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
                "env_detect": ["GOROOT"],
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
                "env_detect": ["DOTNET_ROOT"],
                "priority": 1,
            },
            "msbuild": {
                "files": [".csproj", ".sln"],
                "command": "msbuild /t:Build",
                "env_vars": {},
                "env_detect": ["DOTNET_ROOT"],
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
                # Sort matches for determinism. `rglob` returns
                # filesystem-iteration order (varies between
                # machines and even between runs on the same
                # machine after FS metadata reordering); without
                # sorting `matches[0].parent` was non-
                # deterministic — repos with multiple .csproj /
                # .sln / .gradle files picked DIFFERENT
                # working_dirs across runs, producing different
                # CodeQL DBs and different SARIF outputs for the
                # same source. Sort by path string to pin the
                # selection to "shallowest-then-alphabetical"
                # which matches operator intuition for "primary"
                # build root.
                matches = sorted(
                    self.repo_path.rglob(f"*{build_file}"),
                    key=lambda p: (len(p.parts), str(p)),
                )
                if matches:
                    detected_files.append(build_file)
                    # Use the directory of the first match WITH
                    # containment + executability checks. Pre-fix
                    # `working_dir = matches[0].parent` blindly
                    # used the rglob result, which on Python <
                    # 3.13 follows symlinks — a symlink in the
                    # repo pointing OUT to e.g. /etc could land
                    # us with `working_dir = /etc` which codeql
                    # can't cd into and which leaks the
                    # operator's filesystem layout into logs.
                    # X_OK check refuses dirs we can't actually
                    # browse into.
                    candidate = matches[0].parent
                    try:
                        cand_resolved = candidate.resolve(strict=False)
                        repo_resolved = self.repo_path.resolve(strict=False)
                        cand_resolved.relative_to(repo_resolved)
                        if os.access(candidate, os.X_OK):
                            working_dir = candidate
                        else:
                            logger.debug(
                                "Skipping working_dir %s — not browseable",
                                candidate,
                            )
                    except (ValueError, OSError):
                        logger.debug(
                            "Skipping out-of-tree working_dir candidate %s",
                            candidate,
                        )

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
            env_detect=config.get("env_detect", []),
        )

    def _has_build_script(self, package_json: Path) -> bool:
        """Check if package.json has a build script."""
        try:
            from core.json import load_json
            data = load_json(package_json)
            if data is None:
                return False
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
            # Unknown build-tool type. Pre-fix we returned True
            # ("Assume it's OK if we can't validate") — but the
            # next caller-side step is `--build-command "<bs.cmd>"`
            # against `codeql database create`, which spawns the
            # tool and fails opaquely if it isn't installed. The
            # operator sees a CodeQL extraction error two minutes
            # into a database build, not a clear "tool missing"
            # warning at validation time.
            #
            # Returning False here is the honest answer: we have
            # no evidence the build will succeed. The caller's
            # validation-failed branch logs and skips this
            # language with a useful message; the optimistic-True
            # branch silently let unbuildable matrix entries
            # through.
            #
            # Still log at debug so legitimately-unknown tool
            # types (e.g. obscure JVM build systems we haven't
            # added probes for yet) leave a breadcrumb when
            # operators report unexpected validation failures.
            logger.debug(
                "No validation command for %s; treating as "
                "unvalidated (returning False) — add a probe "
                "command to validation_commands above to opt in.",
                build_system.type,
            )
            return False

        # Pre-flight working_dir exists + is a directory. Pre-fix
        # we passed `cwd=build_system.working_dir` directly to the
        # subprocess; if the path was synthesised to a non-
        # existent location (e.g. detection picked a build-system
        # candidate whose parent was deleted between detection
        # and validation, or a stale BuildSystem object was
        # serialised across runs), Popen raised FileNotFoundError
        # for the cwd — but the operator-visible error read as
        # "build tool not found", confusing the diagnosis. Check
        # explicitly so the warning identifies the actual issue.
        wd = Path(build_system.working_dir) if build_system.working_dir else None
        if wd is not None and not wd.is_dir():
            logger.warning(
                "✗ %s validation skipped: working_dir %r doesn't exist",
                build_system.type, str(wd),
            )
            return False

        try:
            result = _run_trusted(  # --version checks only
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

    # Languages that require compilation for CodeQL database creation.
    COMPILED_LANGUAGES = {"cpp", "java", "csharp", "swift", "rust"}

    # Validates individual compiler flag tokens.
    # No $, backticks, semicolons, pipes, quotes, etc.
    # Note: -I/ (root include) is technically allowed — file permissions are
    # the protection. CodeQL's --source-root prevents system headers from
    # being indexed as project code.
    # Pre-fix this used `^...$`. Python regex `$` matches end-of-
    # string OR just-before-a-trailing-newline, so a flag token
    # `-DEVIL=$(rm -rf $HOME)\n` passed validation: the trailing
    # `\n` was eaten by `$`. The safe-flag token then flowed into
    # the build script as `-DEVIL=$(rm -rf $HOME)` (the newline
    # got stripped) — and even more dangerously, in some
    # contexts the embedded `\n` carried through to subprocess
    # arg lists, where the next process's argv parser saw two
    # arguments: the flag plus whatever followed the newline.
    #
    # Use `\A...\Z` for unambiguous string-boundary anchors:
    # `\Z` doesn't accept the trailing newline, so the
    # injection-shaped flag is correctly rejected.
    _SAFE_FLAG_TOKEN = re.compile(r'\A-?[A-Za-z0-9._/+=-]+\Z')

    def _validate_flags(self, flags: list) -> list:
        """Validate and normalise compiler flags.

        Accepts both single tokens ("-DFOO") and space-separated pairs
        ("-include header.h"). Splits pairs into individual tokens.
        Rejects anything with shell/Make metacharacters.
        """
        safe = []
        for flag in flags:
            if not isinstance(flag, str):
                continue
            # Split space-separated flags like "-include header.h"
            tokens = flag.split()
            if all(self._SAFE_FLAG_TOKEN.match(t) for t in tokens):
                safe.extend(tokens)
            else:
                logger.warning(f"Rejected unsafe compiler flag: {flag}")
        return safe

    def synthesise_build_command(self, language: str) -> Optional[BuildSystem]:
        """Synthesise a build command for compiled languages without a build system.

        Generates a Python build script that compiles each source file via
        subprocess.run (no shell, no quoting issues). CodeQL traces the gcc
        invocations through its preload tracer.

        Flow: heuristic build → dry-run → if failures and CC available,
        CC suggests flags → validated → dry-run again → use best result.

        All temporary files (script + build dir) are created via mkstemp/mkdtemp
        and tracked in BuildSystem.cleanup_paths for the caller to clean up.

        Returns None for unsupported languages or no source files.
        """
        # Pre-fix:
        #   if language not in self.COMPILED_LANGUAGES or language not in ("cpp", "java"):
        #       return None
        # COMPILED_LANGUAGES contains 5 entries (cpp, java,
        # csharp, swift, rust), but the second `or` clause
        # narrows the gate to ("cpp", "java"). With `or`, the
        # condition is True (and we return None) whenever EITHER
        # check trips — and the ("cpp", "java") tuple is strictly
        # narrower than COMPILED_LANGUAGES, so the first check
        # never independently rejects anything the second check
        # accepts. The COMPILED_LANGUAGES test is dead.
        #
        # Worse, the dead check misleads readers: it suggests
        # synthesise_build_command supports the full
        # COMPILED_LANGUAGES set when in fact it gates on the
        # narrow 2-language tuple. The synthesiser body assumes
        # cpp/java only (compiler detection in
        # _detect_build_params, .java vs .cpp source-file
        # filtering); enabling csharp/swift/rust here would just
        # produce empty source_files and return None one branch
        # later — but the misleading first check made it look
        # like the function had broader scope.
        #
        # Replace with the single, honest gate.
        if language not in ("cpp", "java"):
            return None

        source_files, compiler, include_flags, define_flags = self._detect_build_params(language)
        if not source_files:
            return None

        # Create build dir and script once — reused across heuristic and CC
        import tempfile
        build_dir = Path(tempfile.mkdtemp(prefix=".raptor_build_", dir=self.repo_path))
        fd, script_name = tempfile.mkstemp(
            prefix=".raptor_build_", suffix=".py", dir=self.repo_path,
        )
        os.close(fd)
        script_path = Path(script_name)
        build_cmd = f"{sys.executable} {quote(str(script_path))}"
        cleanup = [script_path, build_dir]

        # cleanup_paths is only returned to the caller on SUCCESS (via the
        # BuildSystem at the bottom of this method). If _write_build_script
        # or the first _dry_run raises, the caller never sees cleanup_paths
        # and both the script stub AND the build dir leak UNDER self.repo_path
        # (= pollutes the target repo). Guard with try/except that walks the
        # cleanup list on failure before re-raising.
        def _cleanup_on_failure():
            for p in cleanup:
                try:
                    if p.is_dir():
                        import shutil
                        shutil.rmtree(str(p), ignore_errors=True)
                    else:
                        p.unlink(missing_ok=True)
                except OSError:
                    pass

        try:
            # Write heuristic build script and dry-run
            self._write_build_script(
                script_path, build_dir,
                source_files, compiler, include_flags, define_flags,
            )
        except BaseException:
            _cleanup_on_failure()
            raise
        logger.info(f"Synthesised build script for {language}: {script_path}")
        logger.info(f"  Source files: {len(source_files)}")

        failures = self._dry_run(script_path, language=language)
        build_type = "synthesised"
        confidence = 0.7

        # `failures is None` → dry-run never ran (script crashed,
        # sandbox-launch failed, timeout). We can't measure
        # whether the heuristic flags work, so don't attempt a
        # CC-suggest retry (the second dry-run would fail the same
        # way and waste budget).
        if failures is None:
            logger.warning(
                "  Dry-run didn't execute — using heuristic flags without measurement",
            )
        elif failures:
            heuristic_ok = len(source_files) - len(failures)
            logger.info(f"  Dry-run: {heuristic_ok}/{len(source_files)} compiled, {len(failures)} failed")

            cc_flags = self._cc_suggest_flags(failures, language)
            if cc_flags:
                self._write_build_script(
                    script_path, build_dir, source_files, compiler,
                    include_flags + cc_flags.get("includes", []),
                    define_flags + cc_flags.get("defines", []),
                )
                cc_failures = self._dry_run(script_path, language=language)
                if cc_failures is None:
                    logger.info("  CC retry didn't run — keeping heuristic")
                else:
                    cc_ok = len(source_files) - len(cc_failures)
                    if cc_ok > heuristic_ok:
                        logger.info(f"  CC improved: {heuristic_ok} → {cc_ok} compiled")
                        build_type = "synthesised-cc"
                    else:
                        logger.info("  CC didn't improve, using heuristic")
                    self._write_build_script(
                        script_path, build_dir,
                        source_files, compiler, include_flags, define_flags,
                    )
                    confidence = 0.5
            else:
                confidence = 0.5
        else:
            logger.info("  Dry-run: all files compiled successfully")

        return BuildSystem(
            type=build_type, command=build_cmd,
            working_dir=self.repo_path, env_vars={},
            confidence=confidence, detected_files=[],
            cleanup_paths=cleanup,
        )

    def _detect_build_params(self, language: str):
        """Detect source files, compiler, and include/define flags."""
        source_files = []
        if language == "cpp":
            for ext in (".c", ".cc", ".cpp", ".cxx"):
                source_files.extend(self.repo_path.rglob(f"*{ext}"))
            has_cpp = any(f.suffix in (".cpp", ".cc", ".cxx") for f in source_files)
            compiler = "g++" if has_cpp else "gcc"

            # Auto-detect -I flags from header locations
            include_flags = set()
            for ext in (".h", ".hpp", ".hh"):
                for h in self.repo_path.rglob(f"*{ext}"):
                    try:
                        include_flags.add(f"-I{h.parent.relative_to(self.repo_path)}")
                    except ValueError:
                        pass
            include_flags = sorted(include_flags)
        elif language == "java":
            source_files = list(self.repo_path.rglob("*.java"))
            compiler = "javac"
            include_flags = ["-sourcepath", str(self.repo_path)]
        else:
            return [], "", [], []

        # Validate all auto-detected flags
        include_flags = self._validate_flags(include_flags)
        return source_files, compiler, include_flags, []

    def _java_synthesised_classpath(self) -> List[str]:
        """When we fall through to raw javac (no pom.xml/build.gradle/
        build.xml), any external JARs the code depends on typically
        live under `repo/lib/*.jar` by informal convention. Build a
        classpath from that directory if it exists.

        Returns an empty list on any of:
         - no lib/ dir
         - lib/ exists but has no .jar files
         - repo_path doesn't resolve (shouldn't happen)

        Rationale & edge cases in ~/design/env-handling.md (Q6).
        Repo-scoped construction — does NOT inherit any host CLASSPATH.
        """
        lib_dir = self.repo_path / "lib"
        if not lib_dir.is_dir():
            return []
        jars = sorted(str(p) for p in lib_dir.glob("*.jar"))
        if jars:
            logger.info(
                f"  Java synthesised build: {len(jars)} jar(s) from "
                f"lib/ added to classpath. If CodeQL semantics look "
                f"wrong, inspect lib/ for stale/unused JARs."
            )
        return jars

    def _write_build_script(self, script_path, build_dir,
                            source_files, compiler, include_flags, define_flags):
        """Write a Python build script that compiles via subprocess.run.

        Security model:
        - No shell: compiler args are a Python list → subprocess.run uses execve
          directly. Filenames with spaces, $, quotes, etc. are safe.
        - Data via repr(): all interpolated values use {!r} which produces valid
          Python literals. No code injection via crafted paths or flags.
        - Flags validated: _validate_flags rejects shell/Make metacharacters
          before any flag reaches the script.
        - Path traversal check: realpath + startswith('..') prevents symlinks
          from writing object files outside the build directory.
        - File permissions: script is chmod 0o500 after write (read+execute
          only) to prevent modification between generation and execution.
        - Build isolation: output goes to a mkdtemp directory, not the source
          tree. Cleanup paths are tracked explicitly on the BuildSystem.

        Reuses the same script_path and build_dir across heuristic and CC
        attempts — one directory, one script, one cleanup.
        """
        # SECURITY: validate all flags before they reach the generated script
        include_flags = self._validate_flags(include_flags)
        define_flags = self._validate_flags(define_flags)

        files_list = [str(f) for f in source_files]
        repo_root = str(self.repo_path)
        is_java = compiler == "javac"

        # Java-only: build classpath from repo/lib/*.jar if present.
        # Repo-scoped; does NOT inherit any host CLASSPATH (see
        # core.config.DANGEROUS_ENV_VARS for why CLASSPATH is stripped).
        # Joined with `os.pathsep` inside the generated script so we
        # don't need to know the host's separator at generation time.
        java_classpath_jars: List[str] = (
            self._java_synthesised_classpath() if is_java else []
        )

        script_path.chmod(0o700)  # Temporarily writable for rewrites (CC path)
        # SECURITY: all data interpolated via {!r} (Python repr) — produces
        # valid Python literals, not executable code.
        script_path.write_text(f'''#!/usr/bin/env python3
"""Synthesised by RAPTOR for CodeQL database creation.

Compiles each source file individually via subprocess.run (no shell).
CodeQL traces the compiler invocations through its preload tracer.
Tolerates individual compilation failures.
"""
import os, subprocess, sys

# Strip dynamic-loader injection vars from the env we pass to each
# compile subprocess. CodeQL's tracer wraps the build script with
# its own preload library to capture compiler invocations; the
# script itself shouldn't FORWARD a parent's LD_PRELOAD /
# LD_LIBRARY_PATH / DYLD_* / PYTHONPATH (or other code-injection
# vars) to gcc/javac, which would then attach attacker code at
# every compile step. Build a one-shot scrubbed env here; reuse
# across the per-file loop.
_SCRUB_ENV_VARS = (
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
    "PYTHONPATH", "PYTHONSTARTUP",
    "BASH_ENV", "ENV",
    "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS",
)
_BUILD_ENV = {{k: v for k, v in os.environ.items() if k not in _SCRUB_ENV_VARS}}

COMPILER = {compiler!r}
FLAGS = {(include_flags + define_flags)!r}
BUILD_DIR = {str(build_dir)!r}
REPO_ROOT = os.path.realpath({repo_root!r})
FILES = {files_list!r}
IS_JAVA = {is_java!r}
JAVA_CLASSPATH_JARS = {java_classpath_jars!r}

# Java-only: compose classpath from repo-scoped jar list + build dir.
# os.pathsep handles Linux vs Windows separators (Linux ":").
JAVA_CP = os.pathsep.join(JAVA_CLASSPATH_JARS + [BUILD_DIR]) if IS_JAVA else None

total = len(FILES)
ok = 0
fail = 0
created_dirs = set()
for i, src in enumerate(FILES):
    if i > 0 and i % 50 == 0:
        print(f"  Compiling... {{i}}/{{total}}", file=sys.stderr)

    # SECURITY: resolve symlinks and reject paths that escape the repo root.
    # Prevents writing object files outside the build directory via symlinks.
    rel = os.path.relpath(os.path.realpath(src), REPO_ROOT)
    if rel.startswith('..'):
        fail += 1
        continue

    # SECURITY: subprocess.run with list args — no shell, no injection.
    # Filenames are list elements passed directly to execve.
    if IS_JAVA:
        cmd = [COMPILER] + FLAGS + ["-d", BUILD_DIR]
        if JAVA_CP:
            cmd += ["-cp", JAVA_CP]
        cmd += [src]
    else:
        obj = os.path.join(BUILD_DIR, rel + ".o")
        obj_dir = os.path.dirname(obj)
        if obj_dir not in created_dirs:
            os.makedirs(obj_dir, exist_ok=True)
            created_dirs.add(obj_dir)
        cmd = [COMPILER, "-w"] + FLAGS + ["-c", src, "-o", obj]

    # Per-compile stderr cap. Pre-fix `stderr=subprocess.PIPE`
    # buffered the full stderr stream into the parent before
    # returning — for C++ template-instantiation errors a
    # SINGLE source file can produce tens of MB of stderr.
    # Across hundreds of source files in a target, the script's
    # RSS grew unbounded. Operators saw the build script
    # OOM-killed mid-pass.
    #
    # Use Popen + bounded read(N) so each compile's stderr is
    # capped at 256 KB — enough for a useful diagnostic
    # excerpt, hard upper bound. Drain remaining bytes via
    # /dev/null so the child can finish without SIGPIPE.
    proc = subprocess.Popen(cmd, stderr=subprocess.PIPE, env=_BUILD_ENV)
    _STDERR_CAP = 256 * 1024
    captured = b""
    if proc.stderr is not None:
        captured = proc.stderr.read(_STDERR_CAP)
        # Drain any remainder so the child unblocks on its
        # next stderr write rather than hanging on a full
        # pipe buffer (PIPE_BUF is 64 KB on Linux; without
        # the drain, a child writing > 256 KB sleeps in
        # write(2) waiting for a reader).
        while proc.stderr.read(64 * 1024):
            pass
    # Per-file compile timeout. Pre-fix `proc.wait()` had no
    # bound — a runaway compile (gcc on a pathological template
    # instantiation, javac on infinite annotation processing,
    # deliberately slow input from an untrusted target) hung
    # the whole build script forever. CodeQL DB build then
    # blocked indefinitely with no progress signal.
    # 120s is comfortably above any legitimate single-file
    # compile (the slowest C++ template compiles in real
    # codebases run ~30s); a hung compile gets killed and
    # counted as a failure so the rest of the pass continues.
    _COMPILE_TIMEOUT_S = 120
    try:
        proc.wait(timeout=_COMPILE_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        fail += 1
        sys.stderr.buffer.write(
            f"\\n[compile timeout {{_COMPILE_TIMEOUT_S}}s on {{src!r}}]\\n".encode()
        )
        continue
    if proc.returncode == 0:
        ok += 1
    else:
        fail += 1
        sys.stderr.buffer.write(captured)
        if proc.stderr is not None and len(captured) >= _STDERR_CAP:
            sys.stderr.buffer.write(
                # Doubled braces escape in the OUTER template so the
                # generated script gets a literal brace pair (runtime
                # f-string reference to the script-local _STDERR_CAP),
                # NOT an outer-scope substitution. Pre-fix the single
                # braces let the OUTER f-string evaluate _STDERR_CAP
                # at template-generation time, which raised NameError
                # because _STDERR_CAP only exists in the GENERATED
                # script scope. (Note: keep this comment free of
                # triple-quotes — the outer template uses triple
                # single-quotes.)
                f"\\n[truncated to first {{_STDERR_CAP // 1024}} KB]\\n".encode()
            )

print(f"Compiled {{ok}}/{{total}} files ({{fail}} failed)")
''')
        # SECURITY: make read+execute only after writing — prevents modification
        # between generation and CodeQL execution (TOCTOU mitigation).
        script_path.chmod(0o500)
        return script_path

    def _dry_run(self, script_path, language: Optional[str] = None) -> Optional[list]:
        """Run the build script and return compilation failures.

        Returns:
          * ``list`` of failures (possibly empty) — script ran to
            completion. `[]` means "ran successfully, no errors".
          * ``None`` — script did NOT run at all (subprocess failed to
            spawn, timeout, sandbox-launch error). Distinct from
            "ran with zero failures" because the CC-flag-suggest path
            (which kicks in `if failures:`) shouldn't fire when we
            simply couldn't measure anything.

        Pre-fix this returned `[]` for both cases. The caller's
        `if failures:` then took the "no improvement needed" branch
        when the script crashed at startup (interpreter mismatch,
        sandbox eviction), silently degrading the synthesised-build
        flow to "use heuristic flags" when the actual problem was
        "we never compiled anything to know if the heuristic worked".

        `language` is used to pick the env vars the build tool expects
        — for Java synthesised builds we auto-detect JAVA_HOME and
        inject it into the script's env. Without this, javac is found
        via PATH but the JDK layout (tools.jar, rt.jar on older JDKs)
        may not resolve. Scoped to this one subprocess — see
        ~/design/env-handling.md.
        """
        # Build env: sanitised base + toolchain auto-detection for the
        # language. For Java synthesised-build path, this is JAVA_HOME.
        # For C/C++, nothing to detect (CC/CXX resolved via PATH).
        from core.config import RaptorConfig
        env = RaptorConfig.get_safe_env()
        if language == "java":
            from core.build.toolchain import apply_toolchain_env
            apply_toolchain_env(env, ["JAVA_HOME"])

        try:
            repo_path = str(self.repo_path)
            # tool_paths: best-guess bind set for the Python interpreter
            # — its bin dir AND its stdlib dir at sys.prefix/lib/
            # pythonX.Y/. Without the stdlib dir, Python would die at
            # `import encodings` (exit 126, no stderr) — caught and
            # retried as Landlock-only by context.py's speculative-C
            # retry. Worst case = same isolation as not passing
            # tool_paths at all.
            import sysconfig
            from pathlib import Path as _P
            _tps = []
            _interp_dir = str(_P(sys.executable).resolve().parent)
            _platstdlib = sysconfig.get_paths().get("platstdlib")
            for _p in (_interp_dir, _platstdlib):
                if _p and _P(_p).is_absolute() \
                        and not _p.startswith(("/usr/", "/lib/", "/lib64/")):
                    _tps.append(_p)
            result = _sandbox_run(
                [sys.executable, str(script_path)],
                block_network=True,
                target=repo_path, output=repo_path,
                cwd=self.repo_path,
                env=env,
                tool_paths=_tps or None,
                capture_output=True, text=True, timeout=300,
            )
            # Script crash (not compilation failure) — treat as
            # "didn't actually run a build" via None sentinel, NOT
            # `[]` ("ran with zero failures"). Pre-fix the empty
            # list collapsed both cases and the CC-flag-suggest
            # path silently skipped its retry attempt.
            if result.returncode != 0 and "Traceback" in result.stderr:
                # `[-2]` reaches the second-to-last line, but
                # `result.stderr.split("\n")[-2]` raises IndexError
                # if stderr has fewer than 2 lines (e.g. the script
                # crashed before printing anything, or printed a
                # single line without a trailing newline). Pre-fix
                # the IndexError aborted the warning emission AND
                # dropped through to the bare `except Exception`
                # below, returning [] (now None) but with the
                # operator-visible cause swallowed. Defensive
                # slicing: take the last non-empty line, or the
                # whole stderr if there's only one line.
                stderr_lines = [l for l in (result.stderr or "").split("\n") if l.strip()]
                tail = stderr_lines[-1] if stderr_lines else "(no stderr)"
                logger.warning(f"Build script crashed: {tail}")
                return None
        except (subprocess.TimeoutExpired, Exception) as e:
            logger.warning("Build script never ran (%r) — treating as 'didn't run'", e)
            return None

        # Parse gcc/g++ errors from stderr
        failures = []
        for line in result.stderr.split("\n"):
            if ": error:" in line or ": fatal error:" in line:
                parts = line.split(":", 1)
                src_file = parts[0].strip() if parts else "unknown"
                error = parts[1].strip() if len(parts) > 1 else "unknown"
                if not any(f["file"] == src_file for f in failures):
                    failures.append({"file": src_file, "error": error})
        return failures

    def _cc_suggest_flags(self, failures: list, language: str) -> Optional[dict]:
        """Ask CC to suggest -I and -D flags to fix compilation failures.

        Security model:
        - CC has read-only access (--allowed-tools Read,Grep,Glob)
        - CC outputs JSON data, not code — parsed by json.loads
        - Every flag from CC goes through _validate_flags before use
        - CC cannot modify the build script or execute commands
        - Invalid/malicious flags are silently rejected
        """
        import shutil as _shutil
        claude_bin = _shutil.which("claude")
        if not claude_bin:
            return None
        # Path allowlist for the resolved claude binary. `which` walks
        # PATH, which an untrusted target repo could influence —
        # `direnv`-style `.envrc`, a `pyproject.toml` build hook, or
        # a Makefile that calls into the build_detector flow can
        # prepend a malicious dir to PATH. The resolved absolute
        # path must come from a known install location so an injected
        # `claude` shim in the target repo doesn't get executed under
        # CC's allowlisted-tool model.
        try:
            real_claude = os.path.realpath(claude_bin)
        except OSError:
            return None
        allowed_prefixes = (
            "/usr/local/bin/",
            "/usr/bin/",
            "/opt/",
            os.path.expanduser("~/.local/bin/"),
            os.path.expanduser("~/.npm-global/bin/"),
            "/snap/",
            "/home/linuxbrew/.linuxbrew/bin/",
            "/opt/homebrew/bin/",
        )
        if not any(real_claude.startswith(p) for p in allowed_prefixes):
            logger.info(
                "  Skipping CC flag inference — `claude` resolves to %r "
                "which is outside the install-location allowlist. "
                "If this is a legitimate location, add it to "
                "_cc_suggest_flags' `allowed_prefixes`.",
                real_claude,
            )
            return None

        failure_sample = "\n".join(
            f"- {f['file']}: {f['error']}" for f in failures[:15]
        )

        from core.security.prompt_envelope import UntrustedBlock, build_prompt
        from core.security.prompt_defense_profiles import CONSERVATIVE

        compiler = "gcc" if language == "cpp" else "javac"
        system = (
            f"I have a {language} project with no build system. "
            f"Compilation with {compiler} -w -c and auto-detected -I flags "
            f"partially works, but {len(failures)} files fail.\n\n"
            "Read the source files to understand what's needed. Then output "
            "ONLY a JSON object with two arrays — no other text:\n\n"
            '{"includes": ["-Ipath1", "-Ipath2"], '
            '"defines": ["-DFOO", "-DBAR=1", "-include header.h"]}\n\n'
            "Rules:\n"
            "- Only suggest -I, -D, -include, and -std flags\n"
            "- Do NOT invent #define values that aren't in the source\n"
            "- Paths should be relative to the project root"
        )
        bundle = build_prompt(
            system=system,
            profile=CONSERVATIVE,
            untrusted_blocks=(
                UntrustedBlock(
                    content=str(self.repo_path),
                    kind="project_path",
                    origin="build_detector",
                ),
                UntrustedBlock(
                    content=failure_sample,
                    kind="compiler_errors",
                    origin="build_detector",
                ),
            ),
        )
        prompt = next(m.content for m in bundle.messages if m.role == "user")

        from core.security.cc_trust import check_repo_claude_trust
        if check_repo_claude_trust(str(self.repo_path)):
            logger.info("  Skipping CC flag inference — target repo has dangerous "
                        "Claude Code config (see earlier warning). "
                        "Pass --trust-repo to override.")
            return None

        try:
            logger.info("  Asking Claude Code for additional compiler flags...")
            from core.llm.cc_adapter import CCDispatchConfig, build_cc_command, strip_json_fences
            config = CCDispatchConfig(
                claude_bin=claude_bin,
                tools="Read,Grep,Glob",
                add_dirs=(str(self.repo_path),),
                budget_usd="2.00",
                timeout_s=180,
                capture_json_envelope=False,
            )
            repo_path = str(self.repo_path)
            # Route hostname allowlist through cc_proxy_hosts so this
            # site picks up the same calibrate-aware policy as
            # cc_dispatch's main entry point — operator override,
            # calibrated SandboxProfile, then provider-aware fallback.
            # Pre-migration this hardcoded ``api.anthropic.com``,
            # which silently broke Bedrock / Vertex / Azure /
            # custom-endpoint setups. The downstream client is
            # ``claude`` either way, so the policy is identical.
            from core.llm.cc_proxy_hosts import proxy_hosts_for_cc_dispatch
            result = _sandbox_run(
                build_cc_command(config),
                target=repo_path, output=repo_path,
                use_egress_proxy=True,
                proxy_hosts=proxy_hosts_for_cc_dispatch(claude_bin),
                caller_label="codeql-build-detect",
                input=prompt, capture_output=True, text=True, timeout=180,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return None

            # Cap JSON parse input. Pre-fix `result.stdout` could be
            # arbitrarily large (CC model hallucinates and emits MB
            # of "JSON"; CC subprocess could be tricked into echoing
            # a large file via Read+output); json.loads would gladly
            # consume the entire blob, allocating proportional
            # memory + serialising it through the parser. The
            # genuine response shape — `{"includes": [...],
            # "defines": [...]}` with maybe 50 entries each at
            # <100 chars — comfortably fits in 100KB. Anything
            # larger is hallucination or attack.
            _CC_JSON_MAX_BYTES = 100 * 1024
            stdout = result.stdout.strip()
            if len(stdout) > _CC_JSON_MAX_BYTES:
                logger.warning(
                    "CC suggest-flags output exceeded %d bytes (%d) — rejecting",
                    _CC_JSON_MAX_BYTES, len(stdout),
                )
                return None
            content = strip_json_fences(stdout)

            import json
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                # Recover by scanning forward through `{` positions and
                # picking the FIRST one whose tail JSON-parses cleanly.
                # Pre-fix `idx = content.index("{")` always picked the
                # first `{` — but LLM prose with embedded `{` glyphs
                # ("the function takes { foo, bar } as params, here is
                # the JSON: {valid}") parsed from the wrong position
                # and silently dropped the real answer. Bound the
                # scan at 16 attempts so a CC output full of literal
                # `{` glyphs (a list of code samples) doesn't burn
                # measurable wallclock retrying.
                data = None
                _attempts = 0
                _start = 0
                while _attempts < 16:
                    idx = content.find("{", _start)
                    if idx < 0:
                        break
                    try:
                        data = json.loads(content[idx:])
                        break
                    except (ValueError, json.JSONDecodeError):
                        _start = idx + 1
                        _attempts += 1
                if data is None:
                    logger.debug(
                        "CC output wasn't valid JSON after %d brace probes",
                        _attempts,
                    )
                    return None

            # Pre-fix `data.get("includes", [])` returned the
            # default `[]` only when the key was MISSING. If the
            # CC LLM emitted `{"includes": null, "defines": null}`
            # (common when the model thought "no useful suggestion"
            # and serialised null instead of an empty array), the
            # `.get("includes", [])` returned None, and
            # `_validate_flags(None)` crashed with `TypeError:
            # 'NoneType' object is not iterable`. Coerce explicit
            # null to [] in addition to the missing-key default.
            #
            # Real failure mode: a quiet json-from-CC failure
            # turned into a Python traceback aborting the whole
            # heuristic-build flow, where the right behaviour is
            # to log "no flags suggested" and proceed with the
            # base build.
            includes = self._validate_flags(data.get("includes") or [])
            defines = self._validate_flags(data.get("defines") or [])

            if includes or defines:
                logger.info(f"  CC suggested {len(includes)} includes, {len(defines)} defines")
                return {"includes": includes, "defines": defines}

        except subprocess.TimeoutExpired:
            logger.info("  CC flag suggestion timed out (180s)")
        except Exception as e:
            logger.debug(f"CC flag suggestion failed: {e}")

        return None

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
            print("WARNING: Build command validation failed")

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
