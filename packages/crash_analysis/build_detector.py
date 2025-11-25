"""
Build System Detector

Auto-detect and configure builds for common build systems with ASan and debug symbols.
"""

import os
import subprocess
import shutil
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict


class BuildSystem(Enum):
    """Supported build systems."""
    CMAKE = "cmake"
    AUTOTOOLS = "autotools"
    MAKEFILE = "makefile"
    MESON = "meson"
    UNKNOWN = "unknown"


@dataclass
class BuildConfig:
    """Build configuration."""
    build_system: BuildSystem
    source_dir: Path
    build_dir: Path

    # Compiler flags
    cc: str = "gcc"
    cxx: str = "g++"
    cflags: str = "-fsanitize=address -g -O1 -fno-omit-frame-pointer"
    cxxflags: str = "-fsanitize=address -g -O1 -fno-omit-frame-pointer"
    ldflags: str = "-fsanitize=address"

    # Build options
    extra_configure_args: List[str] = None
    extra_cmake_args: List[str] = None
    parallel_jobs: int = 4

    def __post_init__(self):
        if self.extra_configure_args is None:
            self.extra_configure_args = []
        if self.extra_cmake_args is None:
            self.extra_cmake_args = []


class BuildDetector:
    """Detect and execute builds for various build systems."""

    def __init__(self, source_dir: Path, build_dir: Optional[Path] = None):
        """
        Initialize build detector.

        Args:
            source_dir: Path to source code
            build_dir: Path for build artifacts (default: source_dir/build)
        """
        self.source_dir = Path(source_dir).resolve()
        self.build_dir = Path(build_dir).resolve() if build_dir else self.source_dir / "build"

    def detect(self) -> BuildSystem:
        """
        Detect the build system used by the project.

        Returns:
            BuildSystem enum value
        """
        # Check for CMake
        if (self.source_dir / "CMakeLists.txt").exists():
            return BuildSystem.CMAKE

        # Check for Autotools
        if (self.source_dir / "configure").exists():
            return BuildSystem.AUTOTOOLS
        if (self.source_dir / "configure.ac").exists():
            return BuildSystem.AUTOTOOLS
        if (self.source_dir / "autogen.sh").exists():
            return BuildSystem.AUTOTOOLS

        # Check for Meson
        if (self.source_dir / "meson.build").exists():
            return BuildSystem.MESON

        # Check for plain Makefile
        if (self.source_dir / "Makefile").exists():
            return BuildSystem.MAKEFILE
        if (self.source_dir / "makefile").exists():
            return BuildSystem.MAKEFILE
        if (self.source_dir / "GNUmakefile").exists():
            return BuildSystem.MAKEFILE

        return BuildSystem.UNKNOWN

    def create_config(
        self,
        build_system: Optional[BuildSystem] = None,
        enable_asan: bool = True,
        enable_debug: bool = True,
        enable_coverage: bool = False,
    ) -> BuildConfig:
        """
        Create a build configuration.

        Args:
            build_system: Override detected build system
            enable_asan: Enable AddressSanitizer
            enable_debug: Enable debug symbols
            enable_coverage: Enable gcov coverage

        Returns:
            BuildConfig with appropriate settings
        """
        if build_system is None:
            build_system = self.detect()

        config = BuildConfig(
            build_system=build_system,
            source_dir=self.source_dir,
            build_dir=self.build_dir,
        )

        # Build compiler flags
        cflags_parts = []
        ldflags_parts = []

        if enable_asan:
            cflags_parts.append("-fsanitize=address")
            ldflags_parts.append("-fsanitize=address")

        if enable_debug:
            cflags_parts.extend(["-g", "-O1", "-fno-omit-frame-pointer"])
        else:
            cflags_parts.append("-O2")

        if enable_coverage:
            cflags_parts.append("--coverage")
            ldflags_parts.append("--coverage")

        config.cflags = " ".join(cflags_parts)
        config.cxxflags = " ".join(cflags_parts)
        config.ldflags = " ".join(ldflags_parts)

        return config

    def configure(self, config: BuildConfig) -> bool:
        """
        Run configuration step for the build system.

        Args:
            config: Build configuration

        Returns:
            True if successful
        """
        config.build_dir.mkdir(parents=True, exist_ok=True)

        env = self._get_build_env(config)

        if config.build_system == BuildSystem.CMAKE:
            return self._configure_cmake(config, env)
        elif config.build_system == BuildSystem.AUTOTOOLS:
            return self._configure_autotools(config, env)
        elif config.build_system == BuildSystem.MESON:
            return self._configure_meson(config, env)
        elif config.build_system == BuildSystem.MAKEFILE:
            # Plain Makefile doesn't need configuration
            return True
        else:
            raise ValueError(f"Cannot configure unknown build system")

    def build(self, config: BuildConfig) -> bool:
        """
        Run the build.

        Args:
            config: Build configuration

        Returns:
            True if successful
        """
        env = self._get_build_env(config)

        if config.build_system == BuildSystem.CMAKE:
            return self._build_cmake(config, env)
        elif config.build_system == BuildSystem.AUTOTOOLS:
            return self._build_make(config, env)
        elif config.build_system == BuildSystem.MESON:
            return self._build_meson(config, env)
        elif config.build_system == BuildSystem.MAKEFILE:
            return self._build_make(config, env)
        else:
            raise ValueError(f"Cannot build unknown build system")

    def configure_and_build(self, config: BuildConfig) -> bool:
        """
        Run both configuration and build steps.

        Args:
            config: Build configuration

        Returns:
            True if successful
        """
        print(f"[*] Detected build system: {config.build_system.value}")
        print(f"[*] Source directory: {config.source_dir}")
        print(f"[*] Build directory: {config.build_dir}")
        print(f"[*] CFLAGS: {config.cflags}")

        if not self.configure(config):
            print("[!] Configuration failed")
            return False

        if not self.build(config):
            print("[!] Build failed")
            return False

        print("[+] Build completed successfully")
        return True

    def _get_build_env(self, config: BuildConfig) -> Dict[str, str]:
        """Get environment variables for the build."""
        env = os.environ.copy()
        env["CC"] = config.cc
        env["CXX"] = config.cxx
        env["CFLAGS"] = config.cflags
        env["CXXFLAGS"] = config.cxxflags
        env["LDFLAGS"] = config.ldflags
        # ASAN options
        env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1"
        return env

    def _configure_cmake(self, config: BuildConfig, env: Dict[str, str]) -> bool:
        """Configure CMake project."""
        cmd = [
            "cmake",
            "-B", str(config.build_dir),
            "-S", str(config.source_dir),
            "-DCMAKE_BUILD_TYPE=Debug",
            f"-DCMAKE_C_COMPILER={config.cc}",
            f"-DCMAKE_CXX_COMPILER={config.cxx}",
            f"-DCMAKE_C_FLAGS={config.cflags}",
            f"-DCMAKE_CXX_FLAGS={config.cxxflags}",
            f"-DCMAKE_EXE_LINKER_FLAGS={config.ldflags}",
            f"-DCMAKE_SHARED_LINKER_FLAGS={config.ldflags}",
        ]
        cmd.extend(config.extra_cmake_args)

        print(f"[*] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, env=env, cwd=config.source_dir)
        return result.returncode == 0

    def _configure_autotools(self, config: BuildConfig, env: Dict[str, str]) -> bool:
        """Configure Autotools project."""
        # Check if we need to run autogen.sh first
        if not (config.source_dir / "configure").exists():
            if (config.source_dir / "autogen.sh").exists():
                print("[*] Running autogen.sh...")
                result = subprocess.run(
                    ["./autogen.sh"],
                    env=env,
                    cwd=config.source_dir
                )
                if result.returncode != 0:
                    return False
            elif (config.source_dir / "configure.ac").exists():
                print("[*] Running autoreconf...")
                result = subprocess.run(
                    ["autoreconf", "-i"],
                    env=env,
                    cwd=config.source_dir
                )
                if result.returncode != 0:
                    return False

        configure_script = config.source_dir / "configure"
        if not configure_script.exists():
            print("[!] No configure script found")
            return False

        cmd = [
            str(configure_script),
            f"--prefix={config.build_dir}/install",
        ]
        cmd.extend(config.extra_configure_args)

        print(f"[*] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, env=env, cwd=config.build_dir)
        return result.returncode == 0

    def _configure_meson(self, config: BuildConfig, env: Dict[str, str]) -> bool:
        """Configure Meson project."""
        cmd = [
            "meson",
            "setup",
            str(config.build_dir),
            str(config.source_dir),
            "--buildtype=debug",
        ]

        print(f"[*] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, env=env, cwd=config.source_dir)
        return result.returncode == 0

    def _build_cmake(self, config: BuildConfig, env: Dict[str, str]) -> bool:
        """Build CMake project."""
        cmd = [
            "cmake",
            "--build", str(config.build_dir),
            "-j", str(config.parallel_jobs),
        ]

        print(f"[*] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, env=env, cwd=config.build_dir)
        return result.returncode == 0

    def _build_make(self, config: BuildConfig, env: Dict[str, str]) -> bool:
        """Build with Make."""
        # Determine the correct working directory
        if config.build_system == BuildSystem.AUTOTOOLS:
            work_dir = config.build_dir
        else:
            work_dir = config.source_dir

        cmd = ["make", f"-j{config.parallel_jobs}"]

        print(f"[*] Running: {' '.join(cmd)} in {work_dir}")
        result = subprocess.run(cmd, env=env, cwd=work_dir)
        return result.returncode == 0

    def _build_meson(self, config: BuildConfig, env: Dict[str, str]) -> bool:
        """Build Meson project."""
        cmd = ["meson", "compile", "-C", str(config.build_dir)]

        print(f"[*] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, env=env, cwd=config.source_dir)
        return result.returncode == 0


def run_custom_build(
    build_cmd: str,
    source_dir: Path,
    env_overrides: Optional[Dict[str, str]] = None,
) -> bool:
    """
    Run a custom build command.

    Args:
        build_cmd: Build command to run
        source_dir: Source directory to run in
        env_overrides: Additional environment variables

    Returns:
        True if successful
    """
    env = os.environ.copy()
    if env_overrides:
        env.update(env_overrides)

    print(f"[*] Running custom build: {build_cmd}")
    result = subprocess.run(
        build_cmd,
        shell=True,
        env=env,
        cwd=source_dir,
    )
    return result.returncode == 0
