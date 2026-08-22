"""Cross-platform dependency satisfaction matrix.

Defines every tool, library, and runtime that RAPTOR can use, grouped
by capability tier.  For each dependency: what platforms it supports,
how to install it, and which RAPTOR modes it enables.

``check_all()`` probes the current system and returns a scored matrix
with [MET] / [NOT MET] verdicts plus install guidance.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping, Optional, Sequence


class Tier(Enum):
    CORE = "core"
    SCANNING = "scanning"
    FUZZING = "fuzzing"
    BINARY_ANALYSIS = "binary-analysis"
    DYNAMIC_ANALYSIS = "dynamic-analysis"
    WEB = "web"
    LLM = "llm"
    SCA = "sca"
    BROKER = "broker"
    OPTIONAL = "optional"


class Platform(Enum):
    LINUX_X86_64 = "linux-x86_64"
    LINUX_AARCH64 = "linux-aarch64"
    MACOS_ARM64 = "macos-arm64"
    MACOS_X86_64 = "macos-x86_64"
    WINDOWS_X86_64 = "windows-x86_64"
    WINDOWS_ARM64 = "windows-arm64"
    ANDROID = "android"
    IOS = "ios"

    @classmethod
    def detect(cls) -> "Platform":
        os_name = platform.system().lower()
        arch = platform.machine().lower()
        norm_arch = {"amd64": "x86_64", "arm64": "aarch64"}.get(arch, arch)

        if os_name == "linux":
            return cls.LINUX_AARCH64 if norm_arch == "aarch64" else cls.LINUX_X86_64
        elif os_name == "darwin":
            return cls.MACOS_ARM64 if norm_arch == "aarch64" else cls.MACOS_X86_64
        elif os_name == "windows":
            return cls.WINDOWS_ARM64 if norm_arch in ("aarch64", "arm64") else cls.WINDOWS_X86_64
        return cls.LINUX_X86_64


@dataclass(frozen=True)
class InstallGuide:
    """Platform-specific install instructions for a dependency."""
    platform: Platform
    method: str
    command: str
    url: Optional[str] = None
    notes: Optional[str] = None


@dataclass(frozen=True)
class Dependency:
    """A single tool, library, or runtime that RAPTOR can use."""
    name: str
    description: str
    tier: Tier
    binary: Optional[str] = None
    python_package: Optional[str] = None
    affects: str = ""
    required: bool = False
    platforms: frozenset[Platform] = field(default_factory=lambda: frozenset(Platform))
    install_guides: tuple[InstallGuide, ...] = ()

    def check(self) -> bool:
        """Check if this dependency is satisfied on the current system."""
        if self.binary:
            return shutil.which(self.binary) is not None
        if self.python_package:
            return _check_python_package(self.python_package)
        return False

    def guide_for(self, plat: Platform) -> Optional[InstallGuide]:
        for g in self.install_guides:
            if g.platform == plat:
                return g
        return None


@dataclass(frozen=True)
class DepCheckResult:
    """Result of checking a single dependency."""
    dep: Dependency
    met: bool
    guide: Optional[InstallGuide] = None


@dataclass(frozen=True)
class MatrixResult:
    """Full dependency satisfaction matrix."""
    platform: Platform
    results: tuple[DepCheckResult, ...]

    @property
    def met_count(self) -> int:
        return sum(1 for r in self.results if r.met)

    @property
    def total_count(self) -> int:
        return len(self.results)

    @property
    def required_met(self) -> int:
        return sum(1 for r in self.results if r.dep.required and r.met)

    @property
    def required_total(self) -> int:
        return sum(1 for r in self.results if r.dep.required)

    def by_tier(self) -> dict[Tier, list[DepCheckResult]]:
        grouped: dict[Tier, list[DepCheckResult]] = {}
        for r in self.results:
            grouped.setdefault(r.dep.tier, []).append(r)
        return grouped


def _check_python_package(name: str) -> bool:
    try:
        __import__(name)
        return True
    except ImportError:
        return False


# ── All platforms shorthand ──────────────────────────────────────────

_LINUX = frozenset({Platform.LINUX_X86_64, Platform.LINUX_AARCH64})
_MACOS = frozenset({Platform.MACOS_ARM64, Platform.MACOS_X86_64})
_WINDOWS = frozenset({Platform.WINDOWS_X86_64, Platform.WINDOWS_ARM64})
_DESKTOP = _LINUX | _MACOS | _WINDOWS
_UNIX = _LINUX | _MACOS
_MOBILE = frozenset({Platform.ANDROID, Platform.IOS})
_ALL = _DESKTOP | _MOBILE


def _g(plat: Platform, method: str, cmd: str,
       url: str | None = None, notes: str | None = None) -> InstallGuide:
    return InstallGuide(platform=plat, method=method, command=cmd,
                        url=url, notes=notes)


# ── Dependency catalog ───────────────────────────────────────────────

DEPENDENCIES: tuple[Dependency, ...] = (

    # ── CORE ─────────────────────────────────────────────────────────
    Dependency(
        name="python3",
        description="Python 3.10+ interpreter — RAPTOR runtime",
        tier=Tier.CORE,
        binary="python3",
        required=True,
        platforms=_ALL,
        affects="/all",
        install_guides=(
            _g(Platform.LINUX_X86_64, "apt", "sudo apt install python3 python3-pip python3-venv",
               url="https://www.python.org/downloads/"),
            _g(Platform.LINUX_AARCH64, "apt", "sudo apt install python3 python3-pip python3-venv",
               url="https://www.python.org/downloads/"),
            _g(Platform.MACOS_ARM64, "brew", "brew install python@3",
               url="https://www.python.org/downloads/macos/"),
            _g(Platform.MACOS_X86_64, "brew", "brew install python@3",
               url="https://www.python.org/downloads/macos/"),
            _g(Platform.WINDOWS_X86_64, "winget", "winget install Python.Python.3.12",
               url="https://www.python.org/downloads/windows/"),
            _g(Platform.WINDOWS_ARM64, "winget", "winget install Python.Python.3.12",
               url="https://www.python.org/downloads/windows/",
               notes="ARM64 native builds available from python.org 3.11+"),
            _g(Platform.ANDROID, "termux", "pkg install python",
               url="https://termux.dev/"),
        ),
    ),
    Dependency(
        name="git",
        description="Git version control — repository operations",
        tier=Tier.CORE,
        binary="git",
        required=True,
        platforms=_ALL,
        affects="/all",
        install_guides=(
            _g(Platform.LINUX_X86_64, "apt", "sudo apt install git"),
            _g(Platform.LINUX_AARCH64, "apt", "sudo apt install git"),
            _g(Platform.MACOS_ARM64, "xcode", "xcode-select --install",
               notes="Ships with Xcode CLT"),
            _g(Platform.MACOS_X86_64, "xcode", "xcode-select --install"),
            _g(Platform.WINDOWS_X86_64, "winget", "winget install Git.Git",
               url="https://git-scm.com/download/win"),
            _g(Platform.WINDOWS_ARM64, "winget", "winget install Git.Git",
               url="https://git-scm.com/download/win"),
            _g(Platform.ANDROID, "termux", "pkg install git"),
        ),
    ),
    Dependency(
        name="claude-code",
        description="Claude Code CLI — agentic decision layer",
        tier=Tier.CORE,
        binary="claude",
        required=False,
        platforms=_DESKTOP,
        affects="/agentic (interactive mode)",
        install_guides=(
            _g(Platform.LINUX_X86_64, "npm", "npm install -g @anthropic-ai/claude-code",
               url="https://docs.anthropic.com/en/docs/claude-code"),
            _g(Platform.LINUX_AARCH64, "npm", "npm install -g @anthropic-ai/claude-code",
               url="https://docs.anthropic.com/en/docs/claude-code"),
            _g(Platform.MACOS_ARM64, "npm", "npm install -g @anthropic-ai/claude-code",
               url="https://docs.anthropic.com/en/docs/claude-code"),
            _g(Platform.MACOS_X86_64, "npm", "npm install -g @anthropic-ai/claude-code"),
            _g(Platform.WINDOWS_X86_64, "npm", "npm install -g @anthropic-ai/claude-code"),
        ),
    ),

    # ── SCANNING ─────────────────────────────────────────────────────
    Dependency(
        name="semgrep",
        description="Semgrep static analysis engine",
        tier=Tier.SCANNING,
        binary="semgrep",
        required=False,
        platforms=_DESKTOP,
        affects="/scan, /agentic",
        install_guides=(
            _g(Platform.LINUX_X86_64, "pip", "pip3 install semgrep",
               url="https://semgrep.dev/docs/getting-started/"),
            _g(Platform.LINUX_AARCH64, "pip", "pip3 install semgrep",
               notes="Native aarch64 wheel available"),
            _g(Platform.MACOS_ARM64, "brew", "brew install semgrep",
               url="https://semgrep.dev/docs/getting-started/"),
            _g(Platform.MACOS_X86_64, "brew", "brew install semgrep"),
            _g(Platform.WINDOWS_X86_64, "pip", "pip3 install semgrep",
               notes="Windows support is experimental"),
        ),
    ),
    Dependency(
        name="codeql",
        description="GitHub CodeQL — deep semantic code analysis",
        tier=Tier.SCANNING,
        binary="codeql",
        required=False,
        platforms=_UNIX | frozenset({Platform.WINDOWS_X86_64}),
        affects="/codeql, /agentic",
        install_guides=(
            _g(Platform.LINUX_X86_64, "manual",
               "curl -fsSL https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip -o /tmp/codeql.zip && sudo unzip -oq /tmp/codeql.zip -d /opt && sudo ln -sf /opt/codeql/codeql /usr/local/bin/codeql",
               url="https://github.com/github/codeql-cli-binaries/releases"),
            _g(Platform.LINUX_AARCH64, "manual",
               "# No official aarch64 binary — cross-compile or use x86_64 via QEMU/Rosetta",
               url="https://github.com/github/codeql-cli-binaries/releases",
               notes="x86_64 only — use QEMU user-mode or a x86_64 broker target"),
            _g(Platform.MACOS_ARM64, "brew", "brew install codeql",
               url="https://github.com/github/codeql-cli-binaries/releases",
               notes="Universal binary — runs natively on Apple Silicon"),
            _g(Platform.MACOS_X86_64, "brew", "brew install codeql"),
            _g(Platform.WINDOWS_X86_64, "manual",
               "Download codeql-win64.zip from releases, extract to C:\\codeql, add to PATH",
               url="https://github.com/github/codeql-cli-binaries/releases"),
        ),
    ),
    Dependency(
        name="coccinelle",
        description="Coccinelle (spatch) — C/C++ semantic patch verification",
        tier=Tier.SCANNING,
        binary="spatch",
        required=False,
        platforms=_UNIX,
        affects="/codeql, /agentic (source_intel verdict-active axes)",
        install_guides=(
            _g(Platform.LINUX_X86_64, "apt", "sudo apt install coccinelle"),
            _g(Platform.LINUX_AARCH64, "apt", "sudo apt install coccinelle"),
            _g(Platform.MACOS_ARM64, "brew", "brew install coccinelle",
               url="https://coccinelle.gitlabpages.inria.fr/website/"),
            _g(Platform.MACOS_X86_64, "brew", "brew install coccinelle"),
        ),
    ),

    # ── FUZZING ──────────────────────────────────────────────────────
    Dependency(
        name="afl++",
        description="AFL++ fuzzer — coverage-guided binary fuzzing",
        tier=Tier.FUZZING,
        binary="afl-fuzz",
        required=False,
        platforms=_LINUX,
        affects="/fuzz",
        install_guides=(
            _g(Platform.LINUX_X86_64, "apt", "sudo apt install afl++ afl++-clang",
               url="https://github.com/AFLplusplus/AFLplusplus",
               notes="Also available via Docker: docker pull aflplusplus/aflplusplus"),
            _g(Platform.LINUX_AARCH64, "apt", "sudo apt install afl++ afl++-clang",
               url="https://github.com/AFLplusplus/AFLplusplus",
               notes="Native aarch64 packages in Ubuntu 22.04+"),
        ),
    ),
    Dependency(
        name="gcc",
        description="GCC compiler — build instrumented fuzz targets",
        tier=Tier.FUZZING,
        binary="gcc",
        required=False,
        platforms=_UNIX | frozenset({Platform.WINDOWS_X86_64}),
        affects="/fuzz (instrumentation builds)",
        install_guides=(
            _g(Platform.LINUX_X86_64, "apt", "sudo apt install build-essential"),
            _g(Platform.LINUX_AARCH64, "apt", "sudo apt install build-essential"),
            _g(Platform.MACOS_ARM64, "xcode", "xcode-select --install",
               notes="Apple Clang; for real GCC use 'brew install gcc'"),
            _g(Platform.MACOS_X86_64, "xcode", "xcode-select --install"),
            _g(Platform.WINDOWS_X86_64, "msys2", "pacman -S mingw-w64-x86_64-gcc",
               url="https://www.msys2.org/"),
        ),
    ),
    Dependency(
        name="cmake",
        description="CMake build system — build complex fuzz/analysis targets",
        tier=Tier.FUZZING,
        binary="cmake",
        required=False,
        platforms=_DESKTOP,
        affects="/fuzz, /crash-analysis (target builds)",
        install_guides=(
            _g(Platform.LINUX_X86_64, "apt", "sudo apt install cmake"),
            _g(Platform.LINUX_AARCH64, "apt", "sudo apt install cmake"),
            _g(Platform.MACOS_ARM64, "brew", "brew install cmake",
               url="https://cmake.org/download/"),
            _g(Platform.MACOS_X86_64, "brew", "brew install cmake"),
            _g(Platform.WINDOWS_X86_64, "winget", "winget install Kitware.CMake",
               url="https://cmake.org/download/"),
        ),
    ),

    # ── BINARY ANALYSIS ──────────────────────────────────────────────
    Dependency(
        name="gdb",
        description="GNU Debugger — crash analysis and exploitation research",
        tier=Tier.BINARY_ANALYSIS,
        binary="gdb",
        required=False,
        platforms=_LINUX | frozenset({Platform.MACOS_X86_64}),
        affects="/crash-analysis, /fuzz",
        install_guides=(
            _g(Platform.LINUX_X86_64, "apt", "sudo apt install gdb"),
            _g(Platform.LINUX_AARCH64, "apt", "sudo apt install gdb"),
            _g(Platform.MACOS_X86_64, "brew", "brew install gdb",
               notes="Requires code-signing; see https://sourceware.org/gdb/wiki/PermissionsDarwin"),
            _g(Platform.MACOS_ARM64, "brew", "brew install gdb",
               notes="Limited on Apple Silicon — lldb is preferred; gdb requires Rosetta"),
        ),
    ),
    Dependency(
        name="rr",
        description="Mozilla rr — record-and-replay debugger for deterministic crash analysis",
        tier=Tier.BINARY_ANALYSIS,
        binary="rr",
        required=False,
        platforms=frozenset({Platform.LINUX_X86_64}),
        affects="/crash-analysis (time-travel debugging)",
        install_guides=(
            _g(Platform.LINUX_X86_64, "apt",
               "sudo apt install rr",
               url="https://rr-project.org/",
               notes="x86_64 only — no ARM support. Requires perf_event_paranoid <= 1"),
        ),
    ),
    Dependency(
        name="jadx",
        description="JADX — Android APK/DEX decompiler",
        tier=Tier.BINARY_ANALYSIS,
        binary="jadx",
        required=False,
        platforms=_DESKTOP,
        affects="Android/APK reverse engineering",
        install_guides=(
            _g(Platform.LINUX_X86_64, "manual",
               "curl -fsSL https://github.com/skylot/jadx/releases/latest/download/jadx-*.zip -o /tmp/jadx.zip && sudo unzip -oq /tmp/jadx.zip -d /opt/jadx && sudo ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx",
               url="https://github.com/skylot/jadx/releases"),
            _g(Platform.LINUX_AARCH64, "manual",
               "Same as x86_64 — jadx is a Java application (platform-independent JAR)",
               url="https://github.com/skylot/jadx/releases",
               notes="Requires JRE 11+"),
            _g(Platform.MACOS_ARM64, "brew", "brew install jadx",
               url="https://github.com/skylot/jadx/releases"),
            _g(Platform.MACOS_X86_64, "brew", "brew install jadx"),
            _g(Platform.WINDOWS_X86_64, "manual",
               "Download jadx-gui-*.exe from releases",
               url="https://github.com/skylot/jadx/releases"),
        ),
    ),

    # ── DYNAMIC ANALYSIS ─────────────────────────────────────────────
    Dependency(
        name="frida",
        description="Frida dynamic instrumentation toolkit",
        tier=Tier.DYNAMIC_ANALYSIS,
        binary="frida",
        required=False,
        platforms=_DESKTOP | _MOBILE,
        affects="/frida, dynamic analysis, /fuzz harness probe",
        install_guides=(
            _g(Platform.LINUX_X86_64, "pip", "pip3 install frida-tools",
               url="https://frida.re/docs/installation/"),
            _g(Platform.LINUX_AARCH64, "pip", "pip3 install frida-tools",
               notes="Native aarch64 wheels available"),
            _g(Platform.MACOS_ARM64, "pip", "pip3 install frida-tools",
               url="https://frida.re/docs/installation/"),
            _g(Platform.MACOS_X86_64, "pip", "pip3 install frida-tools"),
            _g(Platform.WINDOWS_X86_64, "pip", "pip3 install frida-tools"),
            _g(Platform.ANDROID, "manual",
               "Push frida-server to device: adb push frida-server /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/frida-server",
               url="https://frida.re/docs/android/",
               notes="Requires rooted device or frida-gadget injection"),
            _g(Platform.IOS, "manual",
               "Install frida from Cydia/Sileo repo: https://build.frida.re",
               url="https://frida.re/docs/ios/",
               notes="Requires jailbroken device"),
        ),
    ),
    Dependency(
        name="frida-trace",
        description="Frida trace — function-level dynamic tracing",
        tier=Tier.DYNAMIC_ANALYSIS,
        binary="frida-trace",
        required=False,
        platforms=_DESKTOP,
        affects="dynamic tracing",
        install_guides=(
            _g(Platform.LINUX_X86_64, "pip", "pip3 install frida-tools",
               notes="Included in frida-tools package"),
            _g(Platform.LINUX_AARCH64, "pip", "pip3 install frida-tools"),
            _g(Platform.MACOS_ARM64, "pip", "pip3 install frida-tools"),
            _g(Platform.MACOS_X86_64, "pip", "pip3 install frida-tools"),
            _g(Platform.WINDOWS_X86_64, "pip", "pip3 install frida-tools"),
        ),
    ),

    # ── WEB ──────────────────────────────────────────────────────────
    Dependency(
        name="playwright",
        description="Playwright — headless browser for web scanning",
        tier=Tier.WEB,
        python_package="playwright",
        required=False,
        platforms=_DESKTOP,
        affects="/web",
        install_guides=(
            _g(Platform.LINUX_X86_64, "pip",
               "pip3 install playwright && python3 -m playwright install chromium",
               url="https://playwright.dev/python/docs/intro"),
            _g(Platform.LINUX_AARCH64, "pip",
               "pip3 install playwright && python3 -m playwright install chromium",
               notes="aarch64 Chromium builds available from Playwright 1.40+"),
            _g(Platform.MACOS_ARM64, "pip",
               "pip3 install playwright && python3 -m playwright install chromium"),
            _g(Platform.MACOS_X86_64, "pip",
               "pip3 install playwright && python3 -m playwright install chromium"),
            _g(Platform.WINDOWS_X86_64, "pip",
               "pip3 install playwright && python -m playwright install chromium"),
        ),
    ),

    # ── LLM ──────────────────────────────────────────────────────────
    Dependency(
        name="openai-sdk",
        description="OpenAI Python SDK — multi-provider LLM access (OpenAI, Gemini shim, Mistral, Ollama)",
        tier=Tier.LLM,
        python_package="openai",
        required=False,
        platforms=_ALL,
        affects="LLM-powered analysis (multi-provider)",
        install_guides=(
            _g(Platform.LINUX_X86_64, "pip", "pip3 install openai"),
            _g(Platform.LINUX_AARCH64, "pip", "pip3 install openai"),
            _g(Platform.MACOS_ARM64, "pip", "pip3 install openai"),
            _g(Platform.MACOS_X86_64, "pip", "pip3 install openai"),
            _g(Platform.WINDOWS_X86_64, "pip", "pip3 install openai"),
        ),
    ),
    Dependency(
        name="anthropic-sdk",
        description="Anthropic Python SDK — Claude native structured output",
        tier=Tier.LLM,
        python_package="anthropic",
        required=False,
        platforms=_ALL,
        affects="LLM-powered analysis (Anthropic Claude)",
        install_guides=(
            _g(Platform.LINUX_X86_64, "pip", "pip3 install anthropic"),
            _g(Platform.LINUX_AARCH64, "pip", "pip3 install anthropic"),
            _g(Platform.MACOS_ARM64, "pip", "pip3 install anthropic"),
            _g(Platform.MACOS_X86_64, "pip", "pip3 install anthropic"),
            _g(Platform.WINDOWS_X86_64, "pip", "pip3 install anthropic"),
        ),
    ),
    Dependency(
        name="google-genai-sdk",
        description="Google GenAI SDK — Gemini native access",
        tier=Tier.LLM,
        python_package="google.genai",
        required=False,
        platforms=_ALL,
        affects="LLM-powered analysis (Google Gemini native)",
        install_guides=(
            _g(Platform.LINUX_X86_64, "pip", "pip3 install google-genai"),
            _g(Platform.LINUX_AARCH64, "pip", "pip3 install google-genai"),
            _g(Platform.MACOS_ARM64, "pip", "pip3 install google-genai"),
            _g(Platform.MACOS_X86_64, "pip", "pip3 install google-genai"),
            _g(Platform.WINDOWS_X86_64, "pip", "pip3 install google-genai"),
        ),
    ),
    Dependency(
        name="ollama",
        description="Ollama — local LLM runtime (exposed via OpenAI-compatible endpoint)",
        tier=Tier.LLM,
        binary="ollama",
        required=False,
        platforms=_DESKTOP,
        affects="local LLM inference (no API key needed)",
        install_guides=(
            _g(Platform.LINUX_X86_64, "curl",
               "curl -fsSL https://ollama.ai/install.sh | sh",
               url="https://ollama.ai/download"),
            _g(Platform.LINUX_AARCH64, "curl",
               "curl -fsSL https://ollama.ai/install.sh | sh",
               url="https://ollama.ai/download",
               notes="Native aarch64 binary"),
            _g(Platform.MACOS_ARM64, "manual", "Download Ollama.app",
               url="https://ollama.ai/download"),
            _g(Platform.MACOS_X86_64, "manual", "Download Ollama.app",
               url="https://ollama.ai/download"),
            _g(Platform.WINDOWS_X86_64, "manual", "Download OllamaSetup.exe",
               url="https://ollama.ai/download"),
        ),
    ),

    # ── SCA ──────────────────────────────────────────────────────────
    Dependency(
        name="z3-solver",
        description="Z3 SMT solver — path feasibility and one-gadget analysis",
        tier=Tier.SCA,
        python_package="z3",
        required=False,
        platforms=_DESKTOP,
        affects="exploit feasibility analysis (SMT-based constraint solving)",
        install_guides=(
            _g(Platform.LINUX_X86_64, "pip", "pip3 install z3-solver",
               url="https://github.com/Z3Prover/z3"),
            _g(Platform.LINUX_AARCH64, "pip", "pip3 install z3-solver",
               notes="aarch64 wheel available; may need to build from source on older distros"),
            _g(Platform.MACOS_ARM64, "pip", "pip3 install z3-solver"),
            _g(Platform.MACOS_X86_64, "pip", "pip3 install z3-solver"),
            _g(Platform.WINDOWS_X86_64, "pip", "pip3 install z3-solver"),
        ),
    ),

    # ── BROKER ───────────────────────────────────────────────────────
    Dependency(
        name="paramiko",
        description="Paramiko — SSH transport for the broker (Linux/macOS targets)",
        tier=Tier.BROKER,
        python_package="paramiko",
        required=False,
        platforms=_DESKTOP,
        affects="broker SSH transport",
        install_guides=(
            _g(Platform.LINUX_X86_64, "pip", "pip3 install paramiko"),
            _g(Platform.LINUX_AARCH64, "pip", "pip3 install paramiko"),
            _g(Platform.MACOS_ARM64, "pip", "pip3 install paramiko"),
            _g(Platform.MACOS_X86_64, "pip", "pip3 install paramiko"),
            _g(Platform.WINDOWS_X86_64, "pip", "pip3 install paramiko"),
        ),
    ),
    Dependency(
        name="pywinrm",
        description="pywinrm — WinRM transport for the broker (Windows targets)",
        tier=Tier.BROKER,
        python_package="winrm",
        required=False,
        platforms=_DESKTOP,
        affects="broker WinRM transport",
        install_guides=(
            _g(Platform.LINUX_X86_64, "pip", "pip3 install pywinrm"),
            _g(Platform.LINUX_AARCH64, "pip", "pip3 install pywinrm"),
            _g(Platform.MACOS_ARM64, "pip", "pip3 install pywinrm"),
            _g(Platform.MACOS_X86_64, "pip", "pip3 install pywinrm"),
            _g(Platform.WINDOWS_X86_64, "pip", "pip3 install pywinrm"),
        ),
    ),
    Dependency(
        name="sshpass",
        description="sshpass — non-interactive SSH password auth for subprocess paths (rsync, scp)",
        tier=Tier.BROKER,
        binary="sshpass",
        required=False,
        platforms=_UNIX,
        affects="broker SSH password auth (rsync fast-path, CI environments without ssh-agent)",
        install_guides=(
            _g(Platform.LINUX_X86_64, "apt", "sudo apt install sshpass",
               url="https://sourceforge.net/projects/sshpass/",
               notes="Also: brew install sshpass on macOS via custom tap"),
            _g(Platform.LINUX_AARCH64, "apt", "sudo apt install sshpass"),
            _g(Platform.MACOS_ARM64, "brew",
               "brew install hudochenkov/sshpass/sshpass",
               url="https://github.com/hudochenkov/homebrew-sshpass",
               notes="Not in default Homebrew — requires third-party tap"),
            _g(Platform.MACOS_X86_64, "brew",
               "brew install hudochenkov/sshpass/sshpass"),
        ),
    ),
    Dependency(
        name="keyring",
        description="Python keyring — OS credential store integration (macOS Keychain, GNOME Keyring, Windows Credential Manager)",
        tier=Tier.BROKER,
        python_package="keyring",
        required=False,
        platforms=_DESKTOP,
        affects="broker credential storage (raptor broker store-cred)",
        install_guides=(
            _g(Platform.LINUX_X86_64, "pip", "pip3 install keyring",
               notes="Uses SecretService D-Bus API (GNOME Keyring / KDE Wallet)"),
            _g(Platform.LINUX_AARCH64, "pip", "pip3 install keyring"),
            _g(Platform.MACOS_ARM64, "pip", "pip3 install keyring",
               notes="Uses macOS Keychain natively"),
            _g(Platform.MACOS_X86_64, "pip", "pip3 install keyring"),
            _g(Platform.WINDOWS_X86_64, "pip", "pip3 install keyring",
               notes="Uses Windows Credential Manager natively"),
        ),
    ),
    Dependency(
        name="rsync",
        description="rsync — fast incremental file transfer for broker staging",
        tier=Tier.BROKER,
        binary="rsync",
        required=False,
        platforms=_UNIX,
        affects="broker file transfer (fast-path for large repos)",
        install_guides=(
            _g(Platform.LINUX_X86_64, "apt", "sudo apt install rsync"),
            _g(Platform.LINUX_AARCH64, "apt", "sudo apt install rsync"),
            _g(Platform.MACOS_ARM64, "builtin", "# Ships with macOS",
               notes="Pre-installed on macOS"),
            _g(Platform.MACOS_X86_64, "builtin", "# Ships with macOS"),
        ),
    ),

    # ── OPTIONAL / UTILITY ───────────────────────────────────────────
    Dependency(
        name="tree-sitter",
        description="Tree-sitter parsers — rich inventory metadata (decorators, annotations, typed params)",
        tier=Tier.OPTIONAL,
        python_package="tree_sitter",
        required=False,
        platforms=_DESKTOP,
        affects="inventory enrichment (optional)",
        install_guides=(
            _g(Platform.LINUX_X86_64, "pip",
               "pip3 install tree-sitter tree-sitter-python tree-sitter-java tree-sitter-javascript tree-sitter-c tree-sitter-go"),
            _g(Platform.LINUX_AARCH64, "pip",
               "pip3 install tree-sitter tree-sitter-python tree-sitter-java tree-sitter-javascript tree-sitter-c tree-sitter-go"),
            _g(Platform.MACOS_ARM64, "pip",
               "pip3 install tree-sitter tree-sitter-python tree-sitter-java tree-sitter-javascript tree-sitter-c tree-sitter-go"),
            _g(Platform.MACOS_X86_64, "pip",
               "pip3 install tree-sitter tree-sitter-python tree-sitter-java tree-sitter-javascript tree-sitter-c tree-sitter-go"),
            _g(Platform.WINDOWS_X86_64, "pip",
               "pip3 install tree-sitter tree-sitter-python tree-sitter-java tree-sitter-javascript tree-sitter-c tree-sitter-go"),
        ),
    ),
    Dependency(
        name="make",
        description="GNU Make — build system for targets and tooling",
        tier=Tier.OPTIONAL,
        binary="make",
        required=False,
        platforms=_DESKTOP,
        affects="target builds",
        install_guides=(
            _g(Platform.LINUX_X86_64, "apt", "sudo apt install build-essential"),
            _g(Platform.LINUX_AARCH64, "apt", "sudo apt install build-essential"),
            _g(Platform.MACOS_ARM64, "xcode", "xcode-select --install"),
            _g(Platform.MACOS_X86_64, "xcode", "xcode-select --install"),
            _g(Platform.WINDOWS_X86_64, "choco", "choco install make",
               url="https://community.chocolatey.org/packages/make"),
        ),
    ),
)


def check_all(
    platform: Optional[Platform] = None,
) -> MatrixResult:
    """Check all dependencies and return the scored matrix."""
    plat = platform or Platform.detect()
    results: list[DepCheckResult] = []

    for dep in DEPENDENCIES:
        met = dep.check()
        guide = dep.guide_for(plat)
        results.append(DepCheckResult(dep=dep, met=met, guide=guide))

    return MatrixResult(platform=plat, results=tuple(results))


def format_matrix(result: MatrixResult) -> str:
    """Render the matrix as a human-readable report."""
    lines: list[str] = []
    lines.append(f"\nRAPTOR Dependency Matrix — {result.platform.value}")
    lines.append(f"Score: {result.met_count}/{result.total_count} "
                 f"(required: {result.required_met}/{result.required_total})")
    lines.append("=" * 80)

    for tier in Tier:
        tier_results = result.by_tier().get(tier)
        if not tier_results:
            continue

        met = sum(1 for r in tier_results if r.met)
        total = len(tier_results)
        lines.append(f"\n  {tier.value.upper()} ({met}/{total})")
        lines.append(f"  {'-' * 74}")

        for r in tier_results:
            tag = "[  MET  ]" if r.met else "[NOT MET]"
            req = " (required)" if r.dep.required else ""
            lines.append(f"    {tag} {r.dep.name:<20} {r.dep.description}{req}")
            lines.append(f"             affects: {r.dep.affects}")

            if not r.met and r.guide:
                lines.append(f"             install: {r.guide.command}")
                if r.guide.url:
                    lines.append(f"             url:     {r.guide.url}")
                if r.guide.notes:
                    lines.append(f"             note:    {r.guide.notes}")
            elif not r.met:
                supported = [p.value for p in r.dep.platforms]
                lines.append(f"             platforms: {', '.join(supported)}")
                if result.platform not in r.dep.platforms:
                    lines.append(f"             ⚠ not available on {result.platform.value}")

    lines.append("")
    return "\n".join(lines)
