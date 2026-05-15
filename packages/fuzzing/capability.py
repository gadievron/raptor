"""Fuzzing toolchain capability detection.

Different fuzzing tools have different platform requirements. AFL++ on
macOS has a shared memory configuration issue. libFuzzer requires a
clang with the libFuzzer runtime. ASAN/UBSAN/MSAN have varying support
across platforms and architectures.

This module probes the host system, reports what is and is not
available, and lets the orchestrator pick the right fuzzer for the
job rather than failing mid-campaign with a cryptic error.
"""

from __future__ import annotations

import logging
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from core.config import RaptorConfig
from packages.binary_analysis.radare2_understand import probe_capability as _probe_radare2_capability

logger = logging.getLogger(__name__)


@dataclass
class CapabilityReport:
    """Result of a capability probe."""

    platform: str
    arch: str
    is_macos: bool
    is_linux: bool

    # Tools
    afl_fuzz: Optional[str] = None
    afl_cc: Optional[str] = None        # afl-clang-fast or afl-gcc
    afl_cxx: Optional[str] = None
    afl_showmap: Optional[str] = None
    afl_cmin: Optional[str] = None
    afl_tmin: Optional[str] = None
    afl_cov: Optional[str] = None

    clang: Optional[str] = None
    clang_xx: Optional[str] = None
    gcc: Optional[str] = None

    lcov: Optional[str] = None
    gcov: Optional[str] = None
    llvm_cov: Optional[str] = None

    gdb: Optional[str] = None
    rr: Optional[str] = None

    # Binary analysis
    radare2: Optional[str] = None
    has_r2pipe: bool = False
    has_r2ghidra: bool = False

    # libFuzzer / clang fuzzer support
    has_libfuzzer: bool = False
    has_address_sanitizer: bool = False
    has_undefined_sanitizer: bool = False
    has_memory_sanitizer: bool = False
    has_thread_sanitizer: bool = False

    # Platform-specific issues
    afl_shmem_ok: Optional[bool] = None    # macOS: True/False/None=untested
    macos_afl_warning: str = ""

    # Versions (best effort)
    afl_version: str = ""
    clang_version: str = ""

    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def has_afl(self) -> bool:
        return self.afl_fuzz is not None and self.afl_shmem_ok is not False

    def has_clang_fuzzer(self) -> bool:
        return self.clang is not None and self.has_libfuzzer

    def has_any_fuzzer(self) -> bool:
        return self.has_afl() or self.has_clang_fuzzer()

    def to_dict(self) -> Dict:
        d = dict(self.__dict__)
        d["has_afl"] = self.has_afl()
        d["has_clang_fuzzer"] = self.has_clang_fuzzer()
        d["has_any_fuzzer"] = self.has_any_fuzzer()
        return d

    def summary(self) -> str:
        """Human-readable one-page summary."""
        lines = [
            f"Platform: {self.platform} {self.arch}",
            "",
            "Fuzzers:",
            f"  AFL++:                {'yes' if self.has_afl() else 'no'}"
            + (f" ({self.afl_version})" if self.afl_version else "")
            + (f" -- {self.macos_afl_warning}" if self.macos_afl_warning else ""),
            f"  libFuzzer (clang):    {'yes' if self.has_clang_fuzzer() else 'no'}"
            + (f" ({self.clang_version})" if self.clang_version else ""),
            "",
            "Sanitisers:",
            f"  AddressSanitizer:     {'yes' if self.has_address_sanitizer else 'no'}",
            f"  UndefinedBehaviour:   {'yes' if self.has_undefined_sanitizer else 'no'}",
            f"  MemorySanitizer:      {'yes' if self.has_memory_sanitizer else 'no'}",
            f"  ThreadSanitizer:      {'yes' if self.has_thread_sanitizer else 'no'}",
            "",
            "Coverage:",
            f"  lcov:                 {'yes' if self.lcov else 'no'}",
            f"  llvm-cov:             {'yes' if self.llvm_cov else 'no'}",
            f"  afl-cov:              {'yes' if self.afl_cov else 'no'}",
            "",
            "Debuggers:",
            f"  gdb:                  {'yes' if self.gdb else 'no'}",
            f"  rr:                   {'yes' if self.rr else 'no'}",
            "",
            "Binary analysis:",
            f"  radare2:              {'yes' if self.radare2 else 'no'}",
            f"  r2pipe:               {'yes' if self.has_r2pipe else 'no'}",
            f"  r2ghidra plugin:      {'yes' if self.has_r2ghidra else 'no'}",
        ]
        if self.issues:
            lines.append("")
            lines.append("Issues:")
            for issue in self.issues:
                lines.append(f"  - {issue}")
        if self.recommendations:
            lines.append("")
            lines.append("Recommendations:")
            for rec in self.recommendations:
                lines.append(f"  - {rec}")
        return "\n".join(lines)


def probe() -> CapabilityReport:
    """Probe the host system and return a CapabilityReport."""
    sys_platform = platform.system()
    arch = platform.machine()
    is_macos = sys_platform == "Darwin"
    is_linux = sys_platform == "Linux"

    report = CapabilityReport(
        platform=sys_platform,
        arch=arch,
        is_macos=is_macos,
        is_linux=is_linux,
    )

    # Tool discovery
    report.afl_fuzz = shutil.which("afl-fuzz")
    report.afl_cc = (
        shutil.which("afl-clang-fast")
        or shutil.which("afl-clang-lto")
        or shutil.which("afl-gcc")
    )
    report.afl_cxx = (
        shutil.which("afl-clang-fast++")
        or shutil.which("afl-clang-lto++")
        or shutil.which("afl-g++")
    )
    report.afl_showmap = shutil.which("afl-showmap")
    report.afl_cmin = shutil.which("afl-cmin")
    report.afl_tmin = shutil.which("afl-tmin")
    report.afl_cov = shutil.which("afl-cov")

    report.clang = shutil.which("clang")
    report.clang_xx = shutil.which("clang++")
    report.gcc = shutil.which("gcc")

    # On macOS, the default clang in PATH is Apple's command-line clang
    # which does NOT ship the libFuzzer runtime. Homebrew LLVM does.
    # Probe well-known homebrew paths as a fallback so users don't have
    # to manually adjust PATH every time.
    _homebrew_llvm_paths = [
        "/opt/homebrew/opt/llvm/bin/clang",
        "/opt/homebrew/opt/llvm/bin/clang++",
        "/usr/local/opt/llvm/bin/clang",
        "/usr/local/opt/llvm/bin/clang++",
    ]
    if is_macos:
        for hb in _homebrew_llvm_paths:
            if hb.endswith("clang") and Path(hb).exists():
                # Only override if Apple clang doesn't have libFuzzer
                if not report.clang or "/usr/bin/clang" in (report.clang or ""):
                    report.clang = hb
                    break
        for hb in _homebrew_llvm_paths:
            if hb.endswith("clang++") and Path(hb).exists():
                if not report.clang_xx or "/usr/bin/clang++" in (report.clang_xx or ""):
                    report.clang_xx = hb
                    break

    report.lcov = shutil.which("lcov")
    report.gcov = shutil.which("gcov")
    report.llvm_cov = shutil.which("llvm-cov")

    report.gdb = shutil.which("gdb")
    report.rr = shutil.which("rr")

    # radare2 binary analysis stack. The implementation lives in
    # packages.binary_analysis so fuzzing is just one consumer.
    r2_cap = _probe_radare2_capability()
    report.radare2 = r2_cap.get("r2_bin")
    report.has_r2pipe = bool(r2_cap.get("has_r2pipe"))
    report.has_r2ghidra = bool(r2_cap.get("has_r2ghidra"))

    # AFL++ version probe
    if report.afl_fuzz:
        report.afl_version = _probe_version(report.afl_fuzz, ["--help"])

    # Clang sanitiser support
    if report.clang:
        report.clang_version = _probe_version(report.clang, ["--version"])
        report.has_address_sanitizer = _probe_clang_sanitiser(report.clang, "address")
        report.has_undefined_sanitizer = _probe_clang_sanitiser(report.clang, "undefined")
        report.has_memory_sanitizer = _probe_clang_sanitiser(report.clang, "memory")
        report.has_thread_sanitizer = _probe_clang_sanitiser(report.clang, "thread")
        report.has_libfuzzer = _probe_clang_sanitiser(report.clang, "fuzzer")

    # AFL shared memory check on macOS
    if is_macos and report.afl_fuzz:
        report.afl_shmem_ok = _check_macos_afl_shmem(report.afl_fuzz)
        if report.afl_shmem_ok is False:
            report.macos_afl_warning = (
                "shared memory limits too low; run 'sudo afl-system-config'"
            )
            report.issues.append(
                "AFL++ shared memory configuration insufficient on this Mac. "
                "Run 'sudo afl-system-config' to fix, or use libFuzzer instead."
            )
            report.recommendations.append(
                "On macOS, libFuzzer (clang -fsanitize=fuzzer) is generally "
                "more reliable than AFL++. Prefer it where possible."
            )
    elif report.afl_fuzz:
        report.afl_shmem_ok = True

    # Sanity issues
    if not report.has_any_fuzzer():
        report.issues.append("No fuzzer available on this system.")
        if is_macos:
            report.recommendations.append(
                "Install AFL++ via 'brew install afl++' OR use Apple clang's "
                "libFuzzer (already bundled with Xcode command line tools)."
            )
        elif is_linux:
            report.recommendations.append(
                "Install AFL++ ('sudo apt install afl++' or build from source) "
                "or clang with libFuzzer ('sudo apt install clang')."
            )

    # MemorySanitizer is Linux/x86_64 only in practice
    if report.has_memory_sanitizer and (is_macos or arch not in ("x86_64", "amd64")):
        report.has_memory_sanitizer = False
        report.issues.append(
            "MemorySanitizer is supported only on Linux x86_64 in practice; "
            "ignoring."
        )

    # ThreadSanitizer on macOS works on Intel but is limited on Apple Silicon
    if report.has_thread_sanitizer and is_macos and arch == "arm64":
        report.recommendations.append(
            "ThreadSanitizer support on Apple Silicon is partial; expect "
            "false negatives compared with Linux x86_64."
        )

    if not report.afl_cov and report.has_afl():
        report.recommendations.append(
            "afl-cov not found. Install for HTML coverage reports: "
            "https://github.com/mrash/afl-cov"
        )

    if not report.gdb and report.has_any_fuzzer():
        report.recommendations.append(
            "gdb not installed; crash analysis will be limited. "
            "Install via 'brew install gdb' (macOS) or your package manager (Linux)."
        )

    if is_macos and not report.rr:
        # rr does not run on macOS, do not complain
        pass
    elif not report.rr and report.has_any_fuzzer():
        report.recommendations.append(
            "rr not installed; deterministic replay debugging unavailable. "
            "On Linux: 'sudo apt install rr' (Intel CPUs only)."
        )

    logger.info(f"Capability probe: {report.summary().splitlines()[0]}")
    return report


def _probe_version(binary: str, args: List[str]) -> str:
    """Best-effort version extraction. Returns first non-empty version-looking line."""
    try:
        result = subprocess.run(
            [binary] + args,
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = (result.stdout or "") + "\n" + (result.stderr or "")
        for line in output.splitlines():
            if any(c.isdigit() for c in line) and any(
                kw in line.lower() for kw in ("version", "afl", "clang", "gcc")
            ):
                return line.strip()[:120]
    except Exception:
        return ""
    return ""


def _probe_clang_sanitiser(clang: str, sanitizer: str) -> bool:
    """Compile a trivial program with -fsanitize=<name> to verify support.

    For 'fuzzer' specifically, we use a libFuzzer harness (not main) so the
    test mimics what a real harness compilation looks like. For other
    sanitisers we compile a normal main() program.
    """
    import tempfile

    if sanitizer == "fuzzer":
        # libFuzzer replaces main with its own driver. We must provide
        # LLVMFuzzerTestOneInput rather than main, otherwise the link
        # fails with "duplicate symbol _main".
        test_src = (
            "#include <stdint.h>\n"
            "#include <stddef.h>\n"
            "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
            "    (void)data; (void)size; return 0;\n"
            "}\n"
        )
        flag = "-fsanitize=fuzzer"
    else:
        test_src = "int main(void){return 0;}"
        flag = f"-fsanitize={sanitizer}"

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".c", delete=False
        ) as src:
            src.write(test_src)
            src_path = src.name
        with tempfile.NamedTemporaryFile(suffix=".out", delete=False) as out:
            out_path = out.name

        result = subprocess.run(
            [clang, flag, src_path, "-o", out_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0
    except Exception:
        return False
    finally:
        import os
        for p in (locals().get("src_path"), locals().get("out_path")):
            if p:
                try:
                    os.unlink(p)
                except OSError:
                    pass


def _check_macos_afl_shmem(afl_fuzz: str) -> bool:
    """Start a tiny AFL job and look for macOS shared-memory failures.

    `afl-fuzz --help` does not initialise the shared-memory segment, so it
    misses the real failure mode we care about. A one-second non-instrumented
    `/bin/cat` run reaches AFL's shm setup without requiring a project binary.
    """
    cat = "/bin/cat"
    if not Path(cat).exists():
        return True
    try:
        with tempfile.TemporaryDirectory(prefix="raptor-afl-probe-") as tmp:
            tmp_path = Path(tmp)
            seeds = tmp_path / "in"
            out = tmp_path / "out"
            seeds.mkdir()
            (seeds / "seed").write_bytes(b"seed\n")
            env = RaptorConfig.get_safe_env()
            env.setdefault("AFL_SKIP_CPUFREQ", "1")
            env.setdefault("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
            result = subprocess.run(
                [
                    afl_fuzz,
                    "-i", str(seeds),
                    "-o", str(out),
                    "-V", "1",
                    "-n",
                    "--",
                    cat,
                ],
                capture_output=True,
                text=True,
                timeout=15,
                env=env,
            )
        output = (result.stdout or "") + "\n" + (result.stderr or "")
        lowered = output.lower()
        if (
            "shmget" in lowered
            or "shmat" in lowered
            or "shared memory" in lowered
            or "afl-system-config" in lowered
            or "cannot allocate memory" in lowered
            or "operation not permitted" in lowered
        ):
            return False
        return True
    except Exception:
        return True   # If we cannot tell, assume OK and let AFL fail loudly later


def select_fuzzer(
    report: CapabilityReport,
    target_kind: str = "binary",
    *,
    prefer: Optional[str] = None,
) -> Optional[str]:
    """Pick the right fuzzer for a target.

    target_kind:
      'binary'  -- existing executable that reads stdin or argv
      'library' -- C/C++ library, harness needed
      'rust'    -- cargo project
      'python'  -- python package

    prefer: 'afl' or 'libfuzzer' to override. Returns None if no fuzzer
    matches the target on this host.
    """
    if prefer == "afl" and report.has_afl():
        return "afl"
    if prefer == "libfuzzer" and report.has_clang_fuzzer():
        return "libfuzzer"

    if target_kind == "binary":
        if report.has_afl():
            return "afl"
        if report.has_clang_fuzzer():
            return "libfuzzer"
    elif target_kind == "library":
        if report.has_clang_fuzzer():
            return "libfuzzer"
        if report.has_afl():
            return "afl"
    elif target_kind == "rust":
        if shutil.which("cargo-fuzz"):
            return "cargo-fuzz"
        if shutil.which("cargo") and report.has_clang_fuzzer():
            return "libfuzzer"
    elif target_kind == "python":
        if shutil.which("atheris-cli") or _is_python_module_installed("atheris"):
            return "atheris"
    return None


def _is_python_module_installed(name: str) -> bool:
    try:
        __import__(name)
        return True
    except ImportError:
        return False
