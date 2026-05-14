"""Environment self-checks for RAPTOR operators.

The doctor command is intentionally lightweight: it checks local prerequisites
and filesystem assumptions without contacting external services or reading any
secrets.  It is safe to run before an analysis session to explain likely setup
problems in one place instead of failing later inside a scanner wrapper.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import platform
import shutil
import sys
from typing import Iterable


@dataclass(frozen=True)
class DoctorCheck:
    """One doctor check result."""

    name: str
    status: str
    detail: str


_REQUIRED_DIRS = ("core", "packages", "libexec", "bin")
_OPTIONAL_TOOLS = (
    ("claude", "Claude Code launcher"),
    ("semgrep", "static-analysis scans"),
    ("codeql", "CodeQL scans"),
    ("afl-fuzz", "binary fuzzing"),
)


def _status_line(check: DoctorCheck) -> str:
    marker = {"pass": "✓", "warn": "!", "fail": "✗"}.get(check.status, "?")
    return f"{marker} {check.status.upper():4} {check.name}: {check.detail}"


def _repo_root(explicit_root: Path | None = None) -> Path:
    return (explicit_root or Path(__file__).resolve().parents[1]).resolve()


def _check_python() -> DoctorCheck:
    version = sys.version_info
    detail = f"Python {platform.python_version()} at {sys.executable}"
    if version < (3, 10):
        return DoctorCheck("python", "fail", f"{detail}; RAPTOR expects Python >= 3.10")
    return DoctorCheck("python", "pass", detail)


def _check_repo_layout(root: Path) -> DoctorCheck:
    missing = [name for name in _REQUIRED_DIRS if not (root / name).is_dir()]
    if missing:
        return DoctorCheck("repo_layout", "fail", f"missing required directories: {', '.join(missing)}")
    return DoctorCheck("repo_layout", "pass", f"found RAPTOR checkout at {root}")


def _check_writable(path: Path, name: str) -> DoctorCheck:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".raptor-doctor-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        return DoctorCheck(name, "fail", f"not writable: {path} ({exc})")
    return DoctorCheck(name, "pass", f"writable: {path}")


def _check_tool(binary: str, purpose: str) -> DoctorCheck:
    resolved = shutil.which(binary)
    if resolved:
        return DoctorCheck(f"tool:{binary}", "pass", f"{purpose}: {resolved}")
    return DoctorCheck(f"tool:{binary}", "warn", f"not found; needed for {purpose}")


def _check_dangerous_env() -> DoctorCheck:
    dangerous = sorted(
        name for name in ("PYTHONPATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES")
        if os.environ.get(name)
    )
    if dangerous:
        return DoctorCheck(
            "environment",
            "warn",
            "potentially process-influencing env vars are set: " + ", ".join(dangerous),
        )
    return DoctorCheck("environment", "pass", "no common process-influencing env vars detected")


def collect_checks(root: Path | None = None) -> list[DoctorCheck]:
    """Collect RAPTOR doctor checks.

    ``root`` is injectable for tests; callers normally omit it so the checkout
    is inferred from this module's location.
    """

    repo_root = _repo_root(root)
    checks: list[DoctorCheck] = [
        _check_python(),
        _check_repo_layout(repo_root),
        _check_writable(repo_root / "out", "output_dir"),
        _check_writable(repo_root / ".raptor" / "tmp", "state_tmp"),
        _check_dangerous_env(),
    ]
    checks.extend(_check_tool(binary, purpose) for binary, purpose in _OPTIONAL_TOOLS)
    return checks


def render_checks(checks: Iterable[DoctorCheck]) -> str:
    """Render checks as human-readable terminal output."""

    check_list = list(checks)
    lines = ["RAPTOR doctor", "============="]
    lines.extend(_status_line(check) for check in check_list)
    failures = sum(1 for check in check_list if check.status == "fail")
    warnings = sum(1 for check in check_list if check.status == "warn")
    lines.append("")
    lines.append(f"Summary: {failures} failure(s), {warnings} warning(s)")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Run the doctor command."""

    argv = argv or []
    if argv:
        print("usage: raptor doctor", file=sys.stderr)
        return 2
    checks = collect_checks()
    print(render_checks(checks))
    return 1 if any(check.status == "fail" for check in checks) else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
