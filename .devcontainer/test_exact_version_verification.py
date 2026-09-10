from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "containers" / "verify-all-tools.py"


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


all_tools = _load_module("exact_version_verifier_under_test", VERIFIER)


@pytest.mark.parametrize(
    ("expected", "output"),
    [
        ("2.1.263", "2.1.263 (Claude Code)\n"),
        (
            "1.0.83",
            "GitHub Copilot CLI 1.0.83.\n"
            "Run 'copilot update' to check for updates.\n",
        ),
        ("1.172.0", "1.172.0\n"),
        (
            "21.0.12.1",
            'openjdk version "21.0.12.1" 2026-08-18 LTS\n'
            "OpenJDK Runtime Environment Temurin-21.0.12.1+1 "
            "(build 21.0.12.1+1-LTS)\n",
        ),
        ("21.0.12.1", "javac 21.0.12.1\n"),
        ("12.1.3", "12.1.3\n"),
        (
            "9.7.1",
            "Welcome to Gradle 9.7.1!\n"
            "https://docs.gradle.org/9.7.1/release-notes.html\n"
            "Gradle 9.7.1\n",
        ),
        ("4.0.622", "4.0.622\n"),
        (
            "583.0.0",
            '{\n  "Google Cloud SDK": "583.0.0",\n'
            '  "core": "2026.08.31"\n}\n',
        ),
        ("0.33.3", "Warning: client version is 0.33.3\n"),
        ("2.26.4", "CodeQL command-line toolchain release 2.26.4.\n"),
        (
            "6.2.2",
            "radare2 6.2.2 +1 abi:142 @ linux-x86_64\n"
            "birth: git.6.2.2 2026-09-06__16:56:25\n",
        ),
        ("6.2.2", "6.2.2"),
        ("5.6.0", "rr version 5.6.0\n"),
        (
            "1.3.3",
            "spatch version 1.3.3 compiled with OCaml version 4.13.1\n",
        ),
        ("2.2.1", "ffuf version: 2.2.1\n"),
        ("3.11.1", "Nuclei Engine Version: v3.11.1\n"),
        ("1.27.1", "go version go1.27.1 linux/amd64\n"),
        ("1.98.1", "rustc 1.98.1 (48a229cea 2026-09-01)\n"),
        ("0.13.2", "cargo-fuzz 0.13.2\n"),
        (
            "3.9.16",
            "Apache Maven 3.9.16 (2bdd9fdd)\n"
            "Java version: 21.0.12.1, vendor: Eclipse Adoptium\n",
        ),
    ],
)
def test_current_tool_output_forms_match(
    expected: str,
    output: str,
) -> None:
    assert all_tools.version_output_matches(expected, output)


@pytest.mark.parametrize(
    "output",
    [
        "tool 1.2.3.4",
        "tool 1.2.30",
        "tool 1.2.3-rc1",
        "tool v1.2.3-rc.1",
        "tool 1.2.3-beta",
        "tool v1.2.3-beta.2",
        "tool 1.2.3beta",
        "tool 1.2.3b1",
        "tool 1.2.3.dev0",
        "tool 1.2.3+build.5",
        "tool 1.2.3-1+b1",
        "tool 1.2.3~beta1",
    ],
)
def test_materially_different_versions_do_not_match(output: str) -> None:
    assert not all_tools.version_output_matches("1.2.3", output)


def test_matcher_does_not_extract_a_shorter_dotted_tail() -> None:
    assert not all_tools.version_output_matches("2.3.4", "tool 1.2.3.4")


@pytest.mark.parametrize(
    ("expected", "output"),
    [
        ("1.2.3.4", "tool 1.2.3.4"),
        ("1.2.3-rc1", "tool v1.2.3-rc1"),
        ("1.2.3-beta.2", "tool 1.2.3-beta.2"),
        ("1.2.3+build.5", "tool v1.2.3+build.5"),
        ("1.2.3-1+b1", "tool 1.2.3-1+b1"),
    ],
)
def test_explicit_manifest_suffixes_match_exactly(
    expected: str,
    output: str,
) -> None:
    assert all_tools.version_output_matches(expected, output)


def test_java_build_suffix_alone_does_not_match_base_version() -> None:
    output = (
        "OpenJDK Runtime Environment Temurin-21.0.12.1+1 "
        "(build 21.0.12.1+1-LTS)\n"
    )

    assert not all_tools.version_output_matches("21.0.12.1", output)


def test_verify_installed_rejects_prerelease_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = {
        "supported_architectures": ["amd64"],
        "required_binaries": [],
        "required_paths": [],
        "tools": {
            "example": {
                "version": "1.2.3",
                "version_command": ["example", "--version"],
            },
        },
        "python_packages": [],
        "required_python_imports": [],
    }

    monkeypatch.setattr(all_tools.platform, "machine", lambda: "x86_64")

    def run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        if command == ["example", "--version"]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="example 1.2.3-rc1\n",
                stderr="",
            )
        if command[:3] == ["r2", "-q", "-c"]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="ghidra",
                stderr="",
            )
        if command == [sys.executable, "-m", "pip", "check"]:
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(all_tools.subprocess, "run", run)

    errors = all_tools.verify_installed(manifest)

    assert any(
        error.startswith(
            "example version output does not contain 1.2.3:"
        )
        for error in errors
    )
