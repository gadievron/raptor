from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest


ROOT = Path(__file__).resolve().parents[1]
DEVCONTAINER_VERIFIER = ROOT / ".devcontainer" / "test_devcontainer.py"
ALL_TOOLS_MANIFEST = ROOT / "containers" / "all-tools-manifest.json"
ALL_TOOLS_VERIFIER = ROOT / "containers" / "verify-all-tools.py"


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


devcontainer = _load_module(
    "raptor_devcontainer_verifier_under_test", DEVCONTAINER_VERIFIER
)
all_tools = _load_module("raptor_all_tools_verifier_under_test", ALL_TOOLS_VERIFIER)


def test_check_binary_rejects_nonzero_version_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        devcontainer.shutil,
        "which",
        lambda name: f"/usr/local/bin/{name}",
    )
    monkeypatch.setattr(
        devcontainer.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0],
            127,
            stdout="",
            stderr="loader failure",
        ),
    )

    passed, message, version = devcontainer.check_binary("claude")

    assert passed is False
    assert "version check exited 127" in message
    assert version == "loader failure"


def test_check_binary_rejects_version_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        devcontainer.shutil,
        "which",
        lambda name: f"/usr/local/bin/{name}",
    )

    def time_out(command: list[str], **kwargs: object) -> None:
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(devcontainer.subprocess, "run", time_out)

    passed, message, version = devcontainer.check_binary("copilot")

    assert passed is False
    assert "version check timed out" in message
    assert version is None


def test_manifest_pins_cli_version_commands() -> None:
    manifest = all_tools.load_manifest(ALL_TOOLS_MANIFEST)

    assert manifest["tools"]["claude-code"] == {
        "version": "2.1.263",
        "version_command": ["claude", "--version"],
    }
    assert manifest["tools"]["copilot-cli"] == {
        "version": "1.0.83",
        "version_command": ["copilot", "--version"],
    }


@pytest.mark.parametrize(
    ("tool_name", "expected_message"),
    [
        ("claude-code", "Claude Code must be version-checked"),
        ("copilot-cli", "GitHub Copilot CLI must be version-checked"),
    ],
)
def test_manifest_requires_cli_version_commands(
    tmp_path: Path,
    tool_name: str,
    expected_message: str,
) -> None:
    manifest = json.loads(ALL_TOOLS_MANIFEST.read_text(encoding="utf-8"))
    manifest["tools"][tool_name]["version_command"] = ["true"]
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match=expected_message):
        all_tools.load_manifest(manifest_path)


def test_all_tools_verifier_executes_cli_version_commands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    full_manifest = all_tools.load_manifest(ALL_TOOLS_MANIFEST)
    manifest = {
        "supported_architectures": ["amd64"],
        "required_binaries": ["claude", "copilot"],
        "required_paths": [],
        "tools": {
            name: full_manifest["tools"][name]
            for name in ("claude-code", "copilot-cli")
        },
        "python_packages": [],
        "required_python_imports": [],
    }
    commands: list[list[str]] = []

    monkeypatch.setattr(all_tools.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(
        all_tools.shutil,
        "which",
        lambda name: f"/usr/local/bin/{name}",
    )

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command == ["claude", "--version"]:
            return subprocess.CompletedProcess(
                command,
                127,
                stdout="",
                stderr="loader failure",
            )
        if command == ["copilot", "--version"]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="1.0.83",
                stderr="",
            )
        if command[:3] == ["r2", "-q", "-c"]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="ghidra",
                stderr="",
            )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(all_tools.subprocess, "run", run)

    errors = all_tools.verify_installed(manifest)

    assert ["claude", "--version"] in commands
    assert ["copilot", "--version"] in commands
    assert any("claude-code version check exited 127" in error for error in errors)
    assert not any("copilot-cli" in error for error in errors)


@pytest.mark.parametrize(
    ("machine", "required"),
    [
        ("x86_64", True),
        ("amd64", True),
        ("aarch64", False),
        ("arm64", False),
    ],
)
def test_rr_requirement_tracks_container_architecture(
    monkeypatch: pytest.MonkeyPatch,
    machine: str,
    required: bool,
) -> None:
    monkeypatch.setattr(devcontainer.platform, "system", lambda: "Linux")
    monkeypatch.setattr(devcontainer.platform, "machine", lambda: machine)
    monkeypatch.setattr(
        devcontainer,
        "check_binary",
        lambda *args, **kwargs: (False, "missing", None),
    )
    monkeypatch.setattr(
        devcontainer,
        "check_python_package",
        lambda *args, **kwargs: (True, "installed", "1"),
    )
    monkeypatch.setattr(
        devcontainer,
        "check_library",
        lambda *args, **kwargs: (True, "available"),
    )
    monkeypatch.setattr(
        devcontainer,
        "check_compiler_feature",
        lambda *args, **kwargs: (True, "available"),
    )
    monkeypatch.setattr(
        devcontainer,
        "check_env_var",
        lambda *args, **kwargs: (True, "set"),
    )
    monkeypatch.setattr(
        devcontainer,
        "check_rr_kernel",
        lambda: (False, "not configured"),
    )
    monkeypatch.setattr(
        devcontainer,
        "check_raptor_structure",
        lambda: (True, "available"),
    )
    monkeypatch.setattr(devcontainer, "check_raptor_imports", lambda: [])
    monkeypatch.setattr(devcontainer.shutil, "which", lambda name: None)
    monkeypatch.delenv("RAPTOR_ALL_TOOLS", raising=False)
    monkeypatch.delenv("RAPTOR_CONTAINER_PRIVILEGED", raising=False)

    results = devcontainer.run_all_tests(skip_optional=True)
    rr_result = next(result for result in results if result.name == "rr")
    rr_kernel_result = next(
        result for result in results if result.name == "rr kernel config"
    )

    assert rr_result.required is required
    assert rr_kernel_result.required is False
