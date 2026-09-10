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
BASE_NPM_LOCK = ROOT / "containers" / "npm" / "base" / "package-lock.json"
ALL_TOOLS_NPM_LOCK = (
    ROOT / "containers" / "npm" / "all-tools" / "package-lock.json"
)


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
        "package_version": "2.1.263",
        "package_version_command": [
            "node",
            "-p",
            "require('/opt/raptor/npm/base/node_modules/"
            "@anthropic-ai/claude-code/package.json').version",
        ],
        "version_command": ["claude", "--version"],
    }
    assert manifest["tools"]["copilot-cli"] == {
        "version": "1.0.84-3",
        "package_version": "1.0.83",
        "package_version_command": [
            "node",
            "-p",
            "require('/opt/raptor/npm/all-tools/node_modules/"
            "@github/copilot/package.json').version",
        ],
        "version_command": ["copilot", "--version"],
    }
    assert manifest["tools"]["yarn"] == {
        "version": "1.22.22",
        "package_version": "1.22.22",
        "package_version_command": [
            "node",
            "-p",
            "require('/opt/raptor/npm/base/node_modules/"
            "yarn/package.json').version",
        ],
        "version_command": ["yarn", "--version"],
    }
    assert manifest["tools"]["pnpm"] == {
        "version": "11.8.0",
        "package_version": "11.8.0",
        "package_version_command": [
            "node",
            "-p",
            "require('/opt/raptor/npm/base/node_modules/"
            "pnpm/package.json').version",
        ],
        "version_command": ["pnpm", "--version"],
    }


def test_npm_locks_pin_complete_cli_closures_and_integrities() -> None:
    manifest = all_tools.load_manifest(ALL_TOOLS_MANIFEST)
    base_lock = json.loads(BASE_NPM_LOCK.read_text(encoding="utf-8"))
    all_tools_lock = json.loads(ALL_TOOLS_NPM_LOCK.read_text(encoding="utf-8"))
    base_packages = base_lock["packages"]
    all_tools_packages = all_tools_lock["packages"]

    assert base_lock["lockfileVersion"] == 3
    assert all_tools_lock["lockfileVersion"] == 3
    assert base_packages[""]["dependencies"] == {
        "@anthropic-ai/claude-code": "2.1.263",
        "pnpm": "11.8.0",
        "yarn": "1.22.22",
    }
    assert all_tools_packages[""]["dependencies"] == {
        "@github/copilot": "1.0.83"
    }
    assert len(base_packages) - 1 == 11
    assert len(all_tools_packages) - 1 == 10

    for packages in (base_packages, all_tools_packages):
        for path, package in packages.items():
            if not path:
                continue
            assert package["version"]
            assert package["integrity"].startswith("sha512-")

    expected_base = {
        "node_modules/@anthropic-ai/claude-code": (
            "2.1.263",
            "sha512-kvvBK6/69iTRYnq0TKVyxVZs1CxYCJGojshQSP+2qaDb66A2xtI4"
            "zbCuqkZUWLkFGmHSRqhFf/ATpzH2UNKcwg==",
        ),
        "node_modules/pnpm": (
            "11.8.0",
            "sha512-wfXnxMskHI8XS3Q4UdgvQrgCMkr8iw8Ra5atsVqgZmSUjd42lgo7o"
            "QebpbSyndAUATW5S1tfUmNZIknWjlVfJg==",
        ),
        "node_modules/yarn": (
            "1.22.22",
            "sha512-prL3kGtyG7o9Z9Sv8IPfBNrWTDmXB4Qbes8A9rEzt6wkJV8mUvoir"
            "jU0Mp3GGAU06Y0XQyA3/2/RQFVuK7MTfg==",
        ),
    }
    for path, (version, integrity) in expected_base.items():
        assert base_packages[path]["version"] == version
        assert base_packages[path]["integrity"] == integrity

    copilot = all_tools_packages["node_modules/@github/copilot"]
    detect_libc = all_tools_packages["node_modules/detect-libc"]
    assert copilot["version"] == "1.0.83"
    assert copilot["integrity"] == (
        "sha512-M8uZI0V0dahYV1KZij3nGDxaXEGG7I7YUZzQPI7NEZkL/"
        "83Nl/tNTbPdxKtdWZbOmWoXsPKXty/eEYoj6RHDhA=="
    )
    assert copilot["dependencies"]["detect-libc"] == "^2.1.2"
    assert detect_libc == {
        "version": "2.1.2",
        "resolved": (
            "https://registry.npmjs.org/detect-libc/-/detect-libc-2.1.2.tgz"
        ),
        "integrity": (
            "sha512-Btj2BOOO83o3WyH59e8MgXsxEQVcarkUOpEYrubB0urwnN10yQ364rsi"
            "ByU11nZlqWYZm05i/of7io4mzihBtQ=="
        ),
        "license": "Apache-2.0",
        "engines": {"node": ">=8"},
    }
    assert {
        "/opt/raptor/npm/base",
        "/opt/raptor/npm/all-tools",
    } <= set(manifest["required_paths"])


def test_dockerfile_installs_locked_npm_closures_without_global_installs() -> None:
    dockerfile = (
        ROOT / ".devcontainer" / "Dockerfile"
    ).read_text(encoding="utf-8")

    assert "npm install -g" not in dockerfile
    assert dockerfile.count("npm ci --ignore-scripts") == 2
    assert dockerfile.count("--include=optional") == 2
    assert dockerfile.count("--omit=dev") == 2
    for prefix in ("/opt/raptor/npm/base", "/opt/raptor/npm/all-tools"):
        assert f"--prefix {prefix}" in dockerfile
    for binary in ("claude", "yarn", "yarnpkg", "pnpm", "pnpx", "copilot"):
        assert f"/usr/local/bin/{binary}" in dockerfile
    assert (
        "node /opt/raptor/npm/base/node_modules/"
        "@anthropic-ai/claude-code/install.cjs"
    ) in dockerfile


def test_standard_target_runs_locked_claude_executable_probe() -> None:
    dockerfile = (
        ROOT / ".devcontainer" / "Dockerfile"
    ).read_text(encoding="utf-8")
    package_check = dockerfile.index(
        "require('/opt/raptor/npm/base/node_modules/"
        "@anthropic-ai/claude-code/package.json').version"
    )
    executable_probe = dockerfile.index(
        'raptor-verify-all-tools \\\n'
        '    --check-version "${CLAUDE_CODE_VERSION}" claude --version'
    )
    standard_target = dockerfile.index(
        "FROM raptor-base AS raptor-devcontainer"
    )

    assert "ARG CLAUDE_CODE_VERSION=2.1.263" in dockerfile
    assert package_check < executable_probe < standard_target
    assert "claude --version" in dockerfile[executable_probe:standard_target]
    assert "package.json" not in dockerfile[executable_probe:standard_target]


@pytest.mark.parametrize(
    ("tool_name", "expected_message"),
    [
        ("claude-code", "Claude Code must be version-checked"),
        ("copilot-cli", "GitHub Copilot CLI must be version-checked"),
        ("yarn", "Yarn must be version-checked"),
        ("pnpm", "pnpm must be version-checked"),
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
        if command == full_manifest["tools"]["claude-code"][
            "package_version_command"
        ]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="2.1.263",
                stderr="",
            )
        if command == ["claude", "--version"]:
            return subprocess.CompletedProcess(
                command,
                127,
                stdout="",
                stderr="loader failure",
            )
        if command == full_manifest["tools"]["copilot-cli"][
            "package_version_command"
        ]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="1.0.83",
                stderr="",
            )
        if command == ["copilot", "--version"]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="GitHub Copilot CLI 1.0.84-3",
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
    assert full_manifest["tools"]["claude-code"][
        "package_version_command"
    ] in commands
    assert full_manifest["tools"]["copilot-cli"][
        "package_version_command"
    ] in commands
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
