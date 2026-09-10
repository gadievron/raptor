from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "containers" / "all-tools-manifest.json"
VERIFIER = ROOT / "containers" / "verify-all-tools.py"
DEVCONTAINER_VERIFIER = ROOT / ".devcontainer" / "test_devcontainer.py"

EXPECTED_SNAPSHOT_VERSIONS = {
    "semgrep": "1.172.0",
    "java": "21.0.12.1",
    "javac": "21.0.12.1",
    "ghidra": "12.1.3",
    "gradle": "9.7.1",
    "joern": "4.0.622",
    "gcloud": "583.0.0",
    "ollama": "0.33.3",
}


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


all_tools = _load_module("all_tools_version_verifier_under_test", VERIFIER)
devcontainer = _load_module(
    "devcontainer_semgrep_verifier_under_test",
    DEVCONTAINER_VERIFIER,
)


def _write_manifest(tmp_path: Path, manifest: dict) -> Path:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def test_manifest_pins_all_advertised_snapshot_versions() -> None:
    manifest = all_tools.load_manifest(MANIFEST)

    for tool_name, expected_version in EXPECTED_SNAPSHOT_VERSIONS.items():
        tool = manifest["tools"][tool_name]
        assert tool["version"] == expected_version
        assert tool["version_command"]

    assert "semgrep" in manifest["required_binaries"]
    assert all(
        tool.get("version_command")
        for tool in manifest["tools"].values()
    )


def test_manifest_uses_noninteractive_local_version_probes() -> None:
    manifest = all_tools.load_manifest(MANIFEST)
    tools = manifest["tools"]

    assert tools["semgrep"]["version_command"][:2] == ["python3", "-c"]
    assert "importlib.metadata" in tools["semgrep"]["version_command"][2]
    assert tools["ghidra"]["version_command"][:2] == ["python3", "-c"]
    assert "application.properties" in tools["ghidra"]["version_command"][2]
    assert "ghidraRun" not in tools["ghidra"]["version_command"]
    assert tools["joern"]["version_command"][:2] == ["python3", "-c"]
    assert "shutil.which('joern')" in tools["joern"]["version_command"][2]
    assert "io.joern.joern-cli-" in tools["joern"]["version_command"][2]
    assert {"joern", "joern-parse"} <= set(manifest["required_binaries"])
    assert tools["gcloud"]["version_command"] == [
        "gcloud",
        "version",
        "--format=json",
    ]


def test_joern_runtime_probe_uses_local_distribution_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    install = tmp_path / "joern-cli"
    lib = install / "lib"
    lib.mkdir(parents=True)
    joern = install / "joern"
    joern_parse = install / "joern-parse"
    for launcher in (joern, joern_parse):
        launcher.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        launcher.chmod(0o755)
    (lib / "io.joern.joern-cli-4.0.622.jar").write_bytes(b"")

    monkeypatch.setattr(
        all_tools.shutil,
        "which",
        lambda name: {
            "joern": str(joern),
            "joern-parse": str(joern_parse),
        }.get(name),
    )

    def unexpected_subprocess(*args: object, **kwargs: object) -> None:
        raise AssertionError("Joern runtime validation must not launch the CLI")

    monkeypatch.setattr(all_tools.subprocess, "run", unexpected_subprocess)

    manifest = all_tools.load_manifest(MANIFEST)
    assert all_tools.verify_joern_runtime(manifest) == []


def test_joern_runtime_probe_requires_parser_and_exact_distribution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    install = tmp_path / "joern-cli"
    lib = install / "lib"
    lib.mkdir(parents=True)
    joern = install / "joern"
    joern.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    joern.chmod(0o755)
    (lib / "io.joern.joern-cli-4.0.621.jar").write_bytes(b"")

    monkeypatch.setattr(
        all_tools.shutil,
        "which",
        lambda name: str(joern) if name == "joern" else None,
    )
    manifest = all_tools.load_manifest(MANIFEST)
    assert all_tools.verify_joern_runtime(manifest) == [
        "joern-parse not found on PATH"
    ]

    joern_parse = install / "joern-parse"
    joern_parse.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    joern_parse.chmod(0o755)
    monkeypatch.setattr(
        all_tools.shutil,
        "which",
        lambda name: {
            "joern": str(joern),
            "joern-parse": str(joern_parse),
        }.get(name),
    )
    assert all_tools.verify_joern_runtime(manifest) == [
        "Joern distribution version 4.0.621 != 4.0.622"
    ]


def test_manifest_requires_joern_parse(tmp_path: Path) -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    manifest["required_binaries"].remove("joern-parse")

    with pytest.raises(ValueError, match="Joern binary `joern-parse`"):
        all_tools.load_manifest(_write_manifest(tmp_path, manifest))


@pytest.mark.parametrize("tool_name", EXPECTED_SNAPSHOT_VERSIONS)
def test_manifest_rejects_broken_snapshot_versions(
    tmp_path: Path,
    tool_name: str,
) -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    manifest["tools"][tool_name]["version"] = "0.0.0"

    with pytest.raises(ValueError, match="version must be"):
        all_tools.load_manifest(_write_manifest(tmp_path, manifest))


@pytest.mark.parametrize("tool_name", EXPECTED_SNAPSHOT_VERSIONS)
def test_manifest_rejects_missing_snapshot_versions(
    tmp_path: Path,
    tool_name: str,
) -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    del manifest["tools"][tool_name]["version"]

    with pytest.raises(
        ValueError,
        match=rf"{tool_name} must define a non-empty version",
    ):
        all_tools.load_manifest(_write_manifest(tmp_path, manifest))


@pytest.mark.parametrize("tool_name", ["ghidra", "r2ghidra"])
def test_manifest_rejects_missing_version_commands(
    tmp_path: Path,
    tool_name: str,
) -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    del manifest["tools"][tool_name]["version_command"]

    with pytest.raises(
        ValueError,
        match=rf"{tool_name} must define a non-empty version_command",
    ):
        all_tools.load_manifest(_write_manifest(tmp_path, manifest))


@pytest.mark.parametrize("tool_name", EXPECTED_SNAPSHOT_VERSIONS)
def test_runtime_rejects_near_miss_snapshot_versions(
    monkeypatch: pytest.MonkeyPatch,
    tool_name: str,
) -> None:
    tool = all_tools.load_manifest(MANIFEST)["tools"][tool_name]
    manifest = {
        "supported_architectures": ["amd64"],
        "required_binaries": [],
        "required_paths": [],
        "tools": {tool_name: tool},
        "python_packages": [],
        "required_python_imports": [],
    }

    monkeypatch.setattr(all_tools.platform, "machine", lambda: "x86_64")

    def run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        if command == tool["version_command"]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=f"{tool['version']}0",
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
            f"{tool_name} version output does not contain exact "
            f"{tool['version']}:"
        )
        for error in errors
    )


def test_semgrep_check_uses_local_distribution_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        devcontainer.shutil,
        "which",
        lambda name: "/usr/local/bin/semgrep" if name == "semgrep" else None,
    )
    monkeypatch.setattr(
        devcontainer,
        "distribution_version",
        lambda distribution: "1.172.0",
    )

    def unexpected_subprocess(*args: object, **kwargs: object) -> None:
        raise AssertionError("Semgrep version check must not invoke its CLI")

    monkeypatch.setattr(devcontainer.subprocess, "run", unexpected_subprocess)

    passed, message, installed_version = devcontainer.check_semgrep()

    assert passed is True
    assert message == "Found at /usr/local/bin/semgrep"
    assert installed_version == "1.172.0"
