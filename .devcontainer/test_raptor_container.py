from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

from core.json.jsonc import load_jsonc


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "bin" / "raptor-container"


def run_wrapper(
    *args: str,
    home: Path,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = {
        "HOME": str(home),
        "PATH": os.environ["PATH"],
    }
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [str(WRAPPER), *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def dry_run_args(result: subprocess.CompletedProcess[str]) -> list[str]:
    assert result.returncode == 0, result.stderr
    line = result.stdout.strip()
    assert line.startswith("+ ")
    return shlex.split(line[2:])


def mount_values(args: list[str]) -> list[str]:
    return [args[index + 1] for index, arg in enumerate(args[:-1]) if arg == "--mount"]


def volume_values(args: list[str]) -> list[str]:
    return [args[index + 1] for index, arg in enumerate(args[:-1]) if arg == "--volume"]


def option_values(args: list[str], option: str) -> list[str]:
    return [args[index + 1] for index, arg in enumerate(args[:-1]) if arg == option]


def test_help_lists_safe_entrypoints(tmp_path: Path) -> None:
    result = run_wrapper("help", home=tmp_path)

    assert result.returncode == 0
    assert "raptor-container build" in result.stdout
    assert "raptor-container shell" in result.stdout
    assert "--accept-codeql-terms" in result.stdout
    assert "No token, credential file, auth directory" in result.stdout


def test_debian_mirrors_are_https_before_first_apt() -> None:
    dockerfile = (ROOT / ".devcontainer" / "Dockerfile").read_text(
        encoding="utf-8",
    )
    rewrite = dockerfile.index("s|http://deb.debian.org|https://deb.debian.org|g")
    first_apt = dockerfile.index("apt-get update")
    assert rewrite < first_apt


def test_default_build_uses_canonical_target_and_hides_proxy_value(
    tmp_path: Path,
) -> None:
    secret_proxy = "http://proxy-user:proxy-password@proxy.example:8080"
    result = run_wrapper(
        "build",
        "--engine",
        "docker",
        "--dry-run",
        home=tmp_path,
        extra_env={"HTTPS_PROXY": secret_proxy},
    )
    args = dry_run_args(result)

    assert args[:2] == ["docker", "build"]
    assert args[args.index("--file") + 1] == str(ROOT / ".devcontainer" / "Dockerfile")
    assert args[args.index("--target") + 1] == "raptor-devcontainer"
    assert args[args.index("--tag") + 1] == "raptor:devcontainer"
    assert option_values(args, "--build-arg") == [
        "no_proxy",
        "HTTPS_PROXY",
        "NO_PROXY",
    ]
    assert secret_proxy not in result.stdout
    assert "--privileged" not in args


def test_build_proxy_forwarding_can_be_disabled(tmp_path: Path) -> None:
    result = run_wrapper(
        "build",
        "--engine",
        "docker",
        "--no-proxy",
        "--dry-run",
        home=tmp_path,
        extra_env={"HTTPS_PROXY": "http://proxy.example:8080"},
    )
    args = dry_run_args(result)

    assert "--build-arg" not in args


def test_all_tools_build_requires_codeql_acceptance(tmp_path: Path) -> None:
    result = run_wrapper(
        "build",
        "--all-tools",
        "--engine",
        "docker",
        "--dry-run",
        home=tmp_path,
    )

    assert result.returncode == 2
    assert "--all-tools requires --accept-codeql-terms" in result.stderr


def test_all_tools_build_selects_gated_target(tmp_path: Path) -> None:
    result = run_wrapper(
        "build",
        "--all-tools",
        "--accept-codeql-terms",
        "--engine",
        "docker",
        "--dry-run",
        home=tmp_path,
    )
    args = dry_run_args(result)

    assert args[args.index("--target") + 1] == "raptor-all-tools"
    assert args[args.index("--tag") + 1] == "raptor:all-tools"
    assert "ACCEPT_CODEQL_TERMS=1" in args


def test_shell_mounts_only_checkout_by_default(tmp_path: Path) -> None:
    result = run_wrapper(
        "shell",
        "--engine",
        "docker",
        "--dry-run",
        home=tmp_path,
        extra_env={
            "ANTHROPIC_API_KEY": "anthropic-secret",
            "GH_TOKEN": "github-secret",
            "GOOGLE_APPLICATION_CREDENTIALS": "/secret/adc.json",
        },
    )
    args = dry_run_args(result)
    volumes = volume_values(args)

    assert volumes == [f"{ROOT}:/workspaces/raptor:z"]
    assert "--privileged" not in args
    assert "ANTHROPIC_API_KEY" not in args
    assert "GH_TOKEN" not in args
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in args
    assert "anthropic-secret" not in result.stdout
    assert "github-secret" not in result.stdout


def test_shell_explicit_mounts_and_secret_forwarding_are_by_name(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target with spaces"
    output = tmp_path / "output with spaces"
    claude = tmp_path / ".claude"
    copilot = tmp_path / ".copilot"
    credentials = tmp_path / "gcp.json"
    target.mkdir()
    claude.mkdir()
    copilot.mkdir()
    credentials.write_text("{}", encoding="utf-8")

    result = run_wrapper(
        "shell",
        "--all-tools",
        "--target",
        str(target),
        "--output",
        str(output),
        "--claude-auth",
        str(claude),
        "--copilot-auth",
        str(copilot),
        "--gcp-credentials",
        str(credentials),
        "--env",
        "GH_TOKEN",
        "--engine",
        "docker",
        "--dry-run",
        home=tmp_path,
        extra_env={"GH_TOKEN": "github-secret"},
    )
    args = dry_run_args(result)
    volumes = volume_values(args)

    assert f"{target}:/target:z" in volumes
    assert f"{output}:/workspaces/raptor/out:z" in volumes
    assert f"{claude}:/home/raptor/.claude:z" in volumes
    assert f"{copilot}:/home/raptor/.copilot:z" in volumes
    assert (
        f"{credentials}:"
        "/run/raptor-secrets/google-application-credentials.json:ro,z"
    ) in volumes
    assert args[-2:] == ["raptor:all-tools", "bash"]
    assert "GH_TOKEN" in args
    assert "github-secret" not in result.stdout


def test_privileged_and_podman_modes_are_explicit(tmp_path: Path) -> None:
    safe = dry_run_args(
        run_wrapper(
            "shell",
            "--engine",
            "podman",
            "--dry-run",
            home=tmp_path,
        )
    )
    privileged = dry_run_args(
        run_wrapper(
            "shell",
            "--engine",
            "podman",
            "--privileged",
            "--dry-run",
            home=tmp_path,
        )
    )

    assert "--privileged" not in safe
    assert "--privileged" in privileged
    assert "--userns=keep-id:uid=1000,gid=1000" in safe
    assert "--security-opt=label=disable" not in safe
    assert mount_values(safe) == [
        f"type=bind,src={ROOT},dst=/workspaces/raptor,relabel=shared"
    ]


def test_docker_uses_real_host_uid_gid_despite_path_substitution(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "hostile-id-ran"
    fake_id = fake_bin / "id"
    fake_id.write_text(
        """#!/bin/sh
printf 'executed\\n' > "$RAPTOR_HOSTILE_ID_MARKER"
exit 99
""",
        encoding="utf-8",
    )
    fake_id.chmod(0o755)

    result = run_wrapper(
        "shell",
        "--engine",
        "docker",
        "--dry-run",
        home=tmp_path,
        extra_env={
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "RAPTOR_HOSTILE_ID_MARKER": str(marker),
        },
    )
    args = dry_run_args(result)
    env_values = option_values(args, "--env")

    assert args[args.index("--user") + 1] == "0:0"
    assert (
        args[args.index("--entrypoint") + 1]
        == "/usr/local/bin/raptor-container-entrypoint"
    )
    assert f"RAPTOR_RUNTIME_UID={os.geteuid()}" in env_values
    assert f"RAPTOR_RUNTIME_GID={os.getegid()}" in env_values
    assert "RAPTOR_RUNTIME_HOME=/home/raptor" in env_values
    assert "HOME=/home/raptor" in env_values
    assert not marker.exists()


def test_podman_auth_mounts_follow_vscode_home_and_relabel(tmp_path: Path) -> None:
    claude = tmp_path / ".claude"
    claude.mkdir()

    result = run_wrapper(
        "shell",
        "--engine",
        "podman",
        "--claude-auth",
        str(claude),
        "--dry-run",
        home=tmp_path,
    )
    mounts = mount_values(dry_run_args(result))

    assert f"type=bind,src={claude},dst=/home/vscode/.claude,relabel=shared" in mounts


def test_devcontainer_keeps_standard_target_without_implicit_secrets() -> None:
    config = load_jsonc(
        (ROOT / ".devcontainer" / "devcontainer.json").read_text(encoding="utf-8")
    )

    assert config["build"]["dockerfile"] == "Dockerfile"
    assert config["build"]["target"] == "raptor-devcontainer"
    assert config["containerEnv"]["RAPTOR_DIR"] == "/workspaces/raptor"
    assert "runArgs" not in config
    assert "mounts" not in config

    dockerfile = (ROOT / ".devcontainer" / "Dockerfile").read_text(
        encoding="utf-8",
    )
    assert "FROM raptor-all-tools-build AS raptor-all-tools" in dockerfile
    assert "FROM raptor-base AS raptor-devcontainer" in dockerfile
    assert dockerfile.count("ENV RAPTOR_DIR=/workspaces/raptor") == 2
    assert dockerfile.count("ENV PYTHONPATH=/workspaces/raptor\n") == 2


def test_codeql_uses_official_bundle_and_fails_arch_before_download() -> None:
    dockerfile = (ROOT / ".devcontainer" / "Dockerfile").read_text(encoding="utf-8")
    manifest = json.loads(
        (ROOT / "containers" / "all-tools-manifest.json").read_text(encoding="utf-8")
    )
    codeql = manifest["tools"]["codeql"]

    assert codeql["version"] == "2.26.4"
    assert codeql["kind"] == "official-bundle"
    assert codeql["url"].endswith(
        "/codeql-bundle-v2.26.4/codeql-bundle-linux64.tar.zst"
    )
    assert len(codeql["sha256"]) == 64
    assert "codeql-cli-binaries/releases/download" not in dockerfile
    assert "test -d /opt/codeql/qlpacks" in dockerfile
    assert dockerfile.index("only linux/amd64 is published") < dockerfile.index(
        'codeql_url="$(jq'
    )


def test_all_tools_manifest_and_install_commands_cover_major_gaps() -> None:
    dockerfile = (ROOT / ".devcontainer" / "Dockerfile").read_text(encoding="utf-8")
    manifest = json.loads(
        (ROOT / "containers" / "all-tools-manifest.json").read_text(encoding="utf-8")
    )
    installer = (ROOT / "containers" / "install-all-tools-native.sh").read_text(
        encoding="utf-8"
    )
    requirements = (ROOT / ".devcontainer" / "requirements-all-optional.txt").read_text(
        encoding="utf-8"
    ) + (ROOT / "containers" / "requirements-all-tools.txt").read_text(encoding="utf-8")
    all_tools_sources = dockerfile + requirements

    required_binaries = set(manifest["required_binaries"])
    assert {
        "cargo-fuzz",
        "clang",
        "ffuf",
        "go",
        "lcov",
        "mvn",
        "nuclei",
        "r2",
        "spatch",
        "rustc",
        "valgrind",
    } <= required_binaries
    assert manifest["tools"]["coccinelle"]["version"] == "1.3.3"
    assert manifest["tools"]["radare2"]["version"] == "6.2.2"
    assert manifest["tools"]["r2ghidra"]["version"] == "6.2.2"
    assert manifest["tools"]["go"]["version"] == "1.27.1"
    assert manifest["tools"]["rust"]["version"] == "1.98.1"
    assert manifest["tools"]["maven"]["version"] == "3.9.16"
    assert all(
        "version_command" in tool
        for name, tool in manifest["tools"].items()
        if name != "r2ghidra"
    )
    assert 'dpkg -i "$radare2_deb" "$r2ghidra_deb"' in installer
    assert "--enable-python=yes" in installer
    assert '--with-python="$python_bin"' in installer
    assert "COCCIRESULT:coccinelle-python-runtime:" in installer
    assert "cargo install --locked" in installer
    assert "download_sha256 ffuf" in installer
    assert "download_sha256 nuclei" in installer
    for system_package in (
        "ant",
        "clang",
        "lcov",
        "libclang-rt-dev",
        "lldb",
        "strace",
        "valgrind",
    ):
        assert f"    {system_package} \\" in dockerfile
    assert "-r ../requirements-grammars.txt" in requirements
    assert "pwntools==4.15.0" in requirements
    assert "cvss==3.6" in requirements
    assert "atheris==3.1.0" in (
        ROOT / "containers" / "requirements-atheris-amd64.txt"
    ).read_text(encoding="utf-8")

    for expected in (
        "AS raptor-all-tools",
        "ACCEPT_CODEQL_TERMS",
        "COPILOT_CLI_VERSION=1.0.83",
        "CLAUDE_CODE_VERSION=2.1.263",
        "JOERN_VERSION=4.0.622",
        "GHIDRA_VERSION=12.1.3",
        "GRADLE_VERSION=9.7.1",
        "GCLOUD_VERSION=583.0.0",
        "OLLAMA_VERSION=0.33.3",
        "frida==17.17.0",
        "frida-tools==14.10.4",
    ):
        assert expected in all_tools_sources
    assert "frida-server" not in dockerfile


def test_native_build_blockers_are_pinned_and_rootless_safe(tmp_path: Path) -> None:
    dockerfile = (ROOT / ".devcontainer" / "Dockerfile").read_text(encoding="utf-8")
    installer = (ROOT / "containers" / "install-all-tools-native.sh").read_text(
        encoding="utf-8"
    )
    manifest = json.loads(
        (ROOT / "containers" / "all-tools-manifest.json").read_text(encoding="utf-8")
    )

    assert "libpcre-ocaml-dev" in dockerfile
    assert "libpcre2-ocaml-dev" not in dockerfile
    assert (
        "GCLOUD_AMD64_SHA256="
        "84c5e4798836bda13aa82c3e84fa1acd0c4e4ca5318f7141052e3a5a26a7cc97" in dockerfile
    )
    maven_sha512 = manifest["tools"]["maven"]["sha512"]
    assert len(maven_sha512) == 128
    assert maven_sha512.endswith("358b6f6")

    dockerfile_tar_commands = [
        line for line in dockerfile.splitlines() if "&& tar " in line
    ]
    installer_tar_commands = [
        line for line in installer.splitlines() if line.startswith("tar ")
    ]
    assert dockerfile_tar_commands
    assert installer_tar_commands
    assert all("--no-same-owner" in line for line in dockerfile_tar_commands)
    assert all("--no-same-owner" in line for line in installer_tar_commands)

    bad_manifest = json.loads(json.dumps(manifest))
    bad_manifest["tools"]["maven"]["sha512"] += "00"
    bad_path = tmp_path / "bad-manifest.json"
    bad_path.write_text(json.dumps(bad_manifest), encoding="utf-8")
    result = subprocess.run(
        [
            str(ROOT / "containers" / "verify-all-tools.py"),
            "--manifest",
            str(bad_path),
            "--manifest-only",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "exactly 128 lowercase hexadecimal characters" in result.stderr


def test_every_dockerfile_pip_install_uses_all_tools_constraints() -> None:
    dockerfile = (ROOT / ".devcontainer" / "Dockerfile").read_text(encoding="utf-8")
    constraint = "-c /tmp/raptor/containers/constraints-all-tools.txt"

    assert (ROOT / "containers" / "constraints-all-tools.txt").is_file()
    assert (
        "COPY containers/constraints-all-tools.txt "
        "/tmp/raptor/containers/constraints-all-tools.txt"
    ) in dockerfile
    assert dockerfile.count("pip install") == dockerfile.count(constraint)


def test_angr_uses_main_interpreter_with_compatible_z3() -> None:
    dockerfile = (ROOT / ".devcontainer" / "Dockerfile").read_text(encoding="utf-8")
    angr_requirements = (ROOT / "containers" / "requirements-angr.txt").read_text(
        encoding="utf-8"
    )
    manifest = json.loads(
        (ROOT / "containers" / "all-tools-manifest.json").read_text(encoding="utf-8")
    )
    package_versions = {
        package["distribution"]: package["version"]
        for package in manifest["python_packages"]
    }

    assert "angr==9.3.4" in angr_requirements
    assert "z3-solver==4.13.0.0" in angr_requirements
    assert package_versions["angr"] == "9.3.4"
    assert package_versions["z3-solver"] == "4.13.0.0"
    assert "pip install --no-cache-dir --force-reinstall" in dockerfile
    assert "import angr, z3" in dockerfile
    assert "pip check" in dockerfile
    assert "/opt/angr" not in dockerfile
    assert "ANGR_VENV" not in dockerfile


def test_manifest_verifier_and_container_scripts_parse() -> None:
    result = subprocess.run(
        [
            str(ROOT / "containers" / "verify-all-tools.py"),
            "--manifest",
            str(ROOT / "containers" / "all-tools-manifest.json"),
            "--manifest-only",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    for script in (
        ROOT / "bin" / "raptor-container",
        ROOT / "containers" / "install-all-tools-native.sh",
        ROOT / "containers" / "raptor-container-entrypoint",
    ):
        syntax = subprocess.run(
            ["bash", "-n", str(script)],
            text=True,
            capture_output=True,
            check=False,
        )
        assert syntax.returncode == 0, syntax.stderr
    entrypoint = (ROOT / "containers" / "raptor-container-entrypoint").read_text(
        encoding="utf-8"
    )
    assert "setpriv" in entrypoint
    assert "NOPASSWD:ALL" in entrypoint


def test_builder_ignore_files_are_identical_restrictive_allowlists() -> None:
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    containerignore = (ROOT / ".containerignore").read_text(encoding="utf-8")
    active_lines = [
        line.strip()
        for line in dockerignore.splitlines()
        if line.strip() and not line.startswith("#")
    ]

    assert dockerignore == containerignore
    assert active_lines[0] == "**"
    assert {
        "!/.devcontainer/Dockerfile",
        "!/containers/all-tools-manifest.json",
        "!/containers/constraints-all-tools.txt",
        "!/containers/install-all-tools-native.sh",
        "!/containers/raptor-container-entrypoint",
        "!/containers/verify-all-tools.py",
        "!/packages/web/requirements.txt",
        "!/requirements.txt",
        "!/requirements-dev.txt",
        "!/requirements-grammars.txt",
    } <= set(active_lines)
    assert (
        active_lines.index("!/.devcontainer/")
        < active_lines.index("/.devcontainer/**")
        < active_lines.index("!/.devcontainer/Dockerfile")
    )
    assert (
        active_lines.index("!/containers/")
        < active_lines.index("/containers/**")
        < active_lines.index("!/containers/all-tools-manifest.json")
    )
    assert (
        active_lines.index("!/packages/")
        < active_lines.index("/packages/**")
        < active_lines.index("!/packages/web/")
    )
    assert (
        active_lines.index("!/packages/web/")
        < active_lines.index("/packages/web/**")
        < active_lines.index("!/packages/web/requirements.txt")
    )
    for sensitive in (".git", ".env", ".claude", ".copilot", "out", ".venv"):
        assert not any(
            line.startswith("!") and sensitive in line for line in active_lines
        )


@pytest.mark.skipif(shutil.which("podman") is None, reason="podman not installed")
def test_podman_build_context_contains_only_allowlisted_files(tmp_path: Path) -> None:
    constraints = ROOT / "containers" / "constraints-all-tools.txt"
    assert constraints.is_file()

    containerfile = tmp_path / "Containerfile"
    containerfile.write_text("FROM scratch\nCOPY . /context\n", encoding="utf-8")
    tag = f"localhost/raptor-context-test:{os.getpid()}"
    container_id = ""

    try:
        build = subprocess.run(
            [
                "podman",
                "build",
                "--no-cache",
                "--quiet",
                "--tag",
                tag,
                "--file",
                str(containerfile),
                str(ROOT),
            ],
            text=True,
            capture_output=True,
            check=False,
            timeout=120,
        )
        assert build.returncode == 0, build.stderr

        create = subprocess.run(
            ["podman", "create", tag],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        assert create.returncode == 0, create.stderr
        container_id = create.stdout.strip()

        archive = tmp_path / "context.tar"
        with archive.open("wb") as output:
            export = subprocess.run(
                ["podman", "export", container_id],
                stdout=output,
                stderr=subprocess.PIPE,
                check=False,
                timeout=60,
            )
        assert export.returncode == 0, export.stderr.decode()

        with tarfile.open(archive) as exported:
            files = {
                member.name.removeprefix("context/")
                for member in exported.getmembers()
                if member.isfile() and member.name.startswith("context/")
            }

        assert files == {
            ".devcontainer/Dockerfile",
            ".devcontainer/requirements-all-optional.txt",
            "containers/all-tools-manifest.json",
            "containers/constraints-all-tools.txt",
            "containers/install-all-tools-native.sh",
            "containers/raptor-container-entrypoint",
            "containers/requirements-all-tools.txt",
            "containers/requirements-angr.txt",
            "containers/requirements-atheris-amd64.txt",
            "containers/verify-all-tools.py",
            "packages/web/requirements.txt",
            "requirements-dev.txt",
            "requirements-grammars.txt",
            "requirements.txt",
        }
    finally:
        if container_id:
            subprocess.run(
                ["podman", "rm", "--force", container_id],
                capture_output=True,
                check=False,
                timeout=30,
            )
        subprocess.run(
            ["podman", "rmi", "--force", tag],
            capture_output=True,
            check=False,
            timeout=30,
        )
