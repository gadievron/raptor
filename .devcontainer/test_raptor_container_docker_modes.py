from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "bin" / "raptor-container"
ENTRYPOINT = ROOT / "containers" / "raptor-container-entrypoint"
LEGACY_DOCKER_INFO_ENV = "RAPTOR_CONTAINER_DOCKER_INFO"
PERF_SYSCTL_GUIDANCE = "sudo sysctl kernel.perf_event_paranoid=1"
PRODUCTION_SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
RAPTOR_DIR_ASSIGNMENT = 'RAPTOR_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"'
SYSTEM_PATH_ASSIGNMENT = f'RAPTOR_SYSTEM_PATH="{PRODUCTION_SYSTEM_PATH}"'


def run_wrapper(
    *args: str,
    home: Path,
    extra_env: dict[str, str] | None = None,
    wrapper: Path = WRAPPER,
) -> subprocess.CompletedProcess[str]:
    env = {
        "HOME": str(home),
        "PATH": os.environ["PATH"],
    }
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [str(wrapper), *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def install_hermetic_wrapper(tmp_path: Path) -> Path:
    """Copy the wrapper with only its repo root and trusted path redirected."""
    trusted_bin = tmp_path / "trusted-system-bin"
    trusted_bin.mkdir()
    for name in (
        "basename",
        "cat",
        "dirname",
        "id",
        "mkdir",
        "readlink",
        "realpath",
        "stat",
    ):
        helper = shutil.which(name, path=PRODUCTION_SYSTEM_PATH)
        assert helper is not None
        (trusted_bin / name).symlink_to(Path(helper).resolve())

    source = WRAPPER.read_text(encoding="utf-8")
    assert source.count(RAPTOR_DIR_ASSIGNMENT) == 1
    assert source.count(SYSTEM_PATH_ASSIGNMENT) == 1
    source = source.replace(
        RAPTOR_DIR_ASSIGNMENT,
        f"RAPTOR_DIR={shlex.quote(str(ROOT))}",
    ).replace(
        SYSTEM_PATH_ASSIGNMENT,
        f"RAPTOR_SYSTEM_PATH={shlex.quote(str(trusted_bin))}",
    )

    wrapper = tmp_path / "raptor-container"
    wrapper.write_text(source, encoding="utf-8")
    wrapper.chmod(0o755)
    return wrapper


def dry_run_args(result: subprocess.CompletedProcess[str]) -> list[str]:
    assert result.returncode == 0, result.stderr
    line = result.stdout.strip()
    assert line.startswith("+ ")
    return shlex.split(line[2:])


def option_values(args: list[str], option: str) -> list[str]:
    return [args[index + 1] for index, arg in enumerate(args[:-1]) if arg == option]


def install_fake_docker(tmp_path: Path) -> tuple[Path, Path]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(exist_ok=True)
    log = tmp_path / "docker-calls.jsonl"
    docker = fake_bin / "docker"
    docker.write_text(
        """#!/usr/bin/env python3
import json
import os
import sys

args = sys.argv[1:]
with open(os.environ["RAPTOR_TEST_DOCKER_LOG"], "a", encoding="utf-8") as output:
    json.dump(args, output)
    output.write("\\n")

env_log = os.environ.get("RAPTOR_TEST_DOCKER_ENV_LOG")
if env_log:
    with open(env_log, "a", encoding="utf-8") as output:
        json.dump(
            {
                "PATH": os.environ.get("PATH"),
                "no_proxy": os.environ.get("no_proxy"),
                "NO_PROXY": os.environ.get("NO_PROXY"),
            },
            output,
        )
        output.write("\\n")

if args and args[0] == "info":
    print(os.environ["RAPTOR_TEST_DOCKER_INFO"])
elif args and args[0] in {"build", "run"}:
    raise SystemExit(0)
else:
    raise SystemExit(64)
""",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    return fake_bin, log


def install_fake_id(fake_bin: Path, uid: int | None, gid: int | None) -> None:
    fake_id = fake_bin / "id"
    if uid is None or gid is None:
        body = """#!/usr/bin/env bash
printf 'id must not be called in this Docker mode\\n' >&2
exit 99
"""
    else:
        body = f"""#!/usr/bin/env bash
case "${{1:-}}" in
  -u) printf '{uid}\\n' ;;
  -g) printf '{gid}\\n' ;;
  *) exec /usr/bin/id "$@" ;;
esac
"""
    fake_id.write_text(body, encoding="utf-8")
    fake_id.chmod(0o755)


def fake_docker_env(
    fake_bin: Path,
    log: Path,
    security_options: str,
) -> dict[str, str]:
    return {
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "RAPTOR_TEST_DOCKER_INFO": security_options,
        "RAPTOR_TEST_DOCKER_LOG": str(log),
    }


def read_docker_calls(log: Path) -> list[list[str]]:
    return [
        json.loads(line)
        for line in log.read_text(encoding="utf-8").splitlines()
        if line
    ]


def read_engine_environments(log: Path) -> list[dict[str, str | None]]:
    return [
        json.loads(line)
        for line in log.read_text(encoding="utf-8").splitlines()
        if line
    ]


def install_failing_path_helpers(
    fake_bin: Path,
    marker: Path,
    names: tuple[str, ...],
) -> None:
    marker_path = shlex.quote(str(marker))
    for name in names:
        helper = fake_bin / name
        helper.write_text(
            f"""#!/bin/sh
printf '{name}\\n' >> {marker_path}
exit 99
""",
            encoding="utf-8",
        )
        helper.chmod(0o755)


def run_wrapper_with_perf_setting(
    tmp_path: Path,
    value: str,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    if shutil.which("unshare") is None:
        pytest.skip("unshare is not installed")
    namespace_probe = subprocess.run(
        ["unshare", "--user", "--map-root-user", "--mount", "true"],
        text=True,
        capture_output=True,
        check=False,
    )
    if namespace_probe.returncode != 0:
        pytest.skip(f"user mount namespaces unavailable: {namespace_probe.stderr}")

    fake_bin, log = install_fake_docker(tmp_path)
    install_fake_id(fake_bin, uid=2345, gid=3456)
    wrapper = install_hermetic_wrapper(tmp_path)
    perf_setting = tmp_path / "perf_event_paranoid"
    perf_setting.write_text(value, encoding="utf-8")
    env = {
        "HOME": str(tmp_path),
        **fake_docker_env(
            fake_bin,
            log,
            '["name=seccomp,profile=builtin","name=cgroupns"]',
        ),
    }
    result = subprocess.run(
        [
            "unshare",
            "--user",
            "--map-root-user",
            "--mount",
            "/bin/sh",
            "-c",
            (
                '/usr/bin/mount --bind "$1" '
                "/proc/sys/kernel/perf_event_paranoid || exit 77; "
                'shift; exec "$@"'
            ),
            "raptor-perf-test",
            str(perf_setting),
            str(wrapper),
            "shell",
            "--engine",
            "docker",
            "--no-proxy",
            "--privileged",
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode == 77:
        pytest.skip(f"cannot bind test perf sysctl: {result.stderr}")
    return result, log


def test_wrapper_startup_ignores_hostile_bash_env_and_path(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "startup-executed"
    commands = {
        "bash": "/bin/bash",
        "dirname": "/usr/bin/dirname",
        "readlink": "/usr/bin/readlink",
    }
    for name, real_command in commands.items():
        command = fake_bin / name
        command.write_text(
            f"""#!/bin/sh
printf '{name}\\n' >> "$RAPTOR_HOSTILE_WRAPPER_LOG"
exec {real_command} "$@"
""",
            encoding="utf-8",
        )
        command.chmod(0o755)

    bash_env = tmp_path / "bash-env"
    bash_env.write_text(
        """printf 'BASH_ENV\\n' >> "$RAPTOR_HOSTILE_WRAPPER_LOG"
""",
        encoding="utf-8",
    )
    wrapper_link = tmp_path / "raptor-container"
    wrapper_link.symlink_to(WRAPPER)
    result = subprocess.run(
        [str(wrapper_link), "help"],
        cwd=tmp_path,
        env={
            "HOME": str(tmp_path),
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "BASH_ENV": str(bash_env),
            "BASH_FUNC_dirname%%": (
                "() { printf 'imported dirname\\n' >> "
                '"$RAPTOR_HOSTILE_WRAPPER_LOG"; /usr/bin/dirname "$@"; }'
            ),
            "RAPTOR_HOSTILE_WRAPPER_LOG": str(log),
        },
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "raptor-container shell" in result.stdout
    assert WRAPPER.read_text(encoding="utf-8").splitlines()[0] == "#!/bin/bash -p"
    assert not log.exists()


def test_production_wrapper_hardcodes_trusted_system_directories() -> None:
    source = WRAPPER.read_text(encoding="utf-8")

    assert source.count(SYSTEM_PATH_ASSIGNMENT) == 1
    assert 'RAPTOR_SYSTEM_PATH="${RAPTOR_SYSTEM_PATH' not in source


def test_production_wrapper_ignores_inherited_system_path_override(
    tmp_path: Path,
) -> None:
    hostile_bin = tmp_path / "hostile-system-bin"
    hostile_bin.mkdir()
    marker = tmp_path / "hostile-system-helper-ran"
    for name in ("docker", "podman", "id", "realpath", "stat"):
        helper = hostile_bin / name
        helper.write_text(
            f"""#!/bin/sh
printf '{name}\\n' >> "$RAPTOR_HOSTILE_SYSTEM_PATH_LOG"
exec /usr/bin/{name} "$@"
""",
            encoding="utf-8",
        )
        helper.chmod(0o755)

    result = run_wrapper(
        "shell",
        "--engine",
        "docker",
        "--dry-run",
        "--no-proxy",
        home=tmp_path,
        extra_env={
            "PATH": PRODUCTION_SYSTEM_PATH,
            "ENGINE": "podman",
            "ENGINE_EXECUTABLE": str(hostile_bin / "podman"),
            "RAPTOR_SYSTEM_PATH": str(hostile_bin),
            "RAPTOR_HOSTILE_SYSTEM_PATH_LOG": str(marker),
        },
    )

    assert result.returncode == 0, result.stderr
    assert dry_run_args(result)[:2] == ["docker", "run"]
    assert not marker.exists()


def test_wrapper_scrubs_unsafe_path_before_engine_resolution(
    tmp_path: Path,
) -> None:
    safe_bin, log = install_fake_docker(tmp_path)
    env_log = tmp_path / "engine-env.jsonl"
    unsafe_bin = tmp_path / "unsafe-bin"
    unsafe_bin.mkdir()
    unsafe_bin.chmod(0o777)
    hostile_marker = tmp_path / "hostile-docker-ran"
    hostile_docker = unsafe_bin / "docker"
    hostile_docker.write_text(
        """#!/bin/sh
printf 'executed\\n' > "$RAPTOR_HOSTILE_ENGINE_MARKER"
exit 98
""",
        encoding="utf-8",
    )
    hostile_docker.chmod(0o755)

    inherited_path = (
        f":relative-bin:{unsafe_bin}:{safe_bin}:{os.environ['PATH']}:"
    )
    wrapper = install_hermetic_wrapper(tmp_path)
    result = run_wrapper(
        "shell",
        "--engine",
        "docker",
        "--no-proxy",
        home=tmp_path,
        extra_env={
            **fake_docker_env(
                safe_bin,
                log,
                '["name=seccomp,profile=builtin","name=cgroupns"]',
            ),
            "PATH": inherited_path,
            "RAPTOR_HOSTILE_ENGINE_MARKER": str(hostile_marker),
            "RAPTOR_TEST_DOCKER_ENV_LOG": str(env_log),
        },
        wrapper=wrapper,
    )

    assert result.returncode == 0, result.stderr
    assert not hostile_marker.exists()
    engine_path = read_engine_environments(env_log)[0]["PATH"]
    assert engine_path is not None
    path_entries = engine_path.split(":")
    assert path_entries[:2] == [
        str(tmp_path / "trusted-system-bin"),
        str(safe_bin),
    ]
    assert str(unsafe_bin) not in path_entries
    assert "relative-bin" not in path_entries
    assert "" not in path_entries
    assert "dropped unsafe PATH entry (empty entry" in result.stderr
    assert "dropped unsafe PATH entry (relative entry): relative-bin" in result.stderr
    assert (
        f"dropped unsafe PATH entry (world-writable dir): {unsafe_bin}"
        in result.stderr
    )


def test_wrapper_unsafe_path_escape_hatch_keeps_flagged_entries(
    tmp_path: Path,
) -> None:
    unsafe_bin = tmp_path / "unsafe-bin"
    safe_bin = tmp_path / "safe-bin"
    unsafe_bin.mkdir()
    safe_bin.mkdir()
    unsafe_bin.chmod(0o777)

    result = run_wrapper(
        "shell",
        "--engine",
        "docker",
        "--dry-run",
        "--no-proxy",
        home=tmp_path,
        extra_env={
            "PATH": f":relative-bin:{unsafe_bin}:{safe_bin}:",
            "RAPTOR_ALLOW_UNSAFE_PATH": "1",
        },
    )

    assert result.returncode == 0, result.stderr
    assert "dropped unsafe PATH entry" not in result.stderr
    assert "WARNING: keeping unsafe PATH entry (empty entry" in result.stderr
    assert (
        "WARNING: keeping unsafe PATH entry "
        "(relative entry; RAPTOR_ALLOW_UNSAFE_PATH set): relative-bin"
        in result.stderr
    )
    assert (
        "WARNING: keeping unsafe PATH entry "
        f"(world-writable dir; RAPTOR_ALLOW_UNSAFE_PATH set): {unsafe_bin}"
        in result.stderr
    )
    assert str(safe_bin) not in result.stderr


def test_fixed_host_helpers_use_the_trusted_resolver(tmp_path: Path) -> None:
    fake_bin, log = install_fake_docker(tmp_path)
    wrapper = install_hermetic_wrapper(tmp_path)
    marker = tmp_path / "hostile-helper-ran"
    install_failing_path_helpers(
        fake_bin,
        marker,
        ("basename", "cat", "dirname", "id", "mkdir", "realpath", "stat"),
    )
    output = tmp_path / "output"
    dry_output = tmp_path / "dry-output"
    env = {
        **fake_docker_env(
            fake_bin,
            log,
            '["name=seccomp,profile=builtin","name=cgroupns"]',
        ),
    }

    actual = run_wrapper(
        "shell",
        "--engine",
        "docker",
        "--no-proxy",
        "--output",
        str(output),
        home=tmp_path,
        extra_env=env,
        wrapper=wrapper,
    )
    dry_run = run_wrapper(
        "shell",
        "--engine",
        "docker",
        "--dry-run",
        "--no-proxy",
        "--output",
        str(dry_output),
        home=tmp_path,
        extra_env=env,
        wrapper=wrapper,
    )
    help_result = run_wrapper(
        "help",
        home=tmp_path,
        extra_env=env,
        wrapper=wrapper,
    )

    assert actual.returncode == 0, actual.stderr
    assert dry_run.returncode == 0, dry_run.stderr
    assert help_result.returncode == 0, help_result.stderr
    assert output.is_dir()
    assert not dry_output.exists()
    assert not marker.exists()


def test_engine_symlink_is_canonicalized_once(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    engine_link = fake_bin / "docker"
    real_engine = fake_bin / "docker-real"
    hostile_engine = fake_bin / "docker-hostile"
    log = tmp_path / "engine-calls"
    hostile_marker = tmp_path / "hostile-engine-ran"
    real_engine.write_text(
        """#!/usr/bin/python3
import os
import sys

args = sys.argv[1:]
with open(os.environ["RAPTOR_TEST_ENGINE_LOG"], "a", encoding="utf-8") as output:
    output.write(f"real:{args[0]}\\n")

if args[0] == "info":
    link = os.environ["RAPTOR_TEST_ENGINE_LINK"]
    os.unlink(link)
    os.symlink(os.environ["RAPTOR_TEST_HOSTILE_ENGINE"], link)
    print('["name=rootless"]')
elif args[0] != "run":
    raise SystemExit(64)
""",
        encoding="utf-8",
    )
    real_engine.chmod(0o755)
    hostile_engine.write_text(
        """#!/bin/sh
printf 'executed\\n' > "$RAPTOR_HOSTILE_ENGINE_MARKER"
exit 97
""",
        encoding="utf-8",
    )
    hostile_engine.chmod(0o755)
    engine_link.symlink_to(real_engine)

    result = run_wrapper(
        "shell",
        "--engine",
        "docker",
        "--no-proxy",
        home=tmp_path,
        extra_env={
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "RAPTOR_NO_LAUNCHER_HARDENING": "1",
            "RAPTOR_TEST_ENGINE_LOG": str(log),
            "RAPTOR_TEST_ENGINE_LINK": str(engine_link),
            "RAPTOR_TEST_HOSTILE_ENGINE": str(hostile_engine),
            "RAPTOR_HOSTILE_ENGINE_MARKER": str(hostile_marker),
        },
    )

    assert result.returncode == 0, result.stderr
    assert engine_link.resolve() == hostile_engine
    assert log.read_text(encoding="utf-8").splitlines() == [
        "real:info",
        "real:run",
    ]
    assert not hostile_marker.exists()


def test_auto_detection_still_prefers_podman(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "podman").symlink_to("/bin/true")
    (fake_bin / "docker").symlink_to("/bin/true")

    result = run_wrapper(
        "shell",
        "--dry-run",
        "--no-proxy",
        home=tmp_path,
        extra_env={
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "RAPTOR_NO_LAUNCHER_HARDENING": "1",
        },
    )

    assert dry_run_args(result)[:2] == ["podman", "run"]


def test_proxy_exclusions_merge_lowercase_then_uppercase_for_build_and_run(
    tmp_path: Path,
) -> None:
    fake_bin, log = install_fake_docker(tmp_path)
    env_log = tmp_path / "engine-env.jsonl"
    proxy_env = {
        **fake_docker_env(
            fake_bin,
            log,
            '["name=rootless"]',
        ),
        "RAPTOR_NO_LAUNCHER_HARDENING": "1",
        "RAPTOR_TEST_DOCKER_ENV_LOG": str(env_log),
        "no_proxy": "lower.example,,shared.example,Case.example,localhost",
        "NO_PROXY": "upper.example,shared.example,case.example,,127.0.0.1",
    }

    shell_result = run_wrapper(
        "shell",
        "--engine",
        "docker",
        home=tmp_path,
        extra_env=proxy_env,
    )
    build_result = run_wrapper(
        "build",
        "--engine",
        "docker",
        home=tmp_path,
        extra_env=proxy_env,
    )

    assert shell_result.returncode == 0, shell_result.stderr
    assert build_result.returncode == 0, build_result.stderr
    expected = (
        "lower.example,shared.example,Case.example,localhost,"
        "upper.example,case.example,127.0.0.1,::1"
    )
    environments = read_engine_environments(env_log)
    assert len(environments) == 3
    assert all(environment["no_proxy"] == expected for environment in environments)
    assert all(environment["NO_PROXY"] == expected for environment in environments)


def test_entrypoint_does_not_resolve_root_shell_from_checkout_path(
    tmp_path: Path,
) -> None:
    hostile_bin = tmp_path / "checkout" / "bin"
    hostile_bin.mkdir(parents=True)
    marker = tmp_path / "hostile-bash-ran"
    hostile_bash = hostile_bin / "bash"
    hostile_bash.write_text(
        """#!/bin/sh
printf 'executed\\n' > "$RAPTOR_HOSTILE_MARKER"
exit 88
""",
        encoding="utf-8",
    )
    hostile_bash.chmod(0o755)

    result = subprocess.run(
        [str(ENTRYPOINT)],
        cwd=tmp_path / "checkout",
        env={
            "PATH": f"{hostile_bin}:/usr/bin:/bin",
            "RAPTOR_HOSTILE_MARKER": str(marker),
            "RAPTOR_RUNTIME_UID": "not-a-uid",
            "RAPTOR_RUNTIME_GID": "1000",
            "RAPTOR_RUNTIME_PRIVILEGED": "0",
        },
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 64
    assert "invalid UID" in result.stderr
    assert not marker.exists()


def test_entrypoint_does_not_resolve_root_tools_from_checkout_path() -> None:
    with tempfile.TemporaryDirectory(prefix="raptor-entrypoint-") as temp_dir:
        test_root = Path(temp_dir)
        test_root.chmod(0o777)
        entrypoint = test_root / "raptor-container-entrypoint"
        entrypoint.write_bytes(ENTRYPOINT.read_bytes())
        entrypoint.chmod(0o755)

        hostile_bin = test_root / "checkout" / "bin"
        hostile_bin.mkdir(parents=True)
        marker = test_root / "hostile-getent-ran"
        hostile_getent = hostile_bin / "getent"
        hostile_getent.write_text(
            """#!/bin/sh
printf 'executed\\n' >> "$RAPTOR_HOSTILE_MARKER"
exec /usr/bin/getent "$@"
""",
            encoding="utf-8",
        )
        hostile_getent.chmod(0o755)

        runtime_uid = os.geteuid()
        runtime_gid = os.getegid()
        command = [str(entrypoint)]
        if runtime_uid == 0:
            runtime_uid = 65534
            runtime_gid = 65534
            command = [
                "/usr/bin/setpriv",
                f"--reuid={runtime_uid}",
                f"--regid={runtime_gid}",
                "--clear-groups",
                "--",
                str(entrypoint),
            ]

        result = subprocess.run(
            command,
            cwd=test_root / "checkout",
            env={
                "PATH": f"{hostile_bin}:/usr/bin:/bin",
                "RAPTOR_HOSTILE_MARKER": str(marker),
                "RAPTOR_RUNTIME_UID": str(runtime_uid),
                "RAPTOR_RUNTIME_GID": str(runtime_gid),
                "RAPTOR_RUNTIME_HOME": str(test_root / "home"),
                "RAPTOR_RUNTIME_PRIVILEGED": "0",
            },
            text=True,
            capture_output=True,
            check=False,
        )

        assert result.returncode != 0
        assert not marker.exists()


def test_actual_run_uses_docker_info_despite_legacy_override(
    tmp_path: Path,
) -> None:
    fake_bin, log = install_fake_docker(tmp_path)
    install_fake_id(fake_bin, uid=None, gid=None)
    wrapper = install_hermetic_wrapper(tmp_path)

    result = run_wrapper(
        "shell",
        "--engine",
        "docker",
        "--no-proxy",
        home=tmp_path,
        extra_env={
            **fake_docker_env(
                fake_bin,
                log,
                '["name=seccomp,profile=builtin","name=cgroupns"]',
            ),
            LEGACY_DOCKER_INFO_ENV: '["name=rootless"]',
        },
        wrapper=wrapper,
    )

    assert result.returncode == 0, result.stderr
    info_args, run_args = read_docker_calls(log)
    assert info_args == ["info", "--format", "{{json .SecurityOptions}}"]
    assert run_args[0] == "run"
    assert "--pull=never" in run_args
    assert option_values(run_args, "--user") == ["0:0"]
    assert option_values(run_args, "--entrypoint") == [
        "/usr/local/bin/raptor-container-entrypoint"
    ]
    env_values = option_values(run_args, "--env")
    assert f"RAPTOR_RUNTIME_UID={os.geteuid()}" in env_values
    assert f"RAPTOR_RUNTIME_GID={os.getegid()}" in env_values
    assert "RAPTOR_RUNTIME_HOME=/home/raptor" in env_values
    assert "RAPTOR_RUNTIME_PRIVILEGED=0" in env_values
    assert "HOME=/home/raptor" in env_values


def test_rootful_docker_entrypoint_privilege_flag_cannot_be_forwarded_over(
    tmp_path: Path,
) -> None:
    safe = dry_run_args(
        run_wrapper(
            "shell",
            "--engine",
            "docker",
            "--dry-run",
            "--no-proxy",
            "--env",
            "RAPTOR_RUNTIME_PRIVILEGED",
            home=tmp_path,
            extra_env={"RAPTOR_RUNTIME_PRIVILEGED": "1"},
        )
    )
    privileged = dry_run_args(
        run_wrapper(
            "shell",
            "--engine",
            "docker",
            "--dry-run",
            "--no-proxy",
            "--privileged",
            home=tmp_path,
        )
    )

    safe_env = option_values(safe, "--env")
    privileged_env = option_values(privileged, "--env")
    assert safe_env[-2:] == ["RAPTOR_RUNTIME_PRIVILEGED=0", "HOME=/home/raptor"]
    assert privileged_env[-2:] == [
        "RAPTOR_RUNTIME_PRIVILEGED=1",
        "HOME=/home/raptor",
    ]
    assert "--privileged" not in safe
    assert "--privileged" in privileged


@pytest.mark.parametrize("perf_setting", ["2\n", ""])
def test_actual_privileged_run_rejects_unsafe_or_unreadable_perf_sysctl(
    tmp_path: Path,
    perf_setting: str,
) -> None:
    result, log = run_wrapper_with_perf_setting(tmp_path, perf_setting)

    assert result.returncode == 2
    assert PERF_SYSCTL_GUIDANCE in result.stderr
    assert not log.exists()


def test_actual_privileged_run_accepts_safe_perf_sysctl(tmp_path: Path) -> None:
    result, log = run_wrapper_with_perf_setting(tmp_path, "1\n")

    assert result.returncode == 0, result.stderr
    info_args, run_args = read_docker_calls(log)
    assert info_args == ["info", "--format", "{{json .SecurityOptions}}"]
    assert run_args[0] == "run"
    assert "--privileged" in run_args


def test_rootless_docker_uses_container_root_and_existing_home_on_actual_run(
    tmp_path: Path,
) -> None:
    fake_bin, log = install_fake_docker(tmp_path)
    install_fake_id(fake_bin, uid=None, gid=None)
    wrapper = install_hermetic_wrapper(tmp_path)
    claude_auth = tmp_path / ".claude"
    claude_auth.mkdir()

    result = run_wrapper(
        "shell",
        "--engine",
        "docker",
        "--no-proxy",
        "--claude-auth",
        str(claude_auth),
        home=tmp_path,
        extra_env=fake_docker_env(
            fake_bin,
            log,
            '["name=userns","name=rootless","name=cgroupns"]',
        ),
        wrapper=wrapper,
    )

    assert result.returncode == 0, result.stderr
    info_args, run_args = read_docker_calls(log)
    assert info_args == ["info", "--format", "{{json .SecurityOptions}}"]
    assert "--pull=never" in run_args
    assert option_values(run_args, "--user") == ["0:0"]
    assert "--entrypoint" not in run_args
    env_values = option_values(run_args, "--env")
    assert "HOME=/root" in env_values
    assert not any(value.startswith("RAPTOR_RUNTIME_UID=") for value in env_values)
    assert not any(value.startswith("RAPTOR_RUNTIME_GID=") for value in env_values)
    assert not any(value.startswith("RAPTOR_RUNTIME_HOME=") for value in env_values)
    assert not any(
        value.startswith("RAPTOR_RUNTIME_PRIVILEGED=") for value in env_values
    )
    assert f"{claude_auth}:/root/.claude:z" in option_values(run_args, "--volume")


def test_rootful_userns_remap_is_rejected_before_docker_run(
    tmp_path: Path,
) -> None:
    fake_bin, log = install_fake_docker(tmp_path)
    install_fake_id(fake_bin, uid=None, gid=None)
    wrapper = install_hermetic_wrapper(tmp_path)

    result = run_wrapper(
        "shell",
        "--engine",
        "docker",
        "--no-proxy",
        home=tmp_path,
        extra_env=fake_docker_env(
            fake_bin,
            log,
            '["name=seccomp,profile=builtin","name=userns"]',
        ),
        wrapper=wrapper,
    )

    assert result.returncode == 2
    assert "userns-remap cannot safely write" in result.stderr
    assert "rootless Docker" in result.stderr
    assert "'--engine podman'" in result.stderr
    assert read_docker_calls(log) == [["info", "--format", "{{json .SecurityOptions}}"]]


def test_docker_bind_mounts_use_selinux_volume_syntax(tmp_path: Path) -> None:
    target = tmp_path / "target with spaces"
    output = tmp_path / "output with spaces"
    claude_auth = tmp_path / ".claude"
    copilot_auth = tmp_path / ".copilot"
    target.mkdir()
    claude_auth.mkdir()
    copilot_auth.mkdir()

    result = run_wrapper(
        "shell",
        "--engine",
        "docker",
        "--dry-run",
        "--no-proxy",
        "--target",
        str(target),
        "--output",
        str(output),
        "--claude-auth",
        str(claude_auth),
        "--copilot-auth",
        str(copilot_auth),
        home=tmp_path,
        extra_env={
            "ANTHROPIC_API_KEY": "anthropic-secret",
            "GH_TOKEN": "github-secret",
        },
    )
    args = dry_run_args(result)
    volumes = option_values(args, "--volume")

    assert "--mount" not in args
    assert volumes == [
        f"{ROOT}:/workspaces/raptor:z",
        f"{target}:/target:z",
        f"{output}:/workspaces/raptor/out:z",
        f"{claude_auth}:/home/raptor/.claude:z",
        f"{copilot_auth}:/home/raptor/.copilot:z",
    ]
    assert "ANTHROPIC_API_KEY" not in args
    assert "GH_TOKEN" not in args
    assert "anthropic-secret" not in result.stdout
    assert "github-secret" not in result.stdout


def test_target_sets_container_workdir_for_shell_and_command(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()

    shell_args = dry_run_args(
        run_wrapper(
            "shell",
            "--engine",
            "docker",
            "--dry-run",
            "--no-proxy",
            "--target",
            str(target),
            home=tmp_path,
        )
    )
    command_args = dry_run_args(
        run_wrapper(
            "shell",
            "--engine",
            "docker",
            "--dry-run",
            "--no-proxy",
            "--target",
            str(target),
            "--",
            "raptor",
            home=tmp_path,
        )
    )

    for args in (shell_args, command_args):
        assert option_values(args, "--workdir") == ["/target"]
        assert "RAPTOR_CALLER_DIR=/target" in option_values(args, "--env")
    assert shell_args[-1] == "bash"
    assert command_args[-1] == "raptor"


def test_docker_credentials_mount_is_read_only_and_relabelled(
    tmp_path: Path,
) -> None:
    credentials = tmp_path / "gcp.json"
    credentials.write_text("{}", encoding="utf-8")

    result = run_wrapper(
        "shell",
        "--engine",
        "docker",
        "--dry-run",
        "--no-proxy",
        "--gcp-credentials",
        str(credentials),
        home=tmp_path,
    )
    args = dry_run_args(result)

    assert (
        f"{credentials}:"
        "/run/raptor-secrets/google-application-credentials.json:ro,z"
        in option_values(args, "--volume")
    )


def test_docker_rejects_colon_in_volume_source(tmp_path: Path) -> None:
    target = tmp_path / "target:unsafe"
    target.mkdir()

    result = run_wrapper(
        "shell",
        "--engine",
        "docker",
        "--dry-run",
        "--no-proxy",
        "--target",
        str(target),
        home=tmp_path,
    )

    assert result.returncode == 2
    assert "Docker bind mount source cannot contain ':'" in result.stderr
    assert "SELinux relabeling requires --volume syntax" in result.stderr


def test_docker_dry_run_does_not_probe_the_daemon(tmp_path: Path) -> None:
    fake_bin, log = install_fake_docker(tmp_path)

    result = run_wrapper(
        "shell",
        "--engine",
        "docker",
        "--dry-run",
        "--no-proxy",
        home=tmp_path,
        extra_env={
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "RAPTOR_TEST_DOCKER_INFO": '["name=rootless"]',
            "RAPTOR_TEST_DOCKER_LOG": str(log),
        },
    )
    args = dry_run_args(result)

    assert args[:2] == ["docker", "run"]
    assert "--pull=never" in args
    assert option_values(args, "--entrypoint") == [
        "/usr/local/bin/raptor-container-entrypoint"
    ]
    assert not log.exists()


def test_podman_bind_mount_behavior_is_unchanged(tmp_path: Path) -> None:
    result = run_wrapper(
        "shell",
        "--engine",
        "podman",
        "--dry-run",
        "--no-proxy",
        home=tmp_path,
    )
    args = dry_run_args(result)

    assert "--volume" not in args
    assert option_values(args, "--mount") == [
        f"type=bind,src={ROOT},dst=/workspaces/raptor,relabel=shared"
    ]
    assert "--userns=keep-id:uid=1000,gid=1000" in args
    assert "--pull=never" in args
    assert not any(
        value.startswith("RAPTOR_RUNTIME_PRIVILEGED=")
        for value in option_values(args, "--env")
    )


@pytest.mark.skipif(shutil.which("podman") is None, reason="podman not installed")
def test_nonprivileged_entrypoint_blocks_sudo_exploit_and_preserves_mount_ownership(
    tmp_path: Path,
) -> None:
    image = os.environ.get("RAPTOR_TEST_CONTAINER_IMAGE", "raptor:devcontainer")
    image_exists = subprocess.run(
        ["podman", "image", "exists", image],
        capture_output=True,
        check=False,
    )
    if image_exists.returncode != 0:
        pytest.skip(f"local container image not found: {image}")

    mounted_entrypoint = tmp_path / "raptor-container-entrypoint"
    mounted_entrypoint.write_bytes(ENTRYPOINT.read_bytes())
    mounted_entrypoint.chmod(0o755)

    results: dict[int, Path] = {}
    for privileged in (0, 1):
        output = tmp_path / f"mode-{privileged}"
        output.mkdir()
        result = subprocess.run(
            [
                "podman",
                "run",
                "--rm",
                "--pull=never",
                "--userns=keep-id:uid=1000,gid=1000",
                "--user",
                "0:0",
                "--entrypoint",
                "/usr/local/bin/raptor-container-entrypoint",
                "--env",
                "RAPTOR_RUNTIME_UID=1000",
                "--env",
                "RAPTOR_RUNTIME_GID=1000",
                "--env",
                "RAPTOR_RUNTIME_HOME=/home/raptor",
                "--env",
                f"RAPTOR_RUNTIME_PRIVILEGED={privileged}",
                "--volume",
                (
                    f"{mounted_entrypoint}:"
                    "/usr/local/bin/raptor-container-entrypoint:ro,z"
                ),
                "--volume",
                f"{output}:/test-output:z",
                image,
                "bash",
                "-c",
                """
set -euo pipefail
sudo_rc=0
sudo -n id > /test-output/sudo.stdout 2> /test-output/sudo.stderr \
    || sudo_rc=$?
printf '%s\n' "$sudo_rc" > /test-output/sudo.rc
awk '$1 == "NoNewPrivs:" { print $2 }' /proc/self/status \
    > /test-output/no-new-privs
printf 'mounted\n' > /test-output/ownership-probe
""",
            ],
            text=True,
            capture_output=True,
            check=False,
            timeout=120,
        )

        assert result.returncode == 0, result.stderr
        results[privileged] = output
        for artifact in output.iterdir():
            assert artifact.stat().st_uid == os.getuid()
            assert artifact.stat().st_gid == os.getgid()

    assert int((results[0] / "sudo.rc").read_text(encoding="utf-8")) != 0
    assert (results[0] / "no-new-privs").read_text(encoding="utf-8").strip() == "1"
    assert int((results[1] / "sudo.rc").read_text(encoding="utf-8")) == 0
    assert "uid=0(root)" in (results[1] / "sudo.stdout").read_text(encoding="utf-8")
    assert (results[1] / "no-new-privs").read_text(encoding="utf-8").strip() == "0"


def test_explicit_builtin_image_remains_local_only(tmp_path: Path) -> None:
    result = run_wrapper(
        "shell",
        "--engine",
        "docker",
        "--dry-run",
        "--no-proxy",
        "--image",
        "raptor:all-tools",
        home=tmp_path,
    )
    args = dry_run_args(result)

    assert "--pull=never" in args
    assert args[-2:] == ["raptor:all-tools", "bash"]


def test_explicit_custom_image_retains_engine_pull_behavior(
    tmp_path: Path,
) -> None:
    result = run_wrapper(
        "shell",
        "--engine",
        "docker",
        "--dry-run",
        "--no-proxy",
        "--image",
        "registry.example/raptor:custom",
        home=tmp_path,
    )
    args = dry_run_args(result)

    assert "--pull=never" not in args
    assert args[-2:] == ["registry.example/raptor:custom", "bash"]
