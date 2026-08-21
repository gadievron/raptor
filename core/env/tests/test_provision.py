"""Contract tests for core.env.provision (docker CLI intercepted)."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from core.container.proc import RunOutcome
from core.env import provision as pv
from core.env.spec import EnvironmentSpec, RunSpec, SourceSpec
from core.env.store import load_run_spec

_CID = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
_PORTS = '{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"49001"}]}'
_STATE = '{"Running": true, "Status": "running"}'


def _image_spec(**kw: Any) -> EnvironmentSpec:
    return EnvironmentSpec(
        name="nginx-1.25",
        version="1.25.3",
        source=SourceSpec(kind="image",
                          image_ref="nginx@sha256:" + "b" * 64),
        run=RunSpec(surface="http", port=80),
        **kw,
    )


def _docker_ok(cmd: list[str], **_kw: Any) -> RunOutcome:
    if cmd[:3] == ["docker", "run", "-d"]:
        return RunOutcome(returncode=0, stdout=f"{_CID}\n", stderr="",
                          timed_out=False)
    if "NetworkSettings" in " ".join(cmd):
        return RunOutcome(returncode=0, stdout=_PORTS, stderr="",
                          timed_out=False)
    if "{{json .State}}" in cmd:
        return RunOutcome(returncode=0, stdout=_STATE, stderr="",
                          timed_out=False)
    return RunOutcome(returncode=0, stdout="", stderr="", timed_out=False)


def test_provision_image_docker_runtime(tmp_path) -> None:
    spec = _image_spec(verify_plan=[{"type": "container_status"}])
    with patch("core.container.containers.run_cli", side_effect=_docker_ok):
        out = pv.provision(spec, output_dir=tmp_path, workdir=tmp_path)
    assert out.ok, (out.reason, out.detail)
    env = out.environment
    assert env is not None and env.tier == "docker"
    assert env.verified()
    assert env.handle.endpoint() == ("127.0.0.1", 49001)
    # The run-local spec record landed.
    assert load_run_spec(tmp_path) == spec


def test_provision_verify_failure_tears_down(tmp_path) -> None:
    def docker(cmd: list[str], **_kw: Any) -> RunOutcome:
        if "{{json .State}}" in cmd:
            return RunOutcome(
                returncode=0,
                stdout='{"Running": false, "Status": "exited", "ExitCode": 1}',
                stderr="", timed_out=False)
        return _docker_ok(cmd, **_kw)

    spec = _image_spec(verify_plan=[{"type": "container_status"}])
    with patch("core.container.containers.run_cli", side_effect=docker), \
         patch("core.container.lifecycle.run_cli", side_effect=docker):
        out = pv.provision(spec, workdir=tmp_path)
    assert not out.ok and out.reason == "verify_failed"
    assert out.extras["verify_result"]["passed"] is False


def test_provision_refuses_unsupported_kinds(tmp_path) -> None:
    compose_spec = EnvironmentSpec(
        name="stack", source=SourceSpec(kind="compose", compose="services:"))
    out = pv.provision(compose_spec, workdir=tmp_path)
    assert not out.ok and out.reason == "unsupported_source"
    empty_image = EnvironmentSpec(name="x", source=SourceSpec(kind="image"))
    assert pv.provision(empty_image,
                        workdir=tmp_path).reason == "unsupported_source"


def test_provision_dockerfile_builds_then_launches(tmp_path) -> None:
    seen: list[list[str]] = []

    def docker(cmd: list[str], **_kw: Any) -> RunOutcome:
        seen.append(list(cmd))
        return _docker_ok(cmd, **_kw)

    spec = EnvironmentSpec(
        name="built",
        source=SourceSpec(kind="dockerfile",
                          dockerfile="FROM nginx@sha256:" + "c" * 64 + "\n"),
        run=RunSpec(port=80),
    )
    with patch("core.container.build.run_cli", side_effect=docker), \
         patch("core.container.containers.run_cli", side_effect=docker):
        out = pv.provision(spec, verify=False, workdir=tmp_path)
    assert out.ok
    build_cmds = [c for c in seen if c[:2] == ["docker", "build"]]
    assert build_cmds and "--label" in build_cmds[0]
    assert out.environment.image_ref.startswith("raptor-env-local:")


def test_provision_launch_failure_surfaces_class(tmp_path) -> None:
    def refused(cmd: list[str], **_kw: Any) -> RunOutcome:
        if cmd[:3] == ["docker", "run", "-d"]:
            return RunOutcome(returncode=1, stdout="",
                              stderr="manifest unknown", timed_out=False)
        return _docker_ok(cmd, **_kw)

    with patch("core.container.containers.run_cli", side_effect=refused), \
         patch("core.container.containers.time.sleep"):
        out = pv.provision(_image_spec(), workdir=tmp_path)
    assert not out.ok and out.reason == "launch_failed"
    assert out.reason_class == "manifest_unknown"
