"""Contract tests for core.env.handle.DockerHandle (run_cli intercepted)."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from core.container.proc import RunOutcome
from core.env.handle import DockerHandle


def test_endpoint_none_without_port() -> None:
    assert DockerHandle("cid").endpoint() is None
    assert DockerHandle("cid", host_port=8080).endpoint() == \
        ("127.0.0.1", 8080)


def test_tier_is_docker() -> None:
    assert DockerHandle("cid").tier == "docker"


def test_state_logs_exec_teardown_route_to_container_substrate() -> None:
    captured: list[list[str]] = []

    def fake(cmd: list[str], **_kw: Any) -> RunOutcome:
        captured.append(list(cmd))
        stdout = '{"Running": true, "Status": "running"}'
        if cmd[:2] == ["docker", "logs"]:
            stdout = "line1\n"
        if cmd[:2] == ["docker", "exec"]:
            stdout = "out"
        if "Labels" in " ".join(cmd):
            stdout = "me\n"
        return RunOutcome(returncode=0, stdout=stdout, stderr="",
                          timed_out=False)

    h = DockerHandle("cid", host_port=80, owner_label=("o", "me"))
    with patch("core.container.containers.run_cli", side_effect=fake), \
         patch("core.container.exec.run_cli", side_effect=fake):
        assert h.state()["Running"] is True
        assert h.logs().startswith("line1")
        r = h.exec("echo hi")
        assert r.ok and r.stdout == "out"
        h.teardown()
    joined = [" ".join(c) for c in captured]
    assert any(c.startswith("docker stop") for c in joined)
    assert any(c.startswith("docker rm -f") for c in joined)


def test_running_and_wait_stable() -> None:
    h = DockerHandle("cid")
    with patch("core.container.containers.run_cli",
               return_value=RunOutcome(
                   returncode=0,
                   stdout='{"Running": true, "Status": "running"}',
                   stderr="", timed_out=False)):
        assert h.running() is True
        assert h.wait_stable(0) is True


def test_sandbox_handle_gates_on_rootfs_support(tmp_path) -> None:
    """On a tree whose sandbox lacks the image-rootfs mode, SandboxHandle
    must refuse to construct — an exec silently running against the host
    filesystem would be a substrate violation. On a tree WITH support,
    construction validates the rootfs directory."""
    import pytest

    from core.env.handle import SandboxHandle, sandbox_rootfs_supported

    if not sandbox_rootfs_supported():
        with pytest.raises(RuntimeError, match="rootfs"):
            SandboxHandle(tmp_path)
        return
    (tmp_path / "bin").mkdir()
    h = SandboxHandle(tmp_path)
    assert h.tier == "sandbox"
    assert h.endpoint() is None
    assert h.state()["Running"] is True
    h.teardown()
    assert h.state()["Running"] is False


def test_sandbox_handle_exec_strips_loader_env(tmp_path) -> None:
    """SandboxHandle.exec runs the image config Env — agent-authored,
    target-influenceable content. The sandbox call must carry
    strict_env=True so loader vars (LD_PRELOAD et al.) from a hostile
    Dockerfile ENV are stripped rather than applied to the exec
    (loader-var single-gate reinforcement alongside rootfs fail-closed
    gate #5)."""
    from unittest.mock import MagicMock

    from core.env.handle import SandboxHandle, sandbox_rootfs_supported

    if not sandbox_rootfs_supported():
        import pytest
        pytest.skip("sandbox image-rootfs mode unavailable on this tree")

    (tmp_path / "bin").mkdir()
    h = SandboxHandle(
        tmp_path,
        env={"PATH": "/usr/bin", "LD_PRELOAD": "/rootfs/evil.so"},
    )
    run_mock = MagicMock()
    run_mock.return_value = MagicMock(
        returncode=0, stdout="ok", stderr="", sandbox_info={},
    )
    with patch("core.sandbox.run", run_mock):
        outcome = h.exec("true")
    assert outcome.ok
    kwargs = run_mock.call_args.kwargs
    assert kwargs["strict_env"] is True
    # The image env still flows (strict_env strips inside the sandbox
    # layer; the handle passes the dict through unmodified).
    assert kwargs["env"]["LD_PRELOAD"] == "/rootfs/evil.so"
    assert kwargs["rootfs"] == str(tmp_path)
