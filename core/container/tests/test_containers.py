"""Contract tests for core.container.containers — launch/inspect/stop.

All docker traffic is intercepted at the run_cli seam; no daemon needed.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from core.container import containers as cc
from core.container.proc import RunOutcome

_CID = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
_PORTS_JSON = '{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"49000"}]}'


def _fake_run(captured: list[list[str]] | None = None):
    def fake(cmd: list[str], **_kw: Any) -> RunOutcome:
        if captured is not None:
            captured.append(list(cmd))
        stdout = _PORTS_JSON if "inspect" in cmd else f"{_CID}\n"
        return RunOutcome(returncode=0, stdout=stdout, stderr="",
                          timed_out=False)
    return fake


# ── is_external_image ─────────────────────────────────────────────────


def test_bare_hub_names_are_external() -> None:
    assert cc.is_external_image("debian:11")
    assert cc.is_external_image("redis")
    assert cc.is_external_image("mirror.gcr.io/library/nginx:1.25")


def test_local_conventions_are_local() -> None:
    assert not cc.is_external_image("")
    assert not cc.is_external_image("scratch")
    assert not cc.is_external_image("localhost/x:1")
    assert not cc.is_external_image("cve-2020-1:build",
                                    local_prefixes=("cve-",))
    # Without the caller's prefix declared, err toward external.
    assert cc.is_external_image("cve-2020-1:build")


# ── launch_container ──────────────────────────────────────────────────


def test_launch_builds_hardened_command_and_reads_port() -> None:
    captured: list[list[str]] = []
    with patch.object(cc, "run_cli", side_effect=_fake_run(captured)):
        r = cc.launch_container(image="busybox:latest", container_port=80,
                                labels={"raptor.owner": "test"})
    assert r.ok and r.container_id == _CID and r.host_port == 49000
    run_cmd = next(c for c in captured if c[:3] == ["docker", "run", "-d"])
    joined = " ".join(run_cmd)
    assert "--cap-drop ALL" in joined
    assert "--security-opt no-new-privileges:true" in joined
    assert "-p 127.0.0.1::80" in joined
    assert "--label raptor.owner=test" in joined
    assert "--pull always" in joined  # external image
    assert "--memory 4g" in joined and "--pids-limit 512" in joined


def test_launch_skips_pull_for_declared_local_prefix() -> None:
    captured: list[list[str]] = []
    with patch.object(cc, "run_cli", side_effect=_fake_run(captured)):
        cc.launch_container(image="cve-2020-1:build", container_port=80,
                            local_prefixes=("cve-",))
    run_cmd = next(c for c in captured if c[:3] == ["docker", "run", "-d"])
    assert "--pull" not in run_cmd


def test_launch_rejects_env_key_with_equals() -> None:
    r = cc.launch_container(image="x", container_port=80,
                            env={"FOO=BAR": "v"})
    assert not r.ok and r.reason == "invalid_env_key"


def test_launch_drops_flag_shaped_env_keys() -> None:
    captured: list[list[str]] = []
    with patch.object(cc, "run_cli", side_effect=_fake_run(captured)):
        cc.launch_container(image="x:1", container_port=80,
                            env={"-e": "v", "GOOD": "1"})
    run_cmd = next(c for c in captured if c[:3] == ["docker", "run", "-d"])
    assert "GOOD=1" in run_cmd
    assert "-e=v" not in " ".join(run_cmd)


def test_stalled_pull_fails_fast_without_retry() -> None:
    calls: list[list[str]] = []

    def timed_out(cmd: list[str], **_kw: Any) -> RunOutcome:
        calls.append(list(cmd))
        return RunOutcome(returncode=None, stdout="", stderr="",
                          timed_out=True)

    with (patch.object(cc, "run_cli", side_effect=timed_out),
          patch.object(cc.time, "sleep")):
        r = cc.launch_container(image="x:1", container_port=80)
    assert not r.ok and r.reason == "pull_timeout"
    assert r.reason_class == "transport"
    assert len(calls) == 1  # no second full timeout window


def test_transient_failure_retries_once_with_fresh_name() -> None:
    names: list[str] = []

    def flaky(cmd: list[str], **_kw: Any) -> RunOutcome:
        if cmd[:3] == ["docker", "run", "-d"]:
            names.append(cmd[cmd.index("--name") + 1])
            if len(names) == 1:
                return RunOutcome(returncode=1, stdout="",
                                  stderr="i/o timeout", timed_out=False)
        stdout = _PORTS_JSON if "inspect" in cmd else f"{_CID}\n"
        return RunOutcome(returncode=0, stdout=stdout, stderr="",
                          timed_out=False)

    with (patch.object(cc, "run_cli", side_effect=flaky),
          patch.object(cc.time, "sleep")):
        r = cc.launch_container(image="x:1", container_port=80)
    assert r.ok
    assert len(names) == 2 and names[0] != names[1]


def test_permanent_failure_does_not_retry() -> None:
    calls: list[list[str]] = []

    def denied(cmd: list[str], **_kw: Any) -> RunOutcome:
        calls.append(list(cmd))
        return RunOutcome(returncode=1, stdout="",
                          stderr="manifest unknown", timed_out=False)

    with (patch.object(cc, "run_cli", side_effect=denied),
          patch.object(cc.time, "sleep")):
        r = cc.launch_container(image="x:1", container_port=80)
    assert not r.ok and r.reason == "run_failed"
    assert r.reason_class == "manifest_unknown"
    assert len(calls) == 1


# ── stop_container ownership gate ─────────────────────────────────────


def test_stop_refuses_unowned_container() -> None:
    def inspect_other(cmd: list[str], **_kw: Any) -> RunOutcome:
        return RunOutcome(returncode=0, stdout="someone-else\n", stderr="",
                          timed_out=False)

    with patch.object(cc, "run_cli", side_effect=inspect_other) as m:
        ok = cc.stop_container("cid", required_label=("o", "mine"))
    assert ok is False
    assert m.call_count == 1  # inspect only; no stop/rm issued


def test_stop_removes_owned_container() -> None:
    captured: list[list[str]] = []

    def fake(cmd: list[str], **_kw: Any) -> RunOutcome:
        captured.append(list(cmd))
        return RunOutcome(returncode=0, stdout="mine\n", stderr="",
                          timed_out=False)

    ok = None
    with patch.object(cc, "run_cli", side_effect=fake):
        ok = cc.stop_container("cid", required_label=("o", "mine"))
    assert ok is True
    assert ["docker", "stop", "cid"] in captured
    assert ["docker", "rm", "-f", "cid"] in captured


# ── inspect_state error folding ───────────────────────────────────────


def test_inspect_state_folds_failures_to_error_key() -> None:
    def broken(cmd: list[str], **_kw: Any) -> RunOutcome:
        return RunOutcome(returncode=1, stdout="", stderr="no such object",
                          timed_out=False)

    with patch.object(cc, "run_cli", side_effect=broken):
        state = cc.inspect_state("cid")
    assert state == {"_error": "no such object"}


def test_disk_full_retry_prunes_dangling_images_only() -> None:
    """The disk_full retry path prunes DANGLING IMAGES only — never
    `docker system prune`, which would delete unrelated stopped
    containers/networks/build cache on a shared daemon."""
    calls: list[list[str]] = []

    def fake(cmd: list[str], **_kw: Any) -> RunOutcome:
        calls.append(list(cmd))
        if cmd[:3] == ["docker", "run", "-d"]:
            return RunOutcome(returncode=1, stdout="",
                              stderr="no space left on device",
                              timed_out=False)
        return RunOutcome(returncode=0, stdout="", stderr="",
                          timed_out=False)

    with patch.object(cc, "run_cli", side_effect=fake), \
         patch.object(cc.time, "sleep"):
        result = cc.launch_container(image="x:1", container_port=80)
    assert not result.ok and result.reason_class == "disk_full"
    prunes = [c for c in calls if "prune" in c]
    assert prunes == [["docker", "image", "prune", "-f"]]
    assert not any(c[:3] == ["docker", "system", "prune"] for c in calls)


# ── network / publish threading ───────────────────────────────────────


def _fake_run_ip(captured: list[list[str]] | None = None,
                 ip: str = "172.19.0.2"):
    def fake(cmd: list[str], **_kw: Any) -> RunOutcome:
        if captured is not None:
            captured.append(list(cmd))
        if ".IPAddress" in " ".join(cmd):
            return RunOutcome(returncode=0, stdout=f"{ip}\n", stderr="",
                              timed_out=False)
        stdout = _PORTS_JSON if "inspect" in cmd else f"{_CID}\n"
        return RunOutcome(returncode=0, stdout=stdout, stderr="",
                          timed_out=False)
    return fake


def test_launch_on_network_without_publish_reports_container_ip() -> None:
    captured: list[list[str]] = []
    with patch.object(cc, "run_cli", side_effect=_fake_run_ip(captured)):
        result = cc.launch_container(
            image="nginx@sha256:" + "c" * 64, container_port=80,
            network="raptor-env-net-abc123", publish=False,
        )
    assert result.ok, (result.reason, result.stderr)
    assert result.host_ip == "172.19.0.2"
    assert result.host_port == 80 and result.container_port == 80
    run_cmd = next(c for c in captured if c[:3] == ["docker", "run", "-d"])
    assert "--network" in run_cmd
    assert run_cmd[run_cmd.index("--network") + 1] == "raptor-env-net-abc123"
    assert "-p" not in run_cmd  # internal networks cannot publish


def test_launch_rejects_bad_network_shapes() -> None:
    bad = cc.launch_container(
        image="x:1", container_port=80,
        network='evil"}}{{', publish=False)
    assert not bad.ok and bad.reason == "invalid_network"
    no_net = cc.launch_container(image="x:1", container_port=80,
                                 publish=False)
    assert not no_net.ok and no_net.reason == "invalid_network"


def test_create_internal_network_builds_labeled_command() -> None:
    captured: list[list[str]] = []
    with patch.object(cc, "run_cli", side_effect=_fake_run(captured)):
        ok, err = cc.create_internal_network(
            "raptor-env-net-abc123", labels={"raptor-env.id": "abc123"})
    assert ok and err == ""
    assert captured == [[
        "docker", "network", "create", "--internal",
        "--label", "raptor-env.id=abc123", "raptor-env-net-abc123",
    ]]
    assert cc.create_internal_network('x"; rm -rf /')[0] is False


def test_create_internal_network_names_host_bridge() -> None:
    """A caller-supplied bridge_name must reach the daemon as the
    com.docker.network.bridge.name option — the stable interface name
    is what makes the host-gateway residual closable by one static
    operator firewall rule (docs/cve-env.md)."""
    captured: list[list[str]] = []
    with patch.object(cc, "run_cli", side_effect=_fake_run(captured)):
        ok, err = cc.create_internal_network(
            "raptor-env-net-abc123", labels={"raptor-env.id": "abc123"},
            bridge_name="rpenv-abc123def")
    assert ok and err == ""
    assert captured == [[
        "docker", "network", "create", "--internal",
        "-o", "com.docker.network.bridge.name=rpenv-abc123def",
        "--label", "raptor-env.id=abc123", "raptor-env-net-abc123",
    ]]


def test_create_internal_network_refuses_invalid_bridge_name() -> None:
    # IFNAMSIZ bounds a Linux interface name to 15 usable chars, and
    # the option value must stay shell/iptables-literal safe.
    for bad in ("rpenv-0123456789a",  # 16 chars
                "evil name", "a/b", ""):
        ok, err = cc.create_internal_network(
            "raptor-env-net-x", bridge_name=bad)
        assert not ok and "bridge" in err, (bad, ok, err)


def test_read_container_ip_polls_and_validates() -> None:
    with patch.object(cc, "run_cli", side_effect=_fake_run_ip()):
        ip, diag = cc.read_container_ip(_CID, network="netname")
    assert ip == "172.19.0.2" and diag == ""
    ip, diag = cc.read_container_ip(_CID, network='bad"name')
    assert ip is None and "invalid network name" in diag
