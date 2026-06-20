"""Fix B (docker_compose_up): port of cve-build-old's compose.py for
multi-service vulhub stacks (Ghostscript, GitLab, Jira, Confluence).

S23.4 (2026-05-03): added --pull always coverage at end of file.
Cache-bypass cascade-leak fix; see cascade-test/out/cascade-bug-report.md.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml

from cve_env.tools.docker_compose_up import (
    _ACTIVE_STACKS,
    ComposeContainer,
    ComposeError,
    _extract_container_ports,
    _pick_host_port,
    _rewrite_ports_in_place,
    docker_compose_up_payload,
    parse_ps_json,
    pick_primary,
    project_name_for,
    reset_active_stacks,
    rewrite_for_localhost,
    up_stack,
)

# -- project_name_for -------------------------------------------------------


def test_project_name_sanitizes_cve_id() -> None:
    assert project_name_for("CVE-2018-7600") == "cveenv-cve-2018-7600"
    # Each of /,.,.,/ is individually sanitized -> 4 hyphens.
    assert project_name_for("CVE/../bad") == "cveenv-cve----bad"


def test_project_name_lowercases_alphanumeric() -> None:
    assert project_name_for("CVE-ABC-123") == "cveenv-cve-abc-123"


# -- _extract_container_ports -----------------------------------------------


def test_extract_ports_short_form_host_container() -> None:
    spec = {"ports": ["8080:80"]}
    assert _extract_container_ports(spec) == [80]


def test_extract_ports_short_form_host_bind_container() -> None:
    spec = {"ports": ["127.0.0.1:9000:80"]}
    assert _extract_container_ports(spec) == [80]


def test_extract_ports_long_form() -> None:
    spec = {"ports": [{"target": 80, "published": 8080, "protocol": "tcp"}]}
    assert _extract_container_ports(spec) == [80]


def test_extract_ports_with_protocol_suffix() -> None:
    spec = {"ports": ["8080:80/tcp"]}
    assert _extract_container_ports(spec) == [80]


def test_extract_ports_ignores_no_ports_block() -> None:
    assert _extract_container_ports({}) == []
    assert _extract_container_ports({"ports": "not-a-list"}) == []


# -- _rewrite_ports_in_place ------------------------------------------------


def test_rewrite_ports_replaces_with_localhost_ephemeral(tmp_path: Path) -> None:
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        yaml.safe_dump(
            {
                "services": {
                    "web": {"image": "vulhub/drupal:8.5.0", "ports": ["8080:80"]},
                    "db": {"image": "postgres:13", "ports": ["5432:5432"]},
                }
            }
        )
    )
    _rewrite_ports_in_place(compose)
    rewritten = yaml.safe_load(compose.read_text())
    assert rewritten["services"]["web"]["ports"] == ["127.0.0.1:0:80"]
    assert rewritten["services"]["db"]["ports"] == ["127.0.0.1:0:5432"]


def test_rewrite_ports_no_op_when_no_ports(tmp_path: Path) -> None:
    compose = tmp_path / "docker-compose.yml"
    original = yaml.safe_dump({"services": {"web": {"image": "x"}}})
    compose.write_text(original)
    _rewrite_ports_in_place(compose)
    # File should still be parseable and unchanged in services structure.
    data = yaml.safe_load(compose.read_text())
    assert data["services"]["web"] == {"image": "x"}


# -- rewrite_for_localhost (full copy) -------------------------------------


def test_rewrite_for_localhost_copies_siblings(tmp_path: Path) -> None:
    src = tmp_path / "src_compose"
    src.mkdir()
    (src / "docker-compose.yml").write_text(
        yaml.safe_dump(
            {"services": {"web": {"image": "nginx:1.20", "ports": ["8080:80"]}}}
        )
    )
    (src / "index.php").write_text("<?php echo 'hello'; ?>")

    rewritten, staging = rewrite_for_localhost(src / "docker-compose.yml")
    try:
        assert staging.exists()
        assert (staging / "docker-compose.yml").exists()
        # Sibling file must be copied too.
        assert (staging / "index.php").exists()
        # Port rewritten.
        data = yaml.safe_load(rewritten.read_text())
        assert data["services"]["web"]["ports"] == ["127.0.0.1:0:80"]
    finally:
        import shutil as _sh

        _sh.rmtree(staging, ignore_errors=True)


# -- Phase 20A.2: lifecycle label injection --------------------------------


def test_rewrite_ports_injects_cve_id_label_when_cve_id_provided(
    tmp_path: Path,
) -> None:
    """Phase 20A.2: every service gets ``labels: cve-env.cve-id={cve_id}``
    when ``_rewrite_ports_in_place`` is called with a non-empty cve_id.
    """
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        yaml.safe_dump(
            {
                "services": {
                    "web": {"image": "nginx:1.20", "ports": ["8080:80"]},
                    "db": {"image": "postgres:14"},
                }
            }
        )
    )
    _rewrite_ports_in_place(compose, cve_id="CVE-2024-12345")
    data = yaml.safe_load(compose.read_text())
    for svc_name, spec in data["services"].items():
        labels = spec.get("labels", {})
        assert isinstance(labels, dict), (
            f"{svc_name}: expected dict, got {type(labels).__name__}"
        )
        assert labels.get("cve-env.owner") == "cve-env", f"{svc_name}: missing owner"
        assert labels.get("cve-env.cve-id") == "CVE-2024-12345", (
            f"{svc_name}: missing cve-id"
        )


def test_rewrite_ports_no_labels_when_cve_id_empty(tmp_path: Path) -> None:
    """Phase 20A.2: empty cve_id (default) preserves existing test
    contract — no label injection. Matches `test_rewrite_ports_no_op_when_no_ports`.
    """
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(yaml.safe_dump({"services": {"web": {"image": "nginx"}}}))
    _rewrite_ports_in_place(compose, cve_id="")
    data = yaml.safe_load(compose.read_text())
    assert "labels" not in data["services"]["web"]


def test_rewrite_ports_merges_with_existing_dict_labels(tmp_path: Path) -> None:
    """Phase 20A.2: user-supplied labels (dict form) are preserved alongside
    the injected lifecycle labels. Our keys win on collision.
    """
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        yaml.safe_dump(
            {
                "services": {
                    "web": {
                        "image": "nginx",
                        "labels": {"user.tier": "prod", "cve-env.owner": "overridden"},
                    }
                }
            }
        )
    )
    _rewrite_ports_in_place(compose, cve_id="CVE-2024-99999")
    labels = yaml.safe_load(compose.read_text())["services"]["web"]["labels"]
    assert labels["user.tier"] == "prod", "user-supplied label preserved"
    assert labels["cve-env.owner"] == "cve-env", "our key wins on collision"
    assert labels["cve-env.cve-id"] == "CVE-2024-99999"


def test_rewrite_ports_merges_with_existing_list_labels(tmp_path: Path) -> None:
    """Phase 20A.2: user-supplied labels in list form ("key=value" strings)
    are normalized to dict form and merged with the injected labels.
    """
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        yaml.safe_dump(
            {
                "services": {
                    "web": {"image": "nginx", "labels": ["user.tier=prod", "team=red"]}
                }
            }
        )
    )
    _rewrite_ports_in_place(compose, cve_id="CVE-2024-12345")
    labels = yaml.safe_load(compose.read_text())["services"]["web"]["labels"]
    assert isinstance(labels, dict), "list form normalized to dict"
    assert labels["user.tier"] == "prod"
    assert labels["team"] == "red"
    assert labels["cve-env.owner"] == "cve-env"
    assert labels["cve-env.cve-id"] == "CVE-2024-12345"


def test_rewrite_for_localhost_threads_cve_id_to_rewrite(tmp_path: Path) -> None:
    """Phase 20A.2: ``rewrite_for_localhost`` passes ``cve_id`` to
    ``_rewrite_ports_in_place`` so the staged compose ends up labeled.
    Regression for the Phase 19.7 smoke-surfaced lifecycle gap (compose
    containers had ZERO cve-env labels pre-20A.2).
    """
    src = tmp_path / "src_compose"
    src.mkdir()
    (src / "docker-compose.yml").write_text(
        yaml.safe_dump(
            {"services": {"web": {"image": "nginx:1.20", "ports": ["8080:80"]}}}
        )
    )
    rewritten, staging = rewrite_for_localhost(
        src / "docker-compose.yml", cve_id="CVE-2024-99999"
    )
    try:
        labels = yaml.safe_load(rewritten.read_text())["services"]["web"]["labels"]
        assert labels.get("cve-env.cve-id") == "CVE-2024-99999"
        assert labels.get("cve-env.owner") == "cve-env"
    finally:
        import shutil as _sh

        _sh.rmtree(staging, ignore_errors=True)


# -- Phase 20A.2 integration: real compose-up → cleanup loop ----------------


@pytest.mark.slow
def test_phase_20a_2_compose_label_cleanup_end_to_end(tmp_path: Path) -> None:
    """Phase 20A.2 integration: real compose stack, real cleanup_containers.

    Brings up a minimal 1-service compose via ``docker compose -p X up -d``
    on a label-injected compose YAML, asserts the container carries the
    ``cve-env.cve-id`` label, then runs ``lifecycle.cleanup_containers``
    with the same cve_id and asserts the container is gone.

    Requires a running docker daemon. Skipped by default (``slow`` marker).
    Run with ``uv run pytest refactor/tests/unit/test_docker_compose_up.py
    -m slow -k phase_20A_2 -v``.
    """
    import subprocess
    import uuid

    from cve_env.tools.docker_compose_up import _compose_invocation
    from cve_env.utils.lifecycle import cleanup_containers

    # Skip cleanly if docker is unavailable so the test is portable.
    try:
        probe = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if probe.returncode != 0:
            pytest.skip(f"docker daemon not available: {probe.stderr.strip()}")
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker CLI not usable: {exc}")

    # Use the project's compose invocation (V2 plugin if available, else
    # legacy `docker-compose` binary). Matches the actual production path.
    compose_argv = list(_compose_invocation())
    if not compose_argv:
        pytest.skip("no docker compose invocation available (V2 or V1)")

    # Unique cve_id per run so parallel test runs don't collide.
    cve_id = f"CVE-TEST-{uuid.uuid4().hex[:8]}"

    # Write a minimal compose file using a tiny long-running image. The
    # `command: sleep 60` keeps it alive long enough for the test loop.
    src = tmp_path / "src_compose"
    src.mkdir()
    (src / "docker-compose.yml").write_text(
        yaml.safe_dump(
            {
                "services": {
                    "worker": {
                        "image": "alpine:3.19",
                        "command": ["sleep", "60"],
                    }
                }
            }
        )
    )

    rewritten, staging = rewrite_for_localhost(
        src / "docker-compose.yml", cve_id=cve_id
    )
    project = project_name_for(cve_id)
    try:
        # Bring the stack up. Real subprocess; honor the host's docker.
        up = subprocess.run(
            [*compose_argv, "-f", str(rewritten), "-p", project, "up", "-d"],
            capture_output=True,
            text=True,
            timeout=90,
        )
        if up.returncode != 0:
            pytest.skip(
                f"docker compose up failed (likely image pull): {up.stderr[:300]}"
            )

        # Verify the container exists with our cve-id label.
        ps_pre = subprocess.run(
            ["docker", "ps", "-aq", "--filter", f"label=cve-env.cve-id={cve_id}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert ps_pre.returncode == 0
        pre_ids = [i for i in ps_pre.stdout.strip().splitlines() if i.strip()]
        assert pre_ids, (
            f"compose container missing cve-env.cve-id={cve_id} label after up "
            f"(stdout={ps_pre.stdout!r}); Phase 20A.2 regression"
        )

        # The actual unit under test: cleanup by cve_id.
        removed = cleanup_containers(cve_id, timeout=30.0)
        assert removed >= 1, f"cleanup_containers returned {removed}, expected ≥1"

        # Verify removal: container should be gone.
        ps_post = subprocess.run(
            ["docker", "ps", "-aq", "--filter", f"label=cve-env.cve-id={cve_id}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        post_ids = [i for i in ps_post.stdout.strip().splitlines() if i.strip()]
        assert not post_ids, (
            f"cleanup_containers did not remove all matching containers; "
            f"survivors: {post_ids}"
        )
    finally:
        # Belt-and-suspenders teardown for any survivors.
        subprocess.run(
            [*compose_argv, "-f", str(rewritten), "-p", project, "down", "-v"],
            capture_output=True,
            timeout=60,
        )
        survivors = subprocess.run(
            ["docker", "ps", "-aq", "--filter", f"label=cve-env.cve-id={cve_id}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        ids = [i for i in (survivors.stdout or "").strip().splitlines() if i.strip()]
        if ids:
            subprocess.run(
                ["docker", "rm", "-f", *ids], capture_output=True, timeout=30
            )
        import shutil as _sh

        _sh.rmtree(staging, ignore_errors=True)


# -- parse_ps_json ----------------------------------------------------------


def test_parse_ps_json_array_format() -> None:
    raw = json.dumps(
        [
            {
                "ID": "abc123",
                "Service": "web",
                "Publishers": [{"PublishedPort": 32768, "TargetPort": 80}],
            }
        ]
    )
    out = parse_ps_json(raw)
    assert len(out) == 1
    assert out[0].service == "web"
    assert out[0].host_port == 32768
    assert out[0].container_port == 80


def test_parse_ps_json_line_delimited() -> None:
    web_pubs = [{"PublishedPort": 8080, "TargetPort": 80}]
    raw = "\n".join(
        [
            json.dumps({"ID": "a1", "Service": "web", "Publishers": web_pubs}),
            json.dumps({"ID": "b2", "Service": "db", "Publishers": []}),
        ]
    )
    out = parse_ps_json(raw)
    assert len(out) == 2
    assert out[0].service == "web"
    assert out[1].service == "db"
    assert out[1].host_port is None


def test_parse_ps_json_empty() -> None:
    assert parse_ps_json("") == ()
    assert parse_ps_json("   ") == ()


# -- _pick_host_port --------------------------------------------------------


def test_pick_host_port_prefers_http_ports() -> None:
    publishers = [
        {"PublishedPort": 33333, "TargetPort": 6379},  # redis
        {"PublishedPort": 32768, "TargetPort": 80},  # http (preferred)
    ]
    host, container = _pick_host_port(publishers)
    assert host == 32768
    assert container == 80


def test_pick_host_port_skips_zero_published() -> None:
    publishers = [{"PublishedPort": 0, "TargetPort": 80}]
    assert _pick_host_port(publishers) == (None, None)


def test_pick_host_port_ignores_bad_shape() -> None:
    assert _pick_host_port("not-a-list") == (None, None)
    assert _pick_host_port([{"bad": "shape"}]) == (None, None)


# -- pick_primary -----------------------------------------------------------


def test_pick_primary_prefers_web_hint() -> None:
    a = ComposeContainer(
        service="db", container_id="a", host_port=5432, container_port=5432
    )
    b = ComposeContainer(
        service="web", container_id="b", host_port=80, container_port=80
    )
    assert pick_primary((a, b)).service == "web"


def test_pick_primary_fallback_to_first_with_port() -> None:
    a = ComposeContainer(
        service="worker", container_id="a", host_port=None, container_port=None
    )
    b = ComposeContainer(
        service="queue", container_id="b", host_port=5672, container_port=5672
    )
    assert pick_primary((a, b)).service == "queue"


def test_pick_primary_fallback_to_first_when_no_ports() -> None:
    a = ComposeContainer(
        service="worker", container_id="a", host_port=None, container_port=None
    )
    b = ComposeContainer(
        service="bg", container_id="b", host_port=None, container_port=None
    )
    assert pick_primary((a, b)).service == "worker"


# -- docker_compose_up_payload (integration-ish) ----------------------------


def test_payload_rejects_missing_compose_file(tmp_path: Path) -> None:
    result = docker_compose_up_payload(
        compose_yaml_path=str(tmp_path / "nonexistent.yml"),
        cve_id="CVE-2018-7600",
    )
    assert result["ok"] is False
    assert "not found" in result["reason"]


@patch("cve_env.tools.docker_compose_up._run_compose")
def test_payload_up_success_returns_primary(mock_run: Any, tmp_path: Path) -> None:
    # Two compose invocations happen in up_stack: `up -d` (empty stdout ok) + `ps --format json`.
    def run_compose_side_effect(args: list[str], **kwargs: Any) -> str:
        if "ps" in args:
            return json.dumps(
                [
                    {
                        "ID": "primary-id-abc",
                        "Service": "web",
                        "Publishers": [{"PublishedPort": 32789, "TargetPort": 80}],
                    }
                ]
            )
        return ""  # up -d returns nothing meaningful

    mock_run.side_effect = run_compose_side_effect

    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        yaml.safe_dump(
            {
                "services": {
                    "web": {"image": "vulhub/drupal:8.5.0", "ports": ["8080:80"]}
                }
            }
        )
    )
    result = docker_compose_up_payload(
        compose_yaml_path=str(compose),
        cve_id="CVE-2018-7600",
    )
    try:
        assert result["ok"] is True
        assert result["primary_container_id"] == "primary-id-abc"
        assert result["primary_service"] == "web"
        assert result["host_port"] == 32789
        assert result["host_ip"] == "127.0.0.1"
        assert result["project_name"] == "cveenv-cve-2018-7600"
    finally:
        reset_active_stacks()


@patch("cve_env.tools.docker_compose_up._run_compose")
def test_payload_up_failure_cleans_up(mock_run: Any, tmp_path: Path) -> None:
    mock_run.side_effect = ComposeError("boom", stderr="image not found")
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        yaml.safe_dump({"services": {"web": {"image": "nonexistent:none"}}})
    )
    result = docker_compose_up_payload(
        compose_yaml_path=str(compose),
        cve_id="CVE-TEST",
    )
    assert result["ok"] is False
    assert "compose up failed" in result["reason"]
    assert "image not found" in result["stderr"]


@patch("cve_env.tools.docker_compose_up._run_compose")
def test_reset_active_stacks_idempotent(mock_run: Any, tmp_path: Path) -> None:
    reset_active_stacks()  # clean slate
    assert _ACTIVE_STACKS == {}, "registry must start empty"
    # Up a stack, then reset -- second reset must be a no-op.
    mock_run.side_effect = [
        "",  # up -d
        json.dumps([{"ID": "cid", "Service": "web", "Publishers": []}]),  # ps
        "",  # down -v --remove-orphans
    ]
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        yaml.safe_dump({"services": {"web": {"image": "x", "ports": ["80:80"]}}})
    )
    docker_compose_up_payload(compose_yaml_path=str(compose), cve_id="CVE-X")
    # After up, the stack is registered (the docker_compose_up_payload may end up
    # tearing down on its own depending on ps shape, but at least one call to
    # _run_compose must have happened).
    assert mock_run.called, "compose up should have invoked _run_compose"
    reset_active_stacks()
    # Registry is empty after reset.
    assert _ACTIVE_STACKS == {}, "reset must clear the registry"
    pre_call_count = mock_run.call_count
    reset_active_stacks()
    # Calling again after the registry is empty must not crash AND must not
    # fire any further compose subcommands (idempotent no-op).
    assert _ACTIVE_STACKS == {}
    assert mock_run.call_count == pre_call_count, "second reset must be a no-op"


# -- Phase 67.0 TDD safety net ------------------------------------------------
# Phase 67 audit issue #12 (severity 7): _rewrite_ports_in_place rewrites
# only the top-level ``services.X.ports`` list. Compose specs that escape
# the localhost-only invariant via ``network_mode: host``,
# ``privileged: true``, ``pid: host``, or dangerous ``cap_add`` are
# silently passed through. P17 (no-priv) + P18 (127.0.0.1 only) are
# bypassed. Phase 67.2 adds rejection for these compose features so the
# rewrite_for_localhost step refuses to stage them.


from cve_env.tools.docker_compose_up import (  # noqa: E402
    _rewrite_ports_in_place as _phase67_rewrite,
)


def test_phase67_compose_rewrite_rejects_network_mode_host(tmp_path: Path) -> None:
    """Phase 67.2 contract: a compose service with ``network_mode: host``
    must be rejected before launch (or the rewrite step must strip it),
    because ``network_mode: host`` bypasses the 127.0.0.1-only invariant
    that ``rewrite_for_localhost`` is designed to enforce.
    """
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        yaml.safe_dump(
            {
                "services": {
                    "web": {
                        "image": "vulhub/drupal:8.5.0",
                        "network_mode": "host",  # P18 BYPASS
                        "ports": ["8080:80"],
                    }
                }
            }
        )
    )
    # Phase 67.2 contract: rewrite raises ValueError OR the post-rewrite
    # YAML has network_mode removed. Either way, network_mode=host must
    # NOT survive into the launched stack.
    raised = False
    try:
        _phase67_rewrite(compose)
    except ValueError:
        raised = True
    if not raised:
        rewritten = yaml.safe_load(compose.read_text())
        net_mode = rewritten["services"]["web"].get("network_mode")
        assert net_mode != "host", (
            "Phase 67.2: post-rewrite compose still has network_mode=host "
            "— P18 (127.0.0.1 only) bypass survives"
        )


def test_phase67_compose_rewrite_rejects_privileged_true(tmp_path: Path) -> None:
    """Phase 67.2 contract: compose service with ``privileged: true``
    is a P17 violation; rewrite/launch must refuse it.
    """
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        yaml.safe_dump(
            {
                "services": {
                    "web": {
                        "image": "x",
                        "privileged": True,  # P17 BYPASS
                        "ports": ["8080:80"],
                    }
                }
            }
        )
    )
    raised = False
    try:
        _phase67_rewrite(compose)
    except ValueError:
        raised = True
    if not raised:
        rewritten = yaml.safe_load(compose.read_text())
        priv = rewritten["services"]["web"].get("privileged")
        assert priv is not True, (
            "Phase 67.2: post-rewrite compose still has privileged=true "
            "— P17 (no-priv) bypass survives"
        )


# -- Security hardening: surgical compose strip (SB-1) ----------------------
# Extends the Phase 67.2 strip to close host-escape keys the enumerate-and-strip
# model missed: docker-socket bind mounts, cap_add: ALL, string-form privileged,
# unconfined security_opt, and host IPC/user namespaces. ``devices:`` is kept.


def _rewrite_and_reload(tmp_path: Path, service: dict[str, Any]) -> dict[str, Any]:
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(yaml.safe_dump({"services": {"web": service}}))
    _phase67_rewrite(compose)
    return yaml.safe_load(compose.read_text())["services"]["web"]


def test_compose_strips_docker_socket_volume_keeps_others(tmp_path: Path) -> None:
    web = _rewrite_and_reload(
        tmp_path,
        {
            "image": "x",
            "volumes": ["/var/run/docker.sock:/var/run/docker.sock", "./data:/data"],
        },
    )
    vols = web.get("volumes", [])
    assert not any("docker.sock" in str(v) for v in vols), (
        "docker socket mount must be stripped"
    )
    assert "./data:/data" in vols, "non-socket volumes must be kept"


def test_compose_strips_cap_add_all(tmp_path: Path) -> None:
    web = _rewrite_and_reload(tmp_path, {"image": "x", "cap_add": ["ALL"]})
    assert "ALL" not in [str(c).upper() for c in web.get("cap_add", [])]


def test_compose_strips_string_form_privileged(tmp_path: Path) -> None:
    web = _rewrite_and_reload(tmp_path, {"image": "x", "privileged": "true"})
    assert str(web.get("privileged")).lower() != "true", (
        "string privileged 'true' must be stripped"
    )


def test_compose_strips_security_opt_and_host_namespaces(tmp_path: Path) -> None:
    web = _rewrite_and_reload(
        tmp_path,
        {
            "image": "x",
            "security_opt": ["seccomp:unconfined"],
            "ipc": "host",
            "userns_mode": "host",
        },
    )
    assert "security_opt" not in web
    assert web.get("ipc") != "host"
    assert web.get("userns_mode") != "host"


def test_compose_keeps_devices_intentionally(tmp_path: Path) -> None:
    """``devices:`` is intentionally NOT stripped (a hardware-class CVE may
    legitimately need a device mapping)."""
    web = _rewrite_and_reload(
        tmp_path, {"image": "x", "devices": ["/dev/foo:/dev/foo"]}
    )
    assert web.get("devices") == ["/dev/foo:/dev/foo"]


# -- S23.4 (2026-05-03): docker compose up --pull always --------------------
# Cache-bypass cascade-leak fix. Compose stacks reference registry images
# (vulhub/X, library/X, etc.); --pull always forces fresh fetch, bypassing
# the local Docker layer cache (the cascade-test Phase 2 leak source).


@patch("cve_env.tools.docker_compose_up._run_compose")
def test_up_stack_appends_pull_always(mock_run: MagicMock, tmp_path: Path) -> None:
    """`docker compose up -d` must include `--pull always`."""
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text("services:\n  web:\n    image: vulhub/openssl:1.0.1g\n")
    # Mock _run_compose: first call (up) returns "", second call (ps) returns
    # JSON with a container so up_stack doesn't raise.
    mock_run.side_effect = [
        "",  # up -d output
        json.dumps(
            [
                {
                    "Name": "test_web_1",
                    "Service": "web",
                    "State": "running",
                    "Publishers": [{"PublishedPort": 8080, "TargetPort": 80}],
                }
            ]
        ),
    ]
    import contextlib

    with contextlib.suppress(ComposeError):
        up_stack("test", compose_file, up_timeout_seconds=10.0)
    # First call to _run_compose is the `up` command; assert --pull always present
    up_args = mock_run.call_args_list[0][0][0]
    assert "up" in up_args, f"first _run_compose should be up: {up_args}"
    assert "--pull" in up_args, f"missing --pull in up cmd: {up_args}"
    pull_idx = up_args.index("--pull")
    assert up_args[pull_idx + 1] == "always", f"--pull value not 'always': {up_args}"
