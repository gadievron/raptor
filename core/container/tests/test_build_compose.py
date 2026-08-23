"""Contract tests for core.container.build and core.container.compose.

The cve_env suite pins the full behaviour through its delegating tool
surfaces; these pin the core-native parameterizations (labels, local
prefixes, project-name prefix) that the shims bind.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

import yaml

from core.container import build as cb
from core.container import compose as cco
from core.container.proc import RunOutcome

# ── build ─────────────────────────────────────────────────────────────


def test_extract_from_image_strips_platform_and_stage(tmp_path: Path) -> None:
    text = "FROM --platform=linux/amd64 debian:11 AS base\nRUN true\n"
    assert cb.extract_from_image(text, tmp_path) == "debian:11"
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.19\n")
    assert cb.extract_from_image(None, tmp_path) == "alpine:3.19"


def test_classify_build_error_maps_headers_libs_configure() -> None:
    stderr = (
        "fatal error: openssl/ssl.h: No such file or directory\n"
        "/usr/bin/ld: cannot find -lpcre\n"
    )
    assert cb.classify_build_error(stderr) == ["libssl-dev", "libpcre3-dev"]
    assert cb.classify_build_error("") == []


def test_build_image_command_shape(tmp_path: Path) -> None:
    captured: list[list[str]] = []

    def fake(cmd: list[str], **_kw: Any) -> RunOutcome:
        captured.append(list(cmd))
        return RunOutcome(returncode=0, stdout="ok", stderr="",
                          timed_out=False)

    with patch.object(cb, "run_cli", side_effect=fake):
        r = cb.build_image(
            context_dir=str(tmp_path), tag="t:1",
            dockerfile_text="FROM debian:11\n",
            labels={"k": "v"}, platform="linux/amd64",
        )
    assert r.ok and r.image_tag == "t:1"
    (cmd,) = captured
    joined = " ".join(cmd)
    assert joined.startswith("docker build -t t:1")
    assert "--label k=v" in joined
    assert "--platform linux/amd64" in joined
    assert "--pull" in cmd  # external FROM base
    assert "-f" in cmd  # tempfile Dockerfile


def test_build_image_skips_pull_for_local_prefix(tmp_path: Path) -> None:
    captured: list[list[str]] = []

    def fake(cmd: list[str], **_kw: Any) -> RunOutcome:
        captured.append(list(cmd))
        return RunOutcome(returncode=0, stdout="", stderr="",
                          timed_out=False)

    with patch.object(cb, "run_cli", side_effect=fake):
        cb.build_image(context_dir=str(tmp_path), tag="t:1",
                       dockerfile_text="FROM cve-x:build\n",
                       local_prefixes=("cve-",))
    assert "--pull" not in captured[0]


def test_build_image_bad_context_and_timeout(tmp_path: Path) -> None:
    assert cb.build_image(context_dir="  ", tag="t").reason == "bad_context"
    f = tmp_path / "afile"
    f.write_text("x")
    assert cb.build_image(context_dir=str(f), tag="t").reason == "bad_context"
    with patch.object(cb, "run_cli",
                      return_value=RunOutcome(returncode=None, stdout="",
                                              stderr="", timed_out=True)):
        r = cb.build_image(context_dir=str(tmp_path), tag="t",
                           timeout_seconds=5)
    assert r.reason == "timeout" and r.reason_class == "timeout"


# ── compose ───────────────────────────────────────────────────────────


def test_project_name_prefix_and_sanitization() -> None:
    assert cco.project_name("cveenv", "CVE-2018-7600") == \
        "cveenv-cve-2018-7600"
    assert cco.project_name("raptor", "My App!") == "raptor-my-app-"


def test_inject_labels_merges_and_wins(tmp_path: Path) -> None:
    spec: dict[str, Any] = {"labels": ["user=x", "raptor.owner=old"]}
    cco.inject_labels(spec, labels={"raptor.owner": "new"})
    assert spec["labels"] == {"user": "x", "raptor.owner": "new"}


def _identity_resolver(compose_file: Path) -> dict[str, Any]:
    """Hermetic stand-in for ``docker compose config``: the fixture is
    treated as already resolved (no docker daemon in unit tests)."""
    return yaml.safe_load(compose_file.read_text(encoding="utf-8"))


def test_rewrite_hardens_and_labels(tmp_path: Path) -> None:
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(yaml.safe_dump({
        "services": {
            "web": {
                "image": "nginx:1.25",
                "ports": ["0.0.0.0:8080:80"],
                "privileged": True,
                "network_mode": "host",
                "pid": "host",
                "cap_add": ["SYS_ADMIN", "CHOWN"],
                "volumes": ["/var/run/docker.sock:/var/run/docker.sock",
                            "./html:/usr/share/nginx/html"],
                "devices": ["/dev/mem:/dev/mem", "/dev/null:/dev/null"],
            },
        },
    }))
    with patch.object(cco, "_resolve_effective_model", _identity_resolver):
        staged, staging = cco.rewrite_for_localhost(
            compose, labels={"raptor.owner": "test"})
    try:
        data = yaml.safe_load(staged.read_text())
        svc = data["services"]["web"]
        assert svc["ports"] == ["127.0.0.1:0:80"]
        assert "privileged" not in svc
        assert "network_mode" not in svc
        assert "pid" not in svc
        assert svc["cap_add"] == ["CHOWN"]
        assert svc["volumes"] == ["./html:/usr/share/nginx/html"]
        assert svc["devices"] == ["/dev/null:/dev/null"]
        assert svc["labels"]["raptor.owner"] == "test"
        # Single-container-parity limits are injected per service.
        assert svc["mem_limit"] == "4g"
        assert svc["pids_limit"] == 512
    finally:
        import shutil

        shutil.rmtree(staging, ignore_errors=True)


def test_run_compose_folds_failures_to_compose_error(tmp_path: Path) -> None:
    with (patch.object(cco, "_compose_invocation",
                       return_value=("docker", "compose")),
          patch.object(cco, "run_cli",
                       return_value=RunOutcome(returncode=1, stdout="",
                                               stderr="boom",
                                               timed_out=False))):
        try:
            cco.run_compose(["up"])
        except cco.ComposeError as exc:
            assert exc.stderr == "boom"
        else:  # pragma: no cover
            raise AssertionError("expected ComposeError")
