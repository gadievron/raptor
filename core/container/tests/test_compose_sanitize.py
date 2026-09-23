"""Regression battery for the compose resolve-then-sanitize pipeline.

Each test is the inversion of a demonstrated sanitizer bypass: the raw
rewrite previously ran on the unresolved YAML text, so interpolation
(``privileged: ${X:-true}``), ``include:``, ``extends:`` and every
host-resource key the narrow blocklists missed rode through to
``docker compose up``. The sanitizer now (1) refuses raw constructs the
resolver would satisfy by reading files outside staging, (2) resolves
the full effective model, and (3) rebuilds every service from key
allowlists. Unit tests stub the resolver (no docker daemon needed); the
docker-gated integration test at the bottom exercises the real
``compose config`` seam.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import yaml

from core.container import compose as cco


def _identity_resolver(compose_file: Path) -> dict[str, Any]:
    """Hermetic stand-in for ``docker compose config`` (fixture treated
    as already resolved)."""
    return yaml.safe_load(compose_file.read_text(encoding="utf-8"))


def _sanitize(tmp_path: Path, doc: dict[str, Any], **kw: Any) -> dict[str, Any]:
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(yaml.safe_dump(doc))
    with patch.object(cco, "_resolve_effective_model", _identity_resolver):
        cco._rewrite_ports_in_place(compose, **kw)
    return yaml.safe_load(compose.read_text())


# -- fail-closed pre-resolution gate -----------------------------------------


def test_include_is_refused(tmp_path: Path) -> None:
    with pytest.raises(cco.ComposeError, match="include"):
        _sanitize(tmp_path, {
            "include": ["evil.yml"],
            "services": {"web": {"image": "x"}},
        })


def test_extends_file_outside_staging_refused(tmp_path: Path) -> None:
    for ref in ("/etc/other.yml", "../outside.yml", "${DIR:-/etc}/x.yml"):
        with pytest.raises(cco.ComposeError):
            _sanitize(tmp_path, {
                "services": {
                    "web": {"extends": {"service": "a", "file": ref}},
                },
            })


def test_env_file_outside_staging_refused(tmp_path: Path) -> None:
    for ref in ("/etc/passwd", "../secrets.env", "~/creds.env",
                "${F:-/etc/passwd}"):
        with pytest.raises(cco.ComposeError):
            _sanitize(tmp_path, {
                "services": {"web": {"image": "x", "env_file": ref}},
            })


def test_env_file_inside_staging_allowed(tmp_path: Path) -> None:
    # env_file is resolved away by compose config; the gate only has to
    # let confined references through to the resolver.
    (tmp_path / "ok.env").write_text("A=1\n")
    doc = _sanitize(tmp_path, {
        "services": {"web": {"image": "x", "env_file": "ok.env"}},
    })
    assert "web" in doc["services"]


def test_resolution_failure_is_fail_closed(tmp_path: Path) -> None:
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(yaml.safe_dump({"services": {"web": {"image": "x"}}}))

    def broken(_: Path) -> dict[str, Any]:
        raise cco.ComposeError("resolver unavailable")

    with patch.object(cco, "_resolve_effective_model", broken), \
         pytest.raises(cco.ComposeError):
        cco._rewrite_ports_in_place(compose)


# -- host-resource keys never survive (allowlist rebuild) --------------------


def test_resolved_privileged_and_namespaces_dropped(tmp_path: Path) -> None:
    """The resolver turns ``${X:-true}`` into ``true`` — and whatever it
    produces, privileged/pid/ipc/userns/security_opt die by allowlist."""
    doc = _sanitize(tmp_path, {
        "services": {
            "web": {
                "image": "x",
                "privileged": True,
                "pid": "host",
                "ipc": "host",
                "userns_mode": "host",
                "network_mode": "host",
                "security_opt": ["seccomp=unconfined"],
                "cgroup_parent": "/host.slice",
                "device_cgroup_rules": ["a *:* rwm"],
                "volumes_from": ["container:other"],
                "runtime": "sysbox-runc",
                "oom_kill_disable": True,
                "container_name": "squatter",
            },
        },
    })
    svc = doc["services"]["web"]
    for key in ("privileged", "pid", "ipc", "userns_mode", "network_mode",
                "security_opt", "cgroup_parent", "device_cgroup_rules",
                "volumes_from", "runtime", "oom_kill_disable",
                "container_name"):
        assert key not in svc, f"{key} survived the allowlist"


def test_safe_namespace_values_kept(tmp_path: Path) -> None:
    doc = _sanitize(tmp_path, {
        "services": {
            "a": {"image": "x", "ipc": "shareable"},
            "b": {"image": "x", "ipc": "service:a", "pid": "service:a",
                  "network_mode": "none"},
        },
    })
    assert doc["services"]["a"]["ipc"] == "shareable"
    assert doc["services"]["b"]["ipc"] == "service:a"
    assert doc["services"]["b"]["pid"] == "service:a"
    assert doc["services"]["b"]["network_mode"] == "none"


def test_cap_add_cap_prefix_bypass_closed(tmp_path: Path) -> None:
    doc = _sanitize(tmp_path, {
        "services": {
            "web": {
                "image": "x",
                "cap_add": ["CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "SYS_ADMIN",
                            "NET_RAW", "BPF", "ALL", "CAP_CHOWN", "chown",
                            "NET_BIND_SERVICE"],
            },
        },
    })
    assert doc["services"]["web"]["cap_add"] == [
        "CHOWN", "CHOWN", "NET_BIND_SERVICE"]


def test_host_binds_dropped_staging_binds_kept(tmp_path: Path) -> None:
    (tmp_path / "html").mkdir()
    doc = _sanitize(tmp_path, {
        "services": {
            "web": {
                "image": "x",
                "volumes": [
                    "/etc:/hostetc",                       # absolute host
                    "/var/../var/run:/evade",              # non-canonical
                    "~/secrets:/s",                        # home expansion
                    "../outside:/o",                       # relative escape
                    "./html:/usr/share/nginx/html",        # staging-relative
                    ".:/app",                              # staging root
                    "namedvol:/data",                      # named volume
                    "/anon",                               # anonymous
                    {"type": "bind", "source": "/etc", "target": "/e"},
                    {"type": "bind", "source": str(tmp_path / "html"),
                     "target": "/h"},
                    {"type": "tmpfs", "target": "/scratch"},
                ],
            },
        },
        "volumes": {"namedvol": None},
    })
    vols = doc["services"]["web"]["volumes"]
    assert "/etc:/hostetc" not in vols
    assert "/var/../var/run:/evade" not in vols
    assert "~/secrets:/s" not in vols
    assert "../outside:/o" not in vols
    assert "./html:/usr/share/nginx/html" in vols
    assert ".:/app" in vols
    assert "namedvol:/data" in vols
    assert "/anon" in vols
    assert {"type": "bind", "source": "/etc", "target": "/e"} not in vols
    assert {"type": "bind", "source": str(tmp_path / "html"),
            "target": "/h"} in vols
    assert {"type": "tmpfs", "target": "/scratch"} in vols


def test_symlinked_bind_source_escaping_staging_dropped(tmp_path: Path) -> None:
    (tmp_path / "link").symlink_to("/etc")
    doc = _sanitize(tmp_path, {
        "services": {"web": {"image": "x", "volumes": ["./link:/e"]}},
    })
    assert "volumes" not in doc["services"]["web"]


def test_environment_passthrough_entries_dropped(tmp_path: Path) -> None:
    doc = _sanitize(tmp_path, {
        "services": {
            "web": {
                "image": "x",
                "environment": {"EXPLICIT": "1", "PASS_THROUGH": None},
            },
            "lst": {
                "image": "x",
                "environment": ["KEEP=1", "LEAK_HOST_VAR"],
            },
        },
    })
    assert doc["services"]["web"]["environment"] == {"EXPLICIT": "1"}
    assert doc["services"]["lst"]["environment"] == ["KEEP=1"]


# -- build-context confinement ------------------------------------------------


def test_build_context_escapes_refused(tmp_path: Path) -> None:
    for context in ("/home", "../..", "https://github.com/x/y.git",
                    "git@github.com:x/y.git"):
        with pytest.raises(cco.ComposeError):
            _sanitize(tmp_path, {
                "services": {"web": {"build": {"context": context}}},
            })


def test_build_dockerfile_escape_refused(tmp_path: Path) -> None:
    with pytest.raises(cco.ComposeError):
        _sanitize(tmp_path, {
            "services": {"web": {"build": {
                "context": ".", "dockerfile": "../../Dockerfile"}}},
        })


def test_build_additional_contexts_refused(tmp_path: Path) -> None:
    with pytest.raises(cco.ComposeError):
        _sanitize(tmp_path, {
            "services": {"web": {"build": {
                "context": ".", "additional_contexts": {"h": "/home"}}}},
        })


def test_build_confined_kept_dangerous_subkeys_dropped(tmp_path: Path) -> None:
    doc = _sanitize(tmp_path, {
        "services": {
            "web": {
                "build": {
                    "context": ".",
                    "dockerfile": "Dockerfile",
                    "args": {"V": "1"},
                    "ssh": ["default"],
                    "privileged": True,
                    "network": "host",
                },
            },
        },
    })
    build = doc["services"]["web"]["build"]
    assert build["context"] == "."
    assert build["args"] == {"V": "1"}
    for key in ("ssh", "privileged", "network"):
        assert key not in build


# -- ports ---------------------------------------------------------------------


def test_port_range_bounds_checked_before_iteration() -> None:
    # The inversion of the "0-4000000000 spins the worker" PoC: hostile
    # endpoints are rejected before any range is constructed.
    assert cco._extract_container_ports({"ports": ["0-4000000000"]}) == []
    assert cco._extract_container_ports({"ports": ["70000-70010"]}) == []
    assert cco._extract_container_ports({"ports": ["5-3"]}) == []
    assert cco._extract_container_ports(
        {"ports": ["9000-9003"]}) == [9000, 9001, 9002, 9003]


def test_ports_capped_per_service(tmp_path: Path) -> None:
    doc = _sanitize(tmp_path, {
        "services": {"web": {"image": "x", "ports": ["1000-2000"]}},
    })
    ports = doc["services"]["web"]["ports"]
    assert len(ports) == cco._MAX_PORTS_PER_SERVICE
    assert ports[0] == "127.0.0.1:0:1000"


# -- stack-level limits --------------------------------------------------------


def test_limits_injected_on_every_service(tmp_path: Path) -> None:
    doc = _sanitize(tmp_path, {
        "services": {
            "a": {"image": "x"},
            "b": {"image": "x", "mem_limit": "512g", "pids_limit": 100000,
                  "deploy": {"resources": {"limits": {"memory": "512g"}}}},
        },
    })
    for svc in doc["services"].values():
        assert svc["mem_limit"] == "4g"
        assert svc["memswap_limit"] == "4g"
        assert svc["cpus"] == 2
        assert svc["pids_limit"] == 512
        assert "deploy" not in svc


def test_service_count_capped(tmp_path: Path) -> None:
    services = {f"s{i}": {"image": "x"} for i in range(cco._MAX_SERVICES + 1)}
    with pytest.raises(cco.ComposeError, match="services"):
        _sanitize(tmp_path, {"services": services})


# -- top-level definitions -----------------------------------------------------


def test_volume_definition_host_bind_escape_stripped(tmp_path: Path) -> None:
    doc = _sanitize(tmp_path, {
        "services": {"web": {"image": "x", "volumes": ["v:/data"]}},
        "volumes": {
            "v": {"driver": "local",
                  "driver_opts": {"type": "none", "o": "bind",
                                  "device": "/etc"},
                  "external": True},
        },
    })
    assert doc["volumes"]["v"] is None


def test_network_definitions_confined(tmp_path: Path) -> None:
    doc = _sanitize(tmp_path, {
        "services": {"web": {"image": "x"}},
        "networks": {
            "hostnet": {"external": True, "name": "host"},
            "shadow": {"driver": "bridge",
                       "ipam": {"config": [{"subnet": "10.0.0.0/8"}]},
                       "driver_opts": {"com.docker.network.bridge.name":
                                       "docker0"}},
            "ok": {"internal": True},
        },
    })
    # Escape shapes stripped AND every definition forced internal.
    assert doc["networks"]["hostnet"] == {"internal": True}
    assert doc["networks"]["shadow"] == {"internal": True, "driver": "bridge"}
    assert doc["networks"]["ok"] == {"internal": True}


def test_secret_sources_confined(tmp_path: Path) -> None:
    (tmp_path / "ok.txt").write_text("fine")
    doc = _sanitize(tmp_path, {
        "services": {"web": {"image": "x", "secrets": ["s"]}},
        "secrets": {"s": {"file": "./ok.txt"}},
    })
    assert doc["secrets"]["s"] == {"file": "./ok.txt"}
    for bad in ({"file": "/etc/shadow"}, {"file": "~/.aws/credentials"},
                {"environment": "HOME"}, {"external": True}):
        with pytest.raises(cco.ComposeError):
            _sanitize(tmp_path, {
                "services": {"web": {"image": "x"}},
                "secrets": {"s": bad},
            })


# -- staging copy --------------------------------------------------------------


def test_staging_prunes_escaping_symlinks_keeps_internal(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "docker-compose.yml").write_text(
        yaml.safe_dump({"services": {"web": {"image": "x"}}}))
    secret = tmp_path / "host-secret.txt"
    secret.write_text("marker")
    (src / "steal.txt").symlink_to(secret)          # escapes staging
    (src / "real.txt").write_text("data")
    (src / "alias.txt").symlink_to("real.txt")      # stays inside
    with patch.object(cco, "_resolve_effective_model", _identity_resolver):
        staged, staging = cco.rewrite_for_localhost(src / "docker-compose.yml")
    try:
        stolen = staging / "steal.txt"
        # Neither dereferenced content (the old symlinks=False bug) nor a
        # live escaping link may exist in staging.
        assert not stolen.exists() and not stolen.is_symlink()
        alias = staging / "alias.txt"
        assert alias.is_symlink() and alias.read_text() == "data"
    finally:
        shutil.rmtree(staging, ignore_errors=True)


# -- real-resolver integration (docker-gated) ----------------------------------


def _compose_available() -> bool:
    try:
        probe = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return probe.returncode == 0


@pytest.mark.skipif(not _compose_available(),
                    reason="docker compose unavailable")
def test_real_resolver_defeats_interpolation_bypass(tmp_path: Path) -> None:
    """End-to-end inversion of the critical PoC: ``privileged:
    ${UNSET:-true}`` + CAP_-prefixed caps + host binds through the REAL
    ``docker compose config`` seam."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "docker-compose.yml").write_text(yaml.safe_dump({
        "services": {
            "base": {"image": "alpine:latest", "command": ["sleep", "1"]},
            "web": {
                "extends": {"service": "base"},
                "ports": ["8080:80"],
                "privileged": "${G1_UNSET_VAR:-true}",
                "cap_add": ["CAP_SYS_PTRACE", "CHOWN"],
                "volumes": ["/etc:/hostetc", "./html:/w"],
                "environment": {"LEAK_HOME": "${HOME}",
                                "LEAK_PATH": "${PATH}"},
            },
        },
    }))
    (src / "html").mkdir()
    staged, staging = cco.rewrite_for_localhost(src / "docker-compose.yml")
    try:
        data = yaml.safe_load(staged.read_text())
        web = data["services"]["web"]
        assert web["image"] == "alpine:latest"          # extends resolved
        assert "privileged" not in web                  # interpolation dead
        assert web.get("cap_add") == ["CHOWN"]          # CAP_ prefix dead
        vols = web.get("volumes") or []
        assert not any(
            (isinstance(v, dict) and v.get("source") == "/etc")
            or (isinstance(v, str) and v.startswith("/etc:"))
            for v in vols
        )
        assert web["ports"] == ["127.0.0.1:0:80"]
        assert web["pids_limit"] == 512
        # Interpolation ran against the MINIMAL resolver env: the
        # launcher's HOME/PATH never reach the container.
        env = web.get("environment") or {}
        import os as _os
        real_home = _os.environ.get("HOME", "")
        if real_home:
            assert env.get("LEAK_HOME") != real_home
        assert env.get("LEAK_PATH") in (cco._RESOLVER_PATH, "", None)
        # Every stack network is internal (no routed egress).
        assert data["networks"]["default"]["internal"] is True
    finally:
        shutil.rmtree(staging, ignore_errors=True)


# -- review-response regressions ----------------------------------------------
# Inversions of the adversarial-review PoCs: transitive resolution-graph
# reads (staged extends target's own env_file, depth-2 extends.file),
# interpolation env leaks, ulimits/stop_grace passthrough, host-gateway
# extra_hosts, and compose-stack egress.


def test_staged_extends_env_file_refused(tmp_path: Path) -> None:
    """A staged extends TARGET declaring an out-of-staging env_file must
    refuse — gating only the primary file left a one-hop bypass that read
    arbitrary host KEY=VALUE files into the hostile container."""
    (tmp_path / "inner.yml").write_text(yaml.safe_dump({
        "services": {"base": {"image": "x",
                              "env_file": "/tmp/host-secret.env"}},
    }))
    with pytest.raises(cco.ComposeError, match="env_file"):
        _sanitize(tmp_path, {
            "services": {
                "web": {"extends": {"file": "inner.yml", "service": "base"}},
            },
        })


def test_depth2_extends_file_refused(tmp_path: Path) -> None:
    (tmp_path / "a.yml").write_text(yaml.safe_dump({
        "services": {"s": {"image": "x",
                           "extends": {"file": "/etc/passwd",
                                       "service": "root"}}},
    }))
    with pytest.raises(cco.ComposeError, match="extends.file"):
        _sanitize(tmp_path, {
            "services": {
                "w": {"extends": {"file": "a.yml", "service": "s"}},
            },
        })


def test_label_file_gated(tmp_path: Path) -> None:
    """label_file is ignored by current compose but gated anyway —
    version drift must not reopen the host-read family."""
    with pytest.raises(cco.ComposeError, match="label_file"):
        _sanitize(tmp_path, {
            "services": {"w": {"image": "x", "label_file": "/etc/hostname"}},
        })


def test_extends_cycle_terminates_and_depth_capped(tmp_path: Path) -> None:
    # Cycle: a <-> b must terminate (and pass the gate — nothing escapes).
    (tmp_path / "a.yml").write_text(yaml.safe_dump({
        "services": {"s": {"image": "x",
                           "extends": {"file": "b.yml", "service": "t"}}},
    }))
    (tmp_path / "b.yml").write_text(yaml.safe_dump({
        "services": {"t": {"image": "x",
                           "extends": {"file": "a.yml", "service": "s"}}},
    }))
    doc = {"services": {"w": {"image": "x",
                              "extends": {"file": "a.yml", "service": "s"}}}}
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(yaml.safe_dump(doc))
    cco._pre_resolution_gate(doc, tmp_path)  # must not recurse forever

    # Depth cap: a chain longer than _PRE_GATE_MAX_DEPTH refuses.
    limit = cco._PRE_GATE_MAX_DEPTH
    for i in range(limit + 2):
        (tmp_path / f"c{i}.yml").write_text(yaml.safe_dump({
            "services": {"s": {"image": "x",
                               "extends": {"file": f"c{i + 1}.yml",
                                           "service": "s"}}},
        }))
    (tmp_path / f"c{limit + 2}.yml").write_text(yaml.safe_dump({
        "services": {"s": {"image": "x"}},
    }))
    chain_doc = {"services": {"w": {"image": "x",
                                    "extends": {"file": "c0.yml",
                                                "service": "s"}}}}
    with pytest.raises(cco.ComposeError, match="depth"):
        cco._pre_resolution_gate(chain_doc, tmp_path)


def test_gated_document_size_capped(tmp_path: Path) -> None:
    big = tmp_path / "big.yml"
    big.write_text("#" + "x" * cco._PRE_GATE_MAX_FILE_BYTES)
    with pytest.raises(cco.ComposeError, match="budget"):
        cco._load_gated_document(big, what="extends target")


def test_resolver_env_is_minimal(tmp_path: Path) -> None:
    """The interpolation environment must not carry the launcher's env —
    ${HOME}/${PATH}/${DOCKER_HOST} previously inlined host identity and
    layout into the resolved model and shipped it into the container."""
    env = cco._resolver_env(tmp_path)
    assert set(env) == {"PATH", "HOME", "DOCKER_CONFIG"}
    assert env["PATH"] == cco._RESOLVER_PATH  # static, not the process PATH
    assert env["HOME"] == str(tmp_path)  # the caller-owned scratch home
    assert env["DOCKER_CONFIG"].startswith(env["HOME"])


def _plant_hostile_resolver_home(source: Path) -> None:
    """Repo-shipped ``.raptor-resolver-home`` — the attacker shape: a
    docker CLI config whose ``cliPluginsExtraDirs`` points at a repo
    directory carrying an executable ``docker-compose`` plugin."""
    planted = source / ".raptor-resolver-home" / ".docker"
    planted.mkdir(parents=True)
    (planted / "config.json").write_text(
        '{"cliPluginsExtraDirs": ["plugins"]}')
    plugins = source / "plugins"
    plugins.mkdir()
    plugin = plugins / "docker-compose"
    plugin.write_text("#!/bin/sh\nexit 0\n")
    plugin.chmod(0o755)


def test_resolver_home_never_inside_staging(tmp_path: Path) -> None:
    """A hostile repo that SHIPS ``.raptor-resolver-home`` (docker CLI
    config + plugin binary) must never have that copy become the
    resolver's HOME/DOCKER_CONFIG — the resolver home is a fresh
    RAPTOR-owned dir outside the staging tree, and it is torn down
    after resolution."""
    source = tmp_path / "repo"
    source.mkdir()
    _plant_hostile_resolver_home(source)
    compose = source / "docker-compose.yml"
    compose.write_text(yaml.safe_dump(
        {"services": {"web": {"image": "img"}}}))

    seen: dict[str, Any] = {}

    def fake_run_resolver(argv: list[str], staging: Path,
                          env: dict[str, str], **kw: Any) -> str:
        seen["staging"] = staging
        seen["env"] = dict(env)
        seen["scratch_home"] = kw.get("scratch_home")
        seen["home_existed"] = Path(env["HOME"]).is_dir()
        seen["config_dir_existed"] = Path(env["DOCKER_CONFIG"]).is_dir()
        seen["config_json"] = sorted(
            p.name for p in Path(env["DOCKER_CONFIG"]).iterdir())
        return "services: {}\n"

    staged, staging = cco.rewrite_for_localhost(compose)
    try:
        with patch.object(cco, "_run_resolver", fake_run_resolver):
            cco._resolve_effective_model(staged)
    finally:
        cco.cleanup_staging(staging)

    home = Path(seen["env"]["HOME"])
    staging_prefix = str(seen["staging"].resolve())
    assert not str(home.resolve()).startswith(staging_prefix)
    assert not str(
        Path(seen["env"]["DOCKER_CONFIG"]).resolve()
    ).startswith(staging_prefix)
    # The resolver saw a fresh RAPTOR-owned home: real dirs, an EMPTY
    # config dir (the planted config.json never aliases in), and the
    # sandbox grant handle for it.
    assert seen["home_existed"] and seen["config_dir_existed"]
    assert seen["config_json"] == []
    assert seen["scratch_home"] == home
    # Torn down after resolution.
    assert not home.exists()


def test_planted_resolver_home_file_does_not_break_resolution(
        tmp_path: Path) -> None:
    """A repo shipping ``.raptor-resolver-home`` as a plain FILE used to
    make the resolver-env mkdir raise a raw FileExistsError (escaping
    the ComposeError contract). The name is now inert repo data."""
    source = tmp_path / "repo"
    source.mkdir()
    (source / ".raptor-resolver-home").write_text("not a directory")
    compose = source / "docker-compose.yml"
    compose.write_text(yaml.safe_dump(
        {"services": {"web": {"image": "img"}}}))

    staged, staging = cco.rewrite_for_localhost(compose)
    try:
        with patch.object(cco, "_run_resolver",
                          lambda *a, **kw: "services: {}\n"):
            resolved = cco._resolve_effective_model(staged)
    finally:
        cco.cleanup_staging(staging)
    assert resolved == {"services": {}}


def test_resolver_scratch_home_cleaned_on_failure(tmp_path: Path) -> None:
    """The scratch home is torn down on the resolution-failure path too
    (fail closed must not strand tmpdirs)."""
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(yaml.safe_dump(
        {"services": {"web": {"image": "img"}}}))
    seen: dict[str, Any] = {}

    def failing_run_resolver(argv: list[str], staging: Path,
                             env: dict[str, str], **kw: Any) -> str:
        seen["home"] = Path(env["HOME"])
        raise cco.ComposeError("config exploded")

    with patch.object(cco, "_run_resolver", failing_run_resolver), \
            pytest.raises(cco.ComposeError, match="config exploded"):
        cco._resolve_effective_model(compose)
    assert not seen["home"].exists()


def test_resolver_sandbox_granted_scratch_home(tmp_path: Path) -> None:
    """The sandbox leg confines reads to staging — the out-of-staging
    scratch home must ride the read + write grants or docker's config
    discovery fails under confinement."""
    seen: dict[str, Any] = {}

    def fake_sandbox_run(argv: list[str], **kw: Any):
        seen.update(kw)

        class _P:
            returncode = 0
            stdout = "services: {}\n"
            stderr = ""
            sandbox_info: dict[str, Any] = {}

        return _P()

    scratch = tmp_path / "scratch-home"
    scratch.mkdir()
    import core.sandbox as sb
    with patch.object(sb, "run", fake_sandbox_run):
        cco._run_resolver(["docker", "compose", "config"], tmp_path,
                          cco._resolver_env(scratch),
                          scratch_home=scratch)
    assert seen.get("readable_paths") == [str(scratch)]
    assert seen.get("writable_paths") == [str(scratch)]


def test_resolver_failure_never_retried_unconfined(tmp_path: Path) -> None:
    """rc!=0 INSIDE the sandbox is a resolution failure (fail closed) —
    it must not fall back to an unconfined retry."""
    calls: list[list[str]] = []

    def fake_sandbox_run(argv: list[str], **_kw: Any):
        calls.append(list(argv))

        class _P:
            returncode = 1
            stdout = ""
            stderr = "config exploded"

        return _P()

    import core.sandbox as sb
    with patch.object(sb, "run", fake_sandbox_run), \
         patch.object(cco, "run_cli",
                      side_effect=AssertionError("unconfined retry")), \
         pytest.raises(cco.ComposeError, match="config exploded"):
        cco._run_resolver(["docker", "compose", "config"], tmp_path,
                          cco._resolver_env(tmp_path))
    assert len(calls) == 1


def test_resolver_fallback_refuses_truncated_output(tmp_path: Path) -> None:
    """Unconfined-fallback leg: a tail-capped resolver stdout can still
    be a VALID YAML document describing a subset stack — parsing it would
    sanitize and launch a partial model as if complete. A truncated
    outcome must refuse (fail closed); an untruncated one must keep
    flowing (the refuse-good-runs direction)."""
    from core.container.proc import RunOutcome
    from core.sandbox import SandboxSetupError

    import core.sandbox as sb

    def _outcome(truncated: bool) -> RunOutcome:
        return RunOutcome(returncode=0, stdout="services: {}\n",
                          stderr="", timed_out=False, truncated=truncated)

    with patch.object(sb, "run",
                      side_effect=SandboxSetupError("no sandbox tier")):
        with patch.object(cco, "run_cli",
                          return_value=_outcome(truncated=True)), \
             pytest.raises(cco.ComposeError, match="truncated"):
            cco._run_resolver(["docker", "compose", "config"], tmp_path,
                              cco._resolver_env(tmp_path))
        with patch.object(cco, "run_cli",
                          return_value=_outcome(truncated=False)):
            raw = cco._run_resolver(
                ["docker", "compose", "config"], tmp_path,
                cco._resolver_env(tmp_path))
        assert raw == "services: {}\n"


def test_primary_compose_file_size_capped(tmp_path: Path) -> None:
    """The primary document gets the same 5MiB budget as gated
    extends/env_file targets — an oversized hostile compose file must
    refuse before parsing, not memory-DoS the sanitizer."""
    compose = tmp_path / "docker-compose.yml"
    body = yaml.safe_dump({"services": {"web": {"image": "x"}}})
    compose.write_text(
        body + "# " + "x" * cco._PRE_GATE_MAX_FILE_BYTES + "\n")
    with pytest.raises(cco.ComposeError, match="budget"), \
            patch.object(cco, "_resolve_effective_model",
                         _identity_resolver):
        cco._rewrite_ports_in_place(compose)


def test_resolver_narrows_etc_reads(tmp_path: Path) -> None:
    """The resolver sandbox must swap the wholesale /etc read grant for
    the loader/TLS minimum (omit_etc_reads) — it has no business reading
    host-identity files, and on the Landlock-only tier no private mount
    view narrows /etc for it."""
    seen: dict[str, Any] = {}

    def fake_sandbox_run(argv: list[str], **kw: Any):
        seen.update(kw)

        class _P:
            returncode = 0
            stdout = "services: {}\n"
            stderr = ""
            sandbox_info: dict[str, Any] = {}

        return _P()

    import core.sandbox as sb
    with patch.object(sb, "run", fake_sandbox_run):
        cco._run_resolver(["docker", "compose", "config"], tmp_path,
                          cco._resolver_env(tmp_path))
    assert seen.get("restrict_reads") is True
    assert seen.get("omit_etc_reads") is True


def test_resolver_surfaces_mount_ns_degradation(
        tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """A sandbox that ENGAGED but fell back from mount-ns to the
    Landlock-only tier mid-setup used to stay silent toward compose —
    the degraded read boundary must be surfaced in the log."""

    def fake_sandbox_run(argv: list[str], **_kw: Any):
        class _P:
            returncode = 0
            stdout = "services: {}\n"
            stderr = ""
            sandbox_info = {
                "mount_ns_degraded": "spawn setup failed: uid mapping",
            }

        return _P()

    import core.sandbox as sb
    with caplog.at_level("WARNING", logger=cco.logger.name), \
            patch.object(sb, "run", fake_sandbox_run):
        out = cco._run_resolver(["docker", "compose", "config"], tmp_path,
                                cco._resolver_env(tmp_path))
    assert out == "services: {}\n"
    degraded_warnings = [r for r in caplog.records
                         if "Landlock-only" in r.getMessage()]
    assert degraded_warnings, (
        "mount-ns degradation must be surfaced to the compose log")


def test_ulimits_and_stop_grace_dropped(tmp_path: Path) -> None:
    doc = _sanitize(tmp_path, {
        "services": {"web": {"image": "x",
                             "ulimits": {"memlock": -1},
                             "stop_grace_period": "10m"}},
    })
    svc = doc["services"]["web"]
    assert "ulimits" not in svc
    assert "stop_grace_period" not in svc


def test_extra_hosts_host_gateway_stripped(tmp_path: Path) -> None:
    doc = _sanitize(tmp_path, {
        "services": {
            "lst": {"image": "x",
                    "extra_hosts": ["hostgw:host-gateway",
                                    "pinned:10.9.9.9"]},
            "map": {"image": "x",
                    "extra_hosts": {"hostgw": "host-gateway",
                                    "pinned": "10.9.9.9"}},
            "only": {"image": "x",
                     "extra_hosts": ["hostgw:host-gateway"]},
        },
    })
    assert doc["services"]["lst"]["extra_hosts"] == ["pinned:10.9.9.9"]
    assert doc["services"]["map"]["extra_hosts"] == {"pinned": "10.9.9.9"}
    assert "extra_hosts" not in doc["services"]["only"]


def test_network_mode_bridge_dropped(tmp_path: Path) -> None:
    """network_mode bridge/default would detach a service from the
    internal project network onto the masqueraded default bridge."""
    doc = _sanitize(tmp_path, {
        "services": {
            "a": {"image": "x", "network_mode": "bridge"},
            "b": {"image": "x", "network_mode": "default"},
            "c": {"image": "x", "network_mode": "none"},
        },
    })
    assert "network_mode" not in doc["services"]["a"]
    assert "network_mode" not in doc["services"]["b"]
    assert doc["services"]["c"]["network_mode"] == "none"


def test_stack_networks_forced_internal(tmp_path: Path) -> None:
    """Every stack network — including the implicit project default —
    is internal: routed egress dies while the host->container-IP verify
    path keeps working (documented residual: the bridge gateway address
    still reaches host services bound on 0.0.0.0)."""
    doc = _sanitize(tmp_path, {
        "services": {"web": {"image": "x"}},
    })
    assert doc["networks"]["default"] == {"internal": True}
    doc = _sanitize(tmp_path, {
        "services": {"web": {"image": "x", "networks": ["custom"]}},
        "networks": {"custom": {"internal": False}},
    })
    assert doc["networks"]["custom"]["internal"] is True
    assert doc["networks"]["default"] == {"internal": True}


def test_down_stack_bounds_stop_timeout(tmp_path: Path) -> None:
    with patch.object(cco, "run_compose") as mock_run:
        cco.down_stack("proj", tmp_path / "docker-compose.yml")
    args = mock_run.call_args_list[0][0][0]
    idx = args.index("--timeout")
    assert args[idx + 1] == "30"


def test_unpublished_container_gets_container_ip_endpoint() -> None:
    # Batched form: two unpublished containers resolve from ONE
    # docker-inspect invocation (one JSON line each, keyed by full Id).
    inspect_payload = (
        '{"id":"cid1full",'
        '"nets":{"proj_default":{"IPAddress":"172.19.0.7"}},'
        '"exposed":{"80/tcp":{},"9999/tcp":{}}}\n'
        '{"id":"cid2full",'
        '"nets":{"proj_default":{"IPAddress":"172.19.0.8"}},'
        '"exposed":{"6379/tcp":{}}}'
    )

    from core.container.proc import RunOutcome
    calls: list[list[str]] = []

    def _fake_run_cli(argv, **kwargs):
        calls.append(argv)
        return RunOutcome(returncode=0, stdout=inspect_payload,
                          stderr="", timed_out=False)

    published = cco.ComposeContainer(service="lb", container_id="cid0",
                                     host_port=8080, container_port=80)
    with patch.object(cco, "run_cli", _fake_run_cli):
        out = cco._with_container_endpoints((
            published,
            cco.ComposeContainer(service="web", container_id="cid1",
                                 host_port=None, container_port=None),
            cco.ComposeContainer(service="cache", container_id="cid2",
                                 host_port=None, container_port=None),
        ))
    assert len(calls) == 1  # one batched spawn, not one per container
    assert "cid1" in calls[0] and "cid2" in calls[0]
    assert "cid0" not in calls[0]  # published containers not inspected
    assert out[0] is published
    assert out[1].host_ip == "172.19.0.7"
    assert out[1].host_port == 80  # preferred HTTP-shaped port wins
    assert out[1].container_port == 80
    assert out[2].host_ip == "172.19.0.8"
    assert out[2].host_port == 6379

    # Inspect failure leaves the containers untouched (best-effort).
    with patch.object(cco, "run_cli",
                      return_value=RunOutcome(returncode=1, stdout="",
                                              stderr="no such object",
                                              timed_out=False)):
        out = cco._with_container_endpoints((
            cco.ComposeContainer(service="web", container_id="cid",
                                 host_port=None, container_port=None),
        ))
    assert out[0].host_port is None and out[0].host_ip == "127.0.0.1"


# -- staging keepalive (live-owner protection for the reaper) ------------------


class TestStagingKeepalive:
    """The staging dir is reaper-listed (raptor-compose-): a live stack
    bind-mounts from it while nothing refreshes its top-level mtime, so
    ownership carries a scratch keepalive from creation until
    cleanup_staging()."""

    @pytest.fixture(autouse=True)
    def _isolated_keepalive(self, monkeypatch):
        from core.run import scratch as scratch_mod
        monkeypatch.setattr(scratch_mod, "_keepalive_paths", set())

    def _src(self, tmp_path: Path) -> Path:
        src = tmp_path / "src"
        src.mkdir()
        (src / "docker-compose.yml").write_text(
            yaml.safe_dump({"services": {"web": {"image": "x"}}}))
        return src

    def test_registered_until_cleanup_staging(self, tmp_path: Path) -> None:
        from core.run import scratch as scratch_mod
        src = self._src(tmp_path)
        with patch.object(cco, "_resolve_effective_model",
                          _identity_resolver):
            _, staging = cco.rewrite_for_localhost(
                src / "docker-compose.yml")
        try:
            assert str(staging) in scratch_mod._keepalive_paths
        finally:
            cco.cleanup_staging(staging)
        assert str(staging) not in scratch_mod._keepalive_paths
        assert not staging.exists()

    def test_failed_rewrite_unregisters(self, tmp_path: Path,
                                        monkeypatch) -> None:
        from core.run import scratch as scratch_mod
        src = self._src(tmp_path)

        def _boom(*a: Any, **kw: Any) -> None:
            raise cco.ComposeError("rewrite failed")

        monkeypatch.setattr(cco, "_rewrite_ports_in_place", _boom)
        with pytest.raises(cco.ComposeError):
            cco.rewrite_for_localhost(src / "docker-compose.yml")
        assert scratch_mod._keepalive_paths == set()


# -- device allowlist (S: raw host devices must never map into a stack) --------


class TestDeviceFilter:
    """The allowlist must hold under lexical evasion: /dev/fd is a
    symlinked dir, so a ``..`` traversal through it reaches raw host
    disks while satisfying a naive prefix match."""

    def _kept(self, devices: list[Any]) -> list[Any]:
        spec: dict[str, Any] = {"devices": list(devices)}
        cco._filter_devices(spec)
        return spec.get("devices", [])

    def test_safe_pseudo_devices_kept(self) -> None:
        kept = self._kept([
            "/dev/null:/dev/null",
            "/dev/urandom:/dev/urandom:r",
            {"source": "/dev/zero", "target": "/dev/zero"},
            "/dev/fd/1:/dev/fd/1",
        ])
        assert len(kept) == 4

    def test_traversal_through_dev_fd_dropped(self) -> None:
        assert self._kept(["/dev/fd/../../../dev/sda:/dev/sda:rwm"]) == []
        assert self._kept(
            [{"source": "/dev/fd/../../../dev/nvme0n1", "target": "/dev/x"}]
        ) == []

    def test_prefix_lookalikes_dropped(self) -> None:
        # Exact match only: "/dev/nullXYZ" passed the old startswith.
        assert self._kept(["/dev/nullXYZ:/dev/n"]) == []
        assert self._kept(["/dev/fd/notdigit:/dev/x"]) == []
        assert self._kept(["/dev/sda:/dev/sda"]) == []

    def test_kept_sources_are_forwarded_normalized(self) -> None:
        # dockerd resolves ".." THROUGH symlinks, so a raw
        # "/dev/fd/0/../1" names a different object than its lexical
        # form — only the normalized spelling may be forwarded.
        assert self._kept(["/dev/fd/0/../1:/dev/x:rwm"]) == \
            ["/dev/fd/1:/dev/x:rwm"]
        assert self._kept(
            [{"source": "/dev/fd/0/../1", "target": "/dev/n"}]
        ) == [{"source": "/dev/fd/1", "target": "/dev/n"}]
        # POSIX normpath preserves a leading "//" (implementation-
        # defined root), so the double-slash spelling stays dropped —
        # fail closed rather than guess the platform's semantics.
        assert self._kept(["//dev//null:/dev/n"]) == []

    def test_fd_children_must_be_ascii_digits(self) -> None:
        # str.isdigit() admits Unicode digit codepoints; the daemon
        # has no such fd entries — refuse rather than probe.
        assert self._kept(["/dev/fd/١:/dev/x"]) == []

    def test_allow_all_passthrough(self) -> None:
        spec: dict[str, Any] = {"devices": ["/dev/sda:/dev/sda"]}
        cco._filter_devices(spec, allow_all=True)
        assert spec["devices"] == ["/dev/sda:/dev/sda"]


# -- staging failure paths (decode errors, copy budget) ------------------------


def test_gated_document_decode_error_is_compose_error(tmp_path: Path) -> None:
    bad = tmp_path / "docker-compose.yml"
    bad.write_bytes(b"services:\n  a:\n    image: x\xff\n")
    with pytest.raises(cco.ComposeError, match="not valid UTF-8"):
        cco._load_gated_document(bad, what="file")


def test_staging_budget_refuses_oversized_source(
    tmp_path: Path, monkeypatch,
) -> None:
    src = tmp_path / "proj"
    src.mkdir()
    (src / "docker-compose.yml").write_text("services: {}\n")
    (src / "blob.bin").write_bytes(b"x" * 4096)
    monkeypatch.setattr(cco, "_STAGING_MAX_BYTES", 1024)
    with pytest.raises(cco.ComposeError, match="staging budget"):
        cco._require_stageable_size(src)
    # Direction 2: under budget passes silently.
    monkeypatch.setattr(cco, "_STAGING_MAX_BYTES", 1 << 20)
    cco._require_stageable_size(src)


# -- bind-source TOCTOU (writable-bind overlap) -------------------------------
# Sanitize-time realpath approves a bind source; dockerd re-resolves it
# at every container START (and restart). A service with a writable
# bind of a staging directory can therefore swap a path component for a
# symlink after approval, steering a nested bind at a host path when
# its container starts later. The stack-wide overlap pass refuses the
# enabling layouts.


def test_bind_under_cross_service_writable_bind_refused(tmp_path: Path) -> None:
    """The demonstrated sequence: A binds the staging root rw, plants
    staging/link -> /, B (ordered after A) binds ./link/etc — the
    daemon would mount host /etc into B."""
    with pytest.raises(cco.ComposeError, match="writable bind"):
        _sanitize(tmp_path, {
            "services": {
                "planter": {"image": "x", "volumes": [".:/staging:rw"]},
                "victim": {
                    "image": "y",
                    "depends_on": {
                        "planter": {"condition": "service_healthy"}},
                    "volumes": ["./link/etc:/host-etc"],
                },
            },
        })


def test_bind_under_cross_service_writable_dict_bind_refused(
    tmp_path: Path,
) -> None:
    (tmp_path / "www").mkdir()
    with pytest.raises(cco.ComposeError, match="writable bind"):
        _sanitize(tmp_path, {
            "services": {
                "a": {"image": "x", "volumes": [
                    {"type": "bind", "source": "./www", "target": "/w"}]},
                "b": {"image": "y", "volumes": ["./www/html:/h:ro"]},
            },
        })


def test_bind_under_readonly_parent_kept(tmp_path: Path) -> None:
    """A read-only parent bind grants no write channel — no TOCTOU."""
    (tmp_path / "www" / "html").mkdir(parents=True)
    doc = _sanitize(tmp_path, {
        "services": {
            "a": {"image": "x", "volumes": ["./www:/w:ro"]},
            "b": {"image": "y", "volumes": ["./www/html:/h"]},
        },
    })
    assert "./www:/w:ro" in doc["services"]["a"]["volumes"]
    assert "./www/html:/h" in doc["services"]["b"]["volumes"]


def test_disjoint_and_equal_bind_sources_kept(tmp_path: Path) -> None:
    """Equal sources and disjoint siblings cannot be re-pointed: a
    writable bind grants writes INSIDE its source, and replacing the
    source itself needs write access to its parent."""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    doc = _sanitize(tmp_path, {
        "services": {
            "one": {"image": "x", "volumes": ["./a:/a", "./b:/b:ro"]},
            "two": {"image": "y", "volumes": ["./a:/shared:ro"]},
        },
    })
    assert "./a:/a" in doc["services"]["one"]["volumes"]
    assert "./a:/shared:ro" in doc["services"]["two"]["volumes"]


def test_same_service_overlap_without_restart_kept(tmp_path: Path) -> None:
    """One service binding both ./www rw and a nested path has no
    TOCTOU on its own: its mounts are resolved before its own code
    runs, and nothing restarts it."""
    (tmp_path / "www" / "conf").mkdir(parents=True)
    doc = _sanitize(tmp_path, {
        "services": {
            "web": {"image": "x",
                    "volumes": ["./www:/w", "./www/conf:/c:ro"]},
        },
    })
    assert "./www:/w" in doc["services"]["web"]["volumes"]
    assert "./www/conf:/c:ro" in doc["services"]["web"]["volumes"]


def test_same_service_overlap_with_restart_refused(tmp_path: Path) -> None:
    """With a restart policy the single-service replay works: tamper,
    exit, the restart re-resolves the sibling mount through the
    planted symlink (verified live against dockerd)."""
    (tmp_path / "www" / "conf").mkdir(parents=True)
    with pytest.raises(cco.ComposeError, match="writable bind"):
        _sanitize(tmp_path, {
            "services": {
                "web": {"image": "x", "restart": "always",
                        "volumes": ["./www:/w", "./www/conf:/c:ro"]},
            },
        })


def test_secret_file_under_cross_service_writable_bind_refused(
    tmp_path: Path,
) -> None:
    """Non-swarm compose implements file-based secrets/configs as bind
    mounts re-resolved by the daemon at container start — the same
    swap channel as volumes. A secret file nesting under another
    service's writable bind must refuse like any other bind."""
    (tmp_path / "dir").mkdir()
    (tmp_path / "dir" / "tok").write_text("s")
    with pytest.raises(cco.ComposeError, match="writable bind"):
        _sanitize(tmp_path, {
            "services": {
                "a": {"image": "x", "volumes": ["./dir:/d"]},
                "b": {"image": "y", "secrets": ["s1"],
                      "depends_on": ["a"]},
            },
            "secrets": {"s1": {"file": "./dir/tok"}},
        })


def test_config_attachment_dict_form_under_writable_bind_refused(
    tmp_path: Path,
) -> None:
    (tmp_path / "dir").mkdir()
    (tmp_path / "dir" / "cfg").write_text("c")
    with pytest.raises(cco.ComposeError, match="writable bind"):
        _sanitize(tmp_path, {
            "services": {
                "a": {"image": "x", "volumes": ["./dir:/d"]},
                "b": {"image": "y",
                      "configs": [{"source": "c1", "target": "/c"}]},
            },
            "configs": {"c1": {"file": "./dir/cfg"}},
        })


def test_secret_file_outside_writable_binds_kept(tmp_path: Path) -> None:
    (tmp_path / "dir").mkdir()
    (tmp_path / "sec").mkdir()
    (tmp_path / "sec" / "tok").write_text("s")
    doc = _sanitize(tmp_path, {
        "services": {
            "a": {"image": "x", "volumes": ["./dir:/d"]},
            "b": {"image": "y", "secrets": ["s1"]},
        },
        "secrets": {"s1": {"file": "./sec/tok"}},
    })
    assert doc["secrets"]["s1"]["file"] == "./sec/tok"
    assert "s1" in doc["services"]["b"]["secrets"]


class TestNamedVolumeDiscriminator:
    """Any '/'-bearing volume source is a path, never a named volume
    (compose names are [a-zA-Z0-9._-]) — `foo/../x:/x` must take the
    bind lane so the staging containment does not depend on the
    sanitizer running post-resolution."""

    def test_relative_traversal_source_treated_as_bind(self, tmp_path: Path) -> None:
        kept = cco._filter_volumes(["foo/../../etc:/x"], tmp_path)
        assert kept == []

    def test_relative_inside_staging_bind_kept(self, tmp_path: Path) -> None:
        (tmp_path / "data").mkdir()
        kept = cco._filter_volumes(["data/sub/..:/x"], tmp_path)
        assert kept == ["data/sub/..:/x"]

    def test_named_volume_still_named(self, tmp_path: Path) -> None:
        kept = cco._filter_volumes(["pgdata:/var/lib/postgresql"], tmp_path)
        assert kept == ["pgdata:/var/lib/postgresql"]


class TestStagingEntryBudget:
    """Bytes alone miss the inode axis: millions of zero-byte files
    pass any byte cap while copytree exhausts tmpfs inodes."""

    def test_entry_flood_refused(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(cco, "_STAGING_MAX_ENTRIES", 10)
        src = tmp_path / "ctx"
        src.mkdir()
        for i in range(12):
            (src / f"z{i}").touch()  # zero bytes each
        with pytest.raises(cco.ComposeError, match="entry staging budget"):
            cco._require_stageable_size(src)

    def test_small_tree_passes(self, tmp_path: Path) -> None:
        src = tmp_path / "ctx"
        (src / "sub").mkdir(parents=True)
        (src / "sub" / "f").write_text("x")
        cco._require_stageable_size(src)  # no raise
