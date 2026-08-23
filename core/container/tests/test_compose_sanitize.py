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
    assert env["HOME"].startswith(str(tmp_path))  # throwaway, inside staging
    assert env["DOCKER_CONFIG"].startswith(env["HOME"])


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
    inspect_payload = (
        '{"nets":{"proj_default":{"IPAddress":"172.19.0.7"}},'
        '"exposed":{"80/tcp":{},"9999/tcp":{}}}'
    )

    from core.container.proc import RunOutcome
    with patch.object(cco, "run_cli",
                      return_value=RunOutcome(returncode=0,
                                              stdout=inspect_payload,
                                              stderr="",
                                              timed_out=False)):
        out = cco._with_container_endpoint(
            cco.ComposeContainer(service="web", container_id="cid",
                                 host_port=None, container_port=None))
    assert out.host_ip == "172.19.0.7"
    assert out.host_port == 80  # preferred HTTP-shaped port wins
    assert out.container_port == 80

    # Inspect failure leaves the container untouched (best-effort).
    with patch.object(cco, "run_cli",
                      return_value=RunOutcome(returncode=1, stdout="",
                                              stderr="no such object",
                                              timed_out=False)):
        out = cco._with_container_endpoint(
            cco.ComposeContainer(service="web", container_id="cid",
                                 host_port=None, container_port=None))
    assert out.host_port is None and out.host_ip == "127.0.0.1"


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
