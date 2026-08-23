"""Contract tests for core.env.spec + core.env.store."""

from __future__ import annotations

import json

import pytest

from core.env.spec import (
    SPEC_VERSION,
    BuildSpec,
    EnvironmentSpec,
    NetworkPolicy,
    RunSpec,
    SourceSpec,
    ToolchainSpec,
)
from core.env.store import (
    RUN_SPEC_FILENAME,
    SpecStore,
    load_run_spec,
    save_run_spec,
)


def _spec(name: str = "redis-7.0") -> EnvironmentSpec:
    return EnvironmentSpec(
        name=name,
        version="7.0.11",
        cve_id="CVE-2023-0001",
        source=SourceSpec(kind="image",
                          image_ref="redis@sha256:" + "a" * 64),
        build=BuildSpec(command="make -j4",
                        toolchain=ToolchainSpec(cc="gcc-12",
                                                cflags=("-O2", "-g"),
                                                debug=True)),
        run=RunSpec(surface="tcp", port=6379,
                    env=(("REDIS_ARGS", "--save ''"),)),
        network=NetworkPolicy(egress_hosts=("registry.example",)),
        verify_plan=[{"type": "tcp_probe_check", "send_text": "PING\r\n",
                      "expected_response_contains": "PONG"}],
        markers={"banner": "Redis"},
        notes="pre-patch build",
    )


def test_roundtrip_through_json() -> None:
    spec = _spec()
    again = EnvironmentSpec.from_json(spec.to_json())
    assert again == spec
    assert again.spec_version == SPEC_VERSION
    assert again.build.toolchain.cflags == ("-O2", "-g")
    assert again.run.env_dict() == {"REDIS_ARGS": "--save ''"}


def test_env_serializes_as_dict_on_disk() -> None:
    d = _spec().to_dict()
    assert d["run"]["env"] == {"REDIS_ARGS": "--save ''"}


def test_from_dict_tolerates_unknown_keys() -> None:
    d = _spec().to_dict()
    d["future_field"] = {"x": 1}
    d["source"]["future_sub"] = True
    spec = EnvironmentSpec.from_dict(d)
    assert spec.name == "redis-7.0"


def test_name_required() -> None:
    with pytest.raises(ValueError):
        EnvironmentSpec.from_dict({"version": "1"})


def test_run_spec_roundtrip_on_disk(tmp_path) -> None:
    spec = _spec()
    path = save_run_spec(spec, tmp_path)
    assert path.name == RUN_SPEC_FILENAME
    assert json.loads(path.read_text())["name"] == "redis-7.0"
    assert load_run_spec(tmp_path) == spec
    assert load_run_spec(tmp_path / "empty") is None


def test_library_store_slugs_and_lists(tmp_path) -> None:
    store = SpecStore(tmp_path / "env-specs")
    assert store.names() == []
    store.save(_spec("Redis 7.0 (pre-patch)"))
    store.save(_spec("nginx-1.25"))
    assert store.names() == ["nginx-1.25", "redis-7.0-pre-patch"]
    loaded = store.load("Redis 7.0 (pre-patch)")
    assert loaded is not None and loaded.version == "7.0.11"
    assert store.load("absent") is None


def test_slug_rejects_empty_and_traversal_shapes(tmp_path) -> None:
    store = SpecStore(tmp_path)
    with pytest.raises(ValueError):
        store.path_for("///")
    # Traversal characters collapse into safe dashes inside one dir.
    p = store.path_for("../../etc/passwd")
    assert p.parent == tmp_path
    assert ".." not in p.name


def test_network_policy_mode_round_trips_and_defaults_isolated() -> None:
    """mode is additive: old specs (no field) deserialize to the
    fail-closed default; explicit values survive the round trip."""
    assert NetworkPolicy().mode == "isolated"
    assert NetworkPolicy.from_dict({}).mode == "isolated"
    spec = EnvironmentSpec(
        name="x", network=NetworkPolicy(mode="unrestricted"))
    reloaded = EnvironmentSpec.from_json(spec.to_json())
    assert reloaded.network.mode == "unrestricted"
