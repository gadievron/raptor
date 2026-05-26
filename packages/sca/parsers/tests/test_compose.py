"""Tests for the docker-compose parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.sca.parsers.compose import (
    _is_compose_file,
    _split_image_ref,
    parse,
)


pytest.importorskip("yaml")


def _write(tmp_path: Path, content: str, name: str = "docker-compose.yml") -> Path:
    p = tmp_path / name
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# _is_compose_file
# ---------------------------------------------------------------------------


def test_is_compose_file_canonical():
    assert _is_compose_file(Path("docker-compose.yml"))
    assert _is_compose_file(Path("docker-compose.yaml"))
    assert _is_compose_file(Path("compose.yml"))
    assert _is_compose_file(Path("compose.yaml"))


def test_is_compose_file_overlay():
    """``docker-compose.dev.yml`` and ``compose.prod.yaml`` —
    operator overlay convention."""
    assert _is_compose_file(Path("docker-compose.dev.yml"))
    assert _is_compose_file(Path("compose.prod.yaml"))


def test_is_compose_file_case_insensitive():
    assert _is_compose_file(Path("DOCKER-COMPOSE.YML"))


def test_is_compose_file_rejects_unrelated():
    assert not _is_compose_file(Path("config.yml"))
    assert not _is_compose_file(Path("settings.yaml"))


# ---------------------------------------------------------------------------
# Image extraction
# ---------------------------------------------------------------------------


def test_simple_services(tmp_path):
    p = _write(tmp_path, """\
services:
  db:
    image: postgres:16-alpine
  cache:
    image: redis:7.2-alpine
""")
    deps = parse(p)
    by_name = {d.name: d for d in deps}
    assert "postgres" in by_name
    assert "redis" in by_name
    assert by_name["postgres"].version == "16-alpine"
    assert by_name["postgres"].ecosystem == "OCI"
    assert by_name["postgres"].source_kind == "compose"
    assert by_name["postgres"].purl == "pkg:oci/postgres@16-alpine"
    assert by_name["postgres"].source_extra["service"] == "db"
    assert by_name["postgres"].source_extra["image_ref"] == "postgres:16-alpine"


def test_service_with_build_only_skipped(tmp_path):
    """``build:`` without ``image:`` is a local-build service —
    not a registry pull."""
    p = _write(tmp_path, """\
services:
  app:
    build: ./app
""")
    assert parse(p) == []


def test_image_with_registry_prefix(tmp_path):
    p = _write(tmp_path, """\
services:
  worker:
    image: ghcr.io/myorg/worker:v2.1.0
""")
    [d] = parse(p)
    assert d.name == "ghcr.io/myorg/worker"
    assert d.version == "v2.1.0"


def test_image_without_tag(tmp_path):
    p = _write(tmp_path, """\
services:
  vague:
    image: alpine
""")
    [d] = parse(p)
    assert d.name == "alpine"
    assert d.version is None


def test_image_with_digest_pin(tmp_path):
    sha = "sha256:" + "a" * 64
    p = _write(tmp_path, f"""\
services:
  pinned:
    image: postgres@{sha}
""")
    [d] = parse(p)
    assert d.name == "postgres"
    assert d.version == sha


def test_image_with_port_in_registry(tmp_path):
    """``localhost:5000/myimg:v1`` — registry has a port; tag is
    after the LAST colon following a slash."""
    p = _write(tmp_path, """\
services:
  local:
    image: localhost:5000/myimg:v1
""")
    [d] = parse(p)
    assert d.name == "localhost:5000/myimg"
    assert d.version == "v1"


def test_no_services_block(tmp_path):
    p = _write(tmp_path, """\
version: '3'
volumes:
  data: {}
""")
    assert parse(p) == []


def test_malformed_yaml(tmp_path):
    p = _write(tmp_path, ":")
    assert parse(p) == []


# ---------------------------------------------------------------------------
# _split_image_ref
# ---------------------------------------------------------------------------


def test_split_simple():
    assert _split_image_ref("postgres:16") == ("postgres", "16")


def test_split_with_registry():
    assert _split_image_ref("ghcr.io/x/y:1.2") == ("ghcr.io/x/y", "1.2")


def test_split_no_tag():
    assert _split_image_ref("alpine") == ("alpine", None)


def test_split_digest_pin():
    sha = "sha256:" + "a" * 64
    assert _split_image_ref(f"foo@{sha}") == ("foo", sha)


def test_split_localhost_port():
    assert _split_image_ref(
        "localhost:5000/myimg:v1",
    ) == ("localhost:5000/myimg", "v1")


# ---------------------------------------------------------------------------
# Discovery integration
# ---------------------------------------------------------------------------


def test_discovery_finds_compose_files(tmp_path):
    from packages.sca.discovery import find_manifests
    _write(tmp_path, "services:\n  x:\n    image: foo:1\n")
    _write(
        tmp_path,
        "services:\n  y:\n    image: bar:1\n",
        name="compose.dev.yaml",
    )
    manifests = find_manifests(tmp_path)
    composes = [
        m for m in manifests
        if m.path.name in ("docker-compose.yml", "compose.dev.yaml")
    ]
    assert len(composes) == 2
    assert all(m.ecosystem == "OCI" for m in composes)


def test_fragment_file_skipped_quietly(tmp_path, caplog):
    """Fragment-shape compose files (no top-level ``services:``,
    first content line is indented) are silently skipped, not
    WARN-logged. Grafana's ``devenv/docker/blocks/*/docker-compose.yaml``
    files follow this pattern — they're meant to be ``include``d
    into a parent compose file. Surfaced by the May 2026
    200-project sweep against Grafana.
    """
    import logging
    from packages.sca.parsers.compose import parse
    p = tmp_path / "docker-compose.yaml"
    p.write_text(
        "  sensu-backend:\n"
        "    image: sensu/sensu:latest\n"
        "    ports:\n"
        "      - \"3080:3000\"\n",
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING):
        out = parse(p)
    assert out == []
    warn = [
        r for r in caplog.records
        if r.levelno >= logging.WARNING
        and "YAML parse failed" in r.getMessage()
    ]
    assert warn == [], (
        f"fragment compose file emitted WARN: "
        f"{[r.getMessage() for r in warn]}"
    )
