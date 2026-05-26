"""Tests for base-image → Debian suite resolution and its attribution to
apt deps parsed from a Dockerfile."""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.sca.parsers.inline_installs import _extract_apt_via_core_dockerfile
from packages.sca.parsers.inline_installs._base_image_suite import (
    debian_suite_from_image,
    stage_image_map,
)
from core.dockerfile import parse_dockerfile


@pytest.mark.parametrize("ref,expected", [
    ("debian:bookworm", "bookworm"),
    ("debian:bookworm-slim", "bookworm"),
    ("debian:bookworm-backports", "bookworm"),
    ("debian:12", "bookworm"),                 # permanent number map
    ("debian:11", "bullseye"),
    ("debian:stable", "stable"),               # alias passes through
    ("debian:sid", "sid"),
    ("debian", "stable"),                      # bare = current stable
    ("debian:latest", "stable"),
    # Debian-derived images carry the codename in the tag.
    ("python:3.12-bookworm-slim", "bookworm"),
    ("node:20-bullseye", "bullseye"),
    ("docker.io/library/debian:trixie", "trixie"),
    ("myreg.example.com:5000/debian:bookworm", "bookworm"),
    ("debian:bookworm@sha256:abc123", "bookworm"),
    # Not a determinable Debian suite -> None (caller skips, never guesses).
    ("ubuntu:22.04", None),
    ("ubuntu:jammy", None),                    # Ubuntu codename, not Debian
    ("alpine:3.19", None),
    ("scratch", None),
    ("python:3.12", None),                     # Debian-based but tag is silent
    ("", None),
])
def test_debian_suite_from_image(ref, expected) -> None:
    assert debian_suite_from_image(ref) == expected


def test_stage_image_map_follows_from_stage_chains() -> None:
    text = (
        "FROM debian:bookworm AS builder\n"
        "RUN apt-get install -y gcc\n"
        "FROM builder AS final\n"
        "RUN apt-get install -y nginx\n"
        "FROM alpine\n"
    )
    m = stage_image_map(parse_dockerfile(text))
    assert m["builder"] == "debian:bookworm"
    assert m["final"] == "debian:bookworm"     # final -> builder -> image
    assert m[None] == "alpine"                 # the AS-less FROM


def test_apt_dep_carries_governing_base_image_suite() -> None:
    text = (
        "FROM debian:bookworm-slim\n"
        "RUN apt-get install -y nginx=1.22.1-9+deb12u6 curl\n"
    )
    deps = _extract_apt_via_core_dockerfile(text, Path("/x/Dockerfile"))
    assert deps, "expected apt deps extracted"
    for d in deps:
        assert d.ecosystem == "Debian"
        assert d.source_extra == {
            "base_image": "debian:bookworm-slim", "suite": "bookworm",
        }


def test_apt_dep_from_non_debian_base_has_no_suite() -> None:
    """An apt-get on an Ubuntu base resolves suite=None — harden won't pin
    it (we have no Ubuntu version data)."""
    text = "FROM ubuntu:22.04\nRUN apt-get install -y nginx\n"
    deps = _extract_apt_via_core_dockerfile(text, Path("/x/Dockerfile"))
    assert deps
    for d in deps:
        assert d.source_extra == {"base_image": "ubuntu:22.04", "suite": None}


def test_multistage_runtime_vs_builder_suites() -> None:
    """Each apt dep is attributed to its own stage's base image."""
    text = (
        "FROM debian:bullseye AS build\n"
        "RUN apt-get install -y build-essential\n"
        "FROM debian:bookworm\n"
        "RUN apt-get install -y nginx\n"
    )
    deps = _extract_apt_via_core_dockerfile(text, Path("/x/Dockerfile"))
    by_name = {d.name: d for d in deps}
    assert by_name["build-essential"].source_extra["suite"] == "bullseye"
    assert by_name["nginx"].source_extra["suite"] == "bookworm"
