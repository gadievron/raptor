"""Tests for the project-platform-matrix discovery."""

from __future__ import annotations

from pathlib import Path

from packages.sca.platform_matrix import (
    discover_platform_matrix,
)
from packages.sca.platform_matrix.glibc_db import (
    LibcVersion,
    lookup_distro_libc,
    lookup_runner_libc,
)


# ---------------------------------------------------------------------------
# glibc_db
# ---------------------------------------------------------------------------

def test_lookup_distro_debian_bookworm() -> None:
    assert lookup_distro_libc("debian:bookworm") == \
        LibcVersion("glibc", (2, 36))


def test_lookup_python_image_extracts_codename() -> None:
    """The canonical devcontainer base shape:
    ``python:3.12-bookworm`` → glibc 2.36 via bookworm codename."""
    assert lookup_distro_libc("python:3.12-bookworm") == \
        LibcVersion("glibc", (2, 36))


def test_lookup_python_slim_extracts_codename() -> None:
    assert lookup_distro_libc("python:3.13-slim-bookworm") == \
        LibcVersion("glibc", (2, 36))


def test_lookup_python_alpine_extracts_musl() -> None:
    assert lookup_distro_libc("python:3.13-alpine3.19") == \
        LibcVersion("musl", (1, 2, 4))


def test_lookup_unknown_returns_none() -> None:
    assert lookup_distro_libc("photon:5.0") is None


def test_lookup_runner_ubuntu_22_04() -> None:
    assert lookup_runner_libc("ubuntu-22.04") == \
        LibcVersion("glibc", (2, 35))


# ---------------------------------------------------------------------------
# discover_platform_matrix
# ---------------------------------------------------------------------------

def _arch_libc(matrix) -> set:
    """Helper: extract (arch, libc) tuples from a matrix."""
    out = set()
    for p in matrix:
        out.add((p.arch, p.libc))
    return out


def test_discover_default_when_no_signals(tmp_path: Path) -> None:
    matrix = discover_platform_matrix(tmp_path)
    pairs = _arch_libc(matrix)
    # Fallback: x86_64 + glibc 2.17.
    assert ("x86_64", LibcVersion("glibc", (2, 17))) in pairs


def test_discover_dockerfile_bookworm_multi_arch(tmp_path: Path) -> None:
    """A bookworm-based Dockerfile yields BOTH x86_64 and
    aarch64 pairs because the image is multi-arch by convention."""
    (tmp_path / "Dockerfile").write_text("FROM python:3.13-bookworm\n")
    matrix = discover_platform_matrix(tmp_path)
    pairs = _arch_libc(matrix)
    assert ("x86_64", LibcVersion("glibc", (2, 36))) in pairs
    assert ("aarch64", LibcVersion("glibc", (2, 36))) in pairs


def test_discover_platform_flag_constrains_arch(tmp_path: Path) -> None:
    """``FROM --platform=linux/amd64 python:3.13-bookworm`` →
    only x86_64, not multi-arch."""
    (tmp_path / "Dockerfile").write_text(
        "FROM --platform=linux/amd64 python:3.13-bookworm\n"
    )
    matrix = discover_platform_matrix(tmp_path)
    arches = {p.arch for p in matrix}
    assert arches == {"x86_64"}


def test_discover_skips_stage_reuse(tmp_path: Path) -> None:
    """Multi-stage ``FROM build AS runtime`` (where ``build`` is
    a prior stage name) shouldn't produce a platform pair."""
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.13-bookworm AS build\n"
        "RUN do-build\n"
        "FROM build AS runtime\n"
    )
    matrix = discover_platform_matrix(tmp_path)
    sources = [p.source for p in matrix]
    # Only one FROM emission (python:3.13-bookworm).
    assert sum(1 for s in sources if "build" in s and ":" not in s) == 0


def test_discover_devcontainer_image(tmp_path: Path) -> None:
    devcontainer = tmp_path / ".devcontainer"
    devcontainer.mkdir()
    (devcontainer / "devcontainer.json").write_text(
        '{\n  "image": "mcr.microsoft.com/'
        'devcontainers/python:1-3.12-bookworm"\n}\n'
    )
    matrix = discover_platform_matrix(tmp_path)
    libcs = {p.libc for p in matrix}
    assert LibcVersion("glibc", (2, 36)) in libcs


def test_discover_devcontainer_tolerates_comments(
    tmp_path: Path,
) -> None:
    """devcontainer.json is technically JSONC (comments allowed)."""
    devcontainer = tmp_path / ".devcontainer"
    devcontainer.mkdir()
    (devcontainer / "devcontainer.json").write_text(
        '// devcontainer.json — comments and trailing'
        ' commas are allowed\n'
        '{\n'
        '  "image": "python:3.13-bookworm" // some note\n'
        '}\n'
    )
    matrix = discover_platform_matrix(tmp_path)
    libcs = {p.libc for p in matrix}
    assert LibcVersion("glibc", (2, 36)) in libcs


def test_discover_gha_runs_on_ubuntu(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "name: ci\n"
        "on: push\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-22.04\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    matrix = discover_platform_matrix(tmp_path)
    libcs = {p.libc for p in matrix}
    assert LibcVersion("glibc", (2, 35)) in libcs


def test_discover_gha_matrix_strategy_multiple_runners(
    tmp_path: Path,
) -> None:
    """``runs-on: ${{ matrix.os }}`` + ``matrix.os: [ubuntu-22.04,
    ubuntu-24.04]`` → both libc versions emitted."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "jobs:\n"
        "  test:\n"
        "    runs-on: ${{ matrix.os }}\n"
        "    strategy:\n"
        "      matrix:\n"
        "        os: [ubuntu-22.04, ubuntu-24.04]\n"
    )
    matrix = discover_platform_matrix(tmp_path)
    libcs = {p.libc for p in matrix}
    assert LibcVersion("glibc", (2, 35)) in libcs
    assert LibcVersion("glibc", (2, 39)) in libcs


def test_discover_excludes_out_directories(tmp_path: Path) -> None:
    """Dockerfiles inside ``out/`` / ``node_modules/`` / ``.venv/``
    are SCA / build outputs — skip."""
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "Dockerfile").write_text(
        "FROM python:3.13-trixie\n"
    )
    (tmp_path / "Dockerfile").write_text("FROM python:3.13-bookworm\n")
    matrix = discover_platform_matrix(tmp_path)
    libcs = {p.libc for p in matrix}
    assert LibcVersion("glibc", (2, 36)) in libcs
    assert LibcVersion("glibc", (2, 39)) not in libcs


# ---------------------------------------------------------------------------
# buildx bake configs
# ---------------------------------------------------------------------------

def test_discover_bake_hcl_single_target(tmp_path: Path) -> None:
    """A docker-bake.hcl with a single target's multi-arch
    platforms list contributes those arches to the matrix."""
    (tmp_path / "docker-bake.hcl").write_text('''\
target "default" {
  platforms = ["linux/amd64", "linux/arm64", "linux/arm/v7"]
}
''')
    matrix = discover_platform_matrix(tmp_path)
    arches = {p.arch for p in matrix}
    assert "x86_64" in arches
    assert "aarch64" in arches
    assert "armv7l" in arches


def test_discover_bake_hcl_multiline(tmp_path: Path) -> None:
    """Multi-line ``platforms = [...]`` list with comments is
    handled — operators format bake configs verbosely."""
    (tmp_path / "docker-bake.hcl").write_text('''\
target "release" {
  platforms = [
    "linux/amd64",        // x86 servers
    "linux/arm64",        // graviton / apple silicon
    "linux/ppc64le",
  ]
}
''')
    matrix = discover_platform_matrix(tmp_path)
    arches = {p.arch for p in matrix}
    assert "x86_64" in arches
    assert "aarch64" in arches
    assert "ppc64le" in arches


def test_discover_bake_hcl_multiple_targets(tmp_path: Path) -> None:
    """Each ``target`` block contributes its own platforms;
    set-based dedup means overlap is free."""
    (tmp_path / "docker-bake.hcl").write_text('''\
target "amd64-only" {
  platforms = ["linux/amd64"]
}
target "release" {
  platforms = ["linux/amd64", "linux/arm64", "linux/s390x"]
}
''')
    matrix = discover_platform_matrix(tmp_path)
    arches = {p.arch for p in matrix}
    assert "x86_64" in arches
    assert "aarch64" in arches
    assert "s390x" in arches


def test_discover_bake_json(tmp_path: Path) -> None:
    """JSON variant — same semantics, structured shape."""
    (tmp_path / "docker-bake.json").write_text('''\
{
  "target": {
    "default": {
      "platforms": ["linux/amd64", "linux/arm64"]
    },
    "extra": {
      "platforms": ["linux/386"]
    }
  }
}
''')
    matrix = discover_platform_matrix(tmp_path)
    arches = {p.arch for p in matrix}
    assert "x86_64" in arches
    assert "aarch64" in arches
    assert "i686" in arches


def test_discover_bake_malformed_json_does_not_crash(tmp_path: Path) -> None:
    """Operator typo → broken JSON. Walker logs + moves on; other
    signals still register normally."""
    (tmp_path / "docker-bake.json").write_text('{"target": {broken')
    (tmp_path / "Dockerfile").write_text("FROM python:3.13-bookworm\n")
    matrix = discover_platform_matrix(tmp_path)
    # Dockerfile still contributed; the broken bake didn't kill anything.
    libcs = {p.libc for p in matrix}
    assert LibcVersion("glibc", (2, 36)) in libcs


def test_discover_bake_override_layered_on(tmp_path: Path) -> None:
    """``docker-bake.override.hcl`` ADDS to the base config (set
    union semantics)."""
    (tmp_path / "docker-bake.hcl").write_text('''\
target "default" {
  platforms = ["linux/amd64"]
}
''')
    (tmp_path / "docker-bake.override.hcl").write_text('''\
target "default" {
  platforms = ["linux/arm64"]
}
''')
    matrix = discover_platform_matrix(tmp_path)
    arches = {p.arch for p in matrix}
    assert "x86_64" in arches
    assert "aarch64" in arches


# ---------------------------------------------------------------------------
# GHA docker/build-push-action step input
# ---------------------------------------------------------------------------

def test_discover_gha_build_push_action_platforms(tmp_path: Path) -> None:
    """``docker/build-push-action`` with explicit ``platforms:`` is
    the dominant modern multi-arch release pipeline. Walker lifts
    the arches into the matrix even when ``runs-on:`` is just
    ubuntu-latest (x86_64 runner + QEMU emulation for arm64)."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "release.yml").write_text('''\
name: release
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker/setup-qemu-action@v3
      - uses: docker/setup-buildx-action@v3
      - uses: docker/build-push-action@v5
        with:
          context: .
          platforms: linux/amd64,linux/arm64
          push: true
''')
    matrix = discover_platform_matrix(tmp_path)
    arches = {p.arch for p in matrix}
    assert "aarch64" in arches, (
        f"build-push-action's arm64 missed; got {arches}"
    )


def test_discover_gha_build_push_action_inline_list(tmp_path: Path) -> None:
    """YAML inline-list variant: ``platforms: [linux/amd64, linux/arm64]``."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "release.yml").write_text('''\
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker/build-push-action@v5
        with:
          platforms: [linux/amd64, linux/arm64, linux/arm/v7]
''')
    matrix = discover_platform_matrix(tmp_path)
    arches = {p.arch for p in matrix}
    assert {"x86_64", "aarch64", "armv7l"}.issubset(arches), (
        f"missed an inline-list arch; got {arches}"
    )


def test_discover_gha_build_push_skips_variable_refs(tmp_path: Path) -> None:
    """``platforms: ${{ matrix.platforms }}`` — operator-driven
    template. We can't resolve the variable; skip gracefully."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "release.yml").write_text('''\
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker/build-push-action@v5
        with:
          platforms: ${{ matrix.platforms }}
''')
    # Should not crash; no aarch64 (variable couldn't be resolved)
    matrix = discover_platform_matrix(tmp_path)
    # Default x86_64 still contributed via runs-on parsing
    arches = {p.arch for p in matrix}
    assert "x86_64" in arches


def test_discover_gha_build_push_two_steps(tmp_path: Path) -> None:
    """Two separate build-push-action steps in one workflow each
    contribute their own platforms (set dedup combines)."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "release.yml").write_text('''\
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker/build-push-action@v5
        with:
          platforms: linux/amd64
      - run: echo "between steps"
      - uses: docker/build-push-action@v5
        with:
          platforms: linux/arm64,linux/ppc64le
''')
    matrix = discover_platform_matrix(tmp_path)
    arches = {p.arch for p in matrix}
    assert {"x86_64", "aarch64", "ppc64le"}.issubset(arches)


# ---------------------------------------------------------------------------
# Combined: Dockerfile + GHA build-push-action
# ---------------------------------------------------------------------------

def test_dockerfile_platform_amd64_only_overridden_by_gha(tmp_path: Path) -> None:
    """The classic bite: Dockerfile says ``--platform=linux/amd64``
    (operator intent: only x86_64), but the GHA pipeline actually
    builds for arm64 too via buildx. Our matrix should reflect the
    GHA's truth — the deployment target."""
    (tmp_path / "Dockerfile").write_text(
        "FROM --platform=linux/amd64 python:3.13-bookworm\n"
    )
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "release.yml").write_text('''\
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker/build-push-action@v5
        with:
          platforms: linux/amd64,linux/arm64
''')
    matrix = discover_platform_matrix(tmp_path)
    arches = {p.arch for p in matrix}
    # Dockerfile contributed x86_64+glibc 2.36 (the libc-resolved
    # entry). build-push-action additionally contributed aarch64
    # (with libc=None — the wheel-compat layer treats it as
    # "no libc constraint").
    assert "x86_64" in arches
    assert "aarch64" in arches, (
        f"missed aarch64 from build-push-action override; arches={arches}"
    )
