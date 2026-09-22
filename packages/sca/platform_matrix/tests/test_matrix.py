"""Tests for the project-platform-matrix discovery."""

from __future__ import annotations

import logging
from pathlib import Path

from packages.sca.platform_matrix import (
    discover_platform_matrix,
)
from packages.sca.platform_matrix.glibc_db import (
    LibcVersion,
    lookup_distro_libc,
    lookup_runner_libc,
)
from packages.sca.platform_matrix.matrix import (
    PlatformPair,
    ProjectPlatformMatrix,
    _walk_devcontainer,
)


# ---------------------------------------------------------------------------
# PlatformPair identity — source is diagnostic-only
# ---------------------------------------------------------------------------

def test_pair_identity_ignores_source() -> None:
    """Two pairs differing only in ``source`` are the same platform:
    equal AND hash-equal, so set membership dedups them. With source
    in the identity, N declaration sites of one (arch, libc) made N
    'distinct' pairs and the compat checker emitted N findings with
    identical finding_ids."""
    libc = LibcVersion("glibc", (2, 36))
    a = PlatformPair(arch="x86_64", libc=libc,
                     source="Dockerfile FROM debian:bookworm")
    b = PlatformPair(arch="x86_64", libc=libc,
                     source="GHA runs-on: ubuntu-22.04")
    assert a == b
    assert hash(a) == hash(b)


def test_matrix_dedups_same_pair_from_many_sources() -> None:
    """The matrix keeps ONE pair per genuine (arch, libc) combo and
    retains the FIRST-discovered source (set.add keeps the existing
    element on equality) so reports still say where it came from."""
    libc = LibcVersion("glibc", (2, 36))
    matrix = ProjectPlatformMatrix()
    matrix.add(PlatformPair(arch="x86_64", libc=libc,
                            source="first-seen"))
    matrix.add(PlatformPair(arch="x86_64", libc=libc,
                            source="later-duplicate"))
    assert len(matrix) == 1
    [pair] = matrix
    assert pair.source == "first-seen"


def test_pair_identity_still_distinguishes_real_axes() -> None:
    """compare=False on source must not collapse genuinely different
    platforms: arch, libc, and macos_version still participate."""
    libc = LibcVersion("glibc", (2, 36))
    base = PlatformPair(arch="x86_64", libc=libc, source="s")
    assert base != PlatformPair(arch="aarch64", libc=libc, source="s")
    assert base != PlatformPair(
        arch="x86_64", libc=LibcVersion("glibc", (2, 39)), source="s",
    )
    assert base != PlatformPair(
        arch="x86_64", libc=None, source="s", macos_version=(13, 0),
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


# ---------------------------------------------------------------------------
# _walk_devcontainer: unknown-libc visibility
# ---------------------------------------------------------------------------

def _write_devcontainer(tmp_path: Path, image: str) -> Path:
    p = tmp_path / "devcontainer.json"
    p.write_text('{"image": "%s"}' % image, encoding="utf-8")
    return p


def test_devcontainer_unknown_libc_logs_debug(tmp_path: Path, caplog) -> None:
    path = _write_devcontainer(tmp_path, "totally-unknown-image:v1")
    matrix = ProjectPlatformMatrix()
    with caplog.at_level(logging.DEBUG,
                         logger="packages.sca.platform_matrix.matrix"):
        _walk_devcontainer(path, matrix, tmp_path)
    assert any(
        "unknown libc" in rec.getMessage()
        for rec in caplog.records
    ), "devcontainer walker should log unknown-libc at DEBUG"


def test_devcontainer_unknown_libc_still_registers_pairs(
    tmp_path: Path,
) -> None:
    """Logging is visibility-only — an unknown image must still
    register the same pair set (both arches, libc=None)."""
    path = _write_devcontainer(tmp_path, "totally-unknown-image:v1")
    matrix = ProjectPlatformMatrix()
    _walk_devcontainer(path, matrix, tmp_path)
    assert len(matrix) == 2
    assert {p.arch for p in matrix} == {"x86_64", "aarch64"}
    assert all(p.libc is None for p in matrix)


def test_devcontainer_known_image_does_not_log_unknown(
    tmp_path: Path, caplog,
) -> None:
    path = _write_devcontainer(tmp_path, "debian:bookworm")
    matrix = ProjectPlatformMatrix()
    with caplog.at_level(logging.DEBUG,
                         logger="packages.sca.platform_matrix.matrix"):
        _walk_devcontainer(path, matrix, tmp_path)
    resolved = [p for p in matrix if p.libc is not None]
    if resolved:            # glibc DB knows bookworm
        assert not any(
            "unknown libc" in rec.getMessage()
            for rec in caplog.records
        )


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


def test_is_dockerfile_accepts_capital_d_suffix_variant() -> None:
    """``<variant>.Dockerfile`` is a name shape the other Dockerfile
    consumers in this package accept — the platform-matrix discovery
    pass must recognise it too, alongside the existing forms."""
    from packages.sca.platform_matrix.matrix import _is_dockerfile

    assert _is_dockerfile(Path("base.Dockerfile"))
    assert _is_dockerfile(Path("Dockerfile"))
    assert _is_dockerfile(Path("Dockerfile.slim"))
    assert _is_dockerfile(Path("app.dockerfile"))
    assert not _is_dockerfile(Path("dockerfile_notes.md"))


# ---------------------------------------------------------------------------
# Discovery reads are containment-checked (never follow escapes)
# ---------------------------------------------------------------------------

def test_walk_dockerfile_refuses_symlink_escape(tmp_path: Path) -> None:
    """A symlinked Dockerfile resolving outside the scanned target
    must be refused — the discovery pass previously read it bare
    (symlink-following, unbounded), unlike every parser in the
    package."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "Dockerfile").write_text(
        "FROM debian:bookworm\n", encoding="utf-8")
    target = tmp_path / "repo"
    target.mkdir()
    link = target / "Dockerfile"
    link.symlink_to(outside / "Dockerfile")

    from packages.sca.platform_matrix.matrix import _walk_dockerfile
    matrix = ProjectPlatformMatrix()
    _walk_dockerfile(link, matrix, target)
    assert len(matrix) == 0


def test_devcontainer_dockerfile_reference_cannot_escape_target(
    tmp_path: Path,
) -> None:
    """A hostile devcontainer.json "build.dockerfile" pointing above
    the target must not pull out-of-tree files into discovery."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "Dockerfile").write_text(
        "FROM debian:bookworm\n", encoding="utf-8")
    target = tmp_path / "repo"
    (target / ".devcontainer").mkdir(parents=True)
    (target / ".devcontainer" / "devcontainer.json").write_text(
        '{"build": {"dockerfile": "../../outside/Dockerfile"}}',
        encoding="utf-8",
    )
    from packages.sca.platform_matrix.matrix import discover_platform_matrix
    matrix = discover_platform_matrix(target)
    # Only the no-signal default may appear — never bookworm pairs
    # sourced from the out-of-tree Dockerfile.
    assert not any("Dockerfile" in p.source for p in matrix)


def test_walk_gha_refuses_symlinked_workflow(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "ci.yml").write_text(
        "jobs:\n  a:\n    runs-on: ubuntu-22.04\n", encoding="utf-8")
    target = tmp_path / "repo"
    wfdir = target / ".github" / "workflows"
    wfdir.mkdir(parents=True)
    (wfdir / "ci.yml").symlink_to(outside / "ci.yml")

    from packages.sca.platform_matrix.matrix import _walk_gha_workflows
    matrix = ProjectPlatformMatrix()
    _walk_gha_workflows(target, matrix)
    assert len(matrix) == 0


def test_blank_line_run_is_fast(tmp_path: Path) -> None:
    """Hostile Dockerfile + workflow carrying blank-line RUNS the
    greedy span cannot hand to a match: under the MULTILINE ``^``
    anchor a ``\\s*`` indent matched at every line start inside a run
    and re-scanned the remainder per anchor — quadratic (and the
    build-push uses-line's adjacent ``^\\s*-?\\s*`` pair hung outright
    on 16KB). Horizontal-only indent is linear. Both-direction bound:
    fast AND the files' real signals still discover."""
    import time

    run = "\n" * (1 << 17)
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.13-bookworm\nRUN echo hi\n" + run + "# end\n")
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    # The single-line SPACE run guards the uses-line pattern's other
    # hostile shape: two adjacent unbounded spans backtrack
    # quadratically on horizontal runs too, so the optional ``-``
    # span must live behind the literal ``-``.
    (wf_dir / "ci.yml").write_text(
        "jobs:\n  build:\n"
        "    runs-on: ubuntu-22.04\n"
        "    steps:\n"
        "      - uses: docker/build-push-action@v5\n"
        "        with:\n"
        "          platforms: linux/amd64,linux/arm64\n"
        + " " * (1 << 16) + "\n"
        + run + "# end\n")
    start = time.monotonic()
    matrix = discover_platform_matrix(tmp_path)
    assert time.monotonic() - start < 5.0
    pairs = _arch_libc(matrix)
    assert ("x86_64", LibcVersion("glibc", (2, 36))) in pairs
    assert any(arch == "aarch64" for arch, _ in pairs)


def test_unclosed_matrix_os_bracket_is_fast(tmp_path: Path) -> None:
    """A hostile ``os: [`` with no closing bracket and a long
    whitespace tail: the old ``\\[\\s*([^\\]]+)\\s*\\]`` spelling made
    ``\\s*`` and ``[^\\]]+`` compete over the same whitespace —
    quadratic on a SINGLE anchor (16KB hung the walk). The capture now
    owns the body and consumers strip the items."""
    import time

    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "jobs:\n  build:\n"
        "    runs-on: ${{ matrix.os }}\n"
        "    strategy:\n"
        "      matrix:\n"
        "        os: [" + " " * (1 << 17) + "\n")
    start = time.monotonic()
    discover_platform_matrix(tmp_path)
    assert time.monotonic() - start < 5.0


def test_matrix_os_list_items_with_padding_still_parse(tmp_path: Path) -> None:
    """The bracket-body capture keeps surrounding whitespace; item
    parsing strips it — padded lists resolve the same runners."""
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "jobs:\n  build:\n"
        "    runs-on: ${{ matrix.os }}\n"
        "    strategy:\n"
        "      matrix:\n"
        "        os: [  'ubuntu-22.04' ,  ubuntu-24.04  ]\n")
    matrix = discover_platform_matrix(tmp_path)
    pairs = _arch_libc(matrix)
    # ubuntu-22.04 → glibc 2.35; the 24.04 item must resolve too.
    assert ("x86_64", LibcVersion("glibc", (2, 35))) in pairs
    assert ("x86_64", LibcVersion("glibc", (2, 39))) in pairs
