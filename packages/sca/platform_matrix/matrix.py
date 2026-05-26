"""Walk a project's Dockerfile FROM / GHA runs-on / devcontainer
image refs and aggregate the (arch, libc) combinations the
project actually runs on.

Output: :class:`ProjectPlatformMatrix` — a set of
:class:`PlatformPair` tuples. Each pair represents one
(architecture, libc family + version) combo that any installed
Python wheel must satisfy.

The matrix is the *input* to :mod:`packages.sca.wheel_compat`'s
cross-check: for each pair in the matrix, does the candidate
PyPI package have an installable wheel?

Discovery sources (in walk order):

1. **Dockerfiles** — ``FROM <image>:<tag>`` lines. The
   :mod:`packages.sca.platform_matrix.glibc_db` table maps known
   images to libc versions. ``--platform=linux/<arch>`` flags on
   ``FROM`` constrain the architecture set.

2. **.devcontainer/devcontainer.json** — ``image:`` field or
   ``build.dockerfile`` pointer. Same libc resolution as Dockerfile.

3. **buildx bake configs** — ``docker-bake.{hcl,json}`` + override
   variants. Declares multi-arch build targets via
   ``platforms = ["linux/amd64", "linux/arm64", ...]``. The
   project's true deployment surface when ``docker buildx bake`` is
   the release driver; the Dockerfile's own ``--platform=`` may
   declare narrower targets that don't reflect production.

4. **GHA ``docker/build-push-action`` step inputs** — the dominant
   modern multi-arch release pipeline. ``with: platforms:
   linux/amd64,linux/arm64`` declares the OUTPUT image's arches
   independent of ``runs-on:`` (which is the runner arch — usually
   x86_64 + QEMU emulation for arm64).

5. **GitHub Actions** — ``.github/workflows/*.yml`` ``runs-on:``
   values. Standard runner labels map to known platforms. Matrix
   strategies (``strategy.matrix.platform``) multiply the set.

If no signal is found, the matrix defaults to
``{(x86_64, glibc 2.17)}`` (the manylinux2014 baseline — what
PyPI's source-build runners use). This is conservative: it
under-flags compat issues for arch-restricted projects that
hadn't declared their arch explicitly.

Architecture canonicalisation:
* ``amd64`` / ``x86_64`` / ``linux/amd64``  → ``x86_64``
* ``arm64`` / ``aarch64`` / ``linux/arm64`` → ``aarch64``
* ``armv7`` / ``arm/v7`` / ``linux/arm/v7``  → ``armv7l``
* ``i386`` / ``386``                          → ``i686``
* ``ppc64le`` / ``s390x`` pass through.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Set, Tuple

from packages.sca.platform_matrix.glibc_db import (
    LibcVersion,
    lookup_distro_libc,
    lookup_runner_libc,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PlatformPair:
    """One (arch, OS-constraint) combo a Python wheel must install on.

    On Linux the OS constraint is the libc family + version. On macOS
    it's the macOS version (Apple Silicon projects pinned to a
    specific runner version, e.g. macos-13 vs macos-14, accept
    different wheel-tag windows). On Windows there's effectively no
    version constraint — wheel tags only encode bitness.
    """

    arch: str                  # "x86_64" | "aarch64" | "armv7l" | "i686" | …
    libc: Optional[LibcVersion]
    # Source-trace for diagnostics ("Dockerfile FROM python:3.13-bookworm",
    # "GHA runs-on: ubuntu-22.04", etc.). Not used by the compat
    # checker; surfaces in operator-facing reports so a flagged
    # incompat says WHERE the platform came from.
    source: str = ""
    # macOS minimum version the project accepts wheels against. A
    # project on a macos-13 runner has macos_version=(13, 0); a wheel
    # tagged ``macosx_14_0_arm64`` is too new and gets refused. ``None``
    # for non-macOS pairs.
    macos_version: Optional[Tuple[int, int]] = None

    def as_str(self) -> str:
        if self.macos_version is not None:
            return f"{self.arch}/macos-{self.macos_version[0]}.{self.macos_version[1]}"
        libc = self.libc.as_str() if self.libc else "no-libc"
        return f"{self.arch}/{libc}"


@dataclass
class ProjectPlatformMatrix:
    """The set of (arch, libc) pairs the project supports."""

    pairs: Set[PlatformPair] = field(default_factory=set)

    def add(self, pair: PlatformPair) -> None:
        self.pairs.add(pair)

    def __bool__(self) -> bool:
        return bool(self.pairs)

    def __iter__(self):
        return iter(self.pairs)

    def __len__(self) -> int:
        return len(self.pairs)


# ---------------------------------------------------------------------------
# Architecture canonicalisation
# ---------------------------------------------------------------------------

_ARCH_ALIASES = {
    "x86_64": "x86_64", "amd64": "x86_64", "linux/amd64": "x86_64",
    "aarch64": "aarch64", "arm64": "aarch64", "linux/arm64": "aarch64",
    "linux/aarch64": "aarch64",
    "armv7l": "armv7l", "armv7": "armv7l", "linux/arm/v7": "armv7l",
    "arm/v7": "armv7l",
    "i686": "i686", "i386": "i686", "386": "i686", "linux/386": "i686",
    "ppc64le": "ppc64le", "linux/ppc64le": "ppc64le",
    "s390x": "s390x", "linux/s390x": "s390x",
}


def _canonical_arch(arch_ref: str) -> str:
    """Normalise platform / arch strings to canonical names.
    Unknown forms pass through unchanged."""
    return _ARCH_ALIASES.get(arch_ref, arch_ref)


# ---------------------------------------------------------------------------
# Dockerfile FROM parsing
# ---------------------------------------------------------------------------

_FROM_RE = re.compile(
    r"^\s*FROM\s+"                   # FROM keyword
    r"(?:--platform=(\S+)\s+)?"       # optional --platform=...
    r"(\S+)"                          # image[:tag][@digest]
    r"(?:\s+AS\s+\S+)?\s*$",          # optional AS stage
    re.MULTILINE | re.IGNORECASE,
)


def _from_image_to_distro(image_ref: str) -> Optional[str]:
    """Strip digest + reduce to a distro-lookup key.

    Examples:
      ``python:3.13-bookworm@sha256:abc`` → ``python:3.13-bookworm``
      ``debian:bookworm`` → ``debian:bookworm``
      ``mcr.microsoft.com/devcontainers/python:1-3.12-bookworm`` →
        ``python:1-3.12-bookworm`` (registry+namespace stripped)
    """
    # Strip digest.
    ref = image_ref.split("@", 1)[0]
    # Strip registry / namespace prefix to leave the trailing
    # ``name:tag`` form. The glibc DB tolerates the Python-image
    # codename suffix.
    if "/" in ref:
        ref = ref.rsplit("/", 1)[-1]
    return ref


def _walk_dockerfile(
    path: Path, matrix: ProjectPlatformMatrix,
) -> None:
    """Parse FROM lines + add discovered (arch, libc) pairs."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.debug("platform_matrix: failed to read %s: %s", path, e)
        return

    for match in _FROM_RE.finditer(text):
        platform_flag = match.group(1)  # may be None
        image_ref = match.group(2)
        # Skip multi-stage FROM-AS references (``FROM build AS rt``
        # where ``build`` is a prior stage name, not an image).
        if ":" not in image_ref and "/" not in image_ref:
            # No tag + no registry — looks like a stage name. The
            # ``FROM stage AS new_stage`` pattern is the case.
            continue
        # Strip variant suffixes like ``-slim``, ``-alpine`` keep
        # the distro lookup focused: ``python:3.13-slim-bookworm``
        # is bookworm-based.
        distro_key = _from_image_to_distro(image_ref)
        libc = lookup_distro_libc(distro_key or image_ref)
        if libc is None:
            logger.debug(
                "platform_matrix: unknown libc for image %r (from %s)",
                image_ref, path,
            )
            # Still register the platform pair so the matrix
            # records that we walked the file; libc=None means
            # "we couldn't determine the libc, don't gate on it".
        if platform_flag:
            archs = [_canonical_arch(platform_flag)]
        else:
            # No --platform → image is multi-arch by convention.
            # Use the project's default multi-arch set (x86_64 +
            # aarch64, the two GHA + Apple-Silicon default targets).
            archs = ["x86_64", "aarch64"]
        for arch in archs:
            matrix.add(PlatformPair(
                arch=arch, libc=libc,
                source=f"Dockerfile FROM {image_ref} in {path.name}",
            ))


# ---------------------------------------------------------------------------
# devcontainer.json
# ---------------------------------------------------------------------------

def _walk_devcontainer(
    path: Path, matrix: ProjectPlatformMatrix,
) -> None:
    """Parse a ``devcontainer.json`` and lift the ``image:`` /
    ``build.dockerfile`` reference into the matrix.

    devcontainer.json technically supports comments (JSONC); we
    try standard JSON first and fall back to a comment-strip pass.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.debug("platform_matrix: failed to read %s: %s", path, e)
        return

    # devcontainer.json is JSONC (comments + trailing commas). Use the shared
    # string-aware loader — a naive ``//`` strip mangles a ``//`` inside a URL
    # value (e.g. an "image" / "features" URL) and silently breaks the parse.
    from core.json.jsonc import load_jsonc
    try:
        data = load_jsonc(text)
    except ValueError:        # JSONDecodeError is a ValueError subclass
        return
    if not isinstance(data, dict):
        return

    image = data.get("image")
    if isinstance(image, str):
        distro_key = _from_image_to_distro(image)
        libc = lookup_distro_libc(distro_key or image)
        for arch in ("x86_64", "aarch64"):
            matrix.add(PlatformPair(
                arch=arch, libc=libc,
                source=f"devcontainer.json image: {image}",
            ))

    build = data.get("build")
    if isinstance(build, dict):
        dockerfile_rel = build.get("dockerfile")
        if isinstance(dockerfile_rel, str):
            dockerfile_path = (path.parent / dockerfile_rel).resolve()
            if dockerfile_path.exists():
                _walk_dockerfile(dockerfile_path, matrix)


# ---------------------------------------------------------------------------
# buildx bake (docker-bake.hcl / docker-bake.json)
# ---------------------------------------------------------------------------

# Filenames docker buildx recognises by default (the override
# variants get loaded when present, on top of the base file).
_BAKE_HCL_NAMES = (
    "docker-bake.hcl", "docker-bake.override.hcl",
)
_BAKE_JSON_NAMES = (
    "docker-bake.json", "docker-bake.override.json",
)

# Regex over an HCL bake file. Matches both single-line and
# multi-line list shapes:
#   platforms = ["linux/amd64", "linux/arm64"]
#   platforms = [
#     "linux/amd64",
#     "linux/arm64",
#   ]
# Non-greedy + DOTALL captures up to the first closing bracket.
# Mismatch-tolerant: HCL allows comments inside the list, our
# regex eats them as part of the captured group and splits on
# comma afterwards (string-stripping handles whitespace).
_BAKE_PLATFORMS_RE = re.compile(
    r"platforms\s*=\s*\[(?P<list>[^\]]*?)\]", re.DOTALL,
)


def _extract_platforms_from_text(captured: str) -> Iterable[str]:
    """Split a bake ``platforms = [...]`` list-body into individual
    platform strings. Tolerates inline ``//`` + ``#`` comments +
    trailing commas + mixed quoting; returns the de-quoted, trimmed
    values."""
    # Strip line comments BEFORE splitting on comma. Otherwise an
    # entry like ``"linux/amd64", // x86 servers`` parses as two
    # items: the value and "// x86 servers\nlinux/arm64..." which
    # makes the next value vanish into a comment-prefixed string.
    cleaned_lines = []
    for line in captured.splitlines():
        # ``//`` comment — HCL form
        if "//" in line:
            line = line.split("//", 1)[0]
        # ``#`` comment — also HCL-allowed
        if "#" in line:
            line = line.split("#", 1)[0]
        cleaned_lines.append(line)
    captured = "\n".join(cleaned_lines)

    for raw in captured.split(","):
        item = raw.strip()
        if not item:
            continue
        # Strip surrounding quotes (single or double)
        if (item.startswith('"') and item.endswith('"')) or (
                item.startswith("'") and item.endswith("'")):
            item = item[1:-1]
        if item:
            yield item


def _walk_bake_hcl(
    path: Path, matrix: ProjectPlatformMatrix,
) -> None:
    """Parse a ``docker-bake.hcl`` and lift any ``platforms = [...]``
    into the matrix.

    Caveats — by design:

    * We don't resolve HCL variables (``platforms = var.platforms``).
      Bake configs that funnel through a variable just won't
      contribute; the trade-off is "regex" vs. depending on
      python-hcl2.
    * We don't model ``inherits = [...]``; each target's own
      ``platforms`` block is read in isolation. Most real bake
      configs declare platforms at target level rather than
      relying on inheritance for them.
    * Comments inside a ``platforms`` list are stripped. Other
      file-level comments are irrelevant — we only look at
      ``platforms = [...]`` shapes.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.debug("platform_matrix: failed to read %s: %s", path, e)
        return

    for match in _BAKE_PLATFORMS_RE.finditer(text):
        captured = match.group("list")
        for platform_ref in _extract_platforms_from_text(captured):
            # Bake platform refs look like Docker's ``linux/amd64``
            # form. ``_canonical_arch`` already maps these.
            arch = _canonical_arch(platform_ref)
            if not arch:
                continue
            matrix.add(PlatformPair(
                arch=arch, libc=None,
                source=f"docker-bake.hcl platforms in {path.name}",
            ))


def _walk_bake_json(
    path: Path, matrix: ProjectPlatformMatrix,
) -> None:
    """Same as :func:`_walk_bake_hcl` but for the JSON variant.

    JSON shape:
      ``{"target": {"<name>": {"platforms": [...]}}}``
    Some configs use ``"group"`` blocks too; those carry target
    refs not platforms, so we ignore them.
    """
    import json
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(text)
    except (OSError, json.JSONDecodeError) as e:
        logger.debug(
            "platform_matrix: failed to parse %s as bake JSON: %s",
            path, e,
        )
        return

    targets = data.get("target") if isinstance(data, dict) else None
    if not isinstance(targets, dict):
        return
    for target_data in targets.values():
        if not isinstance(target_data, dict):
            continue
        platforms = target_data.get("platforms")
        if not isinstance(platforms, list):
            continue
        for platform_ref in platforms:
            if not isinstance(platform_ref, str):
                continue
            arch = _canonical_arch(platform_ref)
            if not arch:
                continue
            matrix.add(PlatformPair(
                arch=arch, libc=None,
                source=f"docker-bake.json platforms in {path.name}",
            ))


def _walk_bake_configs(
    target: Path, matrix: ProjectPlatformMatrix,
) -> None:
    """Walk the conventional ``docker-bake.{hcl,json}`` filenames at
    the repo root. Override variants get walked when present —
    they layer on top, contributing additional platforms (set-
    based dedup means duplicates are free)."""
    for name in _BAKE_HCL_NAMES:
        path = target / name
        if path.is_file():
            _walk_bake_hcl(path, matrix)
    for name in _BAKE_JSON_NAMES:
        path = target / name
        if path.is_file():
            _walk_bake_json(path, matrix)


# ---------------------------------------------------------------------------
# GHA workflows
# ---------------------------------------------------------------------------

def _walk_gha_workflows(
    target: Path, matrix: ProjectPlatformMatrix,
) -> None:
    """Walk ``.github/workflows/*.yml`` for ``runs-on:`` values.

    Tolerates the two common shapes:
      * scalar:   ``runs-on: ubuntu-22.04``
      * matrix:   ``runs-on: ${{ matrix.os }}`` with
                   ``strategy.matrix.os: [ubuntu-22.04, ubuntu-24.04]``

    We use a permissive regex rather than a YAML parser so a
    grammar-incomplete workflow (operator typo, in-flight edit)
    doesn't take down the discovery pass.
    """
    workflows_dir = target / ".github" / "workflows"
    if not workflows_dir.is_dir():
        return

    runs_on_re = re.compile(r"^\s*runs-on:\s*([^\n#]+)", re.MULTILINE)
    matrix_os_re = re.compile(
        r"^\s*os:\s*\[\s*([^\]]+)\s*\]", re.MULTILINE,
    )

    for wf in workflows_dir.glob("*.yml"):
        try:
            text = wf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Collect all bare runs-on: values (scalar form).
        for m in runs_on_re.finditer(text):
            value = m.group(1).strip().strip("'\"")
            if "${{" in value:
                # Variable reference — look for matrix.os list.
                for mm in matrix_os_re.finditer(text):
                    items = [
                        s.strip().strip("'\"")
                        for s in mm.group(1).split(",")
                    ]
                    for item in items:
                        _add_runner(item, matrix, wf)
                continue
            _add_runner(value, matrix, wf)

        # ``docker/build-push-action`` step inputs declare the
        # output image's target arches — independent of ``runs-on:``
        # which is the RUNNER arch (typically x86_64 + QEMU
        # emulation for multi-arch builds). Without this, projects
        # using buildx in CI to ship multi-arch images surface only
        # the runner arch and we'd silently miss aarch64-only
        # wheel-compat bites.
        _extract_gha_build_push_platforms(text, matrix, wf)


# Match a ``- uses: docker/build-push-action@...`` step line, then
# look ahead for the next ``platforms:`` value at any indent — the
# YAML structure puts the input under ``with:`` two indent levels
# down, but we don't need to validate it. We only stop scanning
# when we hit the NEXT ``- uses:`` step (boundary).
#
# Same regex-tolerant approach the ``runs-on:`` parser uses — a
# grammar-incomplete workflow (in-flight edit, typo) doesn't take
# down discovery.
_BUILD_PUSH_USES_RE = re.compile(
    r"^\s*-\s*uses:\s*docker/build-push-action@[^\s\n]+",
    re.MULTILINE,
)
_NEXT_STEP_BOUNDARY_RE = re.compile(
    r"^\s*-\s*(?:uses|run|name):", re.MULTILINE,
)
_PLATFORMS_INPUT_RE = re.compile(
    r"^\s*platforms:\s*([^\n#]+)", re.MULTILINE,
)


def _extract_gha_build_push_platforms(
    text: str,
    matrix: ProjectPlatformMatrix,
    workflow: Path,
) -> None:
    """For each ``docker/build-push-action`` step, find the
    ``platforms:`` value inside its block and lift each
    comma-separated arch into the matrix.

    libc=None on every entry — buildx step inputs don't declare
    a base image; the Dockerfile walker contributes the libc per
    arch via its FROM-line resolution. Set-based dedup means the
    Dockerfile's more-specific ``(arch, libc=glibc-2.36)`` and
    our ``(arch, libc=None)`` both stay in the matrix; downstream
    wheel-compat treats libc=None as "no libc constraint" which
    is the lenient behaviour and correct here (build-push-action
    doesn't constrain libc on its own).
    """
    for use_match in _BUILD_PUSH_USES_RE.finditer(text):
        step_start = use_match.end()
        # Find the next step boundary OR end of file to scope our
        # ``platforms:`` search to THIS step's block.
        boundary = _NEXT_STEP_BOUNDARY_RE.search(text, pos=step_start)
        step_end = boundary.start() if boundary else len(text)
        block = text[step_start:step_end]
        platforms_match = _PLATFORMS_INPUT_RE.search(block)
        if platforms_match is None:
            continue
        value = platforms_match.group(1).strip().strip("'\"")
        # ``platforms: linux/amd64,linux/arm64`` — comma-separated.
        # Also handle YAML list inline shape: ``[linux/amd64, ...]``.
        value = value.strip("[]")
        for raw in value.split(","):
            platform_ref = raw.strip().strip("'\"")
            if not platform_ref or "${{" in platform_ref:
                # Skip variable references — we can't resolve
                # GHA expression syntax here.
                continue
            arch = _canonical_arch(platform_ref)
            if not arch:
                continue
            matrix.add(PlatformPair(
                arch=arch, libc=None,
                source=(
                    f"GHA docker/build-push-action platforms in "
                    f"{workflow.name}"
                ),
            ))


# GitHub's macOS runner naming: ``macos-13``, ``macos-14``,
# ``macos-15``, ``macos-latest``. The numeric form maps directly to
# the macOS major version. ``macos-latest`` follows GitHub's policy
# of the second-most-recent stable; track it loosely (current as of
# 2026: latest = 14). If GitHub bumps this, the regression test
# catches the lag; lift the constant when it does.
_MACOS_RUNNER_LATEST = (14, 0)

_MACOS_RUNNER_RE = re.compile(r"^macos-(\d+)(?:\.(\d+))?$")


def _parse_macos_runner_version(runner_ref: str) -> Optional[Tuple[int, int]]:
    """Map a GHA macOS runner label to its (major, minor) macOS
    version. Returns ``None`` for unrecognised labels — let the
    wheel-compat check fall back to "no version constraint" rather
    than emit a misleading verdict."""
    if runner_ref == "macos-latest":
        return _MACOS_RUNNER_LATEST
    m = _MACOS_RUNNER_RE.match(runner_ref)
    if m is None:
        return None
    major = int(m.group(1))
    minor = int(m.group(2)) if m.group(2) else 0
    return (major, minor)


def _add_runner(
    runner_ref: str,
    matrix: ProjectPlatformMatrix,
    workflow: Path,
) -> None:
    """Resolve a runner label to a PlatformPair + add to matrix.

    Standard GHA runners are x86_64-only today (no aarch64 hosted
    runners in the free tier as of 2026; that may change).
    Windows / macOS runners get libc=None.
    """
    libc = lookup_runner_libc(runner_ref)
    if runner_ref.startswith("windows-"):
        matrix.add(PlatformPair(
            arch="x86_64", libc=None,
            source=f"GHA runs-on: {runner_ref} in {workflow.name}",
        ))
        return
    if runner_ref.startswith("macos-"):
        # Modern macOS runners are aarch64 (Apple Silicon).
        arch = "aarch64"
        macos_version = _parse_macos_runner_version(runner_ref)
        matrix.add(PlatformPair(
            arch=arch, libc=None,
            source=f"GHA runs-on: {runner_ref} in {workflow.name}",
            macos_version=macos_version,
        ))
        return
    if libc is None:
        logger.debug(
            "platform_matrix: unknown libc for runner %r in %s",
            runner_ref, workflow,
        )
    matrix.add(PlatformPair(
        arch="x86_64", libc=libc,
        source=f"GHA runs-on: {runner_ref} in {workflow.name}",
    ))


# ---------------------------------------------------------------------------
# Top-level discovery
# ---------------------------------------------------------------------------

_DOCKERFILE_NAMES_RE = re.compile(r"^(Dockerfile|.*\.dockerfile)$|^Containerfile$")


def _is_dockerfile(path: Path) -> bool:
    name = path.name
    if name in ("Dockerfile", "Containerfile"):
        return True
    if name.startswith("Dockerfile."):
        return True
    if name.endswith(".dockerfile"):
        return True
    return False


def _iter_dockerfiles(target: Path) -> Iterable[Path]:
    for p in target.rglob("*"):
        if not p.is_file():
            continue
        if _is_dockerfile(p):
            # Skip SCA / build output directories.
            parts = p.parts
            if any(part in (
                "out", ".out", "node_modules", ".venv", "venv",
                ".tox", "__pycache__", ".git",
            ) for part in parts):
                continue
            yield p


def discover_platform_matrix(target: Path) -> ProjectPlatformMatrix:
    """Walk ``target`` for Dockerfile / devcontainer / buildx-bake /
    GHA-workflow signals and return the aggregated platform matrix.

    If no signals are found, returns a default of
    ``{(x86_64, glibc 2.17)}`` — the manylinux2014 baseline, which
    is the PyPI-side floor for x86_64 wheels.
    """
    matrix = ProjectPlatformMatrix()

    for dockerfile in _iter_dockerfiles(target):
        _walk_dockerfile(dockerfile, matrix)

    devcontainer = target / ".devcontainer" / "devcontainer.json"
    if devcontainer.exists():
        _walk_devcontainer(devcontainer, matrix)

    # buildx bake configs at the repo root — declares multi-arch
    # release targets independently of the Dockerfile. Read BEFORE
    # GHA walking so platforms appear in matrix-source-order from
    # most-authoritative (release configs) to least (CI runners).
    _walk_bake_configs(target, matrix)

    _walk_gha_workflows(target, matrix)

    if not matrix.pairs:
        # Conservative default — matches the dominant "Linux x86_64,
        # manylinux2014 baseline" assumption that PyPI source builds use.
        matrix.add(PlatformPair(
            arch="x86_64",
            libc=LibcVersion("glibc", (2, 17)),
            source="default (no platform signals found)",
        ))

    return matrix
