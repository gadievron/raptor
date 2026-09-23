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

4. **GitHub Actions** — ``.github/workflows/*.yml`` ``runs-on:``
   values. Standard runner labels map to known platforms. Matrix
   strategies (``strategy.matrix.platform``) multiply the set.

5. **GHA ``docker/build-push-action`` step inputs** — the dominant
   modern multi-arch release pipeline. ``with: platforms:
   linux/amd64,linux/arm64`` declares the OUTPUT image's arches
   independent of ``runs-on:`` (which is the runner arch — usually
   x86_64 + QEMU emulation for arm64). Scanned per workflow file
   right after that file's ``runs-on`` values.

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
from ..file_shapes import is_dockerfile as _is_dockerfile
from pathlib import Path
from collections.abc import Iterable

from core.source.contained import read_contained

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
    libc: LibcVersion | None
    # OS family the pair runs on: "linux" | "windows" | "macosx" |
    # None (unknown — e.g. an unrecognised self-hosted runner label).
    # Carried EXPLICITLY: container-provenance pairs (Dockerfile,
    # devcontainer, bake, build-push) are Linux by construction even
    # when their libc is undetermined. Overloading ``libc=None`` as
    # "non-Linux" made the compat matcher reject every Linux wheel
    # for such pairs (false incompat findings per compiled dep) AND
    # accept Windows-only wheels for them (false clean verdicts).
    os: str | None = None
    # Source-trace for diagnostics ("Dockerfile FROM python:3.13-bookworm",
    # "GHA runs-on: ubuntu-22.04", etc.). Not used by the compat
    # checker; surfaces in operator-facing reports so a flagged
    # incompat says WHERE the platform came from.
    #
    # ``compare=False``: the source is diagnostic-only and must not
    # participate in eq/hash. With it in the identity, N declaration
    # sites of the same (arch, libc) made N "distinct" pairs in the
    # ProjectPlatformMatrix set, and check_compat emitted one verdict
    # — and one finding with an IDENTICAL finding_id — per copy.
    # Since ``set.add`` keeps the existing element on equality, the
    # FIRST-discovered source (module-docstring walk order) is the
    # one retained and reported.
    source: str = field(default="", compare=False)
    # macOS minimum version the project accepts wheels against. A
    # project on a macos-13 runner has macos_version=(13, 0); a wheel
    # tagged ``macosx_14_0_arm64`` is too new and gets refused. ``None``
    # for non-macOS pairs.
    macos_version: tuple[int, int] | None = None

    def as_str(self) -> str:
        if self.macos_version is not None:
            return f"{self.arch}/macos-{self.macos_version[0]}.{self.macos_version[1]}"
        libc = self.libc.as_str() if self.libc else "no-libc"
        return f"{self.arch}/{libc}"


@dataclass
class ProjectPlatformMatrix:
    """The set of (arch, libc) pairs the project supports."""

    pairs: set[PlatformPair] = field(default_factory=set)

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

# Leading indent is HORIZONTAL-only ([^\S\n]): under MULTILINE the
# ``^\s*`` spelling re-scans a run of blank lines from every line
# start inside it — quadratic on a hostile Dockerfile (this walk
# runs on every discovered Dockerfile, no timeout).
_FROM_RE = re.compile(
    r"^[^\S\n]*FROM\s+"              # FROM keyword
    r"(?:--platform=(\S+)\s+)?"       # optional --platform=...
    r"(\S+)"                          # image[:tag][@digest]
    r"(?:\s+AS\s+\S+)?\s*$",          # optional AS stage
    re.MULTILINE | re.IGNORECASE,
)


def _from_image_to_distro(image_ref: str) -> str | None:
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


def _read_discovered(root: Path, path: Path) -> str | None:
    """Containment-checked, size-capped read of a file discovered
    under the scanned target.

    Every file this module reads was found under (or referenced
    from) the untrusted target tree — the same file classes the
    parsers read through their bounded reader. A bare ``read_text``
    here followed symlinks (a hostile ``devcontainer.json ->
    /dev/stdin`` or an out-of-tree ``build.dockerfile`` reference
    pulled operator files into the discovery pass) and loaded
    multi-GB planted files whole into memory before the sandbox
    limit."""
    text = read_contained(root, path)
    if text is None:
        logger.debug(
            "platform_matrix: refused or failed to read %s "
            "(outside target, non-regular, or unreadable)", path,
        )
    return text


def _walk_dockerfile(
    path: Path, matrix: ProjectPlatformMatrix, root: Path,
) -> None:
    """Parse FROM lines + add discovered (arch, libc) pairs."""
    text = _read_discovered(root, path)
    if text is None:
        return

    known_stages: set = set()
    for match in _FROM_RE.finditer(text):
        platform_flag = match.group(1)  # may be None
        image_ref = match.group(2)
        as_m = re.search(r'\bAS\s+(\S+)', match.group(0), re.IGNORECASE)
        if as_m:
            known_stages.add(as_m.group(1))
        if image_ref in known_stages:
            continue
        # Reduce the ref to a ``name:tag`` lookup key (digest +
        # registry/namespace stripped). Variant suffixes like
        # ``-slim`` are NOT stripped here — ``lookup_distro_libc``
        # tolerates them and still resolves
        # ``python:3.13-slim-bookworm`` as bookworm-based.
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
                arch=arch, libc=libc, os="linux",
                source=f"Dockerfile FROM {image_ref} in {path.name}",
            ))


# ---------------------------------------------------------------------------
# devcontainer.json
# ---------------------------------------------------------------------------

def _walk_devcontainer(
    path: Path, matrix: ProjectPlatformMatrix, root: Path,
) -> None:
    """Parse a ``devcontainer.json`` and lift the ``image:`` /
    ``build.dockerfile`` reference into the matrix.

    devcontainer.json technically supports comments (JSONC); we
    try standard JSON first and fall back to a comment-strip pass.
    """
    text = _read_discovered(root, path)
    if text is None:
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
        if libc is None:
            logger.debug(
                "platform_matrix: unknown libc for image %r (from %s)",
                image, path,
            )
            # Still register the platform pair — libc=None means
            # "we couldn't determine the libc, don't gate on it".
            # Mirrors the Dockerfile walker.
        for arch in ("x86_64", "aarch64"):
            matrix.add(PlatformPair(
                arch=arch, libc=libc, os="linux",
                source=f"devcontainer.json image: {image}",
            ))

    build = data.get("build")
    if isinstance(build, dict):
        dockerfile_rel = build.get("dockerfile")
        if isinstance(dockerfile_rel, str):
            # Containment is enforced by the read itself: a hostile
            # "dockerfile": "../../..." reference resolves outside
            # the target and _read_discovered refuses it.
            dockerfile_path = (path.parent / dockerfile_rel).resolve()
            if dockerfile_path.exists():
                _walk_dockerfile(dockerfile_path, matrix, root)


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

# Anchor of an HCL bake ``platforms = [`` list opener. The list BODY
# (everything up to the first ``]``, both single-line and multi-line
# shapes) is captured by :func:`_iter_bracket_list_bodies`, never by
# an unbounded regex span: the old ``\[(?P<list>[^\]]*?)\]`` spelling
# re-scanned to EOF for EVERY unclosed ``platforms = [`` anchor — a
# hostile bake file of repeated unclosed openers cost quadratic time
# through the default discovery walk (hours at the 10 MiB read cap).
# Mismatch-tolerant: HCL allows comments inside the list, the body
# consumer splits on comma afterwards (string-stripping handles
# whitespace).
_BAKE_PLATFORMS_ANCHOR_RE = re.compile(r"platforms\s*=\s*\[")


def _iter_bracket_list_bodies(
    text: str, anchor_re: re.Pattern[str],
) -> Iterable[str]:
    """Yield the ``[...]`` body following each ``anchor_re`` match —
    the same matches an ``<anchor>([^\\]]*?)\\]`` finditer produces,
    computed in linear time.

    Equivalence: a lazy ``[^\\]]*?\\]`` body is exactly "everything up
    to the FIRST ``]`` after the opener", and ``finditer`` resumes
    after each match's closing bracket — mirrored here by ``pos``
    jumping past ``close``, so an opener inside a matched body is
    skipped just as the regex engine skips it. Linearity: each failed
    close-bracket search proves every LATER anchor fails too (its
    search range is a subset), so the walk stops instead of re-scanning
    the tail once per anchor (the measured quadratic).
    """
    pos = 0
    while True:
        m = anchor_re.search(text, pos)
        if m is None:
            return
        close = text.find("]", m.end())
        if close == -1:
            return
        yield text[m.end():close]
        pos = close + 1


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
    path: Path, matrix: ProjectPlatformMatrix, root: Path,
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
    text = _read_discovered(root, path)
    if text is None:
        return

    for captured in _iter_bracket_list_bodies(text, _BAKE_PLATFORMS_ANCHOR_RE):
        for platform_ref in _extract_platforms_from_text(captured):
            # Bake platform refs look like Docker's ``linux/amd64``
            # form. ``_canonical_arch`` already maps these.
            arch = _canonical_arch(platform_ref)
            if not arch:
                continue
            matrix.add(PlatformPair(
                arch=arch, libc=None, os="linux",
                source=f"docker-bake.hcl platforms in {path.name}",
            ))


def _walk_bake_json(
    path: Path, matrix: ProjectPlatformMatrix, root: Path,
) -> None:
    """Same as :func:`_walk_bake_hcl` but for the JSON variant.

    JSON shape:
      ``{"target": {"<name>": {"platforms": [...]}}}``
    Some configs use ``"group"`` blocks too; those carry target
    refs not platforms, so we ignore them.
    """
    import json
    text = _read_discovered(root, path)
    if text is None:
        return
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
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
                arch=arch, libc=None, os="linux",
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
            _walk_bake_hcl(path, matrix, target)
    for name in _BAKE_JSON_NAMES:
        path = target / name
        if path.is_file():
            _walk_bake_json(path, matrix, target)


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

    # Leading indent is HORIZONTAL-only ([^\S\n]) — the MULTILINE
    # ``^\s*`` spelling is quadratic on blank-line runs (see
    # _FROM_RE). The ``os:``/``platform:`` regex is an ANCHOR only;
    # the bracket body is walked by _iter_bracket_list_bodies — the
    # old inline ``\[([^\]]+)\]`` body re-scanned to EOF for every
    # unclosed ``os: [`` opener (N openers = quadratic; the landed
    # single-anchor fix bounded the whitespace competition, not the
    # per-anchor tail scan). The body keeps its surrounding
    # whitespace (consumers strip each item).
    runs_on_re = re.compile(r"^[^\S\n]*runs-on:\s*([^\n#]+)", re.MULTILINE)
    matrix_os_anchor_re = re.compile(
        r"^[^\S\n]*(?:os|platform):\s*\[", re.MULTILINE,
    )

    for wf in sorted(workflows_dir.glob("*.yml")) + sorted(workflows_dir.glob("*.yaml")):
        text = _read_discovered(target, wf)
        if text is None:
            continue

        # Collect all bare runs-on: values (scalar form).
        # The matrix os/platform list is scanned ONCE per file and
        # reused: re-running the whole-file scan per ``${{``-bearing
        # ``runs-on:`` match multiplied the scan cost by the number
        # of such matches (a hostile workflow stacked them).
        matrix_items: list[str] | None = None
        for m in runs_on_re.finditer(text):
            value = m.group(1).strip().strip("'\"")
            if "${{" in value:
                # Variable reference — look for matrix.os list.
                if matrix_items is None:
                    matrix_items = [
                        s.strip().strip("'\"")
                        for body in _iter_bracket_list_bodies(
                            text, matrix_os_anchor_re)
                        if body  # old body class was [^\]]+ (non-empty)
                        for s in body.split(",")
                    ]
                for item in matrix_items:
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
# Leading indent is HORIZONTAL-only ([^\S\n]) — the MULTILINE ``^\s*``
# spelling is quadratic on blank-line runs (see _FROM_RE), and the
# uses-line's ADJACENT pair (``^\s*-?\s*``) was worse still: the two
# unbounded spans split a run every possible way per anchor. The
# second span therefore only exists behind the literal ``-`` — two
# adjacent unbounded spans stay quadratic on a hostile single-line
# space run even spelled horizontally.
_BUILD_PUSH_USES_RE = re.compile(
    r"^[^\S\n]*(?:-[^\S\n]*)?uses:\s*docker/build-push-action@[^\s\n]+",
    re.MULTILINE,
)
_NEXT_STEP_BOUNDARY_RE = re.compile(
    r"^[^\S\n]*-\s*(?:uses|run|name):", re.MULTILINE,
)
_PLATFORMS_INPUT_RE = re.compile(
    r"^[^\S\n]*platforms:\s*([^\n#]+)", re.MULTILINE,
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
    # Single forward pass: each step's block ends at the next step
    # boundary AND never extends past the next build-push ``uses:``
    # line (a later match is by definition a new step). Both the
    # boundary search and the platforms search run inside the
    # [step_start, step_end) window via pos/endpos — no tail slice.
    # The old per-match ``search(text, pos=step_start)`` + tail-slice
    # scanned to EOF once per boundary-less ``uses:`` line, so a
    # hostile workflow of stacked dash-less uses lines cost quadratic
    # time (blocks all overlapped the same tail). Windowing changes
    # no discovered platform: a ``platforms:`` after the next uses
    # line belongs to (and is found by) that step's own window, and
    # both steps stamp the identical per-workflow source string.
    use_matches = list(_BUILD_PUSH_USES_RE.finditer(text))
    for i, use_match in enumerate(use_matches):
        step_start = use_match.end()
        window_end = (
            use_matches[i + 1].start()
            if i + 1 < len(use_matches) else len(text)
        )
        boundary = _NEXT_STEP_BOUNDARY_RE.search(
            text, pos=step_start, endpos=window_end)
        step_end = boundary.start() if boundary else window_end
        platforms_match = _PLATFORMS_INPUT_RE.search(
            text, step_start, step_end)
        if platforms_match is None:
            continue
        value = platforms_match.group(1).strip().strip("'\"")
        if value in ("|", ">", "|+", ">+", "|-", ">-"):
            continue
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
                arch=arch, libc=None, os="linux",
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


def _parse_macos_runner_version(runner_ref: str) -> tuple[int, int] | None:
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

    Arm runner labels carry an ``-arm`` / ``-arm64`` SUFFIX on the
    base image label (``ubuntu-24.04-arm``, ``windows-11-arm`` —
    GitHub's hosted arm runners, free for public repos since early
    2025). The suffix is parsed mechanically rather than table-listed:
    arch comes from the suffix, libc from the base label's row (the
    arm image ships the same distro libc). Recording these as x86_64
    hid exactly the aarch64 wheel-gap class this subsystem exists to
    catch for projects whose only arm signal is their CI runner.
    Windows / macOS runners get libc=None.
    """
    arch = "x86_64"
    base_ref = runner_ref
    if runner_ref.endswith(("-arm", "-arm64")):
        arch = "aarch64"
        base_ref = runner_ref.rsplit("-", 1)[0]
    libc = lookup_runner_libc(base_ref)
    if runner_ref.startswith("windows-"):
        matrix.add(PlatformPair(
            arch=arch, libc=None, os="windows",
            source=f"GHA runs-on: {runner_ref} in {workflow.name}",
        ))
        return
    if runner_ref.startswith("macos-"):
        macos_version = _parse_macos_runner_version(runner_ref)
        arch = "aarch64" if macos_version is None or macos_version[0] >= 14 else "x86_64"
        matrix.add(PlatformPair(
            arch=arch, libc=None, os="macosx",
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
        arch=arch, libc=libc,
        # A label the runner table KNOWS is a Linux image; an
        # unrecognised (self-hosted) label stays os=None — unknown,
        # which the compat matcher treats with the legacy lenient
        # fall-through rather than asserting an OS it can't know.
        os="linux" if libc is not None else None,
        source=f"GHA runs-on: {runner_ref} in {workflow.name}",
    ))


# ---------------------------------------------------------------------------
# Top-level discovery
# ---------------------------------------------------------------------------


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
        _walk_dockerfile(dockerfile, matrix, target)

    devcontainer = target / ".devcontainer" / "devcontainer.json"
    if devcontainer.exists():
        _walk_devcontainer(devcontainer, matrix, target)

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
            os="linux",
            source="default (no platform signals found)",
        ))

    return matrix
