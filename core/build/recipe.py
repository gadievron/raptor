"""Build-recipe construction — operator-runnable command sequence
for a target's detected build system.

The codeql ``BuildDetector`` returns a static ``command`` per
build-system type (``./configure && make`` for autotools, ``make``
for plain Makefile, etc.). That's enough for codeql's "run this
under our control" use case, but not enough for /describe's
"tell the operator what to type" — particularly for autotools,
where the operator's clean checkout may need a bootstrap step
to generate ``configure`` from ``configure.ac``.

This module wraps ``BuildDetector`` output and produces a full
recipe by inspecting the target tree for the right bootstrap
script. Multiple consumers benefit (right now /describe; future
``raptor execute`` flag from QoL #14e would too).

The recipe is a list of ``RecipeStep`` rather than a single
shell string so renderers can show steps with hints / optional
markers / why-rationale individually.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass(frozen=True)
class RecipeStep:
    """One step of a build recipe. ``command`` is the operator-
    runnable shell line (without a leading ``$`` prompt or the
    ``cd <target>``; renderers add the target prefix). ``why``
    is one-line operator-readable rationale."""
    command: str
    why: Optional[str] = None
    optional: bool = False


@dataclass(frozen=True)
class BuildRecipe:
    """A full operator-runnable build recipe for a target.
    Empty ``steps`` when the build system is unknown / not
    handled — caller renders "(build instructions: consult the
    project's README)" or similar."""
    build_system: str  # e.g. "autotools", "cmake", "make", "" (unknown)
    steps: List[RecipeStep] = field(default_factory=list)


# Bootstrap-script preference for autotools: pick the first
# one that exists in the target root. Falls back to
# ``autoreconf -fi`` (the canonical generator) when none of
# the project-specific shims are present.
_AUTOTOOLS_BOOTSTRAP_CANDIDATES = (
    "./autogen.sh",
    "./bootstrap",
    "./buildconf",  # used by some Apache projects
)


def build_recipe(target_path: Path, build_system: str) -> BuildRecipe:
    """Construct the recipe for ``target_path`` given its
    detected ``build_system`` type. Inspects the tree for
    bootstrap scripts / generated artefacts so the recipe
    matches what an operator would actually need to run.

    Unknown build system → empty recipe; caller decides how to
    handle (skip the step, or render "consult README")."""
    target_path = Path(target_path)
    builder = _RECIPES.get(build_system)
    if builder is None:
        return BuildRecipe(build_system=build_system)
    return builder(target_path)


# ---------------------------------------------------------------------------
# Per-build-system recipe builders
# ---------------------------------------------------------------------------


def _autotools_recipe(target: Path) -> BuildRecipe:
    """autotools — out-of-source build by default. configure.ac
    is the source of truth; configure + Makefile + Makefile.in
    are generated. autotools fully supports building from a
    separate directory (``mkdir build && cd build && ../configure
    && make``), which keeps object files out of the source tree
    AND puts them in ``build/`` where binary-oracle's auto-detect
    picks them up. Same number of operator commands; strictly
    better outcome.

    Sequence:
      1. (if ``configure`` is missing) regenerate it via the
         project's bootstrap script OR ``autoreconf -fi``
         (runs in source root, the only step that touches it)
      2. ``mkdir -p build && cd build && ../configure`` — generates
         the per-host Makefile inside build/
      3. ``make`` (in build/) — actually builds

    When ``configure`` already exists in source root, step 1 is
    omitted.
    """
    steps: List[RecipeStep] = []
    configure_present = (target / "configure").is_file()
    if not configure_present:
        bootstrap = _find_autotools_bootstrap(target)
        if bootstrap:
            steps.append(RecipeStep(
                command=f"cd <target> && {bootstrap}",
                why=(
                    f"{bootstrap} regenerates ./configure from "
                    f"configure.ac (configure is not in the checkout)"
                ),
            ))
        else:
            steps.append(RecipeStep(
                command="cd <target> && autoreconf -fi",
                why=(
                    "no bootstrap script found; autoreconf -fi "
                    "regenerates ./configure from configure.ac"
                ),
            ))
    # Out-of-source build — keeps object files out of the
    # source tree AND lands them in ``build/`` (one of
    # binary-oracle's auto-detect paths).
    steps.append(RecipeStep(
        command=(
            "cd <target> && mkdir -p build && cd build "
            "&& ../configure && make"
        ),
        why=(
            "out-of-source build keeps object files out of "
            "the source tree and in build/ where binary-oracle "
            "auto-detects them"
        ),
    ))
    return BuildRecipe(build_system="autotools", steps=steps)


def _cmake_recipe(target: Path) -> BuildRecipe:
    """cmake — out-of-source build is the modern convention.
    Reuse an existing build dir if one is present (checks the
    common conventions: ``build``, ``_build``, ``out/build``,
    ``cmake-build-debug``, ``cmake-build-release``); otherwise
    create the canonical ``build`` dir.

    Projects with a less conventional build-dir name (e.g.
    ``my-build``) still get the default-``build`` recipe and
    have to adapt — same trade-off as every IDE that has to
    pick a default."""
    steps: List[RecipeStep] = []
    for existing in (
        "build", "_build", "out/build",
        "cmake-build-debug", "cmake-build-release",
    ):
        if (target / existing).is_dir():
            steps.append(RecipeStep(
                command=f"cd <target>/{existing} && cmake .. && make",
            ))
            return BuildRecipe(build_system="cmake", steps=steps)
    # No existing build dir — create the canonical one.
    steps.append(RecipeStep(
        command=(
            "cd <target> && mkdir -p build && cd build "
            "&& cmake .. && make"
        ),
        why="out-of-source build keeps generated files separate",
    ))
    return BuildRecipe(build_system="cmake", steps=steps)


def _meson_recipe(target: Path) -> BuildRecipe:
    return BuildRecipe(
        build_system="meson",
        steps=[RecipeStep(
            command=(
                "cd <target> && meson setup build && "
                "meson compile -C build"
            ),
        )],
    )


def _make_recipe(target: Path) -> BuildRecipe:
    """Plain hand-written Makefile (no autotools/cmake/meson
    generators present). Just ``make``.

    No out-of-source recipe — plain make obeys the Makefile's
    own object-file conventions, which usually drop ``.o`` files
    next to ``.c`` files in the source tree. Operators on
    untrusted targets should fresh-clone before building."""
    return BuildRecipe(
        build_system="make",
        steps=[RecipeStep(
            command="cd <target> && make",
            why=(
                "warning: plain Makefile builds in-tree, "
                "object files land next to source files"
            ),
        )],
    )


def _cargo_recipe(target: Path) -> BuildRecipe:
    return BuildRecipe(
        build_system="cargo",
        steps=[RecipeStep(command="cd <target> && cargo build --release")],
    )


def _go_recipe(target: Path) -> BuildRecipe:
    return BuildRecipe(
        build_system="go",
        steps=[RecipeStep(command="cd <target> && go build ./...")],
    )


def _poetry_recipe(target: Path) -> BuildRecipe:
    return BuildRecipe(
        build_system="poetry",
        steps=[RecipeStep(command="cd <target> && poetry install")],
    )


def _pip_recipe(target: Path) -> BuildRecipe:
    """Pip — install the package in editable mode if pyproject /
    setup.py is present; else install requirements.txt."""
    steps: List[RecipeStep] = []
    if (target / "pyproject.toml").exists() or (target / "setup.py").exists():
        steps.append(RecipeStep(
            command="cd <target> && pip install -e .",
        ))
    elif (target / "requirements.txt").exists():
        steps.append(RecipeStep(
            command="cd <target> && pip install -r requirements.txt",
        ))
    else:
        # Pip detected without recognisable manifest — fall back
        # to editable install and let pip error if nothing's there.
        steps.append(RecipeStep(
            command="cd <target> && pip install -e .",
        ))
    return BuildRecipe(build_system="pip", steps=steps)


def _npm_recipe(target: Path) -> BuildRecipe:
    return BuildRecipe(
        build_system="npm",
        steps=[RecipeStep(command="cd <target> && npm install")],
    )


def _yarn_recipe(target: Path) -> BuildRecipe:
    return BuildRecipe(
        build_system="yarn",
        steps=[RecipeStep(command="cd <target> && yarn install")],
    )


def _maven_recipe(target: Path) -> BuildRecipe:
    return BuildRecipe(
        build_system="maven",
        steps=[RecipeStep(command="cd <target> && mvn package -DskipTests")],
    )


def _gradle_recipe(target: Path) -> BuildRecipe:
    return BuildRecipe(
        build_system="gradle",
        steps=[RecipeStep(command="cd <target> && ./gradlew build -x test")],
    )


_RECIPES = {
    "autotools": _autotools_recipe,
    "cmake": _cmake_recipe,
    "meson": _meson_recipe,
    "make": _make_recipe,
    "cargo": _cargo_recipe,
    "go": _go_recipe,
    "poetry": _poetry_recipe,
    "pip": _pip_recipe,
    "npm": _npm_recipe,
    "yarn": _yarn_recipe,
    "maven": _maven_recipe,
    "gradle": _gradle_recipe,
}


def _find_autotools_bootstrap(target: Path) -> Optional[str]:
    """Walk ``_AUTOTOOLS_BOOTSTRAP_CANDIDATES`` and return the
    first one present + executable. Returns None when no
    project-specific bootstrap is shipped (caller falls back to
    the canonical ``autoreconf -fi``)."""
    for candidate in _AUTOTOOLS_BOOTSTRAP_CANDIDATES:
        path = target / candidate.lstrip("./")
        if path.is_file():
            return candidate
    return None


__all__ = ["BuildRecipe", "RecipeStep", "build_recipe"]
