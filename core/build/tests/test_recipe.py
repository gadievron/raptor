"""Tests for ``core/build/recipe.py`` — operator-runnable
build recipes per detected build system. Key adversarial test:
autotools recipes adapt to the bootstrap script the project
actually ships (autogen.sh / bootstrap / autoreconf -fi)."""

from __future__ import annotations

from core.build.recipe import (
    RecipeStep,
    build_recipe,
)


class TestUnknownBuildSystem:
    def test_unknown_returns_empty_recipe(self, tmp_path):
        result = build_recipe(tmp_path, "imaginary")
        assert result.build_system == "imaginary"
        assert result.steps == []

    def test_empty_string_returns_empty_recipe(self, tmp_path):
        result = build_recipe(tmp_path, "")
        assert result.steps == []


class TestAutotoolsRecipe:
    """The headline adversarial test — autotools recipes must
    adapt to what's in the tree."""

    def test_clean_checkout_with_autogen_sh_recommends_it(self, tmp_path):
        # Clean autotools checkout: no configure script;
        # autogen.sh is the conventional bootstrap. Recipe
        # uses OUT-OF-SOURCE build (bootstrap in source root,
        # then configure + make in build/ subdir) to keep
        # object files out of the source tree.
        (tmp_path / "configure.ac").write_text("")
        (tmp_path / "autogen.sh").write_text("#!/bin/sh\nautoreconf -fi")
        recipe = build_recipe(tmp_path, "autotools")
        cmds = [s.command for s in recipe.steps]
        # 2 steps: bootstrap (in source root) + combined
        # mkdir/cd/configure/make in build/.
        assert len(recipe.steps) == 2
        assert "./autogen.sh" in cmds[0]
        # Combined out-of-source step does configure + make.
        assert "mkdir -p build" in cmds[1]
        assert "../configure" in cmds[1]
        assert "make" in cmds[1]
        # Bootstrap step explains why.
        assert recipe.steps[0].why and "autogen.sh" in recipe.steps[0].why
        # Out-of-source step explains its anti-pollution
        # rationale.
        assert recipe.steps[1].why and "out-of-source" in recipe.steps[1].why

    def test_clean_checkout_with_bootstrap_script(self, tmp_path):
        # ``bootstrap`` (as monit ships) is also recognised.
        (tmp_path / "configure.ac").write_text("")
        (tmp_path / "bootstrap").write_text("#!/bin/sh\nautoreconf -fi")
        recipe = build_recipe(tmp_path, "autotools")
        assert "./bootstrap" in recipe.steps[0].command

    def test_buildconf_bootstrap_apache_style(self, tmp_path):
        # Apache projects ship ./buildconf rather than bootstrap.
        (tmp_path / "configure.ac").write_text("")
        (tmp_path / "buildconf").write_text("#!/bin/sh\nautoreconf -fi")
        recipe = build_recipe(tmp_path, "autotools")
        assert "./buildconf" in recipe.steps[0].command

    def test_clean_checkout_no_bootstrap_uses_autoreconf(self, tmp_path):
        # No bootstrap script of any kind → fall back to
        # canonical autoreconf -fi.
        (tmp_path / "configure.ac").write_text("")
        recipe = build_recipe(tmp_path, "autotools")
        assert "autoreconf -fi" in recipe.steps[0].command

    def test_configure_already_present_skips_bootstrap(self, tmp_path):
        # If ./configure already exists (operator pulled a
        # release tarball with generated artefacts, or ran
        # autoreconf earlier), skip the bootstrap step entirely.
        # Recipe is a single out-of-source build step.
        (tmp_path / "configure.ac").write_text("")
        (tmp_path / "configure").write_text("#!/bin/sh")
        recipe = build_recipe(tmp_path, "autotools")
        cmds = [s.command for s in recipe.steps]
        # 1 step: combined out-of-source build.
        assert len(recipe.steps) == 1
        assert "mkdir -p build" in cmds[0]
        assert "../configure" in cmds[0]
        assert "make" in cmds[0]
        # No bootstrap-related step.
        assert not any(
            "autoreconf" in c or "autogen" in c or "/bootstrap" in c
            for c in cmds
        )

    def test_configure_present_skips_bootstrap_even_when_autogen_exists(
        self, tmp_path,
    ):
        # Real shape: operator pulled a release tarball that
        # ships BOTH configure (already generated) AND
        # autogen.sh (kept for re-bootstrap). Recipe MUST skip
        # the bootstrap step — running ./autogen.sh would
        # regenerate configure unnecessarily and could break a
        # subsequent ./configure run if autoconf is missing.
        # Pre-fix a "if autogen.sh exists, always run it"
        # regression would slip past the existing tests
        # because each tested one bootstrap scenario in
        # isolation.
        #
        # Post out-of-source refactor: recipe is a single
        # combined step (``mkdir -p build && cd build &&
        # ../configure && make``) when configure is present —
        # no separate bootstrap step.
        (tmp_path / "configure.ac").write_text("")
        (tmp_path / "configure").write_text("#!/bin/sh")
        (tmp_path / "autogen.sh").write_text("#!/bin/sh")
        recipe = build_recipe(tmp_path, "autotools")
        cmds = [s.command for s in recipe.steps]
        assert len(recipe.steps) == 1, (
            f"expected 1 combined out-of-source step (no "
            f"bootstrap) when configure is present; got: {cmds}"
        )
        # The single step must NOT run autogen.sh / autoreconf /
        # bootstrap.
        assert not any("autogen" in c for c in cmds), (
            f"autogen.sh must NOT run when configure exists; "
            f"got: {cmds}"
        )
        assert not any("autoreconf" in c for c in cmds)
        assert not any("/bootstrap" in c for c in cmds)
        # And it MUST be the out-of-source shape.
        assert "mkdir -p build" in cmds[0]
        assert "../configure" in cmds[0]
        assert "make" in cmds[0]

    def test_bootstrap_preference_order(self, tmp_path):
        # When MULTIPLE bootstrap scripts exist (rare but
        # legal), autogen.sh wins per
        # ``_AUTOTOOLS_BOOTSTRAP_CANDIDATES`` ordering — it's
        # the most common modern convention.
        (tmp_path / "configure.ac").write_text("")
        (tmp_path / "autogen.sh").write_text("")
        (tmp_path / "bootstrap").write_text("")
        recipe = build_recipe(tmp_path, "autotools")
        assert "./autogen.sh" in recipe.steps[0].command


class TestCmakeRecipe:
    def test_no_existing_build_dir_creates_one(self, tmp_path):
        (tmp_path / "CMakeLists.txt").write_text("")
        recipe = build_recipe(tmp_path, "cmake")
        cmd = recipe.steps[0].command
        assert "mkdir -p build" in cmd
        assert "cmake .." in cmd
        assert "make" in cmd

    def test_existing_build_dir_reused(self, tmp_path):
        (tmp_path / "CMakeLists.txt").write_text("")
        (tmp_path / "build").mkdir()
        recipe = build_recipe(tmp_path, "cmake")
        cmd = recipe.steps[0].command
        assert "build" in cmd
        # Should NOT re-create the build dir.
        assert "mkdir -p build" not in cmd

    def test_underscore_build_dir_reused(self, tmp_path):
        # Ninja / non-CMake-default convention.
        (tmp_path / "_build").mkdir()
        recipe = build_recipe(tmp_path, "cmake")
        assert "_build" in recipe.steps[0].command
        assert "mkdir" not in recipe.steps[0].command

    def test_cmake_build_debug_dir_reused(self, tmp_path):
        # CLion default — common in JetBrains workflows.
        (tmp_path / "cmake-build-debug").mkdir()
        recipe = build_recipe(tmp_path, "cmake")
        assert "cmake-build-debug" in recipe.steps[0].command
        assert "mkdir" not in recipe.steps[0].command


class TestMakeRecipe:
    def test_plain_make_one_step(self, tmp_path):
        recipe = build_recipe(tmp_path, "make")
        assert len(recipe.steps) == 1
        assert recipe.steps[0].command == "cd <target> && make"


class TestPipRecipe:
    def test_pyproject_present_uses_editable_install(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("")
        recipe = build_recipe(tmp_path, "pip")
        assert "pip install -e ." in recipe.steps[0].command

    def test_setup_py_present_uses_editable_install(self, tmp_path):
        (tmp_path / "setup.py").write_text("")
        recipe = build_recipe(tmp_path, "pip")
        assert "pip install -e ." in recipe.steps[0].command

    def test_requirements_only_uses_requirements_install(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("")
        recipe = build_recipe(tmp_path, "pip")
        assert "pip install -r requirements.txt" in recipe.steps[0].command

    def test_nothing_recognisable_falls_back_to_editable(self, tmp_path):
        # No manifest → default to editable; pip will error
        # with a clear message if there's nothing to install.
        recipe = build_recipe(tmp_path, "pip")
        assert "pip install -e ." in recipe.steps[0].command


class TestOtherBuildSystems:
    """Coverage of the smaller recipe builders."""

    def test_cargo(self, tmp_path):
        recipe = build_recipe(tmp_path, "cargo")
        assert "cargo build" in recipe.steps[0].command

    def test_go(self, tmp_path):
        recipe = build_recipe(tmp_path, "go")
        assert "go build" in recipe.steps[0].command

    def test_meson(self, tmp_path):
        recipe = build_recipe(tmp_path, "meson")
        assert "meson setup" in recipe.steps[0].command

    def test_maven(self, tmp_path):
        recipe = build_recipe(tmp_path, "maven")
        assert "mvn package" in recipe.steps[0].command

    def test_gradle(self, tmp_path):
        recipe = build_recipe(tmp_path, "gradle")
        assert "gradlew" in recipe.steps[0].command


class TestRecipeStepDataclass:
    """Pin the RecipeStep shape — consumer renderers depend
    on the field names."""

    def test_default_values(self):
        step = RecipeStep(command="make")
        assert step.command == "make"
        assert step.why is None
        assert step.optional is False

    def test_with_why_and_optional(self):
        step = RecipeStep(
            command="./bootstrap",
            why="generates configure",
            optional=True,
        )
        assert step.why == "generates configure"
        assert step.optional is True
