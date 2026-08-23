"""Tests for core.paths — the shared path-handling primitives.

Includes parity pins for the two consumers consolidated in the same
change (``core/inventory/lookup.normalise_path`` and
``core/analysis/reach_chokepoint.normalise_path``) plus explicit tests
for the reconciled drift: relative-path normalisation is now identical
in both modes, and an escaping relative path in strict mode returns
``None`` instead of flowing on toward a suppression lookup.
"""

from __future__ import annotations

import os

import pytest

from core.paths import confine, strip_file_uri, to_repo_relative


class TestStripFileUri:
    def test_strips_leading_scheme(self):
        assert strip_file_uri("file://src/main.c") == "src/main.c"

    def test_triple_slash_keeps_absolute(self):
        assert strip_file_uri("file:///abs/path.c") == "/abs/path.c"

    def test_mid_string_scheme_untouched(self):
        # The substring-replace variants this consolidates would
        # corrupt this path; the prefix-only helper must not.
        assert strip_file_uri("src/file://odd.c") == "src/file://odd.c"

    def test_no_scheme_passthrough(self):
        assert strip_file_uri("src/main.c") == "src/main.c"

    def test_no_percent_decoding(self):
        assert strip_file_uri("file://a%2eb.c") == "a%2eb.c"


class TestToRepoRelativeStrict:
    """outside_root="none" — the reach_chokepoint semantics."""

    def test_absolute_under_root(self, tmp_path):
        p = tmp_path / "src" / "a.c"
        assert to_repo_relative(str(p), tmp_path) == os.path.join("src", "a.c")

    def test_absolute_outside_root_returns_none(self, tmp_path):
        assert to_repo_relative("/etc/passwd", tmp_path) is None

    def test_file_uri_under_root(self, tmp_path):
        uri = f"file://{tmp_path}/src/a.c"
        assert to_repo_relative(uri, tmp_path) == os.path.join("src", "a.c")

    def test_file_uri_outside_root_returns_none(self, tmp_path):
        assert to_repo_relative("file:///etc/passwd", tmp_path) is None

    def test_empty_returns_none(self, tmp_path):
        assert to_repo_relative("", tmp_path) is None

    def test_relative_dot_slash_stripped(self, tmp_path):
        assert to_repo_relative("./src/a.c", tmp_path) == os.path.join(
            "src", "a.c")

    def test_relative_plain_passthrough(self, tmp_path):
        assert to_repo_relative("src/a.c", tmp_path) == os.path.join(
            "src", "a.c")

    def test_relative_inner_dot_segments_collapse(self, tmp_path):
        # Reconciled drift: the chokepoint copy only stripped a
        # leading "./", so "src/./a.c" failed to match inventory keys.
        assert to_repo_relative("src/./a.c", tmp_path) == os.path.join(
            "src", "a.c")
        assert to_repo_relative("src/x/../a.c", tmp_path) == os.path.join(
            "src", "a.c")

    def test_escaping_relative_returns_none(self, tmp_path):
        # Reconciled drift: an escaping relative path must never
        # license suppression — strict mode returns None (fail-open).
        assert to_repo_relative("../x.c", tmp_path) is None
        assert to_repo_relative("a/../../x.c", tmp_path) is None

    def test_symlinked_root_spelling_tolerated(self, tmp_path):
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)
        inside = real / "src" / "a.c"
        assert to_repo_relative(str(inside), link) == os.path.join(
            "src", "a.c")


class TestToRepoRelativeBestEffort:
    """outside_root="relative" — the inventory lookup semantics."""

    def test_absolute_under_root(self, tmp_path):
        p = tmp_path / "src" / "a.c"
        assert to_repo_relative(
            str(p), str(tmp_path), outside_root="relative",
        ) == os.path.join("src", "a.c")

    def test_absolute_outside_root_gives_dotdot_relative(self, tmp_path):
        out = to_repo_relative(
            "/etc/passwd", str(tmp_path / "repo"), outside_root="relative",
        )
        assert out is not None
        assert out.startswith("..")

    def test_never_none_on_empty(self, tmp_path):
        # normpath("") == "." — preserved from the lookup copy, whose
        # callers compare keys for equality and expect a string.
        assert to_repo_relative(
            "", str(tmp_path), outside_root="relative") == "."

    def test_relative_normalised(self, tmp_path):
        assert to_repo_relative(
            "./src/./a.c", str(tmp_path), outside_root="relative",
        ) == os.path.join("src", "a.c")

    def test_escaping_relative_survives(self, tmp_path):
        assert to_repo_relative(
            "../x.c", str(tmp_path), outside_root="relative",
        ) == os.path.join("..", "x.c")


class TestToRepoRelativeModeValidation:
    def test_unknown_mode_raises(self, tmp_path):
        with pytest.raises(ValueError):
            to_repo_relative("a.c", tmp_path, outside_root="keep")


class TestConfine:
    def test_relative_inside(self, tmp_path):
        assert confine(tmp_path, "src/a.c") == (
            tmp_path / "src" / "a.c").resolve()

    def test_base_itself_allowed(self, tmp_path):
        assert confine(tmp_path, ".") == tmp_path.resolve()

    def test_traversal_rejected(self, tmp_path):
        assert confine(tmp_path / "sub", "../../etc/passwd") is None

    def test_absolute_outside_rejected(self, tmp_path):
        assert confine(tmp_path, "/etc/passwd") is None

    def test_absolute_inside_allowed(self, tmp_path):
        inner = tmp_path / "src" / "a.c"
        assert confine(tmp_path, str(inner)) == inner.resolve()

    def test_symlink_escape_rejected(self, tmp_path):
        base = tmp_path / "base"
        base.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (base / "sneaky").symlink_to(outside)
        assert confine(base, "sneaky/f.txt") is None

    def test_nonexistent_target_ok(self, tmp_path):
        # Containment is decided lexically-after-resolve; the file
        # need not exist.
        assert confine(tmp_path, "does/not/exist.c") is not None

    def test_prefix_collision_rejected(self, tmp_path):
        # /repo-evil must not pass for base /repo (the startswith-
        # without-separator bug some inline copies carry).
        base = tmp_path / "repo"
        base.mkdir()
        evil = tmp_path / "repo-evil"
        evil.mkdir()
        assert confine(base, str(evil / "f.c")) is None


class TestConsumerParity:
    """The two consolidated consumers keep their exact semantics."""

    def test_lookup_normalise_path_delegates(self, tmp_path):
        from core.inventory.lookup import normalise_path as lookup_norm
        p = tmp_path / "src" / "a.c"
        assert lookup_norm(str(p), str(tmp_path)) == os.path.join(
            "src", "a.c")
        assert lookup_norm(f"file://{p}", str(tmp_path)) == os.path.join(
            "src", "a.c")
        # Out-of-root stays best-effort ../.. — never None.
        out = lookup_norm("/etc/passwd", str(tmp_path / "repo"))
        assert out is not None and out.startswith("..")
        # Empty entry paths keep normalising to "." (key comparison).
        assert lookup_norm("", str(tmp_path)) == "."

    def test_chokepoint_normalise_path_delegates(self, tmp_path):
        from core.analysis.reach_chokepoint import (
            normalise_path as choke_norm,
        )
        p = tmp_path / "src" / "a.c"
        assert choke_norm(str(p), tmp_path) == os.path.join("src", "a.c")
        assert choke_norm("/etc/passwd", tmp_path) is None
        assert choke_norm("", tmp_path) is None
        assert choke_norm("./src/a.c", tmp_path) == os.path.join(
            "src", "a.c")

    def test_chokepoint_escaping_relative_now_none(self, tmp_path):
        # Drift fix pin: pre-consolidation the chokepoint copy passed
        # "../x.c" through unchanged, letting an escaping path flow
        # into the suppression lookup. It must return None (fail-open:
        # never suppress on a path outside the analysed tree).
        from core.analysis.reach_chokepoint import (
            normalise_path as choke_norm,
        )
        assert choke_norm("../x.c", tmp_path) is None


class TestPathToModule:
    """Shared ``path_to_module`` — one implementation for the five
    call-graph consumers (chokepoint, reach_audit, enrichment,
    validate reachability, codeql prefilter)."""

    def test_simple(self):
        from core.paths import path_to_module
        assert path_to_module("packages/foo/bar.py") == "packages.foo.bar"

    def test_windows_separators(self):
        from core.paths import path_to_module
        assert path_to_module("packages\\foo\\bar.py") == "packages.foo.bar"

    def test_no_extension_returns_none(self):
        from core.paths import path_to_module
        assert path_to_module("Makefile") is None

    def test_empty_returns_none(self):
        from core.paths import path_to_module
        assert path_to_module("") is None

    def test_non_python_extension_stripped(self):
        from core.paths import path_to_module
        assert path_to_module("src/main.go") == "src.main"
        assert path_to_module("src/main.js") == "src.main"

    def test_dunder_init_not_collapsed(self):
        # The one divergent copy (core/analysis/reachability.
        # _file_path_to_module) collapses __init__; the shared helper
        # deliberately does not — pin that boundary.
        from core.paths import path_to_module
        assert path_to_module("foo/__init__.py") == "foo.__init__"

    def test_chokepoint_delegates(self):
        from core.analysis import reach_chokepoint
        from core.paths import path_to_module
        assert reach_chokepoint.path_to_module(
            "packages/foo/bar.py"
        ) == path_to_module("packages/foo/bar.py")
