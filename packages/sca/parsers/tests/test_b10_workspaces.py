"""Tests for B10 — npm workspaces / pnpm catalogs / Yarn Berry
resolutions / npm overrides.

These exercise the spec shapes and project-wide pin fields that
modern monorepo / hierarchical-version-config setups use.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from packages.sca.models import PinStyle
from packages.sca.parsers._pnpm_catalog import (
    _clear_cache,
    find_workspace_root,
    get_catalogs,
    resolve_catalog_spec,
)
from packages.sca.parsers.package_json import (
    _flatten_overrides,
    _strip_descriptor,
    parse,
)


@pytest.fixture(autouse=True)
def _clear_catalog_cache():
    """The catalog cache is module-global. Tests must start clean."""
    _clear_cache()
    yield
    _clear_cache()


def _write_pkg(path: Path, data: dict) -> Path:
    path.write_text(json.dumps(data))
    return path


# ---------------------------------------------------------------------------
# workspace: prefix
# ---------------------------------------------------------------------------


def test_workspace_caret_recorded_as_path(tmp_path):
    pkg = _write_pkg(tmp_path / "package.json", {
        "dependencies": {"@my/internal": "workspace:^1.0.0"},
    })
    [d] = parse(pkg)
    assert d.pin_style == PinStyle.PATH
    assert d.version is None


def test_workspace_star(tmp_path):
    pkg = _write_pkg(tmp_path / "package.json", {
        "dependencies": {"shared": "workspace:*"},
    })
    [d] = parse(pkg)
    assert d.pin_style == PinStyle.PATH
    assert d.version is None


def test_workspace_path_form(tmp_path):
    pkg = _write_pkg(tmp_path / "package.json", {
        "dependencies": {"local": "workspace:./pkgs/local"},
    })
    [d] = parse(pkg)
    assert d.pin_style == PinStyle.PATH
    assert d.version is None


# ---------------------------------------------------------------------------
# pnpm catalog resolution
# ---------------------------------------------------------------------------


def test_catalog_default_resolved(tmp_path):
    """Default ``catalog:`` resolves via pnpm-workspace.yaml's
    top-level ``catalog`` map."""
    (tmp_path / "pnpm-workspace.yaml").write_text(
        "catalog:\n  react: ^18.2.0\n",
    )
    sub = tmp_path / "packages" / "app"
    sub.mkdir(parents=True)
    pkg = _write_pkg(sub / "package.json", {
        "dependencies": {"react": "catalog:"},
    })
    [d] = parse(pkg)
    assert d.pin_style == PinStyle.CARET
    assert d.version == "18.2.0"


def test_catalog_named_resolved(tmp_path):
    """``catalog:react17`` resolves via the ``catalogs.react17``
    section."""
    (tmp_path / "pnpm-workspace.yaml").write_text(
        "catalogs:\n  react17:\n    react: ^17.0.0\n",
    )
    sub = tmp_path / "packages" / "legacy"
    sub.mkdir(parents=True)
    pkg = _write_pkg(sub / "package.json", {
        "dependencies": {"react": "catalog:react17"},
    })
    [d] = parse(pkg)
    assert d.version == "17.0.0"


def test_catalog_unresolved_no_yaml(tmp_path):
    """No pnpm-workspace.yaml in any ancestor → emit UNKNOWN-pin
    row so the operator at least sees the dep name."""
    pkg = _write_pkg(tmp_path / "package.json", {
        "dependencies": {"react": "catalog:"},
    })
    [d] = parse(pkg)
    assert d.pin_style == PinStyle.UNKNOWN
    assert d.version is None
    assert "could not be resolved" in d.parser_confidence.reason


def test_catalog_unresolved_missing_entry(tmp_path):
    """YAML exists but the catalog doesn't declare the package —
    same UNKNOWN-pin fallback."""
    (tmp_path / "pnpm-workspace.yaml").write_text(
        "catalog:\n  vue: ^3.0.0\n",
    )
    pkg = _write_pkg(tmp_path / "package.json", {
        "dependencies": {"react": "catalog:"},
    })
    [d] = parse(pkg)
    assert d.pin_style == PinStyle.UNKNOWN
    assert d.parser_confidence.level == "low"


# ---------------------------------------------------------------------------
# pnpm catalog parser internals
# ---------------------------------------------------------------------------


def test_find_workspace_root_walks_up(tmp_path):
    (tmp_path / "pnpm-workspace.yaml").write_text("catalog: {}\n")
    deep = tmp_path / "a" / "b" / "c"
    deep.mkdir(parents=True)
    assert find_workspace_root(deep) == tmp_path


def test_find_workspace_root_returns_none_when_absent(tmp_path):
    deep = tmp_path / "a" / "b"
    deep.mkdir(parents=True)
    assert find_workspace_root(deep) is None


def test_get_catalogs_caches_per_root(tmp_path):
    """Second call shouldn't re-read the YAML file."""
    yaml_path = tmp_path / "pnpm-workspace.yaml"
    yaml_path.write_text("catalog:\n  a: ^1.0\n")
    first = get_catalogs(tmp_path)
    yaml_path.unlink()
    # File gone, but cached map should still be returned identically.
    second = get_catalogs(tmp_path)
    assert first == second
    assert "" in first and first[""]["a"] == "^1.0"


def test_get_catalogs_returns_empty_on_missing_yaml(tmp_path):
    assert get_catalogs(tmp_path) == {}


def test_resolve_catalog_spec_default():
    catalogs = {"": {"react": "^18.0"}}
    assert resolve_catalog_spec("catalog:", "react", catalogs) == "^18.0"


def test_resolve_catalog_spec_named():
    catalogs = {"react17": {"react": "^17.0"}}
    assert resolve_catalog_spec(
        "catalog:react17", "react", catalogs,
    ) == "^17.0"


def test_resolve_catalog_spec_returns_none_when_missing():
    catalogs = {"": {"react": "^18.0"}}
    assert resolve_catalog_spec(
        "catalog:react17", "react", catalogs,
    ) is None
    assert resolve_catalog_spec(
        "catalog:", "lodash", catalogs,
    ) is None


def test_resolve_catalog_spec_returns_none_for_non_catalog():
    assert resolve_catalog_spec("^1.0.0", "react", {}) is None


# ---------------------------------------------------------------------------
# resolutions / overrides
# ---------------------------------------------------------------------------


def test_overrides_flat(tmp_path):
    pkg = _write_pkg(tmp_path / "package.json", {
        "name": "app",
        "overrides": {
            "lodash": "4.17.21",
            "minimist": "1.2.6",
        },
    })
    deps = parse(pkg)
    by_name = {d.name: d for d in deps}
    assert "lodash" in by_name
    assert by_name["lodash"].version == "4.17.21"
    assert by_name["lodash"].source_kind == "override"
    assert by_name["lodash"].direct is True
    assert by_name["minimist"].source_kind == "override"


def test_resolutions_yarn_classic(tmp_path):
    pkg = _write_pkg(tmp_path / "package.json", {
        "name": "app",
        "resolutions": {
            "@types/react": "18.0.0",
        },
    })
    deps = parse(pkg)
    assert len(deps) == 1
    d = deps[0]
    assert d.name == "@types/react"
    assert d.version == "18.0.0"
    assert d.source_kind == "override"


def test_resolutions_yarn_berry_descriptor_key(tmp_path):
    """Yarn Berry resolutions keys can carry a descriptor:
    ``"foo@npm:^1.0": "1.0.5"``. The descriptor is stripped to
    leave just the package name."""
    pkg = _write_pkg(tmp_path / "package.json", {
        "name": "app",
        "resolutions": {
            "lodash@npm:^4.0.0": "4.17.21",
        },
    })
    deps = parse(pkg)
    assert len(deps) == 1
    assert deps[0].name == "lodash"
    assert deps[0].version == "4.17.21"


def test_overrides_nested_with_root_pin(tmp_path):
    """``"foo": {".": "1.0", "bar": "2.0"}`` — the ``"."`` is the
    tree-root pin; nested entries flatten into separate rows."""
    pkg = _write_pkg(tmp_path / "package.json", {
        "name": "app",
        "overrides": {
            "foo": {".": "1.0.0", "bar": "2.0.0"},
        },
    })
    deps = parse(pkg)
    by_name = {d.name: d for d in deps}
    assert by_name["foo"].version == "1.0.0"
    assert by_name["bar"].version == "2.0.0"


def test_overrides_alongside_dependencies(tmp_path):
    """Both ``dependencies`` and ``overrides`` populate; each emits
    its own row, distinguishable by source_kind."""
    pkg = _write_pkg(tmp_path / "package.json", {
        "name": "app",
        "dependencies": {"react": "^18.0.0"},
        "overrides": {"react": "18.2.0"},
    })
    deps = parse(pkg)
    sources = {(d.name, d.source_kind, d.version) for d in deps}
    assert ("react", "manifest", "18.0.0") in sources
    assert ("react", "override", "18.2.0") in sources


# ---------------------------------------------------------------------------
# _flatten_overrides + _strip_descriptor
# ---------------------------------------------------------------------------


def test_flatten_overrides_handles_mixed_shapes():
    block = {
        "lodash": "4.17.21",
        "react": {".": "18.2.0", "react-dom": "18.2.0"},
        "@types/node": "20.0.0",
    }
    flat = _flatten_overrides(block)
    pairs = sorted(flat)
    assert pairs == [
        ("@types/node", "20.0.0"),
        ("lodash", "4.17.21"),
        ("react", "18.2.0"),
        ("react-dom", "18.2.0"),
    ]


def test_flatten_overrides_skips_non_string_values():
    """A bogus ``"foo": 42`` shouldn't crash or emit a row."""
    flat = _flatten_overrides({"foo": 42, "bar": "1.0"})
    assert flat == [("bar", "1.0")]


def test_strip_descriptor_plain():
    assert _strip_descriptor("lodash") == "lodash"


def test_strip_descriptor_with_npm_prefix():
    assert _strip_descriptor("lodash@npm:^4.0.0") == "lodash"


def test_strip_descriptor_scoped():
    assert _strip_descriptor("@types/react@npm:^18.0") == "@types/react"


def test_strip_descriptor_scoped_no_descriptor():
    assert _strip_descriptor("@types/react") == "@types/react"


def test_strip_descriptor_yarn_parent_child_resolution():
    """Yarn's ``parent/child`` resolution key — the parent is only a
    position filter; the actual package name is the child. Pre-fix
    SCA used the whole ``parent/child`` string as a package name
    and emitted a URL-encoded ``parent%2Fchild`` registry lookup
    that npm returned 405 on. Surfaced by the May 2026 200-project
    sweep against Grafana's resolutions block:

        "ngtemplate-loader/loader-utils": "^2.0.0"

    means "pin ``loader-utils`` to ^2.0.0 when ``ngtemplate-loader``
    transitively pulls it in" — record ``loader-utils`` only.
    """
    assert _strip_descriptor(
        "ngtemplate-loader/loader-utils",
    ) == "loader-utils"


def test_strip_descriptor_yarn_parent_child_with_descriptor():
    """``parent/child@selector`` — strip parent THEN descriptor."""
    assert _strip_descriptor(
        "ngtemplate-loader/loader-utils@npm:^2.0",
    ) == "loader-utils"


def test_strip_descriptor_scoped_not_treated_as_parent_child():
    """A scoped-name key (``@scope/pkg``) starts with ``@`` and must
    NOT be mistaken for a yarn parent/child resolution. The /
    inside the scope is part of the package's canonical name."""
    assert _strip_descriptor("@scope/pkg") == "@scope/pkg"
    assert _strip_descriptor("@scope/pkg@npm:^1.0") == "@scope/pkg"


# ---------------------------------------------------------------------------
# npm / Yarn workspaces — find_npm_workspace_root + workspace_root linkage
# ---------------------------------------------------------------------------


class TestNpmWorkspaceRoot:
    """``find_npm_workspace_root`` walks up to find the root
    ``package.json`` whose ``workspaces`` field globs to include a
    given member path. Used by the ``package_json`` parser to stamp
    ``Dependency.workspace_root`` so hygiene checks group correctly."""

    def _project(self, tmp_path: Path, files: dict) -> Path:
        for rel, contents in files.items():
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(contents)
        return tmp_path

    def test_finds_root_via_simple_glob(self, tmp_path: Path):
        from packages.sca.parsers._pnpm_catalog import (
            find_npm_workspace_root,
        )
        root = self._project(tmp_path, {
            "package.json": json.dumps({
                "name": "monorepo",
                "workspaces": ["packages/*"],
            }),
            "packages/foo/package.json": json.dumps({
                "name": "foo", "version": "1.0",
            }),
            "packages/bar/package.json": json.dumps({
                "name": "bar", "version": "1.0",
            }),
        })
        assert find_npm_workspace_root(
            root / "packages/foo/package.json"
        ) == root.resolve()
        assert find_npm_workspace_root(
            root / "packages/bar/package.json"
        ) == root.resolve()

    def test_finds_root_via_explicit_path(self, tmp_path: Path):
        """Workspaces field can list explicit paths, not just globs."""
        from packages.sca.parsers._pnpm_catalog import (
            find_npm_workspace_root,
        )
        root = self._project(tmp_path, {
            "package.json": json.dumps({
                "workspaces": ["apps/web", "apps/api"],
            }),
            "apps/web/package.json": "{}",
            "apps/api/package.json": "{}",
            "apps/cli/package.json": "{}",       # NOT in workspaces
        })
        assert find_npm_workspace_root(
            root / "apps/web/package.json"
        ) == root.resolve()
        assert find_npm_workspace_root(
            root / "apps/api/package.json"
        ) == root.resolve()
        # cli isn't a member — no root.
        assert find_npm_workspace_root(
            root / "apps/cli/package.json"
        ) is None

    def test_yarn_nohoist_object_form(self, tmp_path: Path):
        """Yarn classic accepts ``"workspaces": {"packages": [...]}``
        for nohoist configurations."""
        from packages.sca.parsers._pnpm_catalog import (
            find_npm_workspace_root,
        )
        root = self._project(tmp_path, {
            "package.json": json.dumps({
                "workspaces": {
                    "packages": ["pkgs/*"],
                    "nohoist": ["**/some-dep"],
                },
            }),
            "pkgs/foo/package.json": "{}",
        })
        assert find_npm_workspace_root(
            root / "pkgs/foo/package.json"
        ) == root.resolve()

    def test_negation_pattern_excludes_member(self, tmp_path: Path):
        """``!packages/legacy`` excludes a path even if an earlier
        glob included it."""
        from packages.sca.parsers._pnpm_catalog import (
            find_npm_workspace_root,
        )
        root = self._project(tmp_path, {
            "package.json": json.dumps({
                "workspaces": ["packages/*", "!packages/legacy"],
            }),
            "packages/active/package.json": "{}",
            "packages/legacy/package.json": "{}",
        })
        assert find_npm_workspace_root(
            root / "packages/active/package.json"
        ) == root.resolve()
        assert find_npm_workspace_root(
            root / "packages/legacy/package.json"
        ) is None

    def test_recursive_glob(self, tmp_path: Path):
        """Yarn Berry's ``**`` matches arbitrary depth."""
        from packages.sca.parsers._pnpm_catalog import (
            find_npm_workspace_root,
        )
        root = self._project(tmp_path, {
            "package.json": json.dumps({
                "workspaces": ["nested/**"],
            }),
            "nested/a/package.json": "{}",
            "nested/a/b/package.json": "{}",
        })
        assert find_npm_workspace_root(
            root / "nested/a/package.json"
        ) == root.resolve()
        assert find_npm_workspace_root(
            root / "nested/a/b/package.json"
        ) == root.resolve()

    def test_no_workspaces_field_returns_none(self, tmp_path: Path):
        from packages.sca.parsers._pnpm_catalog import (
            find_npm_workspace_root,
        )
        root = self._project(tmp_path, {
            "package.json": json.dumps({"name": "single"}),
            "lib/foo/package.json": "{}",
        })
        assert find_npm_workspace_root(
            root / "lib/foo/package.json"
        ) is None

    def test_unreadable_or_malformed_skipped(self, tmp_path: Path):
        """A package.json that's unreadable / non-JSON / non-object
        shouldn't crash the walk-up — keep walking."""
        from packages.sca.parsers._pnpm_catalog import (
            find_npm_workspace_root,
        )
        root = self._project(tmp_path, {
            "package.json": json.dumps({"workspaces": ["**/foo"]}),
            "broken/package.json": "this is not json",
            "broken/foo/package.json": "{}",
        })
        assert find_npm_workspace_root(
            root / "broken/foo/package.json"
        ) == root.resolve()

    def test_root_itself_isnt_member_of_its_own_workspaces(
        self, tmp_path: Path,
    ):
        """find_npm_workspace_root(root_pkg) returns None — root
        isn't a workspace member of itself."""
        from packages.sca.parsers._pnpm_catalog import (
            find_npm_workspace_root,
        )
        root = self._project(tmp_path, {
            "package.json": json.dumps({"workspaces": ["packages/*"]}),
            "packages/foo/package.json": "{}",
        })
        assert find_npm_workspace_root(
            root / "package.json"
        ) is None


class TestWorkspaceRootStampedOnDeps:
    """``parse(member_pkg)`` populates ``Dependency.workspace_root``
    with the monorepo root path, so hygiene checks group multi-
    workspace deps under one logical project."""

    def _project(self, tmp_path: Path, files: dict) -> Path:
        for rel, contents in files.items():
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(contents)
        return tmp_path

    def test_member_deps_carry_workspace_root(self, tmp_path: Path):
        root = self._project(tmp_path, {
            "package.json": json.dumps({"workspaces": ["packages/*"]}),
            "packages/foo/package.json": json.dumps({
                "name": "foo", "version": "1.0",
                "dependencies": {"lodash": "^4.0.0"},
            }),
        })
        deps = parse(root / "packages/foo/package.json")
        assert len(deps) == 1
        assert deps[0].workspace_root == root.resolve()

    def test_root_deps_carry_workspace_root_pointing_at_self(
        self, tmp_path: Path,
    ):
        """The workspace ROOT itself can have its own ``dependencies``.
        Stamp them with workspace_root=root_dir too, so hygiene
        groups root-deps with member-deps under the same monorepo
        identity."""
        root = self._project(tmp_path, {
            "package.json": json.dumps({
                "workspaces": ["packages/*"],
                "dependencies": {"react": "^18.0.0"},
            }),
        })
        deps = parse(root / "package.json")
        assert len(deps) == 1
        assert deps[0].workspace_root == root.resolve()

    def test_non_workspace_pkg_has_no_workspace_root(self, tmp_path: Path):
        """A standalone package.json (no workspaces field, no parent
        workspace) leaves workspace_root unset (None)."""
        root = self._project(tmp_path, {
            "package.json": json.dumps({
                "name": "lonely",
                "dependencies": {"lodash": "1.0.0"},
            }),
        })
        deps = parse(root / "package.json")
        assert len(deps) == 1
        assert deps[0].workspace_root is None

    def test_pnpm_workspace_takes_precedence(self, tmp_path: Path):
        """When both pnpm-workspace.yaml AND a workspaces field
        exist, the pnpm root wins (canonical for that toolchain)."""
        root = self._project(tmp_path, {
            "pnpm-workspace.yaml": "packages:\n  - 'packages/*'\n",
            "package.json": json.dumps({"workspaces": ["packages/*"]}),
            "packages/foo/package.json": json.dumps({
                "name": "foo",
                "dependencies": {"lodash": "1.0.0"},
            }),
        })
        deps = parse(root / "packages/foo/package.json")
        assert deps[0].workspace_root == root.resolve()
