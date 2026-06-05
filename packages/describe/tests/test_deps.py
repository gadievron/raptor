"""Tests for ``packages/describe/deps.py``."""

from __future__ import annotations

from packages.describe.deps import (
    DependencyCounts,
    detect_dependency_counts,
)


class TestDetectDependencyCounts:
    def test_empty_tree_returns_empty(self, tmp_path):
        result = detect_dependency_counts(tmp_path)
        assert result == DependencyCounts(by_ecosystem={}, truncated=False)

    def test_npm_direct_deps_counted(self, tmp_path):
        (tmp_path / "package.json").write_text(
            '{"name": "demo", "version": "1.0.0",'
            '"dependencies": {'
            '  "react": "^18.0.0",'
            '  "lodash": "^4.17.21",'
            '  "express": "^4.18.0"'
            '},'
            '"devDependencies": {'
            '  "jest": "^29.0.0"'
            '}'
            '}'
        )
        result = detect_dependency_counts(tmp_path)
        # 3 prod + 1 dev = 4 direct deps. /sca's npm parser
        # counts both dependencies + devDependencies as direct.
        assert result.by_ecosystem.get("npm", 0) == 4

    def test_gomod_direct_deps_counted(self, tmp_path):
        # /sca's gomod parser uses ecosystem id "Go" (matches its
        # registry name, not the manifest filename).
        (tmp_path / "go.mod").write_text(
            "module example.com/demo\n\n"
            "go 1.21\n\n"
            "require (\n"
            "    github.com/gin-gonic/gin v1.9.1\n"
            "    github.com/sirupsen/logrus v1.9.3\n"
            ")\n"
        )
        result = detect_dependency_counts(tmp_path)
        assert result.by_ecosystem.get("Go", 0) >= 2

    def test_cargo_direct_deps_counted(self, tmp_path):
        # /sca's cargo parser uses ecosystem id "Cargo".
        (tmp_path / "Cargo.toml").write_text(
            '[package]\n'
            'name = "demo"\n'
            'version = "0.1.0"\n'
            'edition = "2021"\n\n'
            '[dependencies]\n'
            'tokio = "1"\n'
            'serde = "1"\n'
        )
        result = detect_dependency_counts(tmp_path)
        assert result.by_ecosystem.get("Cargo", 0) >= 2

    def test_multiple_ecosystems_counted_independently(self, tmp_path):
        # Ecosystem ids come from /sca parsers verbatim:
        # package_json → "npm", gomod → "Go".
        (tmp_path / "package.json").write_text(
            '{"name": "d", "version": "0.1.0",'
            '"dependencies": {"react": "^18.0.0"}}'
        )
        (tmp_path / "go.mod").write_text(
            "module demo\n\n"
            "go 1.21\n\n"
            "require github.com/gin-gonic/gin v1.9.1\n"
        )
        result = detect_dependency_counts(tmp_path)
        assert result.by_ecosystem.get("npm", 0) >= 1
        assert result.by_ecosystem.get("Go", 0) >= 1

    def test_lockfile_alone_does_not_inflate_count(self, tmp_path):
        # No package.json — just a lockfile. Lockfile is_lockfile=True
        # so the count stays 0 (avoids reporting transitive-dep counts
        # as direct).
        (tmp_path / "package-lock.json").write_text(
            '{"name": "d", "lockfileVersion": 3, "packages": {'
            '  "": {"name": "d"},'
            '  "node_modules/a": {"version": "1.0.0"},'
            '  "node_modules/b": {"version": "1.0.0"},'
            '  "node_modules/c": {"version": "1.0.0"}'
            '}}'
        )
        result = detect_dependency_counts(tmp_path)
        # Even with 3 transitive packages in the lockfile,
        # by_ecosystem stays empty because is_lockfile=True
        # manifests are skipped.
        assert "npm" not in result.by_ecosystem
