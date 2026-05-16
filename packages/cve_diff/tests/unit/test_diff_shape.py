"""Unit tests for cve_diff.diffing.shape — the diff-content classifier."""

from __future__ import annotations

import pytest

from cve_diff.diffing import shape


class TestClassifyOne:
    @pytest.mark.parametrize("path", [
        "CHANGELOG.md",
        "NEWS",
        "HISTORY.rst",
        "docs/RelNotes/2.39.4.txt",
        "Documentation/RelNotes/2.39.4.txt",
        "RELEASE_NOTES.md",
    ])
    def test_notes(self, path: str):
        assert shape._classify_one(path) == "notes"

    @pytest.mark.parametrize("path", [
        "VERSION",
        "configure.ac",
        "Dockerfile",
        "package.json",
        "go.mod",
        "Cargo.lock",
        "SPECS/openssh.spec",
        "debian/changelog",
        "rpm/opencryptoki.spec",
        ".gitmodules",
    ])
    def test_packaging(self, path: str):
        assert shape._classify_one(path) == "packaging"

    @pytest.mark.parametrize("path", [
        "net/netfilter/nft_set_rbtree.c",
        "Lib/zipfile.py",
        "lib/auth/rsa_psk.c",
        "src/main.rs",
        "pkg/server/handler.go",
        "app/controllers/users_controller.rb",
    ])
    def test_source(self, path: str):
        assert shape._classify_one(path) == "source"


class TestClassify:
    def test_empty_is_source(self):
        assert shape.classify([]) == "source"

    def test_single_source_file(self):
        assert shape.classify(["lib/foo.c"]) == "source"

    def test_only_notes(self):
        assert shape.classify(["CHANGELOG.md", "docs/RelNotes/2.39.4.txt"]) == "notes_only"

    def test_only_packaging(self):
        assert shape.classify(["VERSION", "configure.ac"]) == "packaging_only"

    def test_notes_plus_packaging_is_packaging_only(self):
        assert shape.classify(["CHANGELOG.md", "VERSION", "configure.ac"]) == "packaging_only"

    def test_one_source_file_makes_it_source(self):
        assert shape.classify(["CHANGELOG.md", "VERSION", "lib/foo.c"]) == "source"

    def test_runc_changelog_bump_is_packaging_only(self):
        """Regression: CVE-2024-21626 runc CHANGELOG+VERSION bump — was Phase1 'pass'."""
        assert shape.classify(["CHANGELOG.md", "VERSION"]) == "packaging_only"

    def test_moby_buildkit_runc_bump(self):
        """Regression: CVE-2024-23651/2/3 moby/buildkit — Dockerfile only."""
        assert shape.classify(["Dockerfile"]) == "packaging_only"

    def test_kernel_patch_with_notes(self):
        """Regression: don't false-negative real kernel patches."""
        assert shape.classify([
            "net/netfilter/nft_set_rbtree.c",
            "CHANGELOG",
        ]) == "source"
