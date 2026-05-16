"""Tests for the /languages-driven shape classifier."""

from __future__ import annotations

from cve_diff.diffing import shape_dynamic


def _fetcher(payloads: dict[str, dict]) -> shape_dynamic.LanguagesFetcher:
    def fetch(slug: str):
        return payloads.get(slug)
    return fetch


class TestEmptyAndOffline:
    def test_empty_files_returns_source(self) -> None:
        assert shape_dynamic.classify([], "x/y", _fetcher({})) == "source"

    def test_no_slug_falls_back_to_static(self) -> None:
        # Static classifier returns 'source' for a real .c file.
        assert shape_dynamic.classify(["lib/foo.c"], None, _fetcher({})) == "source"

    def test_fetcher_none_falls_back_to_static(self) -> None:
        # Fetcher returns None -> static classifier handles it.
        assert (
            shape_dynamic.classify(
                ["CHANGELOG.md", "VERSION"],
                "x/y",
                fetch=lambda _: None,
            )
            == "packaging_only"
        )


class TestLanguageDriven:
    def test_python_file_in_python_repo_is_source(self) -> None:
        payloads = {"x/y": {"Python": 12345}}
        assert shape_dynamic.classify(["lib/foo.py"], "x/y", _fetcher(payloads)) == "source"

    def test_c_file_in_c_repo_is_source(self) -> None:
        payloads = {"linux/linux": {"C": 99999, "Assembly": 12}}
        assert (
            shape_dynamic.classify(
                ["net/netfilter/nft_set_rbtree.c"],
                "linux/linux",
                _fetcher(payloads),
            )
            == "source"
        )

    def test_python_file_in_go_only_repo_is_not_source(self) -> None:
        """If repo has no Python, a .py change is treated as non-source."""
        payloads = {"x/y": {"Go": 12345}}
        assert (
            shape_dynamic.classify(["scripts/build.py"], "x/y", _fetcher(payloads))
            == "packaging_only"
        )

    def test_unknown_extension_is_not_source(self) -> None:
        """An extension not in our intrinsic map can't validate as source."""
        payloads = {"x/y": {"Python": 12345}}
        assert (
            shape_dynamic.classify(["docs/spec.unknownext"], "x/y", _fetcher(payloads))
            == "packaging_only"
        )

    def test_changelog_only_with_languages_is_notes_only(self) -> None:
        payloads = {"x/y": {"Python": 12345}}
        assert (
            shape_dynamic.classify(["CHANGELOG.md"], "x/y", _fetcher(payloads))
            == "notes_only"
        )

    def test_dockerfile_only_with_languages_is_packaging_only(self) -> None:
        payloads = {"x/y": {"Go": 12345}}
        assert (
            shape_dynamic.classify(["Dockerfile"], "x/y", _fetcher(payloads))
            == "packaging_only"
        )

    def test_one_source_file_among_packaging_makes_it_source(self) -> None:
        payloads = {"x/y": {"C": 12345}}
        assert (
            shape_dynamic.classify(
                ["VERSION", "CHANGELOG.md", "lib/auth.c"],
                "x/y",
                _fetcher(payloads),
            )
            == "source"
        )


class TestRegressionsParityWithStatic:
    """Ensure dynamic mode preserves the regressions captured by static shape."""

    def test_runc_changelog_bump(self) -> None:
        """CVE-2024-21626 — repo is Go but only CHANGELOG.md + VERSION change."""
        payloads = {"opencontainers/runc": {"Go": 99999}}
        assert (
            shape_dynamic.classify(
                ["CHANGELOG.md", "VERSION"],
                "opencontainers/runc",
                _fetcher(payloads),
            )
            == "packaging_only"
        )

    def test_moby_buildkit_dockerfile_bump(self) -> None:
        payloads = {"moby/buildkit": {"Go": 99999}}
        assert (
            shape_dynamic.classify(
                ["Dockerfile"],
                "moby/buildkit",
                _fetcher(payloads),
            )
            == "packaging_only"
        )


class TestExtensionParsing:
    def test_no_extension_path(self) -> None:
        payloads = {"x/y": {"Shell": 100}}
        assert (
            shape_dynamic.classify(["bin/run-me"], "x/y", _fetcher(payloads))
            == "packaging_only"
        )

    def test_dotfile_no_extension(self) -> None:
        assert shape_dynamic._ext(".gitignore") == ""

    def test_extension_case_insensitive(self) -> None:
        payloads = {"x/y": {"C": 100}}
        assert (
            shape_dynamic.classify(["lib/Foo.C"], "x/y", _fetcher(payloads))
            == "source"
        )
