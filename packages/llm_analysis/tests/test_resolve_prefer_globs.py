"""Tests for ``resolve_prefer_globs`` — the operator/catalog
attack-surface ranking arbitrator (QoL #9 L2)."""

from __future__ import annotations

from packages.llm_analysis.agent import (
    _dir_to_glob,
    resolve_prefer_globs,
)


class TestDirToGlob:
    def test_plain_dir_gets_trailing_star(self):
        assert _dir_to_glob("src/http") == "src/http/*"

    def test_trailing_slash_normalised(self):
        assert _dir_to_glob("src/http/") == "src/http/*"

    def test_already_globbed_passes_through(self):
        # Catalog entries like ``src/device/sysdep_*`` already
        # carry the wildcard — must not double-glob.
        assert _dir_to_glob("src/device/sysdep_*") == "src/device/sysdep_*"

    def test_wildcard_anywhere_passes_through(self):
        # Defensive: any ``*`` in the input means the catalog
        # author intended it as a glob; respect that.
        assert _dir_to_glob("**/handlers") == "**/handlers"


class TestOperatorOverridesCatalog:
    """When --prefer is supplied, the operator's globs win
    unconditionally — catalog defaults don't even get consulted
    (the catalog lookup is the slow path; skip it when not needed)."""

    def test_operator_globs_returned_as_is(self, tmp_path):
        # tmp_path is empty so catalog detection would return
        # ``generic`` (no attack_surface_high), but the operator
        # globs short-circuit before we get there.
        operator = ["src/auth/*", "src/api/*"]
        globs, source = resolve_prefer_globs(operator, tmp_path)
        assert globs == operator
        assert source == "--prefer"

    def test_operator_empty_list_falls_through_to_catalog(self, tmp_path):
        # Empty list = ''no operator preference''. Same as None;
        # fall through to catalog detection.
        (tmp_path / "configure.ac").write_text("")
        (tmp_path / "src" / "main.c").parent.mkdir(parents=True)
        (tmp_path / "src" / "main.c").write_text("")
        globs, source = resolve_prefer_globs([], tmp_path)
        # Catalog matches c.userspace-daemon → attack_surface_high
        # populated → globs returned with ``catalog 'X'`` source.
        assert globs is not None
        assert source.startswith("catalog ")


class TestCatalogFallback:
    """When --prefer isn't supplied, the catalog's
    ``attack_surface.high_priority_dirs`` for the matched target
    type becomes the implicit prefer-globs."""

    def test_c_userspace_daemon_target_uses_catalog_defaults(self, tmp_path):
        # Build a tree matching c.userspace-daemon detection
        # (autotools + .c files).
        (tmp_path / "configure.ac").write_text("")
        (tmp_path / "Makefile.am").write_text("")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.c").write_text("")
        globs, source = resolve_prefer_globs(None, tmp_path)
        assert globs is not None
        assert source == "catalog 'c.userspace-daemon'"
        # Catalog stores dirs like ``src/http`` — converted to
        # ``src/http/*`` for fnmatch.
        assert "src/http/*" in globs
        assert "src/api/*" in globs

    def test_python_web_app_target_uses_catalog_defaults(self, tmp_path):
        (tmp_path / "manage.py").write_text("")
        (tmp_path / "settings.py").write_text("")
        (tmp_path / "urls.py").write_text("")
        globs, source = resolve_prefer_globs(None, tmp_path)
        assert source == "catalog 'python.web-app'"
        # python.web-app catalog has globbed entries like
        # ``**/views`` already — should pass through.
        assert globs is not None
        assert any("views" in g for g in globs)

    def test_unmatched_target_returns_none(self, tmp_path):
        # Empty tree → catalog falls back to ``generic``, which
        # has empty attack_surface_high → returns None (no globs
        # to apply). Caller skips the prefer-sort step entirely.
        globs, source = resolve_prefer_globs(None, tmp_path)
        assert globs is None
        assert source is None

    def test_missing_repo_path_returns_none(self):
        globs, source = resolve_prefer_globs(None, None)
        assert globs is None
        assert source is None

    def test_nonexistent_repo_path_returns_none(self, tmp_path):
        # Path doesn't exist on disk → catalog detection walks
        # nothing → falls back to generic → no high_priority_dirs.
        globs, source = resolve_prefer_globs(
            None, tmp_path / "does-not-exist",
        )
        assert globs is None


class TestCatalogLoadFailureToleratedSilently:
    """Catalog substrate is best-effort. Any exception from
    ``load()`` must not break the agent — return (None, None) and
    let the run proceed with no prefer-sort."""

    def test_catalog_exception_returns_none(self, monkeypatch, tmp_path):
        # Inject a catalog.load that raises — agent must shrug
        # and continue.
        import core.run.target_types as tt
        def _boom(_path):
            raise RuntimeError("catalog corrupted")
        monkeypatch.setattr(tt, "load", _boom)
        globs, source = resolve_prefer_globs(None, tmp_path)
        assert globs is None
        assert source is None
