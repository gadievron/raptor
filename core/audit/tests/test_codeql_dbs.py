"""Language-aware CodeQL database routing (multi-language targets)."""

import zipfile

from core.audit.codeql_dbs import (
    CodeqlDbRouter,
    database_language,
    db_contains_source,
    normalise_language,
)


def _make_db(tmp_path, name: str, primary: str | None):
    db = tmp_path / name
    db.mkdir()
    if primary is not None:
        (db / "codeql-database.yml").write_text(
            f"primaryLanguage: {primary}\n", encoding="utf-8",
        )
    return db


class TestDatabaseLanguage:
    def test_reads_primary_language(self, tmp_path):
        db = _make_db(tmp_path, "whatever", "python")
        assert database_language(db) == "python"

    def test_normalises_aliases(self, tmp_path):
        db = _make_db(tmp_path, "whatever", "c")
        assert database_language(db) == "cpp"

    def test_dirname_fallback(self, tmp_path):
        assert database_language(_make_db(tmp_path, "python-db", None)) == "python"
        assert database_language(
            _make_db(tmp_path, "codeql-db-cpp", None)) == "cpp"

    def test_unknown(self, tmp_path):
        db = tmp_path / "mystery"
        db.mkdir()
        # Dirname fallback normalises but cannot invent a language —
        # "mystery" round-trips as-is, which the router then can't
        # match to any file extension. That is the acceptable failure
        # mode (the db only serves files when it's the sole one).
        assert database_language(db) == "mystery"

    def test_normalise_language(self):
        assert normalise_language("C++") == "cpp"
        assert normalise_language("TypeScript") == "javascript"
        assert normalise_language("kotlin") == "java"
        assert normalise_language("") is None
        assert normalise_language(None) is None


class TestRouter:
    def test_no_databases(self):
        router = CodeqlDbRouter([])
        assert router.primary is None
        assert router.for_file("src/a.c") is None

    def test_single_known_language_database_serves_only_its_language(
            self, tmp_path):
        db = _make_db(tmp_path, "python-db", "python")
        router = CodeqlDbRouter([str(db)])
        assert router.primary == str(db)
        assert router.for_file("src/a.py") == str(db)
        # A foreign-language file must NOT reach the sole database:
        # its queries error or return zero rows against a graph that
        # cannot contain the file, and that silence reads as
        # refutation-grade downstream.
        assert router.for_file("src/a.c") is None
        # Files outside the routing table are equally unanswerable.
        assert router.for_file("src/index.php") is None
        # Callers that cannot route (no file in hand) keep the sole db.
        assert router.for_file(None) == str(db)

    def test_single_unknown_language_database_stays_wildcard(
            self, tmp_path):
        db = _make_db(tmp_path, "mystery", None)
        router = CodeqlDbRouter([str(db)])
        # Language undecidable — lenient dispatch is the lesser harm.
        assert router.for_file("src/a.c") == str(db)
        assert router.for_file("src/index.php") == str(db)
        assert router.for_file(None) == str(db)

    def test_multi_database_routes_by_language(self, tmp_path):
        py = _make_db(tmp_path, "python-db", "python")
        cpp = _make_db(tmp_path, "cpp-db", "cpp")
        router = CodeqlDbRouter([str(py), str(cpp)])
        assert router.primary == str(py)
        assert router.for_file("src/a.py") == str(py)
        assert router.for_file("src/a.c") == str(cpp)
        assert router.for_file("src/a.hpp") == str(cpp)
        # Kotlin routes to the Java extractor's database.
        java = _make_db(tmp_path, "java-db", "java")
        router = CodeqlDbRouter([str(py), str(java)])
        assert router.for_file("src/App.kt") == str(java)

    def test_multi_database_no_match_is_none(self, tmp_path):
        py = _make_db(tmp_path, "python-db", "python")
        cpp = _make_db(tmp_path, "cpp-db", "cpp")
        router = CodeqlDbRouter([str(py), str(cpp)])
        assert router.for_file("src/a.rs") is None
        assert router.for_file("Makefile") is None
        assert router.for_file(None) is None

    def test_duplicate_language_first_wins(self, tmp_path):
        a = _make_db(tmp_path, "a-db", "python")
        b = _make_db(tmp_path, "b-db", "python")
        cpp = _make_db(tmp_path, "cpp-db", "cpp")
        router = CodeqlDbRouter([str(a), str(b), str(cpp)])
        assert router.for_file("x.py") == str(a)

    def test_js_extractor_extensions_route_to_javascript(self, tmp_path):
        # The JavaScript extractor owns Vue SFCs (.vue is one of its
        # declared file types) and the TS 4.7 module suffixes.
        js = _make_db(tmp_path, "javascript-db", "javascript")
        py = _make_db(tmp_path, "python-db", "python")
        router = CodeqlDbRouter([str(js), str(py)])
        for name in ("App.vue", "mod.mts", "mod.cts"):
            assert router.for_file(f"src/{name}") == str(js), name


class TestRouterLanguageHint:
    """Checklist-language fallback for extensions outside the table."""

    def test_inc_with_c_hint_routes_to_cpp_db(self, tmp_path):
        cpp = _make_db(tmp_path, "cpp-db", "cpp")
        py = _make_db(tmp_path, "python-db", "python")
        router = CodeqlDbRouter([str(cpp), str(py)])
        # The inventory content-routes .inc; its 'c' tag must
        # normalise to the cpp extractor's database.
        assert router.for_file(
            "src/impl.inc", language_hint="c") == str(cpp)

    def test_inc_with_c_hint_serves_sole_cpp_db(self, tmp_path):
        cpp = _make_db(tmp_path, "cpp-db", "cpp")
        router = CodeqlDbRouter([str(cpp)])
        assert router.for_file(
            "src/impl.inc", language_hint="c") == str(cpp)

    def test_unknown_extension_without_hint_stays_none(self, tmp_path):
        cpp = _make_db(tmp_path, "cpp-db", "cpp")
        py = _make_db(tmp_path, "python-db", "python")
        router = CodeqlDbRouter([str(cpp), str(py)])
        assert router.for_file("src/impl.inc") is None
        assert router.for_file("src/impl.inc", language_hint=None) is None

    def test_known_extension_beats_conflicting_hint(self, tmp_path):
        cpp = _make_db(tmp_path, "cpp-db", "cpp")
        py = _make_db(tmp_path, "python-db", "python")
        router = CodeqlDbRouter([str(cpp), str(py)])
        # Extension stays authoritative: a wrong hint on a mapped
        # suffix must not reroute the file.
        assert router.for_file(
            "src/a.py", language_hint="cpp") == str(py)

    def test_hint_outside_extractor_languages_is_no_route(self, tmp_path):
        cpp = _make_db(tmp_path, "cpp-db", "cpp")
        py = _make_db(tmp_path, "python-db", "python")
        router = CodeqlDbRouter([str(cpp), str(py)])
        # php-routed .inc: no CodeQL extractor, no database, no serve.
        assert router.for_file(
            "web/header.inc", language_hint="php") is None


def _make_src_db(tmp_path, name: str, entries: list[str]):
    db = tmp_path / name
    db.mkdir()
    with zipfile.ZipFile(db / "src.zip", "w") as zf:
        for entry in entries:
            zf.writestr(entry, "int x;\n")
    return db


class TestDbContainsSource:
    """src.zip membership: True/False when provable, None (fail-open)
    when the archive cannot answer."""

    def test_present_absent_and_suffix_anchoring(self, tmp_path):
        db = _make_src_db(tmp_path, "cpp-db", [
            "work/repo/src/table.inc",
            "usr/include/string.h",
        ])
        assert db_contains_source(db, "src/table.inc") is True
        assert db_contains_source(db, "src/orphan.inc") is False
        # Same basename, different parent: the match is /-anchored on
        # the whole relative path (mirrors the sweep's URI match).
        assert db_contains_source(db, "other/table.inc") is False

    def test_missing_or_corrupt_archive_is_unknown(self, tmp_path):
        no_src = tmp_path / "no-src-db"
        no_src.mkdir()
        assert db_contains_source(no_src, "src/a.c") is None
        bad = tmp_path / "bad-src-db"
        bad.mkdir()
        (bad / "src.zip").write_bytes(b"this is not a zip archive")
        assert db_contains_source(bad, "src/a.c") is None

    def test_index_served_from_cache_on_unchanged_archive(
            self, tmp_path, monkeypatch):
        import zipfile as zipfile_mod
        db = _make_src_db(tmp_path, "cached-db", ["work/repo/src/a.c"])
        assert db_contains_source(db, "src/a.c") is True

        def boom(*args, **kwargs):
            raise AssertionError(
                "unchanged archive must be served from the cache",
            )

        monkeypatch.setattr(zipfile_mod, "ZipFile", boom)
        assert db_contains_source(db, "src/a.c") is True
        assert db_contains_source(db, "src/b.c") is False


class TestOrchestratorDbForHint:
    """_codeql_db_for resolves the hint from the run's inventory."""

    def _config(self, tmp_path, router, inventory):
        from core.audit.orchestrator import OrchestratorConfig
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=None, codeql_db_path=None,
        )
        config.codeql_db_router = router
        config.inventory = inventory
        return config

    def test_inc_checklist_c_routes_via_hint(self, tmp_path):
        from core.audit.orchestrator import _codeql_db_for
        cpp = _make_db(tmp_path, "cpp-db", "cpp")
        py = _make_db(tmp_path, "python-db", "python")
        config = self._config(
            tmp_path,
            CodeqlDbRouter([str(cpp), str(py)]),
            {"files": [{"path": "src/table.inc", "language": "c"}]},
        )
        assert _codeql_db_for(config, "src/table.inc") == str(cpp)

    def test_unknown_extension_absent_from_inventory_stays_none(
            self, tmp_path):
        from core.audit.orchestrator import _codeql_db_for
        cpp = _make_db(tmp_path, "cpp-db", "cpp")
        py = _make_db(tmp_path, "python-db", "python")
        config = self._config(
            tmp_path,
            CodeqlDbRouter([str(cpp), str(py)]),
            {"files": [{"path": "src/other.c", "language": "c"}]},
        )
        assert _codeql_db_for(config, "src/table.inc") is None

    def test_known_extension_never_consults_inventory(self, tmp_path):
        from core.audit.orchestrator import _codeql_db_for
        cpp = _make_db(tmp_path, "cpp-db", "cpp")
        py = _make_db(tmp_path, "python-db", "python")
        # A poisoned checklist row on a mapped suffix must be inert:
        # the extension's answer wins without a lookup.
        config = self._config(
            tmp_path,
            CodeqlDbRouter([str(cpp), str(py)]),
            {"files": [{"path": "src/a.py", "language": "cpp"}]},
        )
        assert _codeql_db_for(config, "src/a.py") == str(py)
