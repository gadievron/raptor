"""Language-aware CodeQL database routing (multi-language targets)."""

from core.audit.codeql_dbs import (
    CodeqlDbRouter,
    database_language,
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

    def test_single_database_is_wildcard(self, tmp_path):
        db = _make_db(tmp_path, "python-db", "python")
        router = CodeqlDbRouter([str(db)])
        assert router.primary == str(db)
        # Historic behaviour: one db serves every file, matching or not.
        assert router.for_file("src/a.c") == str(db)
        assert router.for_file("src/a.py") == str(db)
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
