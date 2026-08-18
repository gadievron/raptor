"""Tests for core.audit.summary_cache."""

from __future__ import annotations

import json
from typing import ClassVar

from core.audit.summary_cache import (
    CachedSummary,
    SummaryCache,
    detect_library_version,
    load_summary_cache,
)


class TestCachedSummary:
    def test_to_dict(self):
        cs = CachedSummary(
            function="SSL_read",
            library="openssl",
            version="3.1.2",
            param_preconditions=[{"param": "ssl", "constraint": "!= NULL"}],
            confidence="high",
        )
        d = cs.to_dict()
        assert d["function"] == "SSL_read"
        assert d["library"] == "openssl"
        assert len(d["param_preconditions"]) == 1


class TestSummaryCache:
    def test_store_and_lookup(self, tmp_path):
        cache = SummaryCache(cache_dir=tmp_path)
        summaries = [
            CachedSummary(
                function="SSL_read", library="openssl", version="3.1.2",
                param_preconditions=[{"param": "ssl", "constraint": "!= NULL"}],
            ),
            CachedSummary(
                function="SSL_write", library="openssl", version="3.1.2",
            ),
        ]
        cache.store("openssl", "3.1.2", summaries)

        result = cache.lookup("openssl", "3.1.2", "SSL_read")
        assert result is not None
        assert result.function == "SSL_read"

        result = cache.lookup("openssl", "3.1.2", "nonexistent")
        assert result is None

    def test_has_library(self, tmp_path):
        cache = SummaryCache(cache_dir=tmp_path)
        assert not cache.has_library("openssl", "3.1.2")

        cache.store("openssl", "3.1.2", [
            CachedSummary(function="f", library="openssl", version="3.1.2"),
        ])
        assert cache.has_library("openssl", "3.1.2")
        assert not cache.has_library("openssl", "3.0.0")

    def test_lookup_library(self, tmp_path):
        cache = SummaryCache(cache_dir=tmp_path)
        cache.store("zlib", "1.3", [
            CachedSummary(function="deflate", library="zlib", version="1.3"),
            CachedSummary(function="inflate", library="zlib", version="1.3"),
        ])

        lib = cache.lookup_library("zlib", "1.3")
        assert len(lib) == 2
        assert "deflate" in lib
        assert "inflate" in lib

    def test_available_libraries(self, tmp_path):
        cache = SummaryCache(cache_dir=tmp_path)
        cache.store("openssl", "3.1.2", [
            CachedSummary(function="f", library="openssl", version="3.1.2"),
        ])
        cache.store("zlib", "1.3", [
            CachedSummary(function="g", library="zlib", version="1.3"),
        ])

        avail = cache.available_libraries()
        assert len(avail) == 2
        libs = {a["library"] for a in avail}
        assert "openssl" in libs
        assert "zlib" in libs

    def test_summary_empty(self, tmp_path):
        cache = SummaryCache(cache_dir=tmp_path)
        assert "empty" in cache.summary()

    def test_summary_with_entries(self, tmp_path):
        cache = SummaryCache(cache_dir=tmp_path)
        cache.store("openssl", "3.1.2", [
            CachedSummary(function="f", library="openssl", version="3.1.2"),
        ])
        s = cache.summary()
        assert "openssl" in s

    def test_version_isolation(self, tmp_path):
        cache = SummaryCache(cache_dir=tmp_path)
        cache.store("lib", "1.0", [
            CachedSummary(function="f", library="lib", version="1.0",
                          confidence="high"),
        ])
        cache.store("lib", "2.0", [
            CachedSummary(function="f", library="lib", version="2.0",
                          confidence="medium"),
        ])

        v1 = cache.lookup("lib", "1.0", "f")
        v2 = cache.lookup("lib", "2.0", "f")
        assert v1.confidence == "high"
        assert v2.confidence == "medium"

    def test_persistence(self, tmp_path):
        cache1 = SummaryCache(cache_dir=tmp_path)
        cache1.store("mylib", "0.1", [
            CachedSummary(function="init", library="mylib", version="0.1"),
        ])

        cache2 = SummaryCache(cache_dir=tmp_path)
        result = cache2.lookup("mylib", "0.1", "init")
        assert result is not None
        assert result.function == "init"


class TestPathTraversalRejection:
    """All public methods must reject path-traversal components."""

    _PAYLOADS: ClassVar[list[tuple[str, str]]] = [
        ("../../etc", "passwd"),
        ("openssl", "../../etc"),
        ("../", "1.0"),
        ("lib", "../../../tmp"),
        ("", "1.0"),
        ("lib", ""),
    ]

    def test_store_raises(self, tmp_path):
        import pytest
        cache = SummaryCache(cache_dir=tmp_path)
        for lib, ver in self._PAYLOADS:
            with pytest.raises(ValueError):
                cache.store(lib, ver, [])

    def test_lookup_returns_none(self, tmp_path):
        cache = SummaryCache(cache_dir=tmp_path)
        for lib, ver in self._PAYLOADS:
            assert cache.lookup(lib, ver, "f") is None

    def test_lookup_library_returns_empty(self, tmp_path):
        cache = SummaryCache(cache_dir=tmp_path)
        for lib, ver in self._PAYLOADS:
            assert cache.lookup_library(lib, ver) == {}

    def test_has_library_returns_false(self, tmp_path):
        cache = SummaryCache(cache_dir=tmp_path)
        for lib, ver in self._PAYLOADS:
            assert cache.has_library(lib, ver) is False


class TestDetectLibraryVersion:
    def test_requirements_txt(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "django==4.2.1\nflask>=2.0\n"
        )
        assert detect_library_version(tmp_path, "django") == "4.2.1"
        assert detect_library_version(tmp_path, "flask") == "2.0"

    def test_package_json(self, tmp_path):
        data = {
            "dependencies": {"express": "^4.18.2"},
            "devDependencies": {"jest": "~29.0.0"},
        }
        (tmp_path / "package.json").write_text(json.dumps(data))
        assert detect_library_version(tmp_path, "express") == "4.18.2"
        assert detect_library_version(tmp_path, "jest") == "29.0.0"

    def test_go_mod(self, tmp_path):
        (tmp_path / "go.mod").write_text(
            "module example.com/app\n\n"
            "require (\n"
            "\tgithub.com/gin-gonic/gin v1.9.1\n"
            ")\n"
        )
        assert detect_library_version(tmp_path, "gin") == "1.9.1"

    def test_go_mod_no_substring_match(self, tmp_path):
        """"crypto" must match golang.org/x/crypto, not cryptoutil."""
        (tmp_path / "go.mod").write_text(
            "module example.com/app\n\n"
            "require (\n"
            "\tgithub.com/foo/cryptoutil v0.0.9\n"
            "\tgolang.org/x/crypto v0.21.0\n"
            ")\n"
        )
        assert detect_library_version(tmp_path, "crypto") == "0.21.0"

    def test_go_mod_single_line_require(self, tmp_path):
        (tmp_path / "go.mod").write_text(
            "module example.com/app\n\n"
            "require golang.org/x/net v0.23.0\n"
        )
        assert detect_library_version(tmp_path, "net") == "0.23.0"

    def test_cargo_toml_plain_version(self, tmp_path):
        (tmp_path / "Cargo.toml").write_text(
            '[dependencies]\nserde = "1.0.190"\n'
        )
        assert detect_library_version(tmp_path, "serde") == "1.0.190"

    def test_cargo_toml_inline_table(self, tmp_path):
        """foo = { version = "1.0", features = [...] } must yield 1.0."""
        (tmp_path / "Cargo.toml").write_text(
            "[dependencies]\n"
            'serde = { version = "1.0.190", features = ["derive"] }\n'
        )
        assert detect_library_version(tmp_path, "serde") == "1.0.190"

    def test_cargo_toml_inline_table_no_version(self, tmp_path):
        """git/path deps carry no version — must not return garbage."""
        (tmp_path / "Cargo.toml").write_text(
            "[dependencies]\n"
            'mylib = { git = "https://example.com/mylib.git" }\n'
        )
        assert detect_library_version(tmp_path, "mylib") is None

    def test_not_found(self, tmp_path):
        assert detect_library_version(tmp_path, "nonexistent") is None

    def test_no_manifest(self, tmp_path):
        assert detect_library_version(tmp_path, "anything") is None


class TestLoadSummaryCache:
    def test_creates_cache(self, tmp_path):
        cache = load_summary_cache(tmp_path)
        assert isinstance(cache, SummaryCache)
        assert cache.cache_dir == tmp_path
