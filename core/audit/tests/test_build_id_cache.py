"""Tests for core.audit.build_id_cache."""

from __future__ import annotations

from core.audit.build_id_cache import (
    BuildIDCache,
    import_layer0_findings,
    import_validate_evidence,
    load_build_id_cache,
)


class TestBuildIDCache:
    def test_put_and_get(self, tmp_path):
        cache = BuildIDCache(cache_dir=tmp_path)
        cache.put("abc123", "metadata", {"pie": True}, source_command="audit")
        result = cache.get("abc123", "metadata")
        assert result is not None
        assert result["data"]["pie"] is True
        assert result["build_id"] == "abc123"

    def test_has(self, tmp_path):
        cache = BuildIDCache(cache_dir=tmp_path)
        assert not cache.has("abc123", "metadata")
        cache.put("abc123", "metadata", {"x": 1})
        assert cache.has("abc123", "metadata")

    def test_get_missing(self, tmp_path):
        cache = BuildIDCache(cache_dir=tmp_path)
        assert cache.get("nonexistent", "metadata") is None

    def test_available_artifacts(self, tmp_path):
        cache = BuildIDCache(cache_dir=tmp_path)
        cache.put("abc123", "metadata", {})
        cache.put("abc123", "symbols", {})
        artifacts = cache.available_artifacts("abc123")
        assert "metadata" in artifacts
        assert "symbols" in artifacts

    def test_available_artifacts_empty(self, tmp_path):
        cache = BuildIDCache(cache_dir=tmp_path)
        assert cache.available_artifacts("nonexistent") == []

    def test_evict(self, tmp_path):
        cache = BuildIDCache(cache_dir=tmp_path)
        cache.put("abc123", "metadata", {})
        cache.put("abc123", "symbols", {})
        count = cache.evict("abc123")
        assert count == 2
        assert not cache.has("abc123", "metadata")

    def test_evict_nonexistent(self, tmp_path):
        cache = BuildIDCache(cache_dir=tmp_path)
        assert cache.evict("nope") == 0

    def test_summary_empty(self, tmp_path):
        cache = BuildIDCache(cache_dir=tmp_path)
        assert "empty" in cache.summary()

    def test_summary_with_entries(self, tmp_path):
        cache = BuildIDCache(cache_dir=tmp_path)
        cache.put("abc123", "metadata", {})
        cache.put("def456", "symbols", {})
        s = cache.summary()
        assert "2 binaries" in s
        assert "2 artifacts" in s

    def test_persistence(self, tmp_path):
        cache1 = BuildIDCache(cache_dir=tmp_path)
        cache1.put("abc123", "metadata", {"test": True})

        cache2 = BuildIDCache(cache_dir=tmp_path)
        result = cache2.get("abc123", "metadata")
        assert result is not None
        assert result["data"]["test"] is True

    def test_overwrite(self, tmp_path):
        cache = BuildIDCache(cache_dir=tmp_path)
        cache.put("abc123", "metadata", {"version": 1})
        cache.put("abc123", "metadata", {"version": 2})
        result = cache.get("abc123", "metadata")
        assert result["data"]["version"] == 2


class TestLoadCache:
    def test_creates_cache(self, tmp_path):
        cache = load_build_id_cache(tmp_path)
        assert isinstance(cache, BuildIDCache)
        assert cache.cache_dir == tmp_path


class TestImportHelpers:
    def test_import_validate_evidence(self, tmp_path):
        cache = BuildIDCache(cache_dir=tmp_path)
        cache.put("abc123", "feasibility", {
            "verdict": "likely_exploitable",
            "mitigations": {"pie": True},
        })
        result = import_validate_evidence(cache, "abc123")
        assert result is not None
        assert result["data"]["verdict"] == "likely_exploitable"

    def test_import_validate_evidence_missing(self, tmp_path):
        cache = BuildIDCache(cache_dir=tmp_path)
        assert import_validate_evidence(cache, "abc123") is None

    def test_import_layer0_findings(self, tmp_path):
        cache = BuildIDCache(cache_dir=tmp_path)
        cache.put("abc123", "layer0-findings", {
            "findings": [{"pattern": "format_string"}],
        })
        result = import_layer0_findings(cache, "abc123")
        assert result is not None
        assert len(result["data"]["findings"]) == 1

    def test_import_layer0_missing(self, tmp_path):
        cache = BuildIDCache(cache_dir=tmp_path)
        assert import_layer0_findings(cache, "abc123") is None
