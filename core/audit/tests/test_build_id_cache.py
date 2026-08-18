"""Tests for core.audit.build_id_cache."""

from __future__ import annotations

import json

from core.audit.build_id_cache import (
    BuildIDCache,
    import_layer0_findings,
    import_validate_evidence,
    load_build_id_cache,
    store_oracle_verdicts,
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

    def test_put_invalid_build_id_returns_none(self, tmp_path):
        """Non-hex build IDs are rejected (path-traversal defence)."""
        cache = BuildIDCache(cache_dir=tmp_path)
        assert cache.put("../../etc", "metadata", {"x": 1}) is None
        assert cache.put("", "metadata", {"x": 1}) is None
        # Nothing escaped or landed in the cache dir
        assert list(tmp_path.iterdir()) == []

    def test_put_valid_build_id_returns_path(self, tmp_path):
        cache = BuildIDCache(cache_dir=tmp_path)
        path = cache.put("abc123", "metadata", {"x": 1})
        assert path is not None
        assert path.is_file()

    def test_get_and_has_reject_invalid_build_id(self, tmp_path):
        cache = BuildIDCache(cache_dir=tmp_path)
        assert cache.get("../../etc", "metadata") is None
        assert cache.has("../../etc", "metadata") is False

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


class TestFormatVersioning:
    """The on-disk layout is a public contract shared with external
    consumers — the version must be recorded and detectable."""

    def test_marker_written_on_first_put(self, tmp_path):
        cache = BuildIDCache(cache_dir=tmp_path)
        cache.put("abc123", "metadata", {"x": 1})
        marker = json.loads((tmp_path / "format.json").read_text())
        assert marker == {"format_version": 1}

    def test_envelope_carries_version(self, tmp_path):
        cache = BuildIDCache(cache_dir=tmp_path)
        path = cache.put("abc123", "metadata", {"x": 1})
        assert json.loads(path.read_text())["format_version"] == 1

    def test_existing_marker_left_untouched(self, tmp_path):
        (tmp_path / "format.json").write_text('{"format_version": 1, "writer": "other-tool"}')
        cache = BuildIDCache(cache_dir=tmp_path)
        cache.put("abc123", "metadata", {"x": 1})
        assert "other-tool" in (tmp_path / "format.json").read_text()

    def test_future_version_envelope_reads_as_miss(self, tmp_path):
        """An artifact written by a NEWER producer must not be
        misinterpreted — it reads as a cache miss."""
        cache = BuildIDCache(cache_dir=tmp_path)
        entry_dir = tmp_path / "abc123"
        entry_dir.mkdir()
        (entry_dir / "metadata.json").write_text(json.dumps({
            "format_version": 99,
            "build_id": "abc123",
            "artifact": "metadata",
            "data": {"shape": "unknown"},
        }))
        assert cache.get("abc123", "metadata") is None

    def test_legacy_envelope_without_version_still_reads(self, tmp_path):
        """Pre-versioning envelopes (no format_version field) are
        format 1 by definition."""
        cache = BuildIDCache(cache_dir=tmp_path)
        entry_dir = tmp_path / "abc123"
        entry_dir.mkdir()
        (entry_dir / "metadata.json").write_text(json.dumps({
            "build_id": "abc123",
            "artifact": "metadata",
            "source_command": "",
            "data": {"pie": True},
        }))
        result = cache.get("abc123", "metadata")
        assert result is not None
        assert result["data"]["pie"] is True


def _enriched_inventory(build_id="ab12cd34", path="/build/app"):
    """Inventory shaped like enrich_inventory_with_binary_oracle's output."""
    return {
        "binary_oracle": {
            "binaries": [{"path": path, "build_id": build_id, "tier": "full"}],
            "counts": {"classified": 2},
            "earns_suppression": True,
        },
        "files": [
            {
                "path": "src/a.c",
                "language": "c",
                "items": [
                    {
                        "kind": "function",
                        "name": "parse_header",
                        "metadata": {
                            "binary_oracle": {
                                "classification": "symbol_present",
                                "binaries": [{
                                    "path": path,
                                    "build_id": build_id,
                                    "classification": "symbol_present",
                                    "address": 4096,
                                    "tier": "full",
                                }],
                            },
                        },
                    },
                    {
                        "kind": "function",
                        "name": "dead_helper",
                        "metadata": {
                            "binary_oracle": {
                                "classification": "absent",
                                "binaries": [{
                                    "path": path,
                                    "build_id": build_id,
                                    "classification": "absent",
                                    "address": None,
                                    "tier": "full",
                                }],
                            },
                        },
                    },
                ],
            },
        ],
    }


class TestStoreOracleVerdicts:
    def test_populates_per_build_id(self, tmp_path):
        cache = BuildIDCache(cache_dir=tmp_path)
        written = store_oracle_verdicts(
            cache, _enriched_inventory(), source_command="test",
        )
        assert written == 1
        entry = cache.get("ab12cd34", "oracle-verdicts")
        assert entry is not None
        data = entry["data"]
        assert data["binary_path"] == "/build/app"
        assert data["tier"] == "full"
        assert data["verdicts"]["parse_header"]["classification"] == "symbol_present"
        assert data["verdicts"]["dead_helper"]["classification"] == "absent"

    def test_build_id_change_invalidates(self, tmp_path):
        """A rebuilt binary (new build-ID) never sees the old entry."""
        cache = BuildIDCache(cache_dir=tmp_path)
        store_oracle_verdicts(cache, _enriched_inventory(build_id="aaaa1111"))
        assert cache.get("aaaa1111", "oracle-verdicts") is not None
        # Same binary path, new build-ID: old artifacts don't apply.
        assert cache.get("bbbb2222", "oracle-verdicts") is None
        assert cache.available_artifacts("bbbb2222") == []

    def test_hostile_build_id_skipped(self, tmp_path):
        inv = _enriched_inventory(build_id="../../evil")
        cache = BuildIDCache(cache_dir=tmp_path)
        assert store_oracle_verdicts(cache, inv) == 0
        # Nothing escaped the cache dir and nothing was written.
        assert list(tmp_path.iterdir()) == []
        assert not (tmp_path.parent / "evil").exists()

    def test_malformed_inventory_is_noop(self, tmp_path):
        cache = BuildIDCache(cache_dir=tmp_path)
        assert store_oracle_verdicts(cache, {}) == 0
        assert store_oracle_verdicts(cache, {"binary_oracle": None}) == 0
        assert store_oracle_verdicts(
            cache,
            {"binary_oracle": {"binaries": [{"build_id": "ab12"}]},
             "files": [{"items": [None]}, None]},
        ) == 0


class TestBridgeRoundTrip:
    """Populate-then-merge through the production consumption seam."""

    def test_populate_then_merge_layer0(self, tmp_path):
        from core.audit.binary_bridge import load_binary_bridge

        cache = BuildIDCache(cache_dir=tmp_path / "cache")
        cache.put("ab12cd34", "layer0-findings", {
            "findings": [
                {"function": "parse_header", "target": "sprintf",
                 "binary_path": "/build/app"},
            ],
        }, source_command="external-tool")

        out_dir = tmp_path / "out" / "run1"
        out_dir.mkdir(parents=True)
        result = load_binary_bridge(out_dir, build_id_cache=cache)
        assert result is not None
        assert ("parse_header", "sprintf") in {
            (e.caller, e.sink) for e in result.sink_edges
        }

    def test_partial_cache_tolerated(self, tmp_path):
        """A build-ID dir holding only SOME artifacts (e.g. written by
        the external consumer) is valid — missing files are misses,
        present ones load, and the bridge merge doesn't error."""
        from core.audit.binary_bridge import load_binary_bridge

        cache = BuildIDCache(cache_dir=tmp_path / "cache")
        cache.put("ab12cd34", "metadata", {"pie": True})
        # No layer0-findings, no oracle-verdicts.
        assert cache.get("ab12cd34", "layer0-findings") is None
        assert cache.get("ab12cd34", "metadata") is not None
        assert cache.available_artifacts("ab12cd34") == ["metadata"]

        out_dir = tmp_path / "out" / "run1"
        out_dir.mkdir(parents=True)
        # Nothing mergeable → bridge reports no data (None), not an error.
        assert load_binary_bridge(out_dir, build_id_cache=cache) is None

    def test_populate_then_oracle_verdict_reuse(self, tmp_path):
        """Round-trip for the artifact the oracle flow populates."""
        cache = BuildIDCache(cache_dir=tmp_path)
        store_oracle_verdicts(cache, _enriched_inventory())
        cache2 = load_build_id_cache(tmp_path)  # fresh handle, same dir
        entry = cache2.get("ab12cd34", "oracle-verdicts")
        assert entry is not None
        assert entry["data"]["verdicts"]["dead_helper"]["classification"] == "absent"
