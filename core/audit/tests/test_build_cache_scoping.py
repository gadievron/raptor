"""Build-ID cache scoping, artifact allowlist, and content binding.

The shared build-ID cache is externally writable (documented public
contract) and its keys are linker-choosable. The binary bridge used to
merge EVERY cached build-id's layer0 findings into every audit as
current-target sink evidence, the artifact allowlist was documented
but unenforced, and nothing bound a cached artifact to the binary
content it was computed from.
"""

from __future__ import annotations

import hashlib
import json


def _mk_cache(tmp_path):
    from core.audit.build_id_cache import BuildIDCache

    return BuildIDCache(cache_dir=tmp_path / "cache")


def _layer0(function="harmless_helper", target="system", binary="/x"):
    return {"findings": [{
        "function": function, "target": target, "binary_path": binary,
    }]}


class TestMergeScoping:
    def test_no_current_build_ids_merges_nothing(self, tmp_path):
        from core.audit.binary_bridge import (
            BinaryBridgeResult,
            _merge_from_build_cache,
        )

        cache = _mk_cache(tmp_path)
        cache.put("deadbeef", "layer0-findings", _layer0())
        result = BinaryBridgeResult()
        _merge_from_build_cache(result, cache, None)
        assert result.sink_edges == [], (
            "cache entries must not merge when the current run's "
            "build-ids are unknown"
        )
        result = BinaryBridgeResult()
        _merge_from_build_cache(result, cache, {})
        assert result.sink_edges == []

    def test_only_current_build_ids_merge(self, tmp_path):
        from core.audit.binary_bridge import (
            BinaryBridgeResult,
            _merge_from_build_cache,
        )

        cache = _mk_cache(tmp_path)
        binary = tmp_path / "prog"
        binary.write_bytes(b"current target binary")
        sha = hashlib.sha256(binary.read_bytes()).hexdigest()
        cache.put("deadbeef", "layer0-findings", _layer0("planted", "system"))
        cache.put("cafe1234", "layer0-findings", _layer0("mine", "exec"),
                  binary_sha256=sha)
        result = BinaryBridgeResult()
        _merge_from_build_cache(result, cache, {"cafe1234": str(binary)})
        assert [e.caller for e in result.sink_edges] == ["mine"], (
            "only entries for binaries in the current target set may "
            "merge as sink evidence"
        )

    def test_content_hash_mismatch_rejected(self, tmp_path):
        from core.audit.binary_bridge import (
            BinaryBridgeResult,
            _merge_from_build_cache,
        )

        cache = _mk_cache(tmp_path)
        binary = tmp_path / "prog"
        binary.write_bytes(b"real binary contents")
        cache.put(
            "cafe1234", "layer0-findings", _layer0("forged"),
            binary_sha256="0" * 64,  # hash of a DIFFERENT binary
        )
        result = BinaryBridgeResult()
        _merge_from_build_cache(result, cache, {"cafe1234": str(binary)})
        assert result.sink_edges == [], (
            "an envelope bound to different binary content must not "
            "merge under a matching build-id"
        )

    def test_content_hash_match_merges(self, tmp_path):
        from core.audit.binary_bridge import (
            BinaryBridgeResult,
            _merge_from_build_cache,
        )

        cache = _mk_cache(tmp_path)
        binary = tmp_path / "prog"
        binary.write_bytes(b"real binary contents")
        sha = hashlib.sha256(binary.read_bytes()).hexdigest()
        cache.put(
            "cafe1234", "layer0-findings", _layer0("genuine"),
            binary_sha256=sha,
        )
        result = BinaryBridgeResult()
        _merge_from_build_cache(result, cache, {"cafe1234": str(binary)})
        assert [e.caller for e in result.sink_edges] == ["genuine"]

    def test_load_binary_bridge_passes_scoping(self, tmp_path, monkeypatch):
        from core.audit.binary_bridge import load_binary_bridge

        cache = _mk_cache(tmp_path)
        cache.put("deadbeef", "layer0-findings", _layer0("planted"))
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        result = load_binary_bridge(
            out_dir, build_id_cache=cache, current_build_ids=None,
        )
        assert result is None, (
            "unscoped cache content must not surface bridge data"
        )


class TestArtifactAllowlist:
    def test_put_rejects_unknown_artifact(self, tmp_path):
        cache = _mk_cache(tmp_path)
        assert cache.put("abc123", "not-a-real-artifact", {"x": 1}) is None
        assert not (tmp_path / "cache" / "abc123").exists()

    def test_get_rejects_unknown_artifact(self, tmp_path):
        cache = _mk_cache(tmp_path)
        entry_dir = tmp_path / "cache" / "abc123"
        entry_dir.mkdir(parents=True)
        (entry_dir / "sneaky.json").write_text(json.dumps({
            "format_version": 1, "build_id": "abc123",
            "artifact": "sneaky", "data": {},
        }))
        assert cache.get("abc123", "sneaky") is None
        assert not cache.has("abc123", "sneaky")

    def test_get_rejects_traversal_artifact(self, tmp_path):
        cache = _mk_cache(tmp_path)
        assert cache.get("abc123", "../../../etc/passwd") is None

    def test_known_artifacts_still_roundtrip(self, tmp_path):
        cache = _mk_cache(tmp_path)
        for name in ("metadata", "layer0-findings", "oracle-verdicts"):
            assert cache.put("abc123", name, {"n": name}) is not None
            entry = cache.get("abc123", name)
            assert entry and entry["data"] == {"n": name}


class TestContentBinding:
    def test_get_with_expected_hash_mismatch_is_miss(self, tmp_path):
        cache = _mk_cache(tmp_path)
        cache.put("abc123", "metadata", {"x": 1}, binary_sha256="a" * 64)
        assert cache.get(
            "abc123", "metadata", expected_binary_sha256="b" * 64,
        ) is None

    def test_get_with_expected_hash_match_reads(self, tmp_path):
        cache = _mk_cache(tmp_path)
        cache.put("abc123", "metadata", {"x": 1}, binary_sha256="a" * 64)
        entry = cache.get(
            "abc123", "metadata", expected_binary_sha256="a" * 64,
        )
        assert entry and entry["data"] == {"x": 1}

    def test_legacy_envelope_without_hash_reads_at_buildid_scope(
        self, tmp_path,
    ):
        cache = _mk_cache(tmp_path)
        cache.put("abc123", "metadata", {"x": 1})
        entry = cache.get(
            "abc123", "metadata", expected_binary_sha256="a" * 64,
        )
        assert entry is not None, (
            "legacy envelopes without a recorded hash stay readable "
            "(documented residual: build-id scope only)"
        )

    def test_store_oracle_verdicts_stamps_binary_hash(self, tmp_path):
        from core.audit.build_id_cache import store_oracle_verdicts

        cache = _mk_cache(tmp_path)
        binary = tmp_path / "prog"
        binary.write_bytes(b"binary bytes")
        sha = hashlib.sha256(binary.read_bytes()).hexdigest()
        inventory = {
            "binary_oracle": {"binaries": [
                {"path": str(binary), "build_id": "abc123",
                 "tier": "full_dwarf"},
            ]},
            "files": [{"items": [{
                "name": "fn",
                "metadata": {"binary_oracle": {"binaries": [
                    {"build_id": "abc123",
                     "classification": "symbol_present",
                     "address": 1, "tier": "full_dwarf"},
                ]}},
            }]}],
        }
        assert store_oracle_verdicts(cache, inventory) == 1
        entry = cache.get("abc123", "oracle-verdicts")
        assert entry.get("binary_sha256") == sha


class TestCurrentBinaryBuildIds:
    def test_extracts_from_inventory(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _current_binary_build_ids,
        )

        (tmp_path / "out").mkdir()
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path / "out",
            inventory={"binary_oracle": {"binaries": [
                {"path": "/bin/a", "build_id": "aa11"},
                {"path": "/bin/b", "build_id": "bb22"},
                {"path": "/bin/c"},  # no build-id — skipped
            ]}},
        )
        assert _current_binary_build_ids(config, None) == {
            "aa11": "/bin/a", "bb22": "/bin/b",
        }

    def test_falls_back_to_checklist(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _current_binary_build_ids,
        )

        (tmp_path / "out").mkdir()
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path / "out",
        )
        checklist = {"binary_oracle": {"binaries": [
            {"path": "/bin/a", "build_id": "aa11"},
        ]}}
        assert _current_binary_build_ids(config, checklist) == {
            "aa11": "/bin/a",
        }

    def test_empty_without_binary_oracle(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _current_binary_build_ids,
        )

        (tmp_path / "out").mkdir()
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path / "out",
        )
        assert _current_binary_build_ids(config, {}) == {}
