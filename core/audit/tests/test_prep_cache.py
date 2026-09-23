"""Tests for the shared prep-cache helper (core.audit.prep_cache).

The per-artifact reload caches (return census, field census, sink
discovery, ...) all ride this seam: deterministic input fingerprints,
fingerprint-gated reload, loud rebuild on mismatch/corruption, atomic
best-effort writes.
"""

from __future__ import annotations

import json

from core.audit.prep_cache import (
    PREP_CACHE_DIRNAME,
    content_fingerprint,
    load_prep_cache,
    prep_cache_path,
    source_fingerprint,
    write_prep_cache,
)


class TestFingerprints:
    def test_source_fingerprint_deterministic_and_order_free(self):
        a = {"x.c": "int f(void);\n", "y.c": "int g(void);\n"}
        b = dict(reversed(list(a.items())))
        assert source_fingerprint(a) == source_fingerprint(b)

    def test_source_fingerprint_changes_with_content(self):
        base = {"x.c": "int f(void);\n"}
        assert source_fingerprint(base) != source_fingerprint(
            {"x.c": "int f(void) { return 1; }\n"},
        )

    def test_source_fingerprint_changes_with_path(self):
        assert source_fingerprint({"a.c": "src"}) != source_fingerprint(
            {"b.c": "src"},
        )

    def test_content_fingerprint_is_order_sensitive(self):
        items = [("a", b"1"), ("b", b"2")]
        assert content_fingerprint(items) != content_fingerprint(
            list(reversed(items)),
        )

    def test_content_fingerprint_separates_name_and_content(self):
        # ("ab", "c") must not collide with ("a", "bc").
        assert content_fingerprint([("ab", b"c")]) != content_fingerprint(
            [("a", b"bc")],
        )


class TestLoadWriteCycle:
    def test_round_trip(self, tmp_path):
        payload = {"rows": [1, 2, 3], "nested": {"k": "v"}}
        write_prep_cache(tmp_path, "artifact.json", "fp1", payload,
                         label="test")
        assert prep_cache_path(tmp_path, "artifact.json").is_file()
        assert load_prep_cache(
            tmp_path, "artifact.json", "fp1", label="test",
        ) == payload

    def test_missing_file_is_a_miss(self, tmp_path):
        assert load_prep_cache(
            tmp_path, "absent.json", "fp1", label="test",
        ) is None

    def test_fingerprint_mismatch_is_a_miss(self, tmp_path):
        write_prep_cache(tmp_path, "artifact.json", "fp1", {"a": 1},
                         label="test")
        assert load_prep_cache(
            tmp_path, "artifact.json", "fp2", label="test",
        ) is None

    def test_corrupt_cache_is_a_miss(self, tmp_path):
        cache_dir = tmp_path / PREP_CACHE_DIRNAME
        cache_dir.mkdir()
        (cache_dir / "artifact.json").write_text("{nope")
        assert load_prep_cache(
            tmp_path, "artifact.json", "fp1", label="test",
        ) is None

    def test_write_is_atomic_no_tmp_left_behind(self, tmp_path):
        write_prep_cache(tmp_path, "artifact.json", "fp1", {"a": 1},
                         label="test")
        leftovers = list((tmp_path / PREP_CACHE_DIRNAME).glob("*.tmp"))
        assert leftovers == []

    def test_write_failure_never_raises(self, tmp_path):
        # A file where the cache DIRECTORY should be: mkdir fails.
        (tmp_path / PREP_CACHE_DIRNAME).write_text("in the way")
        write_prep_cache(tmp_path, "artifact.json", "fp1", {"a": 1},
                         label="test")  # must not raise

    def test_failed_replace_leaves_no_tmp_behind(
        self, tmp_path, monkeypatch,
    ):
        # Disk-full-shaped failure between the tempfile write and the
        # atomic rename: the temp file must not strand in the cache
        # dir. Pins the seam property regardless of which writer
        # implements it (today: core.atomic_fs).
        import os

        def failing_replace(src, dst):
            raise OSError("simulated disk full")

        monkeypatch.setattr(os, "replace", failing_replace)
        write_prep_cache(tmp_path, "artifact.json", "fp1", {"a": 1},
                         label="test")  # must not raise
        leftovers = list((tmp_path / PREP_CACHE_DIRNAME).glob("*.tmp"))
        assert leftovers == []
        assert not prep_cache_path(tmp_path, "artifact.json").exists()

    def test_unserialisable_payload_never_raises(self, tmp_path):
        write_prep_cache(tmp_path, "artifact.json", "fp1", {"a": object()},
                         label="test")  # must not raise
        assert load_prep_cache(
            tmp_path, "artifact.json", "fp1", label="test",
        ) is None

    def test_file_shape_carries_fingerprint_and_payload(self, tmp_path):
        write_prep_cache(tmp_path, "artifact.json", "fp1", [1, 2],
                         label="test")
        data = json.loads(
            prep_cache_path(tmp_path, "artifact.json").read_text(),
        )
        assert data["fingerprint"] == "fp1"
        assert data["payload"] == [1, 2]


class TestIntegrityBinding:
    """The cache lives in the target-writable run dir and its
    fingerprint is computed over attacker-knowable inputs with a
    public recipe — fingerprint equality authenticates nothing. Only
    a payload whose run-bound MAC token verifies may hit; everything
    else is a miss (fail toward recompute)."""

    def test_written_row_carries_integrity_token(self, tmp_path):
        write_prep_cache(tmp_path, "artifact.json", "fp1", [1],
                         label="test")
        data = json.loads(
            prep_cache_path(tmp_path, "artifact.json").read_text(),
        )
        assert isinstance(data.get("integrity"), str)

    def test_forged_unstamped_payload_is_a_miss(self, tmp_path):
        # An attacker holding the run-dir write grant can write any
        # bytes and recompute the public fingerprint; they cannot
        # mint a token.
        cache_dir = tmp_path / PREP_CACHE_DIRNAME
        cache_dir.mkdir()
        (cache_dir / "detector-results.json").write_text(json.dumps({
            "fingerprint": "fp1",
            "payload": {"results": [], "forged": "by-run-dir-writer"},
        }))
        assert load_prep_cache(
            tmp_path, "detector-results.json", "fp1", label="test",
        ) is None

    def test_tampered_payload_is_a_miss(self, tmp_path):
        write_prep_cache(tmp_path, "artifact.json", "fp1",
                         {"results": ["real"]}, label="test")
        path = prep_cache_path(tmp_path, "artifact.json")
        data = json.loads(path.read_text())
        data["payload"] = {"results": []}
        path.write_text(json.dumps(data))
        assert load_prep_cache(
            tmp_path, "artifact.json", "fp1", label="test",
        ) is None

    def test_cross_run_replay_is_a_miss(self, tmp_path):
        # A validly-stamped cache copied verbatim from a SIBLING run
        # dir fails the run binding.
        run_a = tmp_path / "a"
        run_a.mkdir()
        run_b = tmp_path / "b"
        (run_b / PREP_CACHE_DIRNAME).mkdir(parents=True)
        write_prep_cache(run_a, "artifact.json", "fp1", [1],
                         label="test")
        (run_b / PREP_CACHE_DIRNAME / "artifact.json").write_bytes(
            prep_cache_path(run_a, "artifact.json").read_bytes(),
        )
        assert load_prep_cache(
            run_b, "artifact.json", "fp1", label="test",
        ) is None
        # The genuine home still hits.
        assert load_prep_cache(
            run_a, "artifact.json", "fp1", label="test",
        ) == [1]
